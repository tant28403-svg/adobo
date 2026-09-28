"""The lab target: a deliberately fragile service you can harden.

This is the *other* half of the tool. An attack generator on its own only proves
you can send packets; the interesting measurement is what the target does with
them. So the app ships in two shapes:

* **no defenses** - unbounded work, no timeouts, no load shedding. It saturates,
  then degrades, then stops answering. This is the baseline you attack.
* **defenses enabled** - rate limiting, a connection cap, a WAF, a circuit
  breaker, a challenge page. Load is shed deliberately and the service stays
  reachable for legitimate users.

Endpoints:

    GET /healthz    cheap liveness check, what the prober hits
    GET /           a small page, plus deliberate per-request work
    GET /api/data   the expensive one: simulates a database query

The work in ``/api/data`` is intentionally CPU-bound and configurable, so a run
can be pushed to the point of saturation without needing real data behind it.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import Any, Iterable
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from ..defenses import (
    ChallengeGate,
    CircuitBreaker,
    ConnectionCap,
    Decision,
    RateLimiter,
    RequestFacts,
    Verdict,
    WafEngine,
    WafRules,
    load_waf_rules,
)
from ..models import DefenseName

__all__ = ["TargetSettings", "create_app", "run_target", "generate_self_signed_cert"]

DEFAULT_WORK_MS = 6
"""Simulated database work per /api/data request. Tuned so an unhardened target
saturates a single core well inside the default policy ceiling of 20k pps."""

DEFAULT_EXEMPT_PATHS = ("/healthz", "/stats")
"""Paths that bypass every mitigation.

This is not a convenience - it is a correctness requirement, for two reasons:

* **The measurement would be invalid without it.** The prober hits ``/healthz``
  from the same address as the flood. If the rate limiter or the WAF's volume
  rules could shed it, every run would end up measuring the mitigation blocking
  its own instrumentation rather than the target's health.
* **A real service would kill itself.** If ``/healthz`` can be rate limited, an
  orchestrator will conclude the pod is unhealthy during the attack and restart
  it. That is a worse outcome than serving degraded responses, and it is exactly
  the "collapse instead of degrade" behaviour this tool exists to detect.

Allowlisting the monitoring path from the edge is standard production practice.
"""


def generate_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    *,
    hostname: str = "localhost",
    valid_days: int = 365,
) -> None:
    """Generate a self-signed certificate for testing.

    Creates a certificate suitable for local testing. Not for production use.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=valid_days)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(hostname)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Write private key
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Write certificate
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class TargetSettings:
    """Everything about the target that a run might want to vary."""

    def __init__(
        self,
        defenses: Iterable[DefenseName] = (),
        *,
        waf_rules: WafRules | None = None,
        work_ms: int = DEFAULT_WORK_MS,
        rate_per_second: float = 50.0,
        burst: int = 100,
        connection_limit: int = 64,
        failure_threshold: int = 5,
        cooldown_seconds: float = 5.0,
        challenge_threshold: int = 5,
        exempt_paths: Iterable[str] | None = None,
        host: str = "127.0.0.1",
        port: int = 8000,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
        http2: bool = False,
    ) -> None:
        self.defenses = [d for d in defenses if d is not DefenseName.NONE]
        self.waf_rules = waf_rules if waf_rules is not None else load_waf_rules()
        self.work_ms = work_ms
        self.host = host
        self.port = port
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        self.http2 = http2
        self.exempt_paths = set(
            exempt_paths if exempt_paths is not None else DEFAULT_EXEMPT_PATHS
        )

        self.rate_limiter = (
            RateLimiter(rate_per_second, burst) if DefenseName.RATE_LIMIT in self.defenses else None
        )
        self.connection_cap = (
            ConnectionCap(connection_limit)
            if DefenseName.CONNECTION_CAP in self.defenses
            else None
        )
        self.waf = WafEngine(self.waf_rules) if DefenseName.WAF in self.defenses else None
        self.circuit_breaker = (
            CircuitBreaker(failure_threshold, cooldown_seconds)
            if DefenseName.CIRCUIT_BREAKER in self.defenses
            else None
        )
        self.challenge = (
            ChallengeGate(challenge_threshold)
            if DefenseName.CHALLENGE_PAGE in self.defenses
            else None
        )

    def active(self) -> list[str]:
        return [d.value for d in self.defenses]

    def stats(self) -> dict[str, Any]:
        stats: dict[str, Any] = {"defenses": self.active(), "work_ms": self.work_ms}
        if self.rate_limiter is not None:
            stats["rate_limiter"] = {"rate": self.rate_limiter.rate, "burst": self.rate_limiter.burst}
        if self.connection_cap is not None:
            stats["connection_cap"] = {
                "limit": self.connection_cap.limit,
                "peak": self.connection_cap.peak,
                "rejected": self.connection_cap.rejected,
            }
        if self.waf is not None:
            stats["waf"] = self.waf.stats()
        if self.circuit_breaker is not None:
            stats["circuit_breaker"] = {"state": self.circuit_breaker.state, "trips": self.circuit_breaker.trips}
        if self.challenge is not None:
            stats["challenge"] = {"served": self.challenge.served}
        return stats


def _facts_from(request: Request) -> RequestFacts:
    client = request.client.host if request.client else "unknown"
    return RequestFacts(
        path=request.url.path,
        method=request.method,
        user_agent=request.headers.get("user-agent"),
        client=client,
        headers={k.lower(): v for k, v in request.headers.items()},
    )


def _verdict_response(verdict: Verdict) -> JSONResponse:
    if verdict.decision is Decision.CHALLENGE:
        return JSONResponse(
            status_code=503,
            content={
                "status": "challenge_required",
                "reason": verdict.reason or "prove you are a browser, then retry",
                "rule": verdict.rule_id,
                "score": verdict.score,
                "hint": "solve the challenge and retry the same request",
            },
            headers={"Retry-After": "5"},
        )
    return JSONResponse(
        status_code=403,
        content={
            "status": "blocked",
            "reason": verdict.reason or "request rejected by policy",
            "rule": verdict.rule_id,
            "score": verdict.score,
        },
    )


def _burn_cpu(ms: int) -> None:
    """Simulate a database round trip.

    Synchronous on purpose: it is offloaded to a thread executor by
    :func:`asyncio.to_thread`, so declaring it ``async`` would return an
    un-awaited coroutine and quietly do no work at all.

    ``asyncio.sleep`` would not load anything either, because it yields the event
    loop. A busy loop in a worker thread is what actually makes a
    single-threaded server saturate, which is the behaviour under test.
    """
    if ms <= 0:
        return
    deadline = time.perf_counter() + (ms / 1000.0)
    while time.perf_counter() < deadline:
        pass


def create_app(settings: TargetSettings | None = None) -> FastAPI:
    """Build the target application."""
    config = settings or TargetSettings()
    app = FastAPI(
        title="adobo lab target",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    app.state.settings = config
    app.state.requests = 0
    app.state.errors = 0

    @app.middleware("http")
    async def mitigations(request: Request, call_next):
        facts = _facts_from(request)

        # Monitoring endpoints bypass every mitigation - see
        # DEFAULT_EXEMPT_PATHS for why this is load-bearing rather than a
        # convenience.
        if request.url.path in config.exempt_paths:
            return await call_next(request)

        # -- circuit breaker: refuse while the dependency is known-bad -------
        if config.circuit_breaker is not None and not config.circuit_breaker.allow():
            app.state.errors += 1
            return JSONResponse(
                status_code=503,
                content={"status": "circuit_open", "reason": "upstream is unhealthy"},
                headers={"Retry-After": "2"},
            )

        # -- WAF: static rules and volume -----------------------------------
        if config.waf is not None:
            verdict = config.waf.evaluate(facts)
            if not verdict.allowed:
                if config.challenge is not None:
                    config.challenge.register_failure(facts.client)
                app.state.errors += 1
                return _verdict_response(verdict)

        # -- challenge gate --------------------------------------------------
        # Deliberately ahead of the rate limiter. If the rate limiter ran first, a
        # client that trips it would be flat 429'd forever and never be offered a
        # challenge, which makes this gate dead code whenever both mitigations are
        # enabled. A 503 challenge is something a legitimate client can solve; a
        # 429 is not, so the recoverable response has to come first.
        if config.challenge is not None and config.challenge.needs_challenge(facts.client):
            app.state.errors += 1
            return _verdict_response(config.challenge.serve_challenge())

        # -- rate limit ------------------------------------------------------
        if config.rate_limiter is not None and not config.rate_limiter.allow(facts.client):
            if config.challenge is not None:
                config.challenge.register_failure(facts.client)
            app.state.errors += 1
            return JSONResponse(
                status_code=429,
                content={"status": "rate_limited", "reason": "too many requests"},
                headers={"Retry-After": "1"},
            )

        # -- connection cap --------------------------------------------------
        if config.connection_cap is not None and not config.connection_cap.acquire():
            app.state.errors += 1
            return JSONResponse(
                status_code=503,
                content={"status": "overloaded", "reason": "too many requests in flight"},
                headers={"Retry-After": "1"},
            )

        try:
            response = await call_next(request)
        except Exception:
            if config.circuit_breaker is not None:
                config.circuit_breaker.record_failure()
            app.state.errors += 1
            raise
        else:
            if config.circuit_breaker is not None:
                config.circuit_breaker.record_success()
            if config.challenge is not None:
                config.challenge.register_success(facts.client)
        finally:
            if config.connection_cap is not None:
                config.connection_cap.release()

        app.state.requests += 1
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        """Liveness. Deliberately does no work, so it stays cheap under load.

        If this endpoint starts timing out, the whole process is saturated - which
        is the signal the prober is looking for.
        """
        return {"status": "ok", "defenses": config.active()}

    @app.get("/")
    async def index() -> dict[str, Any]:
        return {
            "service": "adobo lab target",
            "defenses": config.active(),
            "endpoints": ["/healthz", "/api/data"],
        }

    @app.get("/api/data")
    async def api_data() -> dict[str, Any]:
        await asyncio.to_thread(_burn_cpu, config.work_ms)
        return {
            "status": "ok",
            "records": 42,
            "work_ms": config.work_ms,
            "served": app.state.requests,
        }

    @app.get("/admin")
    async def admin() -> dict[str, Any]:
        await asyncio.to_thread(_burn_cpu, config.work_ms)
        return {"status": "ok", "panel": "this path exists so the WAF has something to protect"}

    @app.get("/stats")
    async def stats() -> dict[str, Any]:
        """What the target has observed, for correlating with the attack side."""
        return {
            "requests": app.state.requests,
            "errors": app.state.errors,
            "settings": config.stats(),
        }

    @app.get("/api/flaky")
    async def flaky(fail: bool = False) -> dict[str, Any]:
        """A route that can fail on demand, standing in for a flaky dependency.

        The circuit breaker needs something to actually break, and every other
        endpoint here succeeds unconditionally. ``/api/flaky?fail=true`` raises,
        which is what lets a run demonstrate the breaker opening, holding load off
        a struggling dependency, and closing again once it recovers.
        """
        if fail:
            raise RuntimeError("simulated upstream failure")
        return {"status": "ok", "dependency": "healthy"}

    @app.get("/slow")
    async def slow() -> PlainTextResponse:
        """A route that can be pushed past a probe timeout on purpose."""
        await asyncio.to_thread(_burn_cpu, config.work_ms * 20)
        return PlainTextResponse("slow response")

    return app


def run_target(
    settings: TargetSettings | None = None,
    *,
    log_level: str = "warning",
    http2: bool = False,
) -> None:
    """Serve the target until interrupted.

    Bound to loopback by default. Serving this on a routable interface would put
    an intentionally fragile service on a network, which is exactly the situation
    the allowlist exists to prevent.

    If ssl_certfile and ssl_keyfile are provided, serves over HTTPS.
    If http2 is True, enables HTTP/2 (requires SSL).
    """
    import ssl
    import uvicorn

    config = settings or TargetSettings()
    uvicorn_kwargs = {
        "app": create_app(config),
        "host": config.host,
        "port": config.port,
        "log_level": log_level,
        "access_log": False,
    }
    if config.ssl_certfile and config.ssl_keyfile:
        uvicorn_kwargs["ssl_certfile"] = config.ssl_certfile
        uvicorn_kwargs["ssl_keyfile"] = config.ssl_keyfile
    if http2 and config.ssl_certfile and config.ssl_keyfile:
        # Create SSL context with ALPN for HTTP/2
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(config.ssl_certfile, config.ssl_keyfile)
        ssl_ctx.set_alpn_protocols(['h2'])
        uvicorn_kwargs["ssl_context"] = ssl_ctx
        # Don't pass certfile/keyfile when using custom ssl_context
        uvicorn_kwargs.pop("ssl_certfile", None)
        uvicorn_kwargs.pop("ssl_keyfile", None)

    uvicorn.run(**uvicorn_kwargs)
