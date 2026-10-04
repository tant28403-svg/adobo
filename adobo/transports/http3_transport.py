"""HTTP/3 transport - HTTP over QUIC, the third protocol alongside HTTP/1.1 and h2.

**Why this transport owns its own event loop.** ``aioquic`` is async-only, and
every other transport here is thread-based: the engine hands each worker thread a
transport and expects ``worker_loop`` to own its pacing until the deadline. The
two do not meet anywhere, so this transport closes the gap by running its loop on
the worker's *own* thread rather than handing work to a loop elsewhere.

That choice matters more than it looks. The alternative - one loop thread shared
by every worker, with ``send_one`` submitting a coroutine and blocking on the
result - adds a thread hand-off to the critical path of every single packet, and
``run_coroutine_threadsafe(...).result()`` cannot be interrupted: a worker
parked on that call would ignore ``request_stop()`` until the coroutine
returned, which is precisely the abandonment bug the engine's join grace exists
to prevent. Running the loop inline has no hand-off to interrupt, so
``request_stop()`` ends the run when the deadline passes.

It is also why this is a self-paced ``worker_loop`` transport like slowloris
rather than a ``send_one`` transport: the pacing belongs inside the coroutine,
next to the send, instead of in a synchronous caller across a thread boundary.

**Counters are honest about what UDP cannot tell us.** ``bytes_received`` and
``responses`` stay at zero, and that is the correct answer rather than a gap.
A UDP datagram is not acknowledged: there is no "received" to count, so any
figure here would be invented. The amplification machinery already treats an
absent measured factor as "not measurable", and this transport keeps it that way
instead of reporting a number that would flow into a resilience score.

**Why the headers are built here rather than by ``build_payload``.** HTTP/3
carries headers as HPACK/QPACK frames over its own connection, not as bytes on a
socket. The HTTP/1.1 request text ``build_payload`` produces cannot be sent on
this transport at all, so the header block is assembled for the protocol
instead - the same host, path, method and persona values, in the shape h3
requires.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, ClassVar

from ..models import AttackProfile, ProfileName, Target, TransportKind
from .base import Transport, TransportError, supports_profile

__all__ = ["H3Probe", "Http3Transport", "aioquic_available", "h3_probe"]

DEFAULT_CONNECT_TIMEOUT = 5.0
"""Seconds for the QUIC handshake, which includes several round trips.

Longer than the TCP transport's one second on purpose. QUIC's handshake is
1-RTT at best and has to establish its own loss recovery and key schedule, so a
one-second budget fails against a healthy target that merely needed two more
round trips - and the failure would be reported as the target refusing traffic.
"""

#: One HTTP/3 stream per request, as a real client does. The engine's batching
#: is a sender-side convenience; each request gets its own stream so responses
#: can be correlated and so a head-of-line block on one cannot stall the rest.
_STREAM_ID = 0


DEFAULT_USER_AGENT = "adobo-lab/0.1 (authorized testing)"
"""The self-identifying agent used when no persona is configured, matching the
default the HTTP/1.1 payload builder sends. A run with no persona has to look the
same on h3 as it does everywhere else, or 'no impersonation' would not be a
consistent claim across transports."""


def _user_agent(persona: Any) -> str:
    """The agent string for *persona*, or the honest default for None."""
    return persona.user_agent if persona is not None else DEFAULT_USER_AGENT


_CLIENT_PROTOCOL: Any = None


def _client_protocol_class() -> Any:
    """The QUIC protocol class this transport connects with, built once.

    aioquic's ``QuicConnectionProtocol`` does not create an HTTP/3 connection for
    you: it negotiates QUIC and stops there. The H3 layer has to be built by hand
    when ``ProtocolNegotiated`` arrives, on the client exactly as on the server.
    Reaching for a ``_h3_connection`` attribute that does not exist is the obvious
    mistake here, and it fails at the first send rather than at connect - which
    is late enough that a connection-only test would never see it.

    Built lazily because aioquic is an optional dependency: importing it at
    module scope would make ``adobo --help`` fail on a machine that has every
    other transport working.
    """
    global _CLIENT_PROTOCOL
    if _CLIENT_PROTOCOL is not None:
        return _CLIENT_PROTOCOL

    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.events import ProtocolNegotiated

    class _H3ClientProtocol(QuicConnectionProtocol):
        """A QUIC client that also speaks HTTP/3."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.http: Any = None
            self.bytes_sent = 0
            # Status per stream, for the prober. Without this the prober cannot
            # tell a 200 from a 503, and an availability figure that cannot see
            # the status code is not measuring availability.
            self.status_by_stream: dict[int, int] = {}

        def connection_made(self, transport: Any) -> None:
            """Count the bytes that actually leave the process.

            aioquic discards the datagram lengths inside ``transmit()``, and the
            alternative - counting the length of the request body - reports zero
            for every request, because an HTTP/3 GET has no body. So a run
            reported "626 packets (0 bytes)", which is worse than no figure: it
            looks like a measurement and contradicts the packet count beside it.

            Wrapping the endpoint's sendto measures the real thing and does not
            depend on aioquic's internals, so it survives the library changing
            how ``transmit()`` is written. Includes QUIC and QPACK framing and
            any retransmission, which the HTTP/1.1 path's payload-only count does
            not - each is honest about what it measures, and the run note says so.
            """
            super().connection_made(transport)
            real_sendto = transport.sendto
            counter = self

            def _counting_sendto(data, addr=None):
                counter.bytes_sent += len(data)
                if addr is None:
                    return real_sendto(data)
                return real_sendto(data, addr)

            transport.sendto = _counting_sendto

        def quic_event_received(self, event: Any) -> None:
            if isinstance(event, ProtocolNegotiated):
                self.http = H3Connection(self._quic)
            if self.http is not None:
                # Status codes are recorded; the bodies and the event count are
                # not. A UDP datagram is not acknowledged, so a tally of what
                # this process happened to receive is not a count of anything the
                # target confirmed. The status is different: it is the target
                # stating how it is doing, which is the one thing availability
                # actually means.
                for h3_event in self.http.handle_event(event):
                    if isinstance(h3_event, HeadersReceived):
                        fields = dict(h3_event.headers)
                        try:
                            self.status_by_stream[h3_event.stream_id] = int(
                                fields.get(b":status", b"0")
                            )
                        except (TypeError, ValueError):
                            pass

    _CLIENT_PROTOCOL = _H3ClientProtocol
    return _CLIENT_PROTOCOL


@dataclass(frozen=True)
class H3Probe:
    """The outcome of one HTTP/3 availability probe.

    ``ok`` follows the same rule as the httpx prober: a status under 500 counts
    as available. ``error`` is None for a status under 400, matching
    :meth:`adobo.engine.RunEngine._single_probe`, so a 503 reads the same way
    whichever protocol produced it.
    """

    ok: bool
    status_code: int | None
    latency_ms: float
    error: str | None


async def h3_probe(
    host: str,
    port: int,
    path: str,
    *,
    timeout: float,
    tls_verify: bool = True,
) -> H3Probe:
    """One HTTP/3 GET against *host*, for the availability prober.

    Without this, an h3 run is probed over HTTP/1.1 on TCP against a target that
    only speaks QUIC. Windows blackholes that connection rather than refusing it,
    so the probe times out, the run reports 0% availability, and a target
    serving perfectly scores 0/100. That is the tool making a confident false
    claim about a live machine, which is worse than reporting nothing at all.

    One connection per probe. Reusing one would be faster, but the prober exists
    to answer "is it up right now", and a held connection keeps answering from a
    state that may predate the load - it would report availability long after the
    target stopped serving. An h2 connection's 100 streams do not buy much either
    at a probe interval measured in hundreds of milliseconds.
    """
    import ssl

    from aioquic.asyncio import connect
    from aioquic.h3.connection import H3_ALPN
    from aioquic.quic.configuration import QuicConfiguration

    started = time.perf_counter()
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_REQUIRED if tls_verify else ssl.CERT_NONE,
        server_name=host,
    )
    manager = connect(host, port, configuration=config,
                      create_protocol=_client_protocol_class())
    try:
        protocol = await asyncio.wait_for(manager.__aenter__(), timeout=timeout)
    except asyncio.TimeoutError:
        await _close_probe(manager)
        return H3Probe(False, None, _elapsed_ms(started),
                       f"ConnectTimeout: no HTTP/3 handshake within {timeout:g}s")
    except Exception as exc:  # noqa: BLE001 - aioquic raises broadly
        await _close_probe(manager)
        detail = str(exc).strip() or f"{type(exc).__name__} with no detail"
        return H3Probe(False, None, _elapsed_ms(started),
                       f"{type(exc).__name__}: {detail}")

    try:
        h3 = getattr(protocol, "http", None)
        if h3 is None:
            return H3Probe(False, None, _elapsed_ms(started),
                           "no HTTP/3: the target negotiated QUIC but not h3")
        stream_id = 0
        h3.send_headers(
            stream_id=stream_id,
            headers=_probe_headers(host, port, path),
            end_stream=True,
        )
        protocol.transmit()

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while stream_id not in protocol.status_by_stream:
            if loop.time() >= deadline:
                return H3Probe(
                    False, None, _elapsed_ms(started),
                    f"ReadTimeout: no HTTP/3 response within {timeout:g}s",
                )
            await asyncio.sleep(0.005)

        status = protocol.status_by_stream[stream_id]
        return H3Probe(
            ok=status < 500,
            status_code=status,
            latency_ms=_elapsed_ms(started),
            error=None if status < 400 else f"HTTP {status}",
        )
    finally:
        await _close_probe(manager)


def _probe_headers(host: str, port: int, path: str) -> list[tuple[bytes, bytes]]:
    """The prober's request headers.

    No persona and no accept header: this is the tool checking whether the target
    is alive, not a request meant to look like anything. It uses the same
    self-identifying agent as every other h3 request so a log that shows one
    cannot be mistaken for the other.
    """
    authority = host if port == 443 else f"{host}:{port}"
    return [
        (b":method", b"GET"),
        (b":authority", authority.encode("ascii", "ignore")),
        (b":scheme", b"https"),
        (b":path", path.encode("ascii", "ignore") or b"/"),
        (b"user-agent", DEFAULT_USER_AGENT.encode("latin-1", "replace")),
    ]


async def _close_probe(manager: Any) -> None:
    """Leave a half-open probe connection. Never raises."""
    try:
        await manager.__aexit__(None, None, None)
    except Exception:  # noqa: BLE001 - teardown must not raise
        pass


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)


def aioquic_available() -> bool:
    """Whether aioquic can be imported.

    HTTP/3 is the only transport with a dependency the tool cannot start without,
    and the import is not optional at module scope: doing it inside the module
    would make a missing package a crash on `adobo --help` rather than a clear
    message on the transport that needs it.
    """
    try:
        import aioquic  # noqa: F401
    except Exception:
        return False
    return True


class Http3Transport(Transport):
    """HTTP flood over QUIC."""

    kind: ClassVar[TransportKind] = TransportKind.H3

    def __init__(
        self,
        target: Target,
        profile: ProfileName,
        *,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        tls_verify: bool = True,
        persona: Any = None,
    ) -> None:
        super().__init__(target, profile)
        if not supports_profile(TransportKind.H3, profile):
            raise TransportError(
                f"The h3 transport cannot generate a {profile.value!r} profile: "
                f"HTTP/3 carries HTTP requests. Use --profile http_flood."
            )
        if not aioquic_available():
            raise TransportError(
                "HTTP/3 needs the aioquic package, which is not installed. "
                "Install it with: pip install aioquic"
            )
        self.connect_timeout = connect_timeout
        self.tls_verify = tls_verify
        self.persona = persona
        self._protocol: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_async: asyncio.Event | None = None
        self._next_stream = _STREAM_ID
        self._sent = 0
        self._handshakes = 0

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        """Nothing is opened here.

        The QUIC connection is an asyncio object and this method runs on the
        engine's thread, before the worker owns the loop that would drive it.
        Opening one would have to cross a thread boundary to be usable and would
        then be driven from a different thread than it was created on. The
        handshake happens inside :meth:`worker_loop`, where the loop exists.
        """
        self._stop.clear()
        self.connections_opened += 1
        self._open = True

    def close(self) -> None:
        self.request_stop()
        loop, self._loop = self._loop, None
        if loop is not None:
            try:
                # Called from the engine after worker_loop has returned, so the
                # loop is no longer running. Closing it releases the transport's
                # socket rather than leaving it to the interpreter's warning.
                loop.close()
            except Exception:  # noqa: BLE001 - teardown must not raise
                pass
        self._open = False

    def request_stop(self) -> None:
        """Ask the run to wind down. Safe to call from any thread.

        The engine calls this from its own thread - ``_stop_workers`` reaches
        every live transport - so the asyncio side has to be signalled through
        ``call_soon_threadsafe``. Setting a bare asyncio.Event from another thread
        is not safe, and the threading.Event cannot be awaited at all: its
        ``wait()`` returns a bool, so ``await wait_for(...)`` on it fails with
        "bool object can't be awaited", which is what it did.
        """
        super().request_stop()
        loop = self._loop
        event = self._stop_async
        if loop is None or event is None:
            return
        try:
            loop.call_soon_threadsafe(event.set)
        except RuntimeError:
            # The loop has already closed. The threading.Event is set, so
            # whatever is still running will see it on its next check.
            pass

    def send_one(self, payload: bytes) -> None:
        """Not used: this transport paces itself, like slowloris.

        ``send_one`` is called from the engine's generic `_pump`, which paces in
        synchronous code. Accepting it and sending would mean a coroutine per
        packet across a thread boundary, which is the design this transport
        exists to avoid.
        """
        self._count_attempt()
        self._count_error()
        raise TransportError("Http3Transport uses worker_loop, not send_one")

    # -- the run -----------------------------------------------------------

    def worker_loop(
        self, worker_id: int, per_worker_pps: float, attack: AttackProfile | None = None
    ) -> None:
        """Drive one QUIC connection, pacing requests until asked to stop.

        Runs the event loop inline on this thread for the whole run. See the
        module docstring for why, and for why that makes the deadline
        reachable: ``self._stop`` is set by the engine's ``_stop_workers``, and
        the coroutine checks it between requests.
        """
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve(per_worker_pps, attack))
        finally:
            try:
                self._teardown_connection()
            finally:
                # Left set deliberately: the engine's next worker on this thread
                # would otherwise inherit it and close a loop that is not ours.
                asyncio.set_event_loop(None)

    async def _serve(self, per_worker_pps: float, attack: AttackProfile | None) -> None:
        from aioquic.asyncio import connect
        from aioquic.h3.connection import H3_ALPN
        from aioquic.quic.configuration import QuicConfiguration

        config = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            verify_mode=self._verify_mode(),
            server_name=self.target.host,
        )
        # connect() is an async context manager, not a coroutine, so it cannot be
        # awaited. Entered and exited explicitly rather than with `async with` so
        # that the timeout wraps *only* the handshake: wrapping the whole run
        # would abandon a worker that had been sending for the full timeout,
        # which is the opposite of what the timeout is for.
        manager = connect(
            self.target.host,
            self.target.port,
            configuration=config,
            create_protocol=_client_protocol_class(),
        )
        try:
            protocol = await asyncio.wait_for(
                manager.__aenter__(), timeout=self.connect_timeout
            )
        except asyncio.TimeoutError as exc:
            raise TransportError(
                f"QUIC handshake to {self.target} did not complete within "
                f"{self.connect_timeout:g}s"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - aioquic raises broadly
            # aioquic reports *why* a handshake was refused through its own
            # logger and raises a bare `ConnectionError('')` - an empty message.
            # Passing that straight through produced "Cannot open an HTTP/3
            # connection to 127.0.0.1:8443: " with nothing after the colon, which
            # tells the operator nothing at all. The usual cause is certificate
            # verification, so name it.
            detail = str(exc).strip()
            if not detail:
                detail = (
                    f"{type(exc).__name__} with no detail from the QUIC stack; "
                    f"the handshake was refused, which is usually certificate "
                    f"verification - retry with --tls-no-verify for a "
                    f"self-signed target"
                )
            raise TransportError(
                f"Cannot open an HTTP/3 connection to {self.target}: {detail}"
            ) from exc

        self._protocol = protocol
        self._handshakes += 1
        try:
            await self._pump(per_worker_pps, attack)
        finally:
            self._protocol = None
            self._stop_async = None
            try:
                await manager.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001 - teardown must not raise
                pass

    async def _pump(self, per_worker_pps: float, attack: AttackProfile | None) -> None:
        """Send at the worker's rate until asked to stop."""
        self._stop_async = asyncio.Event()
        # The engine may already have asked to stop before this coroutine ran;
        # without this the first `while` check would catch it anyway, but the
        # event is also what the wait below parks on.
        if self._stop.is_set():
            self._stop_async.set()

        interval = 1.0 / max(1.0, per_worker_pps)
        loop = asyncio.get_running_loop()
        next_send = loop.time()

        while not self._stop.is_set():
            now = loop.time()
            if now < next_send:
                # Wait on the stop event rather than sleeping, so a stop request
                # lands immediately instead of after a full interval. This is what
                # makes the engine's deadline reachable at all: a bare sleep would
                # park here until the interval elapsed, and the engine's join
                # grace is shorter than that.
                try:
                    await asyncio.wait_for(
                        self._stop_async.wait(), timeout=next_send - now
                    )
                    return
                except asyncio.TimeoutError:
                    pass
            self._send_one_h3(attack)
            next_send += interval
            # A pacing slip must not become a permanent debt: if we are already
            # behind, resynchronise rather than trying to catch up by sending a
            # burst the operator never asked for.
            if next_send < loop.time():
                next_send = loop.time()

    def _send_one_h3(self, attack: AttackProfile | None) -> None:
        """Put one request on the wire. Synchronous and inside the loop.

        aioquic's own ``send_headers``/``send_data`` are synchronous - they
        hand bytes to the transport's datagram endpoint - so no coroutine is
        needed for a single request, only for the pacing above.
        """
        self._count_attempt()
        try:
            protocol = self._protocol
            if protocol is None:
                raise TransportError("the QUIC connection is not open")
            h3 = getattr(protocol, "http", None)
            if h3 is None:
                # The QUIC handshake negotiated but HTTP/3 was never set up,
                # which means the peer did not offer h3. Sending anyway would
                # produce QPACK frames on a connection the target is not
                # reading as HTTP.
                raise TransportError(
                    "the connection negotiated QUIC without HTTP/3; the target "
                    "does not appear to speak h3"
                )
            stream_id = self._next_stream
            self._next_stream += 4
            headers = self._build_headers(attack)
            before = getattr(protocol, "bytes_sent", 0)
            h3.send_headers(
                stream_id=stream_id,
                headers=headers,
                end_stream=False,
            )
            h3.send_data(stream_id=stream_id, data=b"", end_stream=True)
            protocol.transmit()
            # Measured from the endpoint rather than from the request, because an
            # HTTP/3 GET has no body and a body length would report zero bytes
            # for every request sent.
            self._count_sent(max(0, getattr(protocol, "bytes_sent", 0) - before))
            self._sent += 1
        except (TransportError, AttributeError, OSError, RuntimeError) as exc:
            self._count_error()
            raise TransportError(f"HTTP/3 send failed: {exc}") from exc

    def _build_headers(self, attack: AttackProfile | None) -> list[tuple[bytes, bytes]]:
        """The HTTP/3 request headers.

        Bytes, not str: aioquic's QPACK encoder requires both halves to be bytes
        and rejects a str outright. This is a different failure from the
        HTTP/1.1 builder's, where the same values were strings and correct.

        Lower-case, because HTTP/3 requires it: h2 lower-cased them and h3
        forbids uppercase outright, so a header carried over from the HTTP/1.1
        builder would be a protocol error rather than a cosmetic difference.

        The authority carries the port unless it is the default for the scheme,
        which is what RFC 9114 requires and what a real client sends.
        """
        scheme = "https"
        authority = self.target.host
        if self.target.port != 443:
            authority = f"{self.target.host}:{self.target.port}"

        persona = self.persona or (attack.persona() if attack is not None else None)
        headers = [
            (b":method", b"GET"),
            (b":authority", authority.encode("ascii", "ignore")),
            (b":scheme", scheme.encode("ascii")),
            (b":path", b"/api/data"),
            (b"user-agent", _user_agent(persona).encode("latin-1", "replace")),
            (b"accept", b"*/*"),
        ]
        return headers

    def _verify_mode(self) -> Any:
        import ssl

        if self.tls_verify:
            return ssl.CERT_REQUIRED
        return ssl.CERT_NONE

    def _teardown_connection(self) -> None:
        protocol, self._protocol = self._protocol, None
        if protocol is None:
            return
        try:
            protocol.close()
        except Exception:  # noqa: BLE001 - teardown must not raise
            pass

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["http3_requests"] = self._sent
        info["quic_handshakes"] = self._handshakes
        return info