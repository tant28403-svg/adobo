"""Tests for the HTTP/3 transport.

The load-bearing tests run against a **real QUIC server** started in-process with
``aioquic.asyncio.serve`` on loopback. That is not ceremony. HTTP/3 is the one
transport here whose correctness is mostly *ordering*: connect, handshake, then
headers, then data, then transmit - and a mock would pass while the transport
sent a request before the connection existed, used a stream id QUIC reserves for
something else, or reported a request as sent that never left the process.

The counter honesty is tested as carefully as the sending, because it is the more
easily broken half. A UDP datagram is not acknowledged, so ``bytes_received``
must stay absent rather than becoming a plausible-looking number.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from adobo.models import AttackProfile, ProfileName, RunConfig, Target, TransportKind
from adobo.transports import TransportError, get_transport, supports_profile
from adobo.transports.http3_transport import (
    DEFAULT_USER_AGENT,
    Http3Transport,
    aioquic_available,
)

pytestmark = pytest.mark.skipif(
    not aioquic_available(), reason="aioquic is not installed"
)


# ---------------------------------------------------------------------------
# A real QUIC/HTTP-3 server on loopback
# ---------------------------------------------------------------------------


class H3Server:
    """A minimal HTTP/3 origin, in-process, on 127.0.0.1.

    Answers every request with 200 and records what arrived. The recording is
    the point: it is the only thing that distinguishes "the transport sent a
    request" from "a request reached a server".
    """

    def __init__(self, certfile: str, keyfile: str) -> None:
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import ProtocolNegotiated

        self.requests: list[list[tuple[bytes, bytes]]] = []
        self.handshakes = 0
        self._HeadersReceived = HeadersReceived
        self._H3Connection = H3Connection
        self._H3_ALPN = H3_ALPN
        self._config = QuicConfiguration(
            is_client=False,
            alpn_protocols=H3_ALPN,
        )
        # A method, not a constructor argument: QuicConfiguration takes no
        # load_cert_chain kwarg, so the certificate has to be attached after
        # construction.
        self._config.load_cert_chain(certfile, keyfile)
        # serve() calls create_protocol(connection, stream_handler=...), so the
        # signature has to accept a positional connection and a keyword
        # stream_handler. Getting this wrong is what made an earlier attempt fail
        # inside QuicConnectionProtocol.__init__ rather than here.
        server_self = self

        class _Protocol(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._http = None

            def quic_event_received(self, event):
                if isinstance(event, ProtocolNegotiated):
                    server_self.handshakes += 1
                    self._http = server_self._H3Connection(self._quic)
                if self._http is None:
                    return
                for h3_event in self._http.handle_event(event):
                    if isinstance(h3_event, server_self._HeadersReceived):
                        server_self.requests.append(h3_event.headers)
                        self._http.send_headers(
                            stream_id=h3_event.stream_id,
                            headers=[
                                (b":status", b"200"),
                                (b"content-length", b"0"),
                            ],
                            end_stream=True,
                        )
                        self.transmit()

        self._create_protocol = _Protocol
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    def start(self) -> int:
        ready = threading.Event()
        error: list[BaseException] = []

        def _run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop

            async def _boot() -> None:
                from aioquic.asyncio import serve

                server = await serve(
                    "127.0.0.1",
                    0,
                    configuration=self._config,
                    create_protocol=self._create_protocol,
                )
                # serve() returns the DatagramProtocol, and the bound port is on
                # its transport. Passing port=0 asks the OS to choose, which is
                # the only way to get a free port in a parallel test run.
                sockname = server._transport.get_extra_info("sockname")
                self.port = sockname[1]
                ready.set()
                while not self._stop.is_set():
                    await asyncio.sleep(0.05)

            try:
                loop.run_until_complete(_boot())
            except BaseException as exc:  # noqa: BLE001
                error.append(exc)
                ready.set()
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

        self._stop = threading.Event()
        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        if not ready.wait(20):
            raise AssertionError("the h3 test server did not start")
        if error:
            raise error[0]
        return self.port

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


@pytest.fixture(scope="module")
def h3_server(tmp_path_factory) -> H3Server:
    from adobo.target.app import generate_self_signed_cert

    directory = tmp_path_factory.mktemp("h3cert")
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    generate_self_signed_cert(cert, key, hostname="localhost")
    server = H3Server(str(cert), str(key))
    server.start()
    yield server
    server.close()


def _transport(port: int, **kw) -> Http3Transport:
    return Http3Transport(
        Target(host="127.0.0.1", port=port),
        ProfileName.HTTP_FLOOD,
        tls_verify=False,
        **kw,
    )


def _run_worker(transport: Http3Transport, pps: float = 20.0, seconds: float = 0.5):
    """Drive one worker for a fixed wall-clock budget, then stop it.

    Stops by the same event the engine uses (`request_stop`) rather than by a
    deadline argument, so what is exercised is the path the engine's
    `_stop_workers` actually takes.
    """
    attack = AttackProfile(
        profile=ProfileName.HTTP_FLOOD, pps=int(pps), duration_seconds=1.0
    )

    def _stopper() -> None:
        import time

        time.sleep(seconds)
        transport.request_stop()

    threading.Thread(target=_stopper, daemon=True).start()
    transport.open()
    transport.worker_loop(0, pps, attack)
    transport.close()
    return transport.snapshot()


# ---------------------------------------------------------------------------
# It actually speaks HTTP/3
# ---------------------------------------------------------------------------


class TestAgainstARealServer:
    def test_a_request_reaches_the_server(self, h3_server) -> None:
        transport = _transport(h3_server.port)
        counters = _run_worker(transport, pps=20.0, seconds=0.5)

        assert h3_server.handshakes >= 1, "no QUIC handshake completed"
        assert h3_server.requests, "the server received no request"
        assert counters.attempted > 0

    def test_the_request_carries_the_right_pseudo_headers(self, h3_server) -> None:
        """Lower-case, and the authority including the port.

        HTTP/3 forbids uppercase outright where HTTP/2 merely lower-cased it, so
        a header block carried over from the HTTP/1.1 builder is a protocol
        error rather than a cosmetic difference.
        """
        _run_worker(_transport(h3_server.port), pps=20.0, seconds=0.4)
        headers = {name: value for name, value in h3_server.requests[0]}
        assert headers[b":method"] == b"GET"
        assert headers[b":scheme"] == b"https"
        assert headers[b":path"] == b"/api/data"
        assert headers[b":authority"] == f"127.0.0.1:{h3_server.port}".encode()
        for name in headers:
            assert name == name.lower(), name

    def test_the_run_is_stoppable(self, h3_server) -> None:
        """The deadline has to be reachable, or every worker is abandoned.

        request_stop() is what the engine's `_stop_workers` calls; if the
        coroutine ignored it, the worker would sleep out the interval regardless
        and the run would report nothing for a profile that had been sending.
        """
        import time

        transport = _transport(h3_server.port)
        started = time.monotonic()
        counters = _run_worker(transport, pps=20.0, seconds=0.3)
        elapsed = time.monotonic() - started
        assert elapsed < 5.0, f"stopping took {elapsed:.1f}s"
        assert counters.attempted > 0

    def test_each_request_gets_its_own_stream(self, h3_server) -> None:
        """One stream per request, as a real client does.

        Reusing a stream for a second request would either be a protocol error
        or silently merge two requests into one response the sender is not
        reading, and the counters would still look healthy.
        """
        before = len(h3_server.requests)
        transport = _transport(h3_server.port)
        _run_worker(transport, pps=25.0, seconds=0.5)
        assert len(h3_server.requests) > before

    def test_the_transport_reports_its_own_totals(self, h3_server) -> None:
        transport = _transport(h3_server.port)
        _run_worker(transport, pps=20.0, seconds=0.4)
        info = transport.describe()
        assert info["http3_requests"] > 0
        assert info["quic_handshakes"] == 1
        assert info["transport"] == TransportKind.H3.value


# ---------------------------------------------------------------------------
# Counters must not invent a figure
# ---------------------------------------------------------------------------


class TestCountersAreHonest:
    def test_no_received_bytes_are_claimed(self, h3_server) -> None:
        """UDP is not acknowledged, so this cannot be measured.

        A non-zero figure here would flow straight into an amplification ratio
        and then into a resilience score, describing something that was never
        observed.
        """
        transport = _transport(h3_server.port)
        counters = _run_worker(transport, pps=20.0, seconds=0.4)
        assert counters.sent > 0
        assert counters.bytes_received == 0
        assert counters.responses == 0

    def test_no_amplification_factor_is_derived(self, h3_server) -> None:
        """The measured factor must be absent, not zero - zero would read as
        "the target amplified nothing", which is a claim."""
        transport = _transport(h3_server.port)
        counters = _run_worker(transport, pps=20.0, seconds=0.4)
        assert counters.measured_amplification is None

    def test_bytes_sent_is_still_counted(self, h3_server) -> None:
        """What the sender did is still knowable, and still has to be reported.

        An HTTP/3 GET has no request body, so counting the body reported zero
        bytes for every request - a run reading "626 packets (0 bytes)", which
        is worse than no figure because it looks measured and contradicts the
        count beside it.
        """
        transport = _transport(h3_server.port)
        counters = _run_worker(transport, pps=20.0, seconds=0.4)
        assert counters.sent > 0
        assert counters.bytes > 0, "a run of requests reported zero bytes"


# ---------------------------------------------------------------------------
# Contract and refusals
# ---------------------------------------------------------------------------


class TestContract:
    def test_only_http_profiles_are_supported(self) -> None:
        assert supports_profile(TransportKind.H3, ProfileName.HTTP_FLOOD) is True
        for profile in (
            ProfileName.UDP_FLOOD,
            ProfileName.SYN_FLOOD,
            ProfileName.DNS_AMPLIFICATION,
            ProfileName.SLOWLORIS,
        ):
            assert supports_profile(TransportKind.H3, profile) is False

    def test_a_udp_profile_is_refused_with_a_reason(self) -> None:
        with pytest.raises(TransportError, match="http_flood"):
            Http3Transport(
                Target(host="127.0.0.1", port=443), ProfileName.UDP_FLOOD
            )

    def test_send_one_is_refused_rather_than_silently_wrong(self) -> None:
        """The engine's generic _pump calls send_one; a self-paced transport has
        to say so instead of accepting a payload it cannot send."""
        transport = Http3Transport(
            Target(host="127.0.0.1", port=443), ProfileName.HTTP_FLOOD
        )
        with pytest.raises(TransportError, match="worker_loop"):
            transport.send_one(b"GET / HTTP/1.1\r\n\r\n")

    def test_opening_opens_no_socket(self) -> None:
        """open() runs before the worker owns the loop that would drive the
        connection, so it must not build one."""
        transport = Http3Transport(
            Target(host="127.0.0.1", port=443), ProfileName.HTTP_FLOOD
        )
        transport.open()
        assert transport._protocol is None
        transport.close()

    def test_the_factory_builds_it(self) -> None:
        config = RunConfig(
            target=Target(host="127.0.0.1", port=443),
            attack=AttackProfile(profile=ProfileName.HTTP_FLOOD),
            transport=TransportKind.H3,
        )
        transport = get_transport(config)
        assert isinstance(transport, Http3Transport)
        assert transport.kind is TransportKind.H3

    def test_a_dead_target_fails_as_a_setup_error(self) -> None:
        """A closed port cannot complete a handshake, and that has to be a
        TransportError rather than a hang or an unhandled aioquic exception."""
        import time

        transport = _transport(9, connect_timeout=1.0)
        started = time.monotonic()
        with pytest.raises(TransportError):
            transport.worker_loop(
                0, 10.0, AttackProfile(profile=ProfileName.HTTP_FLOOD)
            )
        assert time.monotonic() - started < 10.0
        transport.close()


class TestPersonasAndDefaults:
    def test_no_persona_sends_the_honest_agent(self, h3_server) -> None:
        """A run with no persona must look the same on h3 as elsewhere, or "no
        impersonation" stops being a consistent claim across transports."""
        before = len(h3_server.requests)
        _run_worker(_transport(h3_server.port), pps=20.0, seconds=0.3)
        headers = {name: value for name, value in h3_server.requests[before]}
        assert headers[b"user-agent"] == DEFAULT_USER_AGENT.encode()

    def test_a_persona_sends_its_own_agent(self, h3_server) -> None:
        from adobo.fingerprint import FINGERPRINTS

        persona = FINGERPRINTS["chrome_131_win"]
        before = len(h3_server.requests)
        _run_worker(
            _transport(h3_server.port, persona=persona), pps=20.0, seconds=0.3
        )
        headers = {name: value for name, value in h3_server.requests[before]}
        assert headers[b"user-agent"] == persona.user_agent.encode()


class TestProbing:
    """The prober has to speak the protocol the load used.

    An h3 run probed over HTTP/1.1 on TCP asks a question a QUIC-only target
    cannot answer. Windows blackholes that connection rather than refusing it, so
    the probe timed out, availability read 0%, and a target that had answered
    1,200 requests was graded 0/100. These tests exist so that cannot come back.
    """

    def test_a_probe_reaches_an_h3_target(self, h3_server) -> None:
        from adobo.transports.http3_transport import h3_probe

        probe = asyncio.run(
            h3_probe("127.0.0.1", h3_server.port, "/healthz",
                     timeout=5.0, tls_verify=False)
        )
        assert probe.ok is True
        assert probe.status_code == 200
        assert probe.error is None
        assert probe.latency_ms >= 0

    def test_a_dead_port_is_a_failed_probe_not_a_crash(self) -> None:
        from adobo.transports.http3_transport import h3_probe

        probe = asyncio.run(
            h3_probe("127.0.0.1", 9, "/healthz", timeout=1.0, tls_verify=False)
        )
        assert probe.ok is False
        assert probe.error

    def test_an_h3_run_reports_a_real_availability_figure(self, h3_server) -> None:
        """The whole point: a healthy h3 target must not read as 0%."""
        from adobo.engine import RunEngine

        config = RunConfig(
            target=Target(host="127.0.0.1", port=h3_server.port),
            attack=AttackProfile(
                profile=ProfileName.HTTP_FLOOD,
                pps=20,
                duration_seconds=1.0,
                payload_size=128,
                workers=1,
                tls_verify=False,
            ),
            transport=TransportKind.H3,
        )
        outcome = RunEngine(config).run()
        stats = outcome.result.probe
        assert stats.total > 0, "no probes were recorded for an h3 run"
        assert stats.succeeded > 0, (
            f"an h3 target that answered had {stats.succeeded} of "
            f"{stats.total} probes succeed"
        )
        assert stats.availability_pct > 0, (
            f"an h3 target that answered was reported at "
            f"{stats.availability_pct}% availability"
        )

    def test_the_note_cannot_claim_h3_probing_that_did_not_happen(self) -> None:
        """The note must describe what ran, not what the transport implies.

        The disclosure originally derived its wording from the transport kind, so
        an h3 run probed over TCP still said "measured over HTTP/3" - a second
        false claim, printed next to a 0% that came from the wrong protocol.
        """
        from adobo.engine import RunEngine

        config = RunConfig(
            target=Target(host="127.0.0.1", port=9),
            attack=AttackProfile(
                profile=ProfileName.HTTP_FLOOD,
                pps=20,
                duration_seconds=0.4,
                payload_size=128,
                workers=1,
                tls_verify=False,
            ),
            transport=TransportKind.H3,
        )
        engine = RunEngine(config)
        # Force the TCP prober without needing a live target for it.
        engine._probe_protocol = "http/1.1"
        note = engine._h3_note()
        assert note is not None
        assert "measured over HTTP/3" not in note, note
        assert "No HTTP/3 probe was made" in note, note

    def test_the_note_says_how_availability_was_measured(self, h3_server) -> None:
        from adobo.engine import RunEngine

        config = RunConfig(
            target=Target(host="127.0.0.1", port=h3_server.port),
            attack=AttackProfile(
                profile=ProfileName.HTTP_FLOOD,
                pps=20,
                duration_seconds=0.6,
                payload_size=128,
                workers=1,
                tls_verify=False,
            ),
            transport=TransportKind.H3,
        )
        notes = RunEngine(config).run().result.notes
        assert any(
            "measured over HTTP/3" in n for n in notes
        ), notes

    def test_a_tcp_prober_would_have_reported_zero_here(self, h3_server) -> None:
        """Pins *why* this fix exists rather than just that it works.

        Asserts the httpx prober cannot see the target, so a future change that
        quietly routes h3 runs back through TCP fails here instead of silently
        reintroducing the false 0%.
        """
        async def _tcp_probe() -> float | None:
            import httpx

            timeout = httpx.Timeout(1.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                try:
                    response = await client.get(
                        f"http://127.0.0.1:{h3_server.port}/healthz"
                    )
                    return float(response.status_code)
                except Exception:  # noqa: BLE001 - any failure is the point
                    return None

        assert asyncio.run(_tcp_probe()) is None, (
            "the TCP prober can now reach the h3 target, so the h3 prober is "
            "no longer the thing making this measurement"
        )

    def test_a_missing_aioquic_reports_unmeasured_not_zero(self) -> None:
        """A missing package must never become a claim about the target.

        Recording failing probes because the prober could not run would turn an
        absent dependency into 0% availability and a 0/100 score for a machine
        that may be perfectly healthy.
        """
        import subprocess
        import sys

        script = (
            "import sys\n"
            "from importlib.abc import MetaPathFinder\n"
            "class Block(MetaPathFinder):\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] == 'aioquic':\n"
            "            raise ImportError('blocked')\n"
            "        return None\n"
            "sys.meta_path.insert(0, Block())\n"
            "from adobo.engine import RunEngine\n"
            "from adobo.models import (\n"
            "    AttackProfile, ProfileName, RunConfig, Target, TransportKind,\n"
            ")\n"
            "config = RunConfig(\n"
            "    target=Target(host='127.0.0.1', port=8443),\n"
            "    attack=AttackProfile(\n"
            "        profile=ProfileName.HTTP_FLOOD, pps=10,\n"
            "        duration_seconds=0.3, payload_size=128, workers=1,\n"
            "        tls_verify=False,\n"
            "    ),\n"
            "    transport=TransportKind.H3,\n"
            ")\n"
            "outcome = RunEngine(config).run()\n"
            "stats = outcome.result.probe\n"
            "notes = outcome.result.notes\n"
            "assert stats.total == 0, stats.total\n"
            "assert any('unmeasured' in n or 'aioquic' in n for n in notes), notes\n"
            "print('ok')\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "no_aioquic_probe.py"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(path)], capture_output=True, text=True
            )
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout


class TestDisclosure:
    def test_a_run_discloses_that_it_spoke_http3(self, h3_server) -> None:
        """And says the received-bytes figure is absent, not zero."""
        from adobo.engine import RunEngine

        config = RunConfig(
            target=Target(host="127.0.0.1", port=h3_server.port),
            attack=AttackProfile(
                profile=ProfileName.HTTP_FLOOD,
                pps=20,
                duration_seconds=0.4,
                payload_size=128,
                workers=1,
                tls_verify=False,
            ),
            transport=TransportKind.H3,
        )
        outcome = RunEngine(config).run()
        notes = outcome.result.notes
        assert any("HTTP/3 over QUIC" in n for n in notes), notes
        assert any("not acknowledged" in n for n in notes), notes

    def test_other_transports_say_nothing_about_http3(self) -> None:
        from adobo.engine import RunEngine

        config = RunConfig(
            target=Target(host="127.0.0.1", port=9),
            attack=AttackProfile(
                profile=ProfileName.UDP_FLOOD,
                pps=100,
                duration_seconds=0.2,
                payload_size=128,
                workers=1,
            ),
            transport=TransportKind.VIRTUAL,
        )
        outcome = RunEngine(config).run()
        assert not any("HTTP/3" in n for n in outcome.result.notes)