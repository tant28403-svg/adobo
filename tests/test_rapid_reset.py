"""Tests for the HTTP/2 Rapid Reset profile.

The load-bearing test here is :class:`ResetCountingServer`, a real HTTP/2 server
built on the ``h2`` library that counts the ``RST_STREAM`` frames it receives.
Everything else could be satisfied by a mock that records that ``reset_stream``
was called; only this can show that the frames left the process, which is the
entire question. The three traps this profile has - counted-on-``StreamEnded``,
the concurrency-gate deadlock, and a zero byte count - all produce a plausible
wrong number rather than an exception, so each is pinned by asserting on the
number rather than on the absence of a crash.

TLS is real here because the transport always wraps the socket in it. The
certificate is the same self-signed one the HTTP/3 tests generate.
"""

from __future__ import annotations

import socket
import threading

import h2.config
import h2.connection
import h2.events
import pytest

from adobo.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TransportKind,
)
from adobo.transports import RapidResetTransport, get_transport, supports_profile
from adobo.transports.base import TransportError

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


class ResetCountingServer:
    """A real HTTP/2 server that counts what a client actually sent it.

    Sends its own SETTINGS so the transport's handshake completes, answers each
    stream it is *not* told to cancel, and records every ``StreamReset`` the peer
    sends. That last number is the whole point: it is evidence from the far end,
    not a restatement of what the sender believes it did.
    """

    def __init__(self, certfile: str, keyfile: str, *, answer: bool = False) -> None:
        self.resets: list[int] = []
        self.requests: list[int] = []
        self.preface_seen = False
        # answer=True makes the server complete streams normally, which is what a
        # compliant server does for a request that arrives before its reset.
        self.answer = answer
        self._certfile = certfile
        self._keyfile = keyfile
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(client,), daemon=True
            ).start()

    def _handle(self, client: socket.socket) -> None:
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self._certfile, self._keyfile)
        # Without this the handshake succeeds but ALPN selects nothing, and the
        # transport refuses at "server offered None, expected h2" before a single
        # frame is sent - which would make every other test here pass vacuously.
        context.set_alpn_protocols(["h2"])
        try:
            tls = context.wrap_socket(client, server_side=True)
        except (ssl.SSLError, OSError):
            return

        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        conn.initiate_connection()
        buffer = b""
        try:
            tls.settimeout(5.0)
            tls.sendall(conn.data_to_send())
            while not self._stop.is_set():
                try:
                    chunk = tls.recv(65535)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buffer += chunk
                if not self.preface_seen:
                    if CLIENT_PREFACE not in buffer:
                        continue
                    self.preface_seen = True
                try:
                    # The preface is handed to h2 intact: h2 validates and
                    # strips it itself. Peeling it off first - which looked
                    # tidier - hands the library a stream that does not begin
                    # with the magic, and it tears the connection down.
                    events = conn.receive_data(buffer)
                except Exception:  # noqa: BLE001 - malformed input ends it
                    break
                buffer = b""
                for event in events:
                    self._on_event(conn, event)
                tls.sendall(conn.data_to_send())
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def _on_event(self, conn, event) -> None:
        if isinstance(event, h2.events.RequestReceived):
            self.requests.append(event.stream_id)
            if self.answer:
                conn.send_headers(
                    event.stream_id,
                    [(b":status", b"200"), (b"content-length", b"0")],
                )
                conn.end_stream(event.stream_id)
        elif isinstance(event, h2.events.StreamReset):
            # From the peer: this is the Rapid Reset, observed at the far end.
            self.resets.append(event.stream_id)


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    from adobo.target.app import generate_self_signed_cert

    directory = tmp_path_factory.mktemp("rrcert")
    certfile = directory / "cert.pem"
    keyfile = directory / "key.pem"
    generate_self_signed_cert(certfile, keyfile, hostname="localhost")
    return str(certfile), str(keyfile)


@pytest.fixture
def server(cert):
    instance = ResetCountingServer(*cert)
    yield instance
    instance.close()


def _transport(port: int, **kw) -> RapidResetTransport:
    return RapidResetTransport(
        Target(host="127.0.0.1", port=port),
        ProfileName.RAPID_RESET,
        tls_verify=False,
        connect_timeout=5.0,
        send_timeout=5.0,
        **kw,
    )


# ---------------------------------------------------------------------------
# The frames really go out
# ---------------------------------------------------------------------------


class TestAgainstARealServer:
    def test_the_server_receives_the_resets(self, server) -> None:
        """The point of the whole profile, evidenced from the far end."""
        transport = _transport(server.port)
        transport.open()
        try:
            for _ in range(20):
                transport.send_one(b"")
            transport._drain_responses()
        finally:
            transport.close()
        assert server.resets, "the server received no RST_STREAM frames"

    def test_every_reset_has_headers_behind_it(self, server) -> None:
        """A reset with nothing behind it costs the server nothing.

        This is what makes the difference between testing the vulnerable path and
        testing nothing: the server has to allocate stream state and process the
        header block before it learns the stream is gone.
        """
        transport = _transport(server.port)
        transport.open()
        try:
            for _ in range(20):
                transport.send_one(b"")
            transport._drain_responses()
        finally:
            transport.close()
        assert server.resets
        assert len(server.requests) >= len(server.resets)

    def test_the_reset_count_matches_what_was_sent(self, server) -> None:
        transport = _transport(server.port)
        transport.open()
        try:
            for _ in range(25):
                transport.send_one(b"")
            transport._drain_responses()
        finally:
            transport.close()
        assert transport.resets_sent == 25
        assert len(server.resets) >= 20, (
            f"sent 25 resets, server saw {len(server.resets)}"
        )

    def test_a_patched_server_is_left_alone(self, server) -> None:
        """Nothing breaking is the passing result, so the test asserts exactly
        what a server with the fix in place does: keeps answering."""
        transport = _transport(server.port)
        transport.open()
        try:
            for _ in range(10):
                transport.send_one(b"")
            transport._drain_responses()
        finally:
            transport.close()
        assert transport.snapshot().errors == 0
        assert transport.resets_blocked == 0


# ---------------------------------------------------------------------------
# The three traps
# ---------------------------------------------------------------------------


class TestCounting:
    """A stream this transport cancels never ends normally.

    ``H2Transport`` counts a request as sent on ``StreamEnded``. Reused here, a
    run would report 0 packets sent while thousands of HEADERS frames left the
    machine - a clean exit code and a completely false number.
    """

    def test_sent_is_counted_even_though_nothing_ever_ends(self, server) -> None:
        transport = _transport(server.port)
        transport.open()
        try:
            for _ in range(20):
                transport.send_one(b"")
        finally:
            transport.close()
        assert transport.snapshot().sent == 20

    def test_bytes_are_counted(self, server) -> None:
        """Not a fixed length and not zero.

        Two frames go out per reset and neither is the payload the engine hands
        over, so counting the request - or counting nothing - gives "20 packets
        (0 bytes)", which reads as a tool that sent nothing.
        """
        transport = _transport(server.port)
        transport.open()
        try:
            for _ in range(20):
                transport.send_one(b"")
        finally:
            transport.close()
        assert transport.snapshot().bytes > 0

    def test_attempts_and_sent_agree(self, server) -> None:
        """Nothing fails silently: a refused reset would show as blocked."""
        transport = _transport(server.port)
        transport.open()
        try:
            for _ in range(15):
                transport.send_one(b"")
        finally:
            transport.close()
        counters = transport.snapshot()
        assert counters.attempted == counters.sent == 15


class TestBookkeeping:
    """A cancelled stream must leave nothing behind.

    ``H2Transport.send_one`` waits while ``len(self._streams) >= concurrency``,
    and that gate has no timeout. So the question is not "are entries cleaned up"
    but "are they ever created" - a stream cancelled before it can be waited on
    should not be tracked at all.

    This class originally asserted that entries were popped after each reset, on
    the theory that the server might never answer and the dict would fill. The
    tests passed with the pop removed, which meant they were asserting that a
    no-op ran: the entries were never added in the first place. Rewritten to
    assert the invariant that is actually load-bearing.
    """

    def test_cancelled_streams_are_never_tracked(self, server) -> None:
        transport = _transport(server.port, concurrency=20)
        transport.open()
        try:
            for _ in range(60):
                transport.send_one(b"")
            assert len(transport._streams) == 0, (
                f"{len(transport._streams)} stream entries tracked for streams "
                f"that were cancelled immediately"
            )
        finally:
            transport.close()

    def test_more_resets_than_the_concurrency_limit(self, server) -> None:
        """Twice the limit, which is where a tracked stream would have wedged."""
        transport = _transport(server.port, concurrency=10)
        transport.open()
        try:
            for _ in range(30):
                transport.send_one(b"")
        finally:
            transport.close()
        assert transport.resets_sent == 30

    def test_it_does_not_wedge_a_run(self, server) -> None:
        """A hang is the failure mode this guards, so it is bounded in time."""
        import time

        transport = _transport(server.port, concurrency=5)
        transport.open()
        started = time.monotonic()
        try:
            for _ in range(40):
                transport.send_one(b"")
        finally:
            transport.close()
        assert time.monotonic() - started < 10.0

    def test_the_concurrency_setting_does_not_cap_the_resets(self, server) -> None:
        """Stated because it is a deliberate difference, not an oversight.

        The limit bounds simultaneously *open* streams. This profile cancels each
        one before opening the next, so it is never simultaneously open and the
        limit does not apply - capping resets by it would test nothing.
        """
        transport = _transport(server.port, concurrency=4)
        transport.open()
        try:
            for _ in range(40):
                transport.send_one(b"")
        finally:
            transport.close()
        assert transport.resets_sent == 40


# ---------------------------------------------------------------------------
# It must not change http_flood
# ---------------------------------------------------------------------------


class TestHttpFloodIsUntouched:
    def test_http_flood_still_builds_the_plain_transport(self) -> None:
        config = RunConfig(
            target=Target(host="127.0.0.1", port=443),
            attack=AttackProfile(
                profile=ProfileName.HTTP_FLOOD, use_http2=True
            ),
            transport=TransportKind.H2,
        )
        transport = get_transport(config)
        assert type(transport).__name__ == "H2Transport"
        assert not hasattr(transport, "resets_sent")

    def test_rapid_reset_gets_its_own_transport(self) -> None:
        config = RunConfig(
            target=Target(host="127.0.0.1", port=443),
            attack=AttackProfile(profile=ProfileName.RAPID_RESET),
            transport=TransportKind.H2,
        )
        assert isinstance(get_transport(config), RapidResetTransport)

    def test_only_http_profiles_are_accepted(self) -> None:
        assert supports_profile(TransportKind.H2, ProfileName.RAPID_RESET) is True
        assert supports_profile(TransportKind.H2, ProfileName.UDP_FLOOD) is False
        assert supports_profile(TransportKind.SOCKET, ProfileName.RAPID_RESET) is False

    def test_a_socket_transport_refuses_the_profile(self) -> None:
        """It cannot speak h2, so it must say so rather than half-work."""
        from adobo.transports.socket_transport import SocketTransport

        with pytest.raises(TransportError):
            SocketTransport(
                Target(host="127.0.0.1", port=80), ProfileName.RAPID_RESET
            )


# ---------------------------------------------------------------------------
# What the report has to say
# ---------------------------------------------------------------------------


class TestDisclosure:
    def _config(self, profile: ProfileName) -> RunConfig:
        return RunConfig(
            target=Target(host="127.0.0.1", port=9),
            attack=AttackProfile(
                profile=profile,
                pps=100,
                duration_seconds=0.3,
                payload_size=128,
                workers=1,
            ),
            transport=TransportKind.VIRTUAL,
        )

    def test_the_note_explains_the_zero_served_count(self) -> None:
        """Otherwise "0 requests served" reads as a failed run."""
        from adobo.engine import RunEngine

        notes = RunEngine(self._config(ProfileName.RAPID_RESET)).run().result.notes
        assert any("Rapid Reset" in n for n in notes), notes
        assert any("served-request count staying near zero is expected" in n
                   for n in notes), notes

    def test_the_note_names_the_cve(self) -> None:
        from adobo.engine import RunEngine

        notes = RunEngine(self._config(ProfileName.RAPID_RESET)).run().result.notes
        assert any("CVE-2023-44487" in n for n in notes), notes

    def test_the_note_says_nothing_happening_is_success(self) -> None:
        from adobo.engine import RunEngine

        notes = RunEngine(self._config(ProfileName.RAPID_RESET)).run().result.notes
        assert any("which is the passing result" in n for n in notes), notes

    def test_http_flood_has_no_rapid_reset_note(self) -> None:
        """Silence is the signal: the two runs must be tellable apart."""
        from adobo.engine import RunEngine

        notes = RunEngine(self._config(ProfileName.HTTP_FLOOD)).run().result.notes
        assert not any("Rapid Reset" in n for n in notes), notes