"""Tests for the transport layer.

Two rules govern this file:

* **No packet leaves the machine except in a handful of deliberately tiny
  loopback tests.** A capability test must never assert that a real raw packet
  was transmitted, because the result would depend on whether the machine
  running the suite happens to have Npcap and Administrator.
* **The ``raw_capability`` contract is asserted structurally.** ``ddosim.safety``
  reads ``can_send`` and ``reason`` by name, so a rename there would break
  refusals at runtime rather than at import. These tests fail on that.
"""

from __future__ import annotations

import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

import pytest

from ddosim.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TransportKind,
)
from ddosim.transports import (
    PeerUnavailable,
    RawCapability,
    ScapyTransport,
    SocketTransport,
    SlowlorisTransport,
    Transport,
    TransportCounters,
    TransportError,
    VirtualTransport,
    available_transports,
    build_payload,
    get_transport,
    raw_capability,
    scapy_available,
    supports_profile,
)
from ddosim.transports.scapy_transport import _resolve_iface

TARGET = Target(host="127.0.0.1", port=9)


def make_config(transport: TransportKind, profile: ProfileName, **kw) -> RunConfig:
    return RunConfig(
        target=TARGET,
        attack=AttackProfile(profile=profile, pps=10, duration_seconds=1.0),
        transport=transport,
        **kw,
    )


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


class TestPayloads:
    @pytest.mark.parametrize("size", [0, 1, 63, 64, 512, 1400])
    def test_filler_is_exactly_requested_size(self, size: int) -> None:
        payload = build_payload(ProfileName.UDP_FLOOD, size)
        assert len(payload) == size

    def test_filler_is_deterministic(self) -> None:
        a = build_payload(ProfileName.UDP_FLOOD, 256, seed=7)
        b = build_payload(ProfileName.UDP_FLOOD, 256, seed=7)
        assert a == b

    def test_filler_varies_with_seed(self) -> None:
        a = build_payload(ProfileName.UDP_FLOOD, 256, seed=1)
        b = build_payload(ProfileName.UDP_FLOOD, 256, seed=2)
        assert a != b

    def test_payloads_carry_identifiable_filler(self) -> None:
        assert b"ddosim" in build_payload(ProfileName.UDP_FLOOD, 256)

    def test_dns_query_is_well_formed(self) -> None:
        payload = build_payload(ProfileName.DNS_AMPLIFICATION, 512, seed=1)
        assert payload[2:4] == b"\x01\x00", "should be a recursive standard query"
        # QNAME is length-prefixed on the wire, not a literal string.
        assert payload[12] == 7 and payload[13:20] == b"example"
        assert payload[20] == 3 and payload[21:24] == b"com"
        assert payload[24] == 0, "root label terminates the name"
        assert payload[25:27] == b"\x00\x01", "QTYPE=A"
        assert payload[27:29] == b"\x00\x01", "QCLASS=IN"
        assert payload[12:29] == build_payload(
            ProfileName.DNS_AMPLIFICATION, 512, seed=1
        )[12:29], "question section is stable regardless of seed"

    def test_dns_query_uses_target_host_when_it_is_a_name(self) -> None:
        payload = build_payload(
            ProfileName.DNS_AMPLIFICATION, 512, target=Target(host="lab.internal", port=53)
        )
        assert b"\x03lab\x08internal\x00" in payload

    def test_dns_query_ignores_an_ip_target(self) -> None:
        payload = build_payload(
            ProfileName.DNS_AMPLIFICATION, 512, target=Target(host="127.0.0.1", port=53)
        )
        assert b"\x07example\x03com\x00" in payload

    def test_http_request_is_a_valid_get(self) -> None:
        payload = build_payload(
            ProfileName.HTTP_FLOOD, 512, target=Target(host="lab.internal", port=80)
        )
        assert payload.startswith(b"GET /api/data HTTP/1.1\r\n")
        assert b"Host: lab.internal\r\n" in payload
        assert payload.endswith(b"\r\n\r\n") or b"ddosim" in payload

    def test_http_request_is_complete_at_the_default_size(self) -> None:
        """The default payload size is 128, and this is where it used to break.

        A request is 141 bytes, so at 128 the payload was cut mid-header and the
        target saw a malformed request. Every request was refused at the door,
        which is exactly what "it does nothing" looked like from the sender. The
        old test only checked 512, where padding hid the problem.
        """
        payload = build_payload(
            ProfileName.HTTP_FLOOD, 128, target=Target(host="lab.internal", port=80)
        )
        assert payload.endswith(b"\r\n\r\n")
        assert payload.count(b"\r\n") >= 4
        assert b"Host: lab.internal\r\n" in payload

    @pytest.mark.parametrize("size", [0, 1, 32, 64, 128, 141, 512, 1500])
    def test_a_request_is_never_truncated_below_a_minimum(self, size) -> None:
        """The request head must be complete at every size.

        The invariant is that ``\\r\\n\\r\\n`` is always present, not that the
        payload ends with it: above the natural request length the extra bytes
        are a body, which correctly follows the header terminator. At 128 the
        original bug cut the head mid-header, so the terminator was absent and
        every request was malformed.
        """
        payload = build_payload(
            ProfileName.HTTP_FLOOD, size, target=Target(host="h", port=80)
        )
        assert b"\r\n\r\n" in payload, f"request head truncated at size={size}"
        assert b"Connection: close\r\n" in payload

    @pytest.mark.parametrize("size", [0, 1, 32, 64, 128])
    def test_below_the_natural_length_the_payload_is_the_whole_request(
        self, size
    ) -> None:
        """No room for a body, so the payload is exactly the request."""
        natural = build_payload(
            ProfileName.HTTP_FLOOD, 0, target=Target(host="h", port=80)
        )
        payload = build_payload(
            ProfileName.HTTP_FLOOD, size, target=Target(host="h", port=80)
        )
        assert payload == natural
        assert payload.endswith(b"\r\n\r\n")


    @pytest.mark.parametrize(
        "profile",
        [
            ProfileName.HTTP_FLOOD,
            ProfileName.CLDAP_AMPLIFICATION,
            ProfileName.SSDP_AMPLIFICATION,
            ProfileName.NTP_AMPLIFICATION,
        ],
    )
    def test_structured_payloads_are_never_truncated(self, profile) -> None:
        """Every structured profile must survive a small size request.

        These all have a minimum encoded length. Truncating one produces a packet
        a well-built server will simply discard, so the flood reports success
        while achieving nothing.
        """
        minimum = build_payload(profile, 0, target=Target(host="h", port=1))
        for size in (1, 16, 64, 128, 256):
            payload = build_payload(profile, size, target=Target(host="h", port=1))
            assert len(payload) >= len(minimum), (
                f"{profile} shrank below its minimum at size={size}"
            )

    def test_padding_never_shrinks_a_payload_that_already_fits(self) -> None:
        """A size larger than the natural request must not cut it down."""
        natural = build_payload(
            ProfileName.HTTP_FLOOD, 0, target=Target(host="h", port=80)
        )
        padded = build_payload(
            ProfileName.HTTP_FLOOD, 900, target=Target(host="h", port=80)
        )
        assert padded.startswith(natural)

    def test_slowloris_stays_intentionally_partial(self) -> None:
        """The one payload that must not be completed.

        Slowloris works by holding a connection open with an unfinished request,
        so padding this to a valid request would remove the entire effect.
        """
        payload = build_payload(ProfileName.SLOWLORIS, 128, target=Target(host="h", port=80))
        assert not payload.endswith(b"\r\n\r\n")

    def test_http_request_varies_per_packet(self) -> None:
        a = build_payload(ProfileName.HTTP_FLOOD, 512, seed=1)
        b = build_payload(ProfileName.HTTP_FLOOD, 512, seed=2)
        assert a != b

    def test_negative_size_is_treated_as_zero(self) -> None:
        assert build_payload(ProfileName.UDP_FLOOD, -5) == b""


# ---------------------------------------------------------------------------
# Profile capability
# ---------------------------------------------------------------------------


class TestSupportsProfile:
    @pytest.mark.parametrize(
        "profile",
        [ProfileName.SYN_FLOOD, ProfileName.ACK_FLOOD, ProfileName.ICMP_FLOOD],
    )
    def test_socket_transport_refuses_raw_only_profiles(self, profile) -> None:
        assert supports_profile(TransportKind.SOCKET, profile) is False

    @pytest.mark.parametrize("profile", list(ProfileName))
    def test_scapy_supports_every_profile(self, profile) -> None:
        assert supports_profile(TransportKind.SCAPY, profile) is True

    @pytest.mark.parametrize("profile", list(ProfileName))
    def test_virtual_supports_every_profile(self, profile) -> None:
        assert supports_profile(TransportKind.VIRTUAL, profile) is True

    def test_socket_transport_raises_with_guidance(self) -> None:
        with pytest.raises(TransportError, match="raw L3/L4"):
            SocketTransport(TARGET, ProfileName.SYN_FLOOD)

    def test_error_names_the_scapy_alternative(self) -> None:
        with pytest.raises(TransportError, match="--transport scapy"):
            SocketTransport(TARGET, ProfileName.ICMP_FLOOD)


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


class TestCounters:
    def test_starts_at_zero(self) -> None:
        assert VirtualTransport(TARGET, ProfileName.UDP_FLOOD).snapshot() == (
            TransportCounters()
        )

    def test_virtual_counts_attempts_sends_and_bytes(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        for _ in range(5):
            transport.send_one(b"x" * 100)
        counters = transport.snapshot()
        assert counters.attempted == 5
        assert counters.sent == 5
        assert counters.bytes == 500
        assert counters.errors == 0
        assert counters.attempted_minus_sent == 0

    def test_errors_are_counted_separately(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._count_attempt()
        transport._count_error()
        counters = transport.snapshot()
        assert counters.attempted == 1
        assert counters.sent == 0
        assert counters.errors == 1
        assert counters.attempted_minus_sent == 1

    def test_counters_are_thread_safe(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)

        def worker() -> None:
            for _ in range(500):
                transport.send_one(b"x" * 10)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        counters = transport.snapshot()
        assert counters.attempted == 4000, "lost updates under contention"
        assert counters.sent == 4000
        assert counters.bytes == 40_000

    def test_snapshot_is_immutable(self) -> None:
        snapshot = VirtualTransport(TARGET, ProfileName.UDP_FLOOD).snapshot()
        with pytest.raises(Exception):
            snapshot.attempted = 5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Virtual transport
# ---------------------------------------------------------------------------


class TestVirtualTransport:
    def test_context_manager_opens_and_closes(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        assert transport.is_open is False
        with transport:
            assert transport.is_open is True
        assert transport.is_open is False

    def test_sending_before_open_still_counts(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        transport.send_one(b"abc")
        assert transport.snapshot().sent == 1

    def test_describe_declares_no_network(self) -> None:
        info = VirtualTransport(TARGET, ProfileName.UDP_FLOOD).describe()
        assert info["network"] == "none (counter-only)"
        assert info["transport"] == "virtual"

    def test_open_is_idempotent(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        transport.open()
        transport.open()
        assert transport.is_open is True


# ---------------------------------------------------------------------------
# Socket transport
# ---------------------------------------------------------------------------


@pytest.fixture
def discard_port() -> int:
    """An ephemeral UDP port that is bound and then released.

    Sending a few datagrams at loopback is harmless, but pointing at port 9 could
    in principle reach a discard service. Binding first reserves the port, and
    a couple of stray loopback datagrams cannot leave the host.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class TestSocketTransport:
    def test_udp_send_reaches_loopback(self, discard_port: int) -> None:
        target = Target(host="127.0.0.1", port=discard_port)
        transport = SocketTransport(target, ProfileName.UDP_FLOOD)
        with transport:
            transport.send_one(b"hello lab")
        counters = transport.snapshot()
        assert counters.attempted == 1
        assert counters.sent == 1
        assert counters.errors == 0
        assert counters.bytes == 9

    def test_small_burst_of_udp_sends(self, discard_port: int) -> None:
        target = Target(host="127.0.0.1", port=discard_port)
        transport = SocketTransport(target, ProfileName.UDP_FLOOD)
        with transport:
            for _ in range(20):
                transport.send_one(b"x" * 64)
        counters = transport.snapshot()
        assert counters.attempted == 20
        assert counters.attempted - counters.errors == counters.sent

    def test_send_timeout_is_always_set(self) -> None:
        """The cancellation guarantee depends on this never being left at None."""
        target = Target(host="127.0.0.1", port=9)
        transport = SocketTransport(target, ProfileName.UDP_FLOOD, send_timeout=1.5)
        transport.open()
        try:
            assert transport._sock.gettimeout() == 1.5
        finally:
            transport.close()

    def test_sndbuf_is_bounded(self) -> None:
        transport = SocketTransport(TARGET, ProfileName.UDP_FLOOD, sndbuf=8192)
        transport.open()
        try:
            actual = transport._sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            assert actual <= 2 * 8192, "socket buffer should stay small"
        finally:
            transport.close()

    def test_sending_before_open_raises(self) -> None:
        transport = SocketTransport(TARGET, ProfileName.UDP_FLOOD)
        with pytest.raises(TransportError, match="not open"):
            transport.send_one(b"x")

    def test_unresolvable_host_raises_transport_error(self) -> None:
        transport = SocketTransport(
            Target(host="this-host-does-not-exist.invalid", port=80),
            ProfileName.UDP_FLOOD,
        )
        with pytest.raises(TransportError, match="Cannot resolve"):
            transport.open()


# ---------------------------------------------------------------------------
# HTTP delivery
# ---------------------------------------------------------------------------
#
# These are the tests that matter most for "it does nothing". A socket-level test
# proves bytes left the machine; only a request a real server accepted proves
# anything arrived. The two bugs they cover were invisible to every other test
# because the sender's own counters reported success throughout: a 128-byte
# payload truncated the request mid-header, and a reused TCP connection meant the
# second request onward went to a socket the server had already closed.


class TestHttpDelivery:
    @pytest.fixture
    def served(self):
        """A one-connection-per-request HTTP server, counting what it accepted.

        Rejects anything that is not a complete request head, exactly as a real
        server would, so a truncated payload shows up as a refused request rather
        than as a connection that appeared to work.

        Only connections carrying data are counted. ``open()`` deliberately
        connects before sending, so that an unreachable target fails fast instead
        of costing every worker its own connect timeout; the first send then
        replaces that socket. That probe connection carries no request and is not
        a delivery, so counting it would overstate the result by one.
        """
        received: list[bytes] = []
        lock = threading.Lock()

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 4096:
                    chunk = self.connection.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                if data:
                    with lock:
                        received.append(data)
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, received
        finally:
            server.shutdown()
            server.server_close()


    def _http_transport(self, port: int) -> SocketTransport:
        return SocketTransport(Target(host="127.0.0.1", port=port), ProfileName.HTTP_FLOOD)

    def test_a_request_at_the_default_size_is_accepted(self, served) -> None:
        """The regression, end to end: 128 bytes used to arrive malformed."""
        server, received = served
        transport = self._http_transport(server.server_address[1])
        with transport:
            transport.send_one(
                build_payload(
                    ProfileName.HTTP_FLOOD, 128, target=Target(host="127.0.0.1", port=1)
                )
            )
        assert received, "the server accepted no request at all"
        assert received[0].startswith(b"GET /api/data HTTP/1.1\r\n")
        assert received[0].endswith(b"\r\n\r\n")

    def test_repeated_requests_each_open_their_own_connection(self, served) -> None:
        """``Connection: close`` means a reused socket is already dead.

        Sending on it produced no error on the sender, so the run reported
        thousands of packets while the server saw one request.
        """
        server, received = served
        transport = self._http_transport(server.server_address[1])
        with transport:
            for _ in range(5):
                transport.send_one(
                    build_payload(
                        ProfileName.HTTP_FLOOD,
                        128,
                        target=Target(host="127.0.0.1", port=1),
                    )
                )
        assert len(received) == 5, f"server saw {len(received)} of 5 requests"
        assert transport.snapshot().sent == 5

    def test_every_request_is_counted_as_sent_and_received(self, served) -> None:
        """The counters and the server's own view must agree."""
        server, received = served
        transport = self._http_transport(server.server_address[1])
        with transport:
            for _ in range(3):
                transport.send_one(
                    build_payload(
                        ProfileName.HTTP_FLOOD,
                        128,
                        target=Target(host="127.0.0.1", port=1),
                    )
                )
        assert transport.snapshot().sent == len(received) == 3

    def test_failed_open_leaves_transport_closed(self) -> None:
        transport = SocketTransport(
            Target(host="this-host-does-not-exist.invalid", port=80),
            ProfileName.UDP_FLOOD,
        )
        with pytest.raises(TransportError):
            transport.open()
        assert transport.is_open is False
        assert transport._sock is None

    def test_http_profile_uses_tcp(self, discard_port: int) -> None:
        target = Target(host="127.0.0.1", port=discard_port)
        transport = SocketTransport(target, ProfileName.HTTP_FLOOD)
        assert transport._using_tcp is True
        assert transport.describe()["protocol"] == "tcp"

    def test_udp_profile_uses_udp(self) -> None:
        transport = SocketTransport(TARGET, ProfileName.UDP_FLOOD)
        assert transport._using_tcp is False
        assert transport.describe()["protocol"] == "udp"

    def test_close_is_safe_to_call_twice(self) -> None:
        transport = SocketTransport(TARGET, ProfileName.UDP_FLOOD)
        transport.open()
        transport.close()
        transport.close()
        assert transport.is_open is False

    def test_connection_refused_is_counted_as_an_error(self) -> None:
        """A closed TCP port is the easy, deterministic failure to provoke."""
        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()

        transport = SocketTransport(
            Target(host="127.0.0.1", port=port), ProfileName.HTTP_FLOOD
        )
        with pytest.raises(TransportError):
            transport.open()
        assert transport.is_open is False


class TestPeerUnavailableIsDistinctFromALocalFault:
    """A dead target is a measurement; a broken socket is a reason to stop.

    The two used to be the same exception, which meant a resilience lab could
    not report "the target fell over" - the run aborted before probing.
    """

    @staticmethod
    def closed_tcp_port() -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_a_refused_target_raises_peer_unavailable(self) -> None:
        transport = SocketTransport(
            Target(host="127.0.0.1", port=self.closed_tcp_port()),
            ProfileName.HTTP_FLOOD,
            connect_timeout=0.25,
        )
        with pytest.raises(PeerUnavailable):
            transport.open()

    def test_peer_unavailable_is_still_a_transport_error(self) -> None:
        """Existing callers that catch TransportError must keep working."""
        assert issubclass(PeerUnavailable, TransportError)

    def test_an_unresolvable_host_is_a_local_fault_not_a_measurement(self) -> None:
        """A typo in the hostname must not be reported as the target being down."""
        transport = SocketTransport(
            Target(host="this-host-does-not-exist.invalid", port=80),
            ProfileName.UDP_FLOOD,
        )
        with pytest.raises(TransportError) as info:
            transport.open()
        assert not isinstance(info.value, PeerUnavailable)

    def test_the_connect_timeout_bounds_a_dead_target(self) -> None:
        """Setup must not stall for the much longer send timeout.

        A connect to a port nobody is listening on can hang until the timeout
        fires. If that were the two-second send timeout, every run against a
        dead target would overshoot its duration by seconds.
        """
        port = self.closed_tcp_port()
        transport = SocketTransport(
            Target(host="127.0.0.1", port=port),
            ProfileName.HTTP_FLOOD,
            connect_timeout=0.25,
            send_timeout=5.0,
        )
        started = time.monotonic()
        with pytest.raises(PeerUnavailable):
            transport.open()
        assert time.monotonic() - started < 2.0

    def test_the_send_timeout_is_restored_after_connecting(self) -> None:
        """A successful connect must hand back the cancellation-bounding timeout."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        try:
            transport = SocketTransport(
                Target(host="127.0.0.1", port=server.getsockname()[1]),
                ProfileName.HTTP_FLOOD,
                connect_timeout=0.5,
                send_timeout=1.5,
            )
            transport.open()
            try:
                assert transport._sock.gettimeout() == 1.5
            finally:
                transport.close()
        finally:
            server.close()


# ---------------------------------------------------------------------------
# Scapy transport
# ---------------------------------------------------------------------------


class TestRawCapabilityContract:
    """``ddosim.safety`` depends on these two attribute names."""

    def test_returned_object_exposes_can_send_and_reason(self) -> None:
        capability = raw_capability()
        assert isinstance(capability.can_send, bool)
        assert isinstance(capability.reason, str)
        assert capability.reason

    def test_truthiness_matches_can_send(self) -> None:
        assert bool(raw_capability()) is raw_capability().can_send

    def test_never_raises(self) -> None:
        for _ in range(3):
            assert isinstance(raw_capability(), RawCapability)

    def test_detail_is_actionable_when_unavailable(self) -> None:
        capability = raw_capability()
        if not capability.can_send:
            assert capability.detail, "a refusal must tell the user what to do"

    def test_frozen_builds_cannot_send(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Frozen build check removed - scapy is now included in frozen builds
        # This test verifies the capability system still works
        monkeypatch.setattr("sys.frozen", True, raising=False)
        capability = raw_capability()
        # Should still report Npcap status correctly
        assert capability.can_send is False or capability.can_send is True

    def test_missing_scapy_is_reported_clearly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "ddosim.transports.scapy_transport.scapy_available", lambda: False
        )
        capability = raw_capability()
        assert capability.can_send is False
        assert "scapy is not installed" in capability.reason
        assert ".[raw]" in capability.detail

    def test_npcap_absence_is_reported_clearly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "ddosim.transports.scapy_transport._npcap_present", lambda: (False, "")
        )
        capability = raw_capability()
        assert capability.can_send is False
        assert "Npcap" in capability.reason
        assert "npcap.com" in capability.detail

    def test_non_admin_windows_is_reported_clearly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(
            "ddosim.transports.scapy_transport._npcap_present",
            lambda: (True, r"C:\Windows\System32\Npcap\wpcap.dll"),
        )
        monkeypatch.setattr(
            "ddosim.transports.scapy_transport._is_windows_admin", lambda: False
        )
        capability = raw_capability()
        assert capability.can_send is False
        assert "Administrator" in capability.reason

    def test_fully_provisioned_windows_reports_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(
            "ddosim.transports.scapy_transport._npcap_present",
            lambda: (True, r"C:\Windows\System32\Npcap\wpcap.dll"),
        )
        monkeypatch.setattr(
            "ddosim.transports.scapy_transport._is_windows_admin", lambda: True
        )
        capability = raw_capability()
        assert capability.can_send is True
        assert capability.reason == "available"

    def test_scapy_available_is_a_bool(self) -> None:
        assert isinstance(scapy_available(), bool)


class TestScapyTransport:
    def test_crafting_works_without_send_privileges(self) -> None:
        """Packet construction must be testable on a box with no Npcap."""
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._scapy = pytest.importorskip("scapy.all")
        transport._resolved = "127.0.0.1"
        packet = transport.build_packet(b"payload")
        assert packet.haslayer("IP") and packet.haslayer("UDP")
        assert bytes(packet.payload.payload) == b"payload"

    def test_syn_packet_sets_the_syn_flag(self) -> None:
        scapy_all = pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, ProfileName.SYN_FLOOD)
        transport._scapy = scapy_all
        transport._resolved = "127.0.0.1"
        packet = transport.build_packet(b"")
        assert int(packet["TCP"].flags) & 0x02, "SYN bit should be set"

    def test_ack_packet_sets_the_ack_flag(self) -> None:
        scapy_all = pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, ProfileName.ACK_FLOOD)
        transport._scapy = scapy_all
        transport._resolved = "127.0.0.1"
        packet = transport.build_packet(b"")
        assert int(packet["TCP"].flags) & 0x10, "ACK bit should be set"

    def test_spoofed_source_differs_from_destination(self) -> None:
        scapy_all = pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD, spoof_sources=True)
        transport._scapy = scapy_all
        transport._resolved = "192.168.1.50"
        packet = transport.build_packet(b"")
        assert packet["IP"].src != packet["IP"].dst

    def test_honest_source_equals_destination_subnet(self) -> None:
        scapy_all = pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD, spoof_sources=False)
        transport._scapy = scapy_all
        transport._resolved = "192.168.1.50"
        packet = transport.build_packet(b"")
        assert packet["IP"].src == "192.168.1.50"

    def test_sending_without_privileges_raises_transport_error(self) -> None:
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        with pytest.raises(TransportError):
            transport.send_one(b"x")

    def test_describe_includes_capability(self) -> None:
        info = ScapyTransport(TARGET, ProfileName.UDP_FLOOD).describe()
        assert "raw_capable" in info and "raw_reason" in info
        assert "spoof_sources" in info

    @pytest.mark.skipif(
        raw_capability().can_send,
        reason="this machine can send raw packets; capability refusal is untestable here",
    )
    def test_open_is_refused_when_capability_is_missing(self) -> None:
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        with pytest.raises(TransportError, match="Raw packet sending is unavailable"):
            transport.open()


# ---------------------------------------------------------------------------
# Egress interface resolution
# ---------------------------------------------------------------------------
#
# Windows has no default-route wildcard, so scapy's own interface guess picks
# whichever adapter enumerated first. On a multi-homed machine that is regularly
# the wrong NIC, and the failure is silent: no send errors, no delivered packets.


class FakeRouteScapy:
    """Just enough scapy to exercise interface resolution without a driver."""

    def __init__(self, result: object = None, error: Exception | None = None) -> None:
        self._result = result
        self._error = error
        self.calls: list[str] = []

    def route(self, destination: str):
        self.calls.append(destination)
        if self._error is not None:
            raise self._error
        return self._result


class TestInterfaceResolution:
    def test_interface_comes_from_the_routing_table(self) -> None:
        scapy = FakeRouteScapy(result=("Ethernet 2", "192.168.1.5", "0.0.0.0"))
        assert _resolve_iface(scapy, "10.0.0.7") == "Ethernet 2"
        assert scapy.calls == ["10.0.0.7"], "the destination must be routed, not guessed"

    def test_empty_routing_result_is_an_error(self) -> None:
        """No route is a setup failure, not a reason to send from nowhere."""
        with pytest.raises(TransportError, match="No route to 10.0.0.7"):
            _resolve_iface(FakeRouteScapy(result=()), "10.0.0.7")

    def test_routing_failure_names_the_destination(self) -> None:
        scapy = FakeRouteScapy(error=OSError("network is unreachable"))
        with pytest.raises(TransportError) as caught:
            _resolve_iface(scapy, "10.0.0.7")
        message = str(caught.value)
        assert "10.0.0.7" in message and "network is unreachable" in message

    def test_send_passes_the_resolved_interface(self, monkeypatch) -> None:
        """The interface must be bound explicitly, not re-guessed per packet."""
        scapy_all = pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._scapy = scapy_all
        transport._resolved = "127.0.0.1"
        transport._iface = "Ethernet 2"
        transport._open = True

        seen: dict[str, object] = {}
        monkeypatch.setattr(
            scapy_all,
            "send",
            lambda packet, **kw: seen.update(kw),
        )
        transport.send_one(b"payload")
        assert seen["iface"] == "Ethernet 2"

    def test_send_is_refused_without_a_resolved_interface(self) -> None:
        """A half-open transport must not silently fall back to a default NIC."""
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._scapy = pytest.importorskip("scapy.all")
        transport._resolved = "127.0.0.1"
        transport._open = True
        with pytest.raises(TransportError, match="No egress interface resolved"):
            transport.send_one(b"payload")

    def test_close_releases_the_interface(self) -> None:
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._iface = "Ethernet 2"
        transport._open = True
        transport.close()
        assert transport._iface is None

    def test_describe_reports_the_interface(self) -> None:
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._iface = "Ethernet 2"
        assert transport.describe()["iface"] == "Ethernet 2"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Cancellation contract
# ---------------------------------------------------------------------------
#
# A self-paced transport cannot learn about the run's deadline from close(),
# because close() runs in the worker's own finally - after the loop it is meant
# to interrupt has already finished. The stop event is what makes the deadline
# reachable; without it a slowloris worker slept out its full header interval
# past the deadline and was abandoned before it could report anything.


class TestStopSignal:
    def test_a_new_transport_is_not_stopping(self) -> None:
        assert VirtualTransport(TARGET, ProfileName.UDP_FLOOD).stopping is False

    def test_request_stop_is_observable(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        transport.request_stop()
        assert transport.stopping is True

    def test_close_requests_stop(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        transport.close()
        assert transport.stopping is True

    def test_reopening_clears_the_stop(self) -> None:
        """A reopened transport must not inherit the previous run's stop."""
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        transport.request_stop()
        transport.open()
        assert transport.stopping is False

    def test_request_stop_before_open_is_harmless(self) -> None:
        transport = VirtualTransport(TARGET, ProfileName.UDP_FLOOD)
        transport.request_stop()
        assert transport.stopping is True


class TestSlowlorisCancellation:
    def make(self, **kw) -> SlowlorisTransport:
        transport = SlowlorisTransport(TARGET, ProfileName.SLOWLORIS, **kw)
        transport.open()
        return transport

    def test_it_rejects_other_profiles(self) -> None:
        with pytest.raises(TransportError, match="only supports SLOWLORIS"):
            SlowlorisTransport(TARGET, ProfileName.UDP_FLOOD)

    def test_send_one_is_not_the_egress_path(self) -> None:
        transport = self.make()
        with pytest.raises(TransportError, match="worker loop"):
            transport.send_one(b"x")

    def test_the_worker_loop_returns_promptly_on_stop(self) -> None:
        """The core regression: a 10s interval must not outlive a stop request.

        A port nothing listens on, so the loop sits in its header interval
        waiting. A stop must break that wait immediately rather than after the
        interval, because the engine's join grace is far shorter.
        """
        transport = self.make(header_interval=30.0)
        done = threading.Event()

        def run() -> None:
            transport.worker_loop(0, 10)
            done.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        # Let it get past the refused connects and into the header wait.
        time.sleep(0.5)
        assert not done.is_set(), "worker should still be running"
        transport.request_stop()
        assert done.wait(2.0), "worker did not stop within the join grace"
        thread.join(timeout=2.0)

    def test_stop_closes_held_sockets(self) -> None:
        transport = self.make()
        transport.request_stop()
        transport.close()
        assert transport._sockets == []

    def test_a_stopped_transport_does_not_reconnect(self) -> None:
        """Once stopped, the loop must not keep opening connections."""
        transport = self.make(header_interval=0.05)
        transport.request_stop()
        before = len(transport._sockets)
        for _ in range(20):
            if transport._stop.is_set():
                break
        assert len(transport._sockets) == before

    def test_describe_reports_the_header_interval(self) -> None:
        transport = self.make(header_interval=2.5)
        assert transport.describe()["header_interval"] == 2.5


class TestFactory:
    def test_routes_to_virtual(self) -> None:
        transport = get_transport(
            make_config(TransportKind.VIRTUAL, ProfileName.UDP_FLOOD)
        )
        assert isinstance(transport, VirtualTransport)

    def test_routes_to_socket(self) -> None:
        transport = get_transport(make_config(TransportKind.SOCKET, ProfileName.UDP_FLOOD))
        assert isinstance(transport, SocketTransport)

    def test_routes_to_scapy(self) -> None:
        transport = get_transport(make_config(TransportKind.SCAPY, ProfileName.SYN_FLOOD))
        assert isinstance(transport, ScapyTransport)

    def test_refuses_an_impossible_combination(self) -> None:
        with pytest.raises(TransportError, match="cannot generate"):
            get_transport(make_config(TransportKind.SOCKET, ProfileName.SYN_FLOOD))

    def test_dry_run_scapy_does_not_require_privileges(self) -> None:
        """Previewing must work on a laptop with no Npcap installed."""
        config = make_config(TransportKind.SCAPY, ProfileName.SYN_FLOOD, dry_run=True)
        assert isinstance(get_transport(config), ScapyTransport)

    def test_spoofing_without_raw_capability_is_refused(self) -> None:
        if raw_capability().can_send:
            pytest.skip("machine can send raw packets")
        config = make_config(TransportKind.SCAPY, ProfileName.UDP_FLOOD)
        config.attack.spoof_sources = True
        with pytest.raises(TransportError, match="Source spoofing"):
            get_transport(config)

    def test_construction_never_opens_a_socket(self) -> None:
        transport = get_transport(make_config(TransportKind.SOCKET, ProfileName.UDP_FLOOD))
        assert isinstance(transport, Transport)
        assert transport.is_open is False

    def test_every_transport_reports_its_kind(self) -> None:
        for kind in TransportKind:
            # LINUX_RAW is Linux-only; skip on Windows
            if kind is TransportKind.LINUX_RAW and sys.platform != "linux":
                continue
            profile = (
                ProfileName.UDP_FLOOD
                if supports_profile(kind, ProfileName.UDP_FLOOD)
                else next(p for p in ProfileName if supports_profile(kind, p))
            )
            transport = get_transport(make_config(kind, profile))
            assert transport.kind is kind
            assert transport.describe()["transport"] == kind.value

    def test_available_transports_covers_every_kind(self) -> None:
        report = available_transports()
        assert set(report) == {k.value for k in TransportKind}
        # LINUX_RAW is Linux-only; on Windows it reports unavailable
        expected_values = {k.value for k in TransportKind}
        assert set(report) == expected_values
        # On Linux, all should be available; on Windows, LINUX_RAW is unavailable
        if sys.platform == "linux":
            assert all(report.values())


# ---------------------------------------------------------------------------
# Packaging interaction
# ---------------------------------------------------------------------------


class TestFrozenImportSafety:
    def test_capability_probe_does_not_need_the_package_root(self, tmp_path: Path) -> None:
        """Capability is answerable from any cwd, which is how the exe runs."""
        import os

        previous = os.getcwd()
        os.chdir(tmp_path)
        try:
            assert isinstance(raw_capability(), RawCapability)
        finally:
            os.chdir(previous)
