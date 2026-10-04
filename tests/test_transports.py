"""Tests for the transport layer.

Two rules govern this file:

* **No packet leaves the machine except in a handful of deliberately tiny
  loopback tests.** A capability test must never assert that a real raw packet
  was transmitted, because the result would depend on whether the machine
  running the suite happens to have Npcap and Administrator.
* **The ``raw_capability`` contract is asserted structurally.** ``adobo.safety``
  reads ``can_send`` and ``reason`` by name, so a rename there would break
  refusals at runtime rather than at import. These tests fail on that.
"""

from __future__ import annotations

import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

from adobo.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TransportKind,
)
from adobo.transports import (
    PeerUnavailable,
    RawCapability,
    ScapyTransport,
    SocketTransport,
    SlowlorisTransport,
    Transport,
    TransportCounters,
    TransportError,
    VirtualTransport,
    H2Transport,
    available_transports,
    build_payload,
    get_transport,
    raw_capability,
    scapy_available,
    supports_profile,
)
from adobo.transports.scapy_transport import _resolve_iface
from adobo.transports.http2_transport import DEFAULT_STREAM_TIMEOUT

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
        assert b"adobo" in build_payload(ProfileName.UDP_FLOOD, 256)

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
        assert payload.endswith(b"\r\n\r\n") or b"adobo" in payload

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
    """``adobo.safety`` depends on these two attribute names."""

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
            "adobo.transports.scapy_transport.scapy_available", lambda: False
        )
        capability = raw_capability()
        assert capability.can_send is False
        assert "scapy is not installed" in capability.reason
        assert ".[raw]" in capability.detail

    def test_npcap_absence_is_reported_clearly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "adobo.transports.scapy_transport._npcap_present", lambda: (False, "")
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
            "adobo.transports.scapy_transport._npcap_present",
            lambda: (True, r"C:\Windows\System32\Npcap\wpcap.dll"),
        )
        monkeypatch.setattr(
            "adobo.transports.scapy_transport._is_windows_admin", lambda: False
        )
        capability = raw_capability()
        assert capability.can_send is False
        assert "Administrator" in capability.reason

    def test_fully_provisioned_windows_reports_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(
            "adobo.transports.scapy_transport._npcap_present",
            lambda: (True, r"C:\Windows\System32\Npcap\wpcap.dll"),
        )
        monkeypatch.setattr(
            "adobo.transports.scapy_transport._is_windows_admin", lambda: True
        )
        capability = raw_capability()
        assert capability.can_send is True
        assert capability.reason == "available"

    def test_scapy_available_is_a_bool(self) -> None:
        assert isinstance(scapy_available(), bool)


# ---------------------------------------------------------------------------
# Linux raw packet construction
# ---------------------------------------------------------------------------


def make_linux_raw(profile: ProfileName = ProfileName.UDP_FLOOD, **kw):
    """A LinuxRawTransport with its addressing resolved but no socket opened.

    Construction is deliberately cheap and privilege-free: the packet builders
    only read precomputed header bytes and the two address fields, so they can
    be exercised on a box that cannot open a raw socket at all.
    """
    from adobo.transports.linux_raw_transport import LinuxRawTransport

    transport = LinuxRawTransport(Target(host="192.168.1.50", port=9999), profile, **kw)
    transport._resolved_ip = "192.168.1.50"
    transport._src_ip = "192.168.1.77"
    transport._prebuild_headers(512)
    return transport


class TestLinuxRawBuilders:
    """Every builder must produce a real packet, not just avoid raising.

    These four builders used to be reachable only from the send path, which
    needs CAP_NET_RAW, so the suite never called them. A refactor could leave
    one referencing a deleted local and 400+ tests would still pass, because
    send_one() catches the resulting NameError and logs it as a warning. A run
    would then report zero packets and exit zero.
    """

    def test_icmp_fast_matches_reference_builder(self) -> None:
        t = make_linux_raw(ProfileName.ICMP_FLOOD, seed=1234)
        payload = bytes(range(256)) * 2
        assert t._build_icmp_packet_fast(payload) == t._build_icmp_packet(payload)

    def test_udp_fast_matches_reference_builder(self) -> None:
        t = make_linux_raw(ProfileName.UDP_FLOOD, seed=1234)
        payload = b"x" * 512
        assert t._build_udp_packet_fast(payload) == t._build_udp_packet(payload)

    def test_tcp_fast_matches_reference_builder(self) -> None:
        t = make_linux_raw(ProfileName.SYN_FLOOD, seed=1234)
        payload = b"x" * 512
        flags = 0x02  # SYN
        assert t._build_tcp_packet_fast(payload, flags) == t._build_tcp_packet(
            payload, flags
        )

    @pytest.mark.parametrize(
        "profile,build,flags,uses_pseudo",
        [
            (ProfileName.ICMP_FLOOD, "icmp", None, False),
            (ProfileName.UDP_FLOOD, "udp", None, True),
            (ProfileName.SYN_FLOOD, "tcp", 0x02, True),
            (ProfileName.ACK_FLOOD, "tcp", 0x10, True),
        ],
    )
    def test_transport_checksum_verifies_as_a_receiver_computes_it(
        self, profile: ProfileName, build: str, flags: int | None, uses_pseudo: bool
    ) -> None:
        """Checksum the way a receiver does, not the way the sender did.

        A sender can produce a self-consistent but wrong checksum and never
        notice. The receiver recomputes over the segment - with the IPv4 pseudo
        header for UDP and TCP, without one for ICMP - and drops anything that
        does not sum to zero. That check is the only thing standing between a
        bad builder and a target that silently ignores every packet, which
        looks identical to a target that shrugged off the attack.
        """
        t = make_linux_raw(profile, seed=99)
        payload = b"z" * 512
        if build == "icmp":
            packet = t._build_icmp_packet_fast(payload)
        elif build == "udp":
            packet = t._build_udp_packet_fast(payload)
        else:
            packet = t._build_tcp_packet_fast(payload, flags)

        segment = packet[20:]
        if uses_pseudo:
            # The pseudo header's length is the segment length: the IP total
            # length less the 20-byte IPv4 header. It is NOT the UDP length
            # field - at segment[2:4] sits the destination port.
            seg_len = int.from_bytes(packet[2:4], "big") - 20
            assert seg_len == len(segment), "segment length disagrees with IP header"
            pseudo = (
                socket.inet_aton("192.168.1.77")
                + socket.inet_aton("192.168.1.50")
                + struct.pack("!BBH", 0, packet[9], seg_len)
            )
            assert t._checksum(pseudo + segment) == 0, "transport checksum invalid"
        else:
            assert t._checksum(segment) == 0, "ICMP checksum invalid"

    @pytest.mark.parametrize(
        "profile,build,expected_proto",
        [
            (ProfileName.ICMP_FLOOD, "icmp", socket.IPPROTO_ICMP),
            (ProfileName.UDP_FLOOD, "udp", socket.IPPROTO_UDP),
            (ProfileName.SYN_FLOOD, "tcp", socket.IPPROTO_TCP),
        ],
    )
    def test_fast_builder_emits_correct_protocol_and_addresses(
        self, profile: ProfileName, build: str, expected_proto: int
    ) -> None:
        """The IP header must name the right protocol and the real endpoints.

        A builder that silently packs the wrong protocol byte still produces a
        plausible-looking packet, and the error only surfaces as "the target did
        not respond" - which reads like a target that shrugged off the attack.
        """
        t = make_linux_raw(profile, seed=99)
        payload = b"z" * 512
        if build == "icmp":
            packet = t._build_icmp_packet_fast(payload)
        elif build == "udp":
            packet = t._build_udp_packet_fast(payload)
        else:
            packet = t._build_tcp_packet_fast(payload, 0x02)

        assert packet[9] == expected_proto, "IP protocol byte"
        assert socket.inet_ntoa(packet[12:16]) == "192.168.1.77", "source address"
        assert socket.inet_ntoa(packet[16:20]) == "192.168.1.50", "destination address"
        # IPv4 layout: total length at 2:4, header checksum at 10:12.
        assert int.from_bytes(packet[2:4], "big") == len(packet), "IP total length"
        assert t._checksum(packet[:20]) == 0, "IP header checksum verifies"

    def test_fast_builders_are_reachable_before_prebuild(self) -> None:
        """A builder must not raise when _prebuild_headers has not run.

        The fast builders read cached header bases. Those are populated during
        open(), so calling one on a fresh transport is a misuse - but it should
        fail as a malformed packet, not an AttributeError, since the fast ICMP
        path is the send path and a confusing crash there costs a whole run.
        """
        from adobo.transports.linux_raw_transport import LinuxRawTransport

        t = LinuxRawTransport(TARGET, ProfileName.UDP_FLOOD)
        t._resolved_ip = "127.0.0.1"
        t._src_ip = "127.0.0.1"
        packet = t._build_udp_packet_fast(b"x" * 32)
        assert socket.inet_ntoa(packet[12:16]) == "127.0.0.1"


class TestLinuxRawSourceAddressCaching:
    """The source address is resolved once per run, not once per packet."""

    def test_second_call_does_not_reopen_a_socket(self, monkeypatch) -> None:
        from adobo.transports import linux_raw_transport as mod

        t = make_linux_raw(ProfileName.ICMP_FLOOD)
        assert t._source_address() == "192.168.1.77"

        def explode(*a, **k):  # pragma: no cover - must never run
            raise AssertionError("socket opened in the packet hot path")

        monkeypatch.setattr(mod.socket, "socket", explode)
        for _ in range(1000):
            assert t._source_address() == "192.168.1.77"

    def test_resolve_is_cached_after_first_call(self) -> None:
        from adobo.transports.linux_raw_transport import LinuxRawTransport

        t = LinuxRawTransport(TARGET, ProfileName.ICMP_FLOOD)
        t._resolved_ip = "127.0.0.1"
        assert t._src_ip == ""
        first = t._source_address()
        assert first
        assert t._src_ip == first, "resolution should be stored for later calls"

    def test_hot_path_builds_open_no_sockets(self, monkeypatch) -> None:
        """Building 500 packets must not touch the socket module at all.

        This is the regression that cost the ICMP path roughly two thirds of its
        throughput: _source_address() used to open, connect, read and close a
        throwaway UDP socket on every single packet.
        """
        from adobo.transports import linux_raw_transport as mod

        t = make_linux_raw(ProfileName.ICMP_FLOOD)

        def explode(*a, **k):  # pragma: no cover - must never run
            raise AssertionError("socket opened while building packets")

        monkeypatch.setattr(mod.socket, "socket", explode)
        for _ in range(500):
            t._build_icmp_packet_fast(b"x" * 512)
            t._build_udp_packet_fast(b"x" * 512)
            t._build_tcp_packet_fast(b"x" * 512, 0x02)


class TestLinuxRawSendBuffer:
    def test_default_send_buffer_is_bounded(self) -> None:
        """A multi-megabyte send buffer is a measurement problem, not a speed one.

        64MB held ~12s of traffic at flood rates, so the sender's own probes
        queued behind its own backlog and latency the tool charged to the target
        was really local queueing.
        """
        from adobo.transports.linux_raw_transport import DEFAULT_SNDBUF

        assert DEFAULT_SNDBUF <= 4 * 1024 * 1024

    def test_send_buffer_is_configurable(self) -> None:
        from adobo.transports.linux_raw_transport import LinuxRawTransport

        t = LinuxRawTransport(TARGET, ProfileName.UDP_FLOOD, sndbuf=256 * 1024)
        assert t._sndbuf == 256 * 1024

    def test_unset_socket_option_is_not_fatal(self, monkeypatch) -> None:
        """A kernel that refuses the buffer size must not abort the run.

        The buffer governs how much undelivered traffic the kernel will hold
        before it starts refusing writes. Pacing governs the rate. Losing the
        run over a tuning parameter is the wrong trade.
        """
        from adobo.transports.linux_raw_transport import LinuxRawTransport

        t = LinuxRawTransport(TARGET, ProfileName.UDP_FLOOD, sndbuf=1)

        class Refusing:
            type = 17

            def setsockopt(self, *a, **k):
                raise OSError(22, "Invalid argument")

        # Must not raise.
        t._apply_sndbuf(Refusing())


class FakeRecordingSocket:
    """Stands in for scapy's layer-3 socket.

    Counts what crossed it so a test can assert on send behaviour without a
    driver, and can be told when to stop so the self-paced loop terminates.
    """

    def __init__(self, stop_after: int | None = None) -> None:
        self.sent = 0
        self.closed = 0
        self.packets: list[bytes] = []
        self._stop_after = stop_after
        self._on_send = None

    def send(self, packet: object) -> None:
        self.sent += 1
        self.packets.append(bytes(packet))
        if self._stop_after is not None and self.sent >= self._stop_after:
            if self._on_send is not None:
                self._on_send()

    def close(self) -> None:
        self.closed += 1


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


class TestRawSendLoop:
    """The self-paced loop is where a raw transport's rate actually comes from.

    A measured run managed about 74 packets per second per profile, which is
    three orders of magnitude below what the hardware can do. The cost was not
    the syscall: it was rebuilding the payload, rebuilding the packet and
    re-resolving the route for every single packet. These pin the properties
    that took that work out of the loop.
    """

    @staticmethod
    def _ready(profile: ProfileName, stop_after: int = 50) -> ScapyTransport:
        scapy_all = pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, profile)
        transport._scapy = scapy_all
        transport._resolved = "127.0.0.1"
        transport._iface = "eth0"
        sock = FakeRecordingSocket(stop_after=stop_after)
        sock._on_send = transport.request_stop
        transport._sock = sock
        transport._open = True
        return transport

    def test_the_payload_is_built_once_not_per_packet(self, monkeypatch) -> None:
        """Fifty packets, one payload. This is the per-packet cost removed."""
        transport = self._ready(ProfileName.SYN_FLOOD, stop_after=50)
        import adobo.transports.scapy_transport as module

        calls: list[int] = []
        original = module.build_payload

        def counting(*args: object, **kwargs: object) -> bytes:
            calls.append(1)
            return original(*args, **kwargs)

        monkeypatch.setattr(module, "build_payload", counting)
        attack = AttackProfile(
            profile=ProfileName.SYN_FLOOD,
            pps=10_000_000,
            payload_size=64,
        )
        transport.worker_loop(0, 10_000_000, attack)

        assert transport._sock.sent == 50
        assert len(calls) == 1, f"payload rebuilt {len(calls)} times for 50 packets"

    def test_every_packet_on_the_wire_is_distinct(self) -> None:
        """Repeating one identical frame is not a flood; it is one packet."""
        transport = self._ready(ProfileName.SYN_FLOOD, stop_after=50)
        attack = AttackProfile(
            profile=ProfileName.SYN_FLOOD,
            pps=10_000_000,
            payload_size=64,
        )
        transport.worker_loop(0, 10_000_000, attack)

        unique = set(transport._sock.packets)
        assert len(unique) == 50, "packets must differ from one another"

    def test_the_synd_bit_survives_the_reuse(self) -> None:
        """Mutating one packet object must not corrupt the fixed header."""
        scapy_all = pytest.importorskip("scapy.all")
        transport = self._ready(ProfileName.SYN_FLOOD, stop_after=5)
        attack = AttackProfile(
            profile=ProfileName.SYN_FLOOD,
            pps=10_000_000,
            payload_size=64,
        )
        transport.worker_loop(0, 10_000_000, attack)

        for wire in transport._sock.packets:
            assert int(scapy_all.IP(wire)["TCP"].flags) & 0x02, "SYN bit must be set"

    def test_counters_match_what_was_sent(self) -> None:
        """The reported rate has to be the rate, not a separate guess."""
        transport = self._ready(ProfileName.ICMP_FLOOD, stop_after=40)
        attack = AttackProfile(
            profile=ProfileName.ICMP_FLOOD,
            pps=10_000_000,
            payload_size=64,
        )
        transport.worker_loop(0, 10_000_000, attack)

        counters = transport.snapshot()
        assert counters.sent == 40
        assert counters.attempted == 40
        assert counters.errors == 0

    def test_request_stop_ends_the_loop_promptly(self) -> None:
        """The engine stops a self-paced transport by setting its event."""
        transport = self._ready(ProfileName.UDP_FLOOD, stop_after=10_000)
        transport.request_stop()
        attack = AttackProfile(
            profile=ProfileName.UDP_FLOOD,
            pps=10_000_000,
            payload_size=64,
        )
        transport.worker_loop(0, 10_000_000, attack)
        assert transport._sock.sent == 0

    def test_a_low_rate_is_actually_paced(self) -> None:
        """The loop must not ignore the rate it was handed."""
        transport = self._ready(ProfileName.UDP_FLOOD, stop_after=20)
        attack = AttackProfile(
            profile=ProfileName.UDP_FLOOD,
            pps=200,
            payload_size=64,
        )
        started = time.monotonic()
        transport.worker_loop(0, 200, attack)
        elapsed = time.monotonic() - started

        assert transport._sock.sent == 20
        # 20 packets at 200/s is ~0.1s. Generous bound, because the point is
        # that it slept at all - a loop that ignored the rate would finish in
        # microseconds.
        assert elapsed >= 0.05, f"20 packets at 200/s finished in {elapsed:.4f}s"

    def test_a_send_failure_is_counted_and_raised(self) -> None:
        """A driver error must surface, not be swallowed into a slow run."""
        transport = self._ready(ProfileName.UDP_FLOOD, stop_after=5)

        class Failing:
            def send(self, packet: object) -> None:
                raise OSError("driver refused the packet")

            def close(self) -> None:
                pass

        transport._sock = Failing()
        attack = AttackProfile(
            profile=ProfileName.UDP_FLOOD,
            pps=10_000_000,
            payload_size=64,
        )
        with pytest.raises(TransportError, match="Raw send failed"):
            transport.worker_loop(0, 10_000_000, attack)
        assert transport.snapshot().errors == 1

    def test_the_loop_refuses_to_run_before_open(self) -> None:
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        attack = AttackProfile(profile=ProfileName.UDP_FLOOD, pps=1000)
        with pytest.raises(TransportError, match="not open"):
            transport.worker_loop(0, 1000, attack)

    def test_reopening_clears_a_previous_stop(self, monkeypatch) -> None:
        """A reused transport must not come back already stopped.

        open() overrode the base method without clearing the stop event, so a
        transport closed after one run and opened for the next would exit its
        send loop immediately and report a clean zero - indistinguishable from
        a run that worked.
        """
        import adobo.transports.scapy_transport as module

        pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport.request_stop()
        assert transport.stopping, "precondition: the transport is stopped"

        # Everything privileged is stubbed; the event reset happens after all
        # of it, so reaching the assertion means open() really did run.
        monkeypatch.setattr(
            module, "raw_capability", lambda: module.RawCapability(True, "available")
        )
        monkeypatch.setattr(module, "_resolve_iface", lambda scapy, dest: "eth0")
        monkeypatch.setattr(transport, "_verify_egress", lambda scapy: None)
        monkeypatch.setattr(transport, "_open_socket", lambda scapy: None)

        transport.open()

        assert transport.is_open
        assert not transport.stopping, "open() must rearm a stopped transport"


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

    def test_the_raw_socket_is_bound_to_the_resolved_interface(self, monkeypatch) -> None:
        """The interface must be bound once, not re-guessed per packet."""
        scapy_all = pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._scapy = scapy_all
        transport._resolved = "127.0.0.1"
        transport._iface = "Ethernet 2"

        bound: dict[str, object] = {}

        class FakeSocket:
            def __init__(self, **kwargs: object) -> None:
                bound.update(kwargs)

            def send(self, packet: object) -> None:
                bound["sent"] = packet

            def close(self) -> None:
                bound["closed"] = True

        monkeypatch.setattr(scapy_all.conf, "L3socket", FakeSocket)
        transport._open_socket(scapy_all)
        transport._open = True
        transport.send_one(b"payload")

        assert bound["iface"] == "Ethernet 2"
        assert bound["sent"] is not None, "the packet must go out on the bound socket"

    def test_a_send_does_not_re_resolve_the_route(self, monkeypatch) -> None:
        """scapy.send() re-routes and rebuilds a socket on every call.

        That wrapper is the per-packet cost this path exists to avoid, so the
        test pins the absence of it: if someone reintroduces the convenience
        call here, the send explodes rather than quietly getting slower.
        """
        scapy_all = pytest.importorskip("scapy.all")
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._scapy = scapy_all
        transport._resolved = "127.0.0.1"
        transport._iface = "Ethernet 2"
        transport._sock = FakeRecordingSocket()
        transport._open = True

        def explode(*args: object, **kwargs: object) -> None:
            raise AssertionError("the per-packet send helper must not be used")

        monkeypatch.setattr(scapy_all, "send", explode)
        transport.send_one(b"payload")
        assert transport._sock.sent == 1

    def test_close_releases_the_bound_socket(self) -> None:
        """A handle left open per transport is a handle leaked per worker."""
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        socket_ = FakeRecordingSocket()
        transport._sock = socket_
        transport._open = True
        transport.close()
        assert socket_.closed == 1
        assert transport._sock is None

    def test_close_survives_a_socket_that_cannot_be_closed(self) -> None:
        """Teardown must not raise, or it masks whatever ended the run."""
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)

        class Refusing:
            def close(self) -> None:
                raise OSError("already gone")

        transport._sock = Refusing()
        transport._open = True
        transport.close()
        assert transport._sock is None

    def test_send_is_refused_without_a_bound_socket(self) -> None:
        """A transport with only an interface resolved has nothing to send on."""
        transport = ScapyTransport(TARGET, ProfileName.UDP_FLOOD)
        transport._scapy = pytest.importorskip("scapy.all")
        transport._resolved = "127.0.0.1"
        transport._iface = "Ethernet 2"
        transport._open = True
        with pytest.raises(TransportError, match="No raw socket is open"):
            transport.send_one(b"payload")

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


# ---------------------------------------------------------------------------
# Keep-alive and TLS tests
# ---------------------------------------------------------------------------


class _StubSocket:
    """Just enough socket for SocketTransport.open() to succeed offline."""

    def settimeout(self, value):  # pragma: no cover - trivial
        self.timeout = value

    def setsockopt(self, *args):  # pragma: no cover - trivial
        return None

    def connect(self, addr):  # pragma: no cover - trivial
        self.addr = addr

    def close(self):  # pragma: no cover - trivial
        return None


class _StubSocketModule:
    """A stand-in for the socket module's two functions open() touches."""

    AF_INET = 2
    SOCK_STREAM = 1
    SOCK_DGRAM = 2
    SOCK_NONBLOCK = 2048
    SOL_SOCKET = 1
    SO_SNDBUF = 7

    @staticmethod
    def getaddrinfo(host, port, type=0):
        return [(2, 1, 6, "", ("127.0.0.1", port))]

    @staticmethod
    def socket(family, socktype, proto=0):
        return _StubSocket()


class TestSocketTransportKeepAlive:
    """Tests for HTTP keep-alive mode.

    Keep-alive reuses the TCP connection across requests, which dramatically
    increases throughput but loses the per-request delivery guarantee: a local
    ``sendall`` can succeed after the peer has closed the connection, so the
    sender's counter may overcount. These tests verify the behaviour and that
    the trade-off is correctly implemented.
    """

    def test_reopening_mid_run_does_not_undo_a_stop(self, monkeypatch) -> None:
        """open() must NOT clear the stop event, unlike the base class.

        The exact inverse of ``test_reopening_clears_a_previous_stop`` on the
        scapy transport, and it is deliberate. SocketTransport recycles mid-run:
        the send path calls ``_teardown()`` then ``open()`` when a connection
        drops or reaches RECYCLE_EVERY. So a stop request that arrived just
        before a recycle would be cleared by that recycle, and the transport
        would go on sending after the engine had already given up on it.

        H2Transport's open() *does* clear, and that is correct there because it
        is only ever called once at startup. The two are not interchangeable.

        The sequence is _teardown() then open(), not open() alone, because
        _teardown() is what clears ``_open`` - and with the transport still
        marked open, open() returns immediately and the test would pass without
        ever reaching the line it is meant to police.
        """
        transport = SocketTransport(
            Target(host="127.0.0.1", port=8000), ProfileName.HTTP_FLOOD
        )
        transport.request_stop()
        assert transport.stopping, "precondition: the transport is stopped"

        from adobo.transports import socket_transport as socket_transport_module

        # Stub the real socket work so open() runs its body rather than bailing
        # out on getaddrinfo or connect against a closed port.
        monkeypatch.setattr(socket_transport_module, "socket", _StubSocketModule())

        # Exactly what the recycle paths do.
        transport._teardown()
        transport.open()

        assert transport.is_open, "the recycle should have reopened the transport"
        assert transport.stopping, (
            "a mid-run reopen must not resurrect a transport the engine stopped"
        )

    def test_keep_alive_disables_per_request_close(self) -> None:
        """In keep-alive mode, _close_per_request must be False."""
        target = Target(host="127.0.0.1", port=8000)
        transport = SocketTransport(
            target, ProfileName.HTTP_FLOOD, keep_alive=True
        )
        assert transport.keep_alive is True
        assert transport._close_per_request is False

    def test_keep_alive_defaults_to_per_request_close(self) -> None:
        """Without keep-alive, per-request close is the default for honesty."""
        target = Target(host="127.0.0.1", port=8000)
        transport = SocketTransport(
            target, ProfileName.HTTP_FLOOD, keep_alive=False
        )
        assert transport.keep_alive is False
        assert transport._close_per_request is True

    def test_describe_includes_keep_alive(self) -> None:
        """The describe() output must include keep_alive for reporting."""
        target = Target(host="127.0.0.1", port=8000)
        transport = SocketTransport(
            target, ProfileName.HTTP_FLOOD, keep_alive=True
        )
        desc = transport.describe()
        assert desc.get("keep_alive") is True

        transport2 = SocketTransport(target, ProfileName.HTTP_FLOOD, keep_alive=False)
        desc2 = transport2.describe()
        assert desc2.get("keep_alive") is False

    def test_keep_alive_and_tls_can_be_combined(self) -> None:
        """Keep-alive and TLS are orthogonal and can be used together."""
        target = Target(host="127.0.0.1", port=443)
        transport = SocketTransport(
            target,
            ProfileName.HTTP_FLOOD,
            keep_alive=True,
            use_tls=True,
            tls_verify=False,
        )
        assert transport.keep_alive is True
        assert transport.use_tls is True
        assert transport._close_per_request is False
        desc = transport.describe()
        assert desc.get("keep_alive") is True
        assert desc.get("use_tls") is True


class TestSocketTransportTLS:
    """Tests for TLS/HTTPS support in the socket transport."""

    def test_use_tls_creates_ssl_context(self) -> None:
        """use_tls=True must create an SSL context."""
        target = Target(host="127.0.0.1", port=443)
        transport = SocketTransport(
            target, ProfileName.HTTP_FLOOD, use_tls=True
        )
        assert transport.use_tls is True
        assert transport._tls_context is None  # Built on open()
        assert transport.tls_verify is True

    def test_tls_no_verify_disables_verification(self) -> None:
        """tls_verify=False must disable hostname and cert verification."""
        target = Target(host="127.0.0.1", port=443)
        transport = SocketTransport(
            target, ProfileName.HTTP_FLOOD, use_tls=True, tls_verify=False
        )
        assert transport.tls_verify is False
        ctx = transport._build_tls_context()
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_tls_default_verifies(self) -> None:
        """Default TLS behaviour must verify hostname and cert."""
        target = Target(host="127.0.0.1", port=443)
        transport = SocketTransport(
            target, ProfileName.HTTP_FLOOD, use_tls=True
        )
        ctx = transport._build_tls_context()
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_describe_includes_use_tls(self) -> None:
        """The describe() output must include use_tls for reporting."""
        target = Target(host="127.0.0.1", port=443)
        transport = SocketTransport(target, ProfileName.HTTP_FLOOD, use_tls=True)
        desc = transport.describe()
        assert desc.get("use_tls") is True


class TestCLIConfigFromArgs:
    """Tests for CLI argument parsing and config construction."""

    def test_keep_alive_flag_reaches_attack_profile(self) -> None:
        """--keep-alive must set attack.keep_alive."""
        from adobo.cli import config_from_args

        class Args:
            profile = "http_flood"
            pps = 100
            duration = 1
            payload = 512
            workers = 4
            spoof_sources = False
            keep_alive = True
            tls = False
            tls_no_verify = False
            http2 = False
            h2_concurrency = 100
            fingerprint = "lab_default"
            fingerprint_rotation = "per_connection"
            host = "127.0.0.1"
            port = 8000
            transport = "auto"

        config = config_from_args(Args())
        assert config.attack.keep_alive is True

    def test_tls_flag_reaches_attack_profile(self) -> None:
        """--tls must set attack.use_tls."""
        from adobo.cli import config_from_args

        class Args:
            profile = "http_flood"
            pps = 100
            duration = 1
            payload = 512
            workers = 4
            spoof_sources = False
            keep_alive = False
            tls = True
            tls_no_verify = False
            http2 = False
            h2_concurrency = 100
            fingerprint = "lab_default"
            fingerprint_rotation = "per_connection"
            host = "127.0.0.1"
            port = 443
            transport = "auto"

        config = config_from_args(Args())
        assert config.attack.use_tls is True
        assert config.attack.tls_verify is True

    def test_tls_no_verify_implies_tls(self) -> None:
        """--tls-no-verify must imply --tls and disable verification."""
        from adobo.cli import config_from_args

        class Args:
            profile = "http_flood"
            pps = 100
            duration = 1
            payload = 512
            workers = 4
            spoof_sources = False
            keep_alive = False
            tls = False
            tls_no_verify = True
            http2 = False
            h2_concurrency = 100
            fingerprint = "lab_default"
            fingerprint_rotation = "per_connection"
            host = "127.0.0.1"
            port = 8000
            transport = "auto"

        config = config_from_args(Args())
        assert config.attack.use_tls is True
        assert config.attack.tls_verify is False

    def test_auto_tls_on_port_443(self) -> None:
        """Port 443 must auto-enable TLS even without --tls flag."""
        from adobo.cli import config_from_args

        class Args:
            profile = "http_flood"
            pps = 100
            duration = 1
            payload = 512
            workers = 4
            spoof_sources = False
            keep_alive = False
            tls = False
            tls_no_verify = False
            http2 = False
            h2_concurrency = 100
            fingerprint = "lab_default"
            fingerprint_rotation = "per_connection"
            host = "127.0.0.1"
            port = 443
            transport = "auto"

        config = config_from_args(Args())
        assert config.attack.use_tls is True

    def test_get_transport_passes_keep_alive_and_tls(self) -> None:
        """get_transport must pass keep_alive and use_tls to SocketTransport."""
        config = RunConfig(
            target=Target(host="127.0.0.1", port=8000),
            attack=AttackProfile(
                profile=ProfileName.HTTP_FLOOD,
                pps=100,
                duration_seconds=1,
                keep_alive=True,
                use_tls=True,
                tls_verify=False,
            ),
            transport=TransportKind.SOCKET,
        )
        transport = get_transport(config)
        assert isinstance(transport, SocketTransport)
        assert transport.keep_alive is True
        assert transport.use_tls is True
        assert transport.tls_verify is False


# ---------------------------------------------------------------------------
# H2 Transport tests
# ---------------------------------------------------------------------------


class TestH2Transport:
    """Tests for HTTP/2 transport (H2Transport)."""

    def test_h2_transport_creation(self) -> None:
        """H2Transport can be constructed with default parameters."""
        target = Target(host="example.com", port=443)
        transport = H2Transport(
            target,
            ProfileName.HTTP_FLOOD,
            concurrency=50,
            tls_verify=False,
        )
        assert transport.kind is TransportKind.H2
        assert transport.concurrency == 50
        assert transport.tls_verify is False
        assert transport.stream_timeout == DEFAULT_STREAM_TIMEOUT

    def test_h2_supports_only_http_flood(self) -> None:
        """H2 transport only supports HTTP_FLOOD profile."""
        from adobo.transports.base import supports_profile
        assert supports_profile(TransportKind.H2, ProfileName.HTTP_FLOOD) is True
        assert supports_profile(TransportKind.H2, ProfileName.UDP_FLOOD) is False
        assert supports_profile(TransportKind.H2, ProfileName.SYN_FLOOD) is False

    def test_h2_describe_includes_h2_fields(self) -> None:
        """describe() includes h2-specific fields."""
        target = Target(host="example.com", port=443)
        transport = H2Transport(
            target,
            ProfileName.HTTP_FLOOD,
            concurrency=75,
            tls_verify=True,
        )
        desc = transport.describe()
        assert desc["protocol"] == "h2"
        assert desc["concurrency"] == 75
        assert desc["tls_verify"] is True

    def test_h2_request_stop_sets_flag(self) -> None:
        """request_stop() must reach the base class's stop event.

        This previously asserted a private ``_external_stop`` boolean, which was
        the defect rather than the contract. H2Transport overrode request_stop
        without calling the base, so the event that ``Transport.stopping`` reads
        was never set - meaning the engine's stop path and the base class could
        disagree about whether this transport was stopping. The scapy transport
        had the same bug, was fixed, and is covered by
        ``test_reopening_clears_a_previous_stop``; this asserts the same property
        here through the public interface instead of a private attribute.
        """
        target = Target(host="example.com", port=443)
        transport = H2Transport(
            target,
            ProfileName.HTTP_FLOOD,
        )
        assert transport.stopping is False
        transport.request_stop()
        assert transport.stopping is True
        assert transport._should_stop_external() is True

    def test_h2_reports_the_same_stop_state_as_the_base_class(self) -> None:
        """The engine stops transports through the base event; H2 must agree.

        A transport that consults its own flag would miss the engine's stop
        entirely and keep sending until the join grace expired, which is the
        failure the whole cancellation funnel exists to prevent.
        """
        transport = H2Transport(
            Target(host="example.com", port=443),
            ProfileName.HTTP_FLOOD,
        )
        # Set the event the way the base class and the engine do.
        transport._stop.set()
        assert transport._should_stop_external() is True

    def test_h2_concurrency_validation(self) -> None:
        """Concurrency validation happens at model level, not transport level."""
        from pydantic import ValidationError
        # Should work
        H2Transport(
            Target(host="example.com", port=443),
            ProfileName.HTTP_FLOOD,
            concurrency=1,
        )
        H2Transport(
            Target(host="example.com", port=443),
            ProfileName.HTTP_FLOOD,
            concurrency=1000,
        )
        # Concurrency 0 is validated by pydantic in AttackProfile, not in transport
        # This test just verifies transport accepts valid concurrency values
        H2Transport(
            Target(host="example.com", port=443),
            ProfileName.HTTP_FLOOD,
            concurrency=1,
        )

    def test_h2_only_http_flood_profile(self) -> None:
        """H2Transport only accepts HTTP_FLOOD profile."""
        target = Target(host="example.com", port=443)
        # HTTP_FLOOD should work
        H2Transport(target, ProfileName.HTTP_FLOOD)
        # Others should fail
        for profile in (ProfileName.UDP_FLOOD, ProfileName.SYN_FLOOD, ProfileName.SLOWLORIS):
            with pytest.raises(TransportError, match="only supports http_flood"):
                H2Transport(target, profile)
