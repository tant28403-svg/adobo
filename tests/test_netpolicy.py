"""Tests for the allowlist in ``config/lab.yaml``, enforced.

These exist because ``config/lab.yaml`` said "the only networks this tool may
ever send traffic to", ``adobo.__doc__`` said the tool "cannot target an address
that is not written into an allowlist", and ``LabConfig.networks()`` had no
callers anywhere in the package. Every sentence was true of the config file and
false of the program.

That makes this file unusual in one specific way: the interesting assertion is
almost always about something *not* happening. A test that called ``decide()``
and checked the verdict would pass against code where the verdict is computed
and then thrown away, so the tests that matter here drive the real paths - open
a transport, run the engine - and assert that no address outside the allowlist
was reached. The out-of-allowlist addresses used throughout are from the RFC
5737 documentation ranges, which are permanently un-routable, so a test that
somehow did connect would fail rather than send a packet to a real host.
"""

from __future__ import annotations

import socket

import pytest

from adobo.config import LabConfig
from adobo.models import AttackProfile, ProfileName, RunConfig, Target, TransportKind
from adobo.netpolicy import (
    decide,
    is_ip_literal,
    resolve_ipv4,
    resolve_target,
)
from adobo.safety import PolicyViolation
from adobo.transports import PeerUnavailable, TransportError

# RFC 5737 TEST-NET-1/2/3. Never routed, never a real host.
OUTSIDE = "192.0.2.1"
OUTSIDE_ALT = "198.51.100.7"
INSIDE = "127.0.0.1"


def _lab(*cidrs: str) -> LabConfig:
    return LabConfig(allowed_cidrs=list(cidrs or ["127.0.0.0/8"]))


def _config(**kw) -> RunConfig:
    defaults = dict(
        target=Target(host=INSIDE, port=8000),
        attack=AttackProfile(
            profile=ProfileName.UDP_FLOOD,
            pps=100,
            duration_seconds=0.2,
            payload_size=128,
            workers=1,
        ),
        transport=TransportKind.SOCKET,
    )
    defaults.update(kw)
    return RunConfig(**defaults)


# ---------------------------------------------------------------------------
# The judgement itself
# ---------------------------------------------------------------------------


class TestDecide:
    def test_an_address_inside_the_allowlist_permits(self) -> None:
        result = decide(INSIDE, [INSIDE], _lab())
        assert result.ok is True
        assert result.outside == ()
        assert result.permitted == (INSIDE,)

    def test_an_address_outside_the_allowlist_does_not(self) -> None:
        """The case that was never checked before this change."""
        result = decide(OUTSIDE, [OUTSIDE], _lab())
        assert result.ok is False
        assert result.outside == (OUTSIDE,)
        assert result.permitted == ()

    def test_the_shipped_allowlist_is_loopback_only(self) -> None:
        """A checkout with no lab.yaml must be inert, which is what the file says."""
        result = decide(OUTSIDE, [OUTSIDE])
        assert result.ok is False

    def test_a_bare_hostname_is_never_inside_the_allowlist(self) -> None:
        """Anything the policy cannot parse as an address cannot be cleared.

        A resolver that hands back something unparseable is an anomaly worth
        refusing rather than passing through, since a name is exactly the thing
        an allowlist exists to stop.
        """
        result = decide("weird", ["not-an-address"], _lab())
        assert result.ok is False

    def test_an_empty_resolution_permits_nothing_and_blocks_nothing(self) -> None:
        """A name that does not resolve is a broken target, not a refusal.

        ok is true here so a caller cannot mistake "nothing resolved" for
        "something outside the allowlist"; the caller distinguishes them by the
        address count. Treating it as a refusal would report a typo in a hostname
        as a policy denial.
        """
        result = decide("nope.invalid", [], _lab())
        assert result.ok is True
        assert result.addresses == ()
        assert result.dropped is False

    def test_a_partly_permitted_name_drops_only_the_bad_addresses(self) -> None:
        result = decide("mixed", [INSIDE, OUTSIDE], _lab())
        assert result.ok is False
        assert result.dropped is True
        assert result.permitted == (INSIDE,)

    def test_v6_and_v4_never_match_each_other(self) -> None:
        """A v4 address is not inside ::1/128, however the comparison is written.

        ``address in network`` raises TypeError on a mixed family on some
        versions and silently returns False on others. Getting it wrong either
        refuses every dual-stack name or lets a v4 address through a v6-only
        allowlist, and only one of those looks like a bug.
        """
        assert decide("::1", ["::1"], _lab("127.0.0.0/8")).ok is False
        assert decide(INSIDE, [INSIDE], _lab("::1/128")).ok is False

    def test_an_empty_allowlist_permits_nothing(self) -> None:
        """LabConfig forbids an empty list, but decide() is handed one directly."""
        assert decide(INSIDE, [INSIDE], _lab("0.0.0.0/32")).ok is False

    def test_the_refusal_names_the_address_and_the_fix(self) -> None:
        """A refusal an operator cannot act on is a refusal they will work around."""
        message = decide(OUTSIDE, [OUTSIDE], _lab()).refusal()
        assert OUTSIDE in message
        assert "127.0.0.0/8" in message
        assert "allowed_cidrs" in message

    def test_the_note_reports_what_was_dropped(self) -> None:
        note = decide("mixed", [INSIDE, OUTSIDE], _lab()).note()
        assert note is not None
        assert OUTSIDE in note and INSIDE in note

    def test_a_fully_permitted_name_produces_no_note(self) -> None:
        """A normal loopback run must not grow a line of noise."""
        assert decide(INSIDE, [INSIDE], _lab()).note() is None


class TestIsIpLiteral:
    def test_an_address_is_a_literal(self) -> None:
        assert is_ip_literal("127.0.0.1") is True
        assert is_ip_literal("::1") is True

    def test_a_scoped_address_is_still_a_literal(self) -> None:
        assert is_ip_literal("fe80::1%eth0") is True

    def test_a_name_is_not(self) -> None:
        assert is_ip_literal("localhost") is False


# ---------------------------------------------------------------------------
# Resolution, which is where the check meets the wire
# ---------------------------------------------------------------------------


class TestResolveTarget:
    def test_a_permitted_address_resolves_to_itself(self) -> None:
        infos, decision = resolve_target(INSIDE, 8000, socket.SOCK_STREAM)
        assert decision.ok is True
        assert infos[0][4][0] == INSIDE

    def test_an_address_outside_the_allowlist_is_refused(self) -> None:
        """A refusal, not a resolution the caller is trusted to notice."""
        with pytest.raises(PolicyViolation, match=OUTSIDE):
            resolve_target(OUTSIDE, 80, socket.SOCK_STREAM)

    def test_the_refusal_happens_before_a_socket_is_created(self) -> None:
        """open() has to refuse, or the packet leaves before anyone reads it."""
        real = socket.socket

        def _tripwire(*a, **k):  # pragma: no cover - must never run
            raise AssertionError("a socket was created for a refused target")

        socket.socket = _tripwire
        try:
            with pytest.raises(PolicyViolation):
                resolve_target(OUTSIDE, 80, socket.SOCK_STREAM)
        finally:
            socket.socket = real

    def test_an_unresolvable_name_is_not_a_refusal(self) -> None:
        """It stays a broken target, so the transport can word it that way."""
        with pytest.raises(socket.gaierror):
            resolve_target("this-host-does-not-exist.invalid", 80, socket.SOCK_STREAM)

    def test_resolution_is_skipped_for_a_literal(self, monkeypatch) -> None:
        """A literal is already its own answer, and hermetic tests must stay so."""
        def _no_dns(*a, **k):  # pragma: no cover - must never run
            raise AssertionError("getaddrinfo was called for an IP literal")

        monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
        infos, _ = resolve_target(INSIDE, 8000, socket.SOCK_STREAM)
        assert infos[0][4][0] == INSIDE

    def test_a_scoped_literal_is_dialled_with_its_zone(self) -> None:
        """Stripping the scope to check it must not strip it to connect to it."""
        infos, _ = resolve_target("fe80::1%3", 80, socket.SOCK_STREAM,
                                  _lab("fe80::/64"))
        assert infos[0][4][0] == "fe80::1%3"


class TestResolveIpv4:
    def test_a_permitted_literal_resolves(self) -> None:
        assert resolve_ipv4(INSIDE) == INSIDE

    def test_a_refused_literal_raises(self) -> None:
        with pytest.raises(PolicyViolation):
            resolve_ipv4(OUTSIDE)


# ---------------------------------------------------------------------------
# Every transport that reaches an address
# ---------------------------------------------------------------------------


class TestTransportsRefuse:
    """The boundary is at the point of use, so it is checked transport by transport.

    A check in the engine alone would leave all of these open: constructing a
    transport directly is a supported thing to do, and it is how the raw-socket
    builders are tested on a machine that cannot open a raw socket at all.
    """

    def test_socket_transport_refuses(self) -> None:
        from adobo.transports.socket_transport import SocketTransport

        transport = SocketTransport(Target(host=OUTSIDE, port=80),
                                    ProfileName.UDP_FLOOD)
        with pytest.raises(PolicyViolation, match=OUTSIDE):
            transport.open()

    def test_socket_transport_still_opens_inside_the_allowlist(self) -> None:
        from adobo.transports.socket_transport import SocketTransport

        transport = SocketTransport(Target(host=INSIDE, port=9),
                                    ProfileName.UDP_FLOOD)
        transport.open()
        try:
            assert transport.is_open is True
        finally:
            transport.close()

    def test_an_unresolvable_name_is_still_a_transport_error(self) -> None:
        """The message and the exception type the suite has always asserted on."""
        from adobo.transports.socket_transport import SocketTransport

        transport = SocketTransport(
            Target(host="this-host-does-not-exist.invalid", port=80),
            ProfileName.UDP_FLOOD,
        )
        with pytest.raises(TransportError, match="Cannot resolve"):
            transport.open()

    def test_virtual_transport_needs_no_address_at_all(self) -> None:
        """The counter-only transport must not need a resolvable target.

        It is the mode CI and dry runs run on, and the mode that exists precisely
        so a run can execute with no network. Requiring it to resolve would put a
        DNS failure in the middle of a packet-free run.
        """
        from adobo.transports.virtual_transport import VirtualTransport

        transport = VirtualTransport(Target(host="nowhere.invalid", port=80),
                                     ProfileName.UDP_FLOOD)
        transport.open()
        try:
            assert transport.is_open is True
        finally:
            transport.close()

    def test_slowloris_connects_to_the_address_that_was_checked(self) -> None:
        """It resolves once in open() and dials per connection, so the pool matters.

        Connecting to ``target.host`` instead would re-resolve for every socket,
        and a name is not an address.
        """
        from adobo.transports.slowloris_transport import SlowlorisTransport

        transport = SlowlorisTransport(Target(host=INSIDE, port=9),
                                       ProfileName.SLOWLORIS)
        transport.open()
        try:
            assert transport._dial is not None, (
                "open() did not resolve and vet the target, so every socket in "
                "the pool would have re-resolved the name on its own"
            )
            assert transport._dial == (INSIDE, 9)
        finally:
            transport.close()

    def test_slowloris_gets_an_address_its_socket_family_can_dial(self) -> None:
        """It opens AF_INET sockets, so a vetted ::1 would be unconnectable.

        The base resolution may return IPv6 first on a dual-stack host, which is
        why this transport overrides it. Asserted through a faked resolver, since
        it depends on getaddrinfo returning IPv6 ahead of IPv4 - the case that
        only arises on a machine configured for it.
        """
        from adobo.transports.slowloris_transport import SlowlorisTransport

        dual = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 9)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (INSIDE, 9)),
        ]
        real = socket.getaddrinfo
        socket.getaddrinfo = lambda *a, **k: list(dual)
        try:
            transport = SlowlorisTransport(Target(host="localhost", port=9),
                                           ProfileName.SLOWLORIS)
            transport.open()
        finally:
            socket.getaddrinfo = real
        try:
            assert transport._dial == (INSIDE, 9)
        finally:
            transport.close()

    def test_slowloris_refuses_a_target_outside_the_allowlist(self) -> None:
        from adobo.transports.slowloris_transport import SlowlorisTransport

        transport = SlowlorisTransport(Target(host=OUTSIDE, port=80),
                                       ProfileName.SLOWLORIS)
        with pytest.raises(PolicyViolation, match=OUTSIDE):
            transport.open()

    def test_http2_connects_with_a_two_tuple_address(self, monkeypatch) -> None:
        """create_connection rejects anything that is not exactly (host, port).

        An AF_INET6 sockaddr is a 4-tuple, so handing it over verbatim breaks
        every IPv6 target with a ValueError from deep inside the socket module -
        a fault that reads as a broken install rather than a bad address. The
        allowlist change is what put an addrinfo in this code path, so the shape
        it hands on is worth pinning.
        """
        from adobo.transports.http2_transport import H2Transport

        seen = []

        class _Sock:
            def settimeout(self, *_a):  # pragma: no cover - not the subject
                pass

            def sendall(self, *_a):  # pragma: no cover - not the subject
                pass

        def _create(address, **_kw):
            seen.append(address)
            return _Sock()

        class _Ctx:
            def wrap_socket(self, sock, **_kw):  # pragma: no cover
                return sock

        monkeypatch.setattr(
            H2Transport, "_build_tls_context", lambda self: _Ctx()
        )
        real = socket.create_connection
        socket.create_connection = _create
        try:
            transport = H2Transport(
                Target(host="localhost", port=443), ProfileName.HTTP_FLOOD
            )
            with pytest.raises(Exception):
                # Reaches create_connection and then fails later on the real h2
                # handshake; the point is the argument it was given.
                transport.open()
        finally:
            socket.create_connection = real

        assert seen, "create_connection was never reached"
        for address in seen:
            assert isinstance(address, tuple) and len(address) == 2, address
            assert isinstance(address[0], str), address


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


class TestEngineRefuses:
    """Every test here runs the VIRTUAL transport on purpose.

    VIRTUAL never resolves the target, so nothing in the transport layer can
    refuse: if these tests pass, it is the engine that said no. Using SOCKET
    instead would let the transport's own check produce the PolicyViolation and
    the engine gate would never be exercised at all - the tests would keep
    passing if the engine stopped checking entirely, which is exactly the thing
    being added here.
    """

    def test_a_run_aimed_outside_the_allowlist_is_refused(self) -> None:
        from adobo.engine import RunEngine

        engine = RunEngine(_config(target=Target(host=OUTSIDE, port=80),
                                    transport=TransportKind.VIRTUAL))
        with pytest.raises(PolicyViolation, match=OUTSIDE):
            engine.run()

    def test_the_refusal_costs_no_measurement(self) -> None:
        """No result, no report, no partial numbers.

        A refusal that still produced a result object full of zeroes would be
        read as "the target served nothing", which is a different and wrong
        claim about the machine under test.
        """
        from adobo.engine import RunEngine

        with pytest.raises(PolicyViolation):
            RunEngine(_config(target=Target(host=OUTSIDE, port=80),
                              transport=TransportKind.VIRTUAL)).run()

    def test_a_permitted_target_still_runs(self) -> None:
        """The default loopback run must be untouched by any of this."""
        from adobo.engine import RunEngine

        outcome = RunEngine(
            _config(transport=TransportKind.VIRTUAL, dry_run=True)
        ).run()
        assert outcome.result.run_id

    def test_a_dry_run_is_refused_too(self) -> None:
        """A dry run sends nothing, so this is a convenience rather than a gate.

        It is checked anyway because a dry run is how an operator finds out
        whether a run will be accepted, and a dry run that says yes is a promise
        the real run would break.
        """
        from adobo.engine import RunEngine

        with pytest.raises(PolicyViolation):
            RunEngine(_config(target=Target(host=OUTSIDE, port=80),
                              transport=TransportKind.VIRTUAL,
                              dry_run=True)).run()

    def test_a_partly_permitted_name_is_reported_not_refused(self, monkeypatch) -> None:
        """A real run, reading the notes the saved result actually carries.

        Dropping the disallowed addresses means the run reached fewer addresses
        than the name suggests, so it has to say so. Asserting on an
        AllowlistDecision built in the test would prove nothing about whether the
        note reaches the operator - the disclosure-note bug in the fingerprint
        work lived in the caller, not the helper that produced the string, and
        only reading ``RunResult.notes`` off a finished run would have caught it.

        The resolver is faked rather than the transport bypassed, so this still
        goes through ``RunEngine.run()`` end to end. VIRTUAL means the fake is
        never consulted by anything that would put a packet on the wire.
        """
        from adobo.engine import RunEngine

        mixed = [
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", (INSIDE, 9)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", (OUTSIDE, 9)),
        ]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: list(mixed))

        outcome = RunEngine(
            _config(target=Target(host="mixed.example", port=9),
                    transport=TransportKind.VIRTUAL)
        ).run()

        assert any(
            OUTSIDE in note and "dropped" in note
            for note in outcome.result.notes
        ), outcome.result.notes

    def test_the_allowlist_is_checked_before_the_transport_is_opened(
        self, monkeypatch
    ) -> None:
        """Reporting early is the point; opening a socket to find out is not."""
        from adobo.engine import RunEngine

        opened = []
        real_open = None

        from adobo.transports.socket_transport import SocketTransport

        real_open = SocketTransport.open

        def _record(self):
            opened.append(self.target.host)
            return real_open(self)

        monkeypatch.setattr(SocketTransport, "open", _record)
        with pytest.raises(PolicyViolation):
            RunEngine(_config(target=Target(host=OUTSIDE, port=80))).run()
        assert opened == []

    def test_peer_unavailable_is_not_mistaken_for_a_refusal(self) -> None:
        """A target that refuses the connection is the lab's central observation."""
        assert issubclass(PeerUnavailable, TransportError)
        assert not issubclass(PeerUnavailable, PolicyViolation)