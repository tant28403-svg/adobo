"""Tests for nuclear mode's aggregation.

The bugs these cover were all *display* failures. Every one of them produced a
plausible-looking table that was quietly wrong: a profile shown as still starting
while it was sending, a total of zero beside non-zero rows, and a profile
silently dropped from the results even though it had been working. None of them
raised, so nothing caught them - only comparing the table against reality did.

The tests drive the aggregator's event handling directly rather than spawning
processes. Spawning real children to assert on a progress table would be slow
and racy, and the logic under test is the bookkeeping, not the multiprocessing.
"""

from __future__ import annotations

import contextlib
import io
import queue
import socket

import pytest

from adobo.models import (
    AttackProfile,
    AttackStats,
    ProfileName,
    RunConfig,
    RunResult,
    Target,
    TransportKind,
)
from adobo.nuclear import (
    NuclearAggregator,
    NuclearProfile,
    _drop_privilege_profiles,
    _parse_profile_selection,
    build_profiles,
    filter_available_profiles,
    probe_udp_port,
)


def _a_closed_port() -> int:
    """A loopback port with nothing bound to it.

    Bound then released, rather than hardcoding a number like 1. A well-known
    port can be bound by something else on the machine running the suite, which
    would silently turn a "closed port is skipped" test into a no-op.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def make_profile(
    name: str = "udp_flood",
    port: int | None = 9999,
    profile: ProfileName = ProfileName.UDP_FLOOD,
    transport: TransportKind = TransportKind.SOCKET,
) -> NuclearProfile:
    return NuclearProfile(
        name=name,
        profile=profile,
        transport=transport,
        port=port,
        spoof=False,
        requires_admin=False,
    )


def make_result(sent: int) -> RunResult:
    """A finished result carrying *sent*, as a child would publish it."""
    return RunResult(
        run_id="r1",
        config=RunConfig(
            target=Target(host="127.0.0.1", port=9999),
            attack=AttackProfile(
                profile=ProfileName.UDP_FLOOD,
                pps=200,
                duration_seconds=2.0,
            ),
            transport=TransportKind.SOCKET,
        ),
        attack=AttackStats(
            transport=TransportKind.SOCKET,
            dry_run=False,
            packets_sent=sent,
            bytes_sent=sent,
            errors=0,
            duration_actual_s=2.0,
            achieved_pps=sent / 2.0,
        ),
    )


def make_aggregator(profiles: list[NuclearProfile]) -> NuclearAggregator:
    # A plain queue rather than a multiprocessing one: the aggregator only ever
    # calls get_nowait, and a real mp.Queue would need a live context.
    aggregator = NuclearAggregator(
        profiles=profiles,
        target_ip="127.0.0.1",
        pps=200,
        duration=1.0,
    )
    aggregator.result_queue = queue.Queue()
    return aggregator


# ---------------------------------------------------------------------------
# The key mismatch
# ---------------------------------------------------------------------------


class TestResultLookup:
    def test_label_is_the_same_key_the_child_reports_under(self) -> None:
        """The aggregator must look up exactly what the child publishes.

        This was the whole bug: children reported under ``nuclear-<name>`` while
        the display read ``<name>``, so every row missed and stayed
        ``[STARTING]`` for the entire run.
        """
        profile = make_profile("udp_flood")
        aggregator = make_aggregator([profile])
        assert aggregator._label(profile) == "nuclear-udp_flood"

    def test_a_finished_result_is_found_by_its_profile(self) -> None:
        profile = make_profile("udp_flood")
        aggregator = make_aggregator([profile])
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "finished",
                "success": True,
                "result": make_result(100),
            }
        )
        found = aggregator.results.get(aggregator._label(profile))
        assert found is not None
        assert found["result"].attack.packets_sent == 100

    def test_profile_names_are_unique(self) -> None:
        """A duplicate name would make two profiles overwrite each other."""
        profiles = build_profiles("127.0.0.1", 9999, 9999)
        names = [p.name for p in profiles]
        assert len(names) == len(set(names))

    def test_every_profile_reports_under_its_own_label(self) -> None:
        profiles = build_profiles("127.0.0.1", 9999, 9999)
        aggregator = make_aggregator(profiles)
        labels = {aggregator._label(p) for p in profiles}
        assert len(labels) == len(profiles)


# ---------------------------------------------------------------------------
# Event bookkeeping
# ---------------------------------------------------------------------------


class TestEventAbsorption:
    def test_started_is_not_stored_as_a_result(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb({"profile": "nuclear-udp_flood", "event": "started"})
        assert aggregator.started == {"nuclear-udp_flood"}
        assert aggregator.results == {}

    def test_a_finished_profile_is_no_longer_starting(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb({"profile": "nuclear-udp_flood", "event": "started"})
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "finished",
                "success": True,
                "result": make_result(50),
            }
        )
        assert aggregator.started == set()
        assert "nuclear-udp_flood" in aggregator.results

    def test_progress_does_not_overwrite_a_result(self) -> None:
        """A late progress tick must not clobber a finished measurement."""
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "finished",
                "success": True,
                "result": make_result(500),
            }
        )
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "progress",
                "sent": 480,
            }
        )
        assert aggregator.results["nuclear-udp_flood"]["result"].attack.packets_sent == 500
        assert aggregator.progress["nuclear-udp_flood"]["sent"] == 480

    def test_failure_is_recorded_as_a_terminal_result(self) -> None:
        """A crashed child never sends "finished", so its failure is the
        verdict - recorded as the result, and no longer "started"."""
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb({"profile": "nuclear-udp_flood", "event": "started"})
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "failed",
                "success": False,
                "result": None,
                "error": "no route",
                "terminal": True,
            }
        )
        assert aggregator.results["nuclear-udp_flood"]["error"] == "no route"
        assert "nuclear-udp_flood" not in aggregator.started

    def test_a_mid_run_worker_error_does_not_poison_a_successful_finish(self) -> None:
        """The load-bearing ordering test.

        One worker's socket dying mid-run emits a non-terminal "failed". The
        child then completes and emits "finished" with the full counters and
        its own verdict. The old absorption logic recorded the worker error as
        the result and discarded everything after it: a profile that sent
        thousands of packets rendered as [ERROR] with sent=0, in the live
        table for the rest of the run and in the final one.
        """
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb({"profile": "nuclear-udp_flood", "event": "started"})
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "failed",
                "error": "ConnectionResetError: one worker's socket died",
                "terminal": False,
            }
        )
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "finished",
                "success": True,
                "result": make_result(50_000),
            }
        )
        stored = aggregator.results["nuclear-udp_flood"]
        assert stored["success"] is True
        assert stored["result"].attack.packets_sent == 50_000
        assert aggregator.failures["nuclear-udp_flood"]["error"].startswith(
            "ConnectionResetError"
        ), "the worker's reason is kept for context, not for the verdict"

    def test_a_mid_run_worker_error_keeps_the_row_running(self) -> None:
        """A non-terminal failure must not flip the live row to [ERROR] while
        the child is still sending."""
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb({"profile": "nuclear-udp_flood", "event": "started"})
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "failed",
                "error": "timeout",
                "terminal": False,
            }
        )
        assert "nuclear-udp_flood" in aggregator.started
        assert "nuclear-udp_flood" not in aggregator.results

    def test_a_finished_verdict_after_a_mid_run_failure_is_still_honest(self) -> None:
        """The old bug this module was fixed for, in its current form: the
        transport never opened, the finished run re-derives success=False with
        the composed reasons, and that verdict - not a clean success, not the
        raw worker error - is what renders."""
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb({"profile": "nuclear-udp_flood", "event": "started"})
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "failed",
                "error": "TransportError: cannot open",
                "terminal": False,
            }
        )
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "finished",
                "success": False,
                "result": None,
                "error": "no packet was ever sent; the transport refused to open",
            }
        )
        stored = aggregator.results["nuclear-udp_flood"]
        assert stored["success"] is False
        assert "no packet was ever sent" in stored["error"]

    def test_drain_empties_the_queue(self) -> None:
        aggregator = make_aggregator([make_profile()])
        for _ in range(3):
            aggregator.result_queue.put(
                {"profile": "nuclear-udp_flood", "event": "progress", "sent": 1}
            )
        aggregator._drain()
        assert aggregator.result_queue.empty()
        assert aggregator.progress["nuclear-udp_flood"]["sent"] == 1


# ---------------------------------------------------------------------------
# Live table output
# ---------------------------------------------------------------------------


class TestProgressTable:
    def _capture(self, aggregator: NuclearAggregator, elapsed: float) -> str:
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            aggregator._print_progress(elapsed, aggregator.duration - elapsed)
        return buffer.getvalue()

    def test_a_running_profile_reports_live_counters(self) -> None:
        profile = make_profile()
        aggregator = make_aggregator([profile])
        aggregator._absorb({"profile": "nuclear-udp_flood", "event": "started"})
        aggregator._absorb(
            {"profile": "nuclear-udp_flood", "event": "progress", "sent": 1234}
        )
        output = self._capture(aggregator, 1.0)
        assert "1,234" in output
        assert "[RUNNING]" in output
        assert "[STARTING]" not in output

    def test_an_unstarted_profile_reads_starting(self) -> None:
        aggregator = make_aggregator([make_profile()])
        assert "[STARTING]" in self._capture(aggregator, 1.0)

    def test_the_total_matches_the_rows_above_it(self) -> None:
        """The total is a sum of the rows. A zero under non-zero rows is a bug."""
        profiles = [make_profile("a"), make_profile("b")]
        aggregator = make_aggregator(profiles)
        for name, sent in (("a", 1000), ("b", 2000)):
            aggregator._absorb({"profile": f"nuclear-{name}", "event": "started"})
            aggregator._absorb(
                {"profile": f"nuclear-{name}", "event": "progress", "sent": sent}
            )
        output = self._capture(aggregator, 1.0)
        total_line = [ln for ln in output.splitlines() if ln.startswith("TOTAL")][0]
        assert "3,000" in total_line

    def test_a_finished_profile_reads_done_not_running(self) -> None:
        """A completed run showing [RUNNING] is how this table misled before."""
        profile = make_profile()
        aggregator = make_aggregator([profile])
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "finished",
                "success": True,
                "result": make_result(400),
            }
        )
        output = self._capture(aggregator, 1.0)
        assert "[DONE]" in output
        assert "[RUNNING]" not in output

    def test_a_failed_profile_reads_error(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "failed",
                "success": False,
                "result": None,
                "error": "unavailable",
                "terminal": True,
            }
        )
        assert "[ERROR]" in self._capture(aggregator, 1.0)


class TestFinalTable:
    def test_a_silent_profile_is_called_out(self) -> None:
        """A row of zeros must be distinguishable from 'nothing collected'."""
        profiles = [make_profile("udp_flood"), make_profile("http_flood")]
        aggregator = make_aggregator(profiles)
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "finished",
                "success": True,
                "result": make_result(900),
            }
        )
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            aggregator._print_final_results()
        output = buffer.getvalue()
        assert "900" in output
        assert "http_flood" in output
        assert "never reported" in output

    def test_a_fully_reported_run_warns_about_nothing(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "finished",
                "success": True,
                "result": make_result(10),
            }
        )
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            aggregator._print_final_results()
        assert "never reported" not in buffer.getvalue()


# ---------------------------------------------------------------------------
# Profile construction and pre-flight
# ---------------------------------------------------------------------------


class TestBuildProfiles:
    def test_amplification_profiles_use_the_operator_reflector(self) -> None:
        """They used to hardcode 53/123/389/1900 against the target."""
        profiles = build_profiles("127.0.0.1", 8000, 5353)
        amplification = [
            p
            for p in profiles
            if p.profile
            in (
                ProfileName.DNS_AMPLIFICATION,
                ProfileName.NTP_AMPLIFICATION,
                ProfileName.CLDAP_AMPLIFICATION,
                ProfileName.SSDP_AMPLIFICATION,
            )
        ]
        assert amplification, "amplification profiles should exist"
        for profile in amplification:
            assert profile.port == 5353

    def test_no_profile_hardcodes_a_well_known_service_port(self) -> None:
        profiles = build_profiles("127.0.0.1", 8000, 5353)
        for profile in profiles:
            assert profile.port not in (53, 123, 389, 1900)

    def test_direct_profiles_target_the_service_port(self) -> None:
        profiles = build_profiles("127.0.0.1", 8000, 5353)
        for name in ("syn_flood", "ack_flood", "udp_flood", "http_flood", "slowloris"):
            profile = next(p for p in profiles if p.name == name)
            assert profile.port == 8000

    def test_icmp_has_no_port(self) -> None:
        profiles = build_profiles("127.0.0.1", 8000, 5353)
        icmp = next(p for p in profiles if p.name == "icmp_flood")
        assert icmp.port is None

    def test_amplification_profiles_spoof(self) -> None:
        profiles = build_profiles("127.0.0.1", 8000, 5353)
        amplification = [p for p in profiles if p.spoof]
        assert len(amplification) == 4


# ---------------------------------------------------------------------------
# Wizard answers must reach the children
# ---------------------------------------------------------------------------


def _aggregator(**kwargs) -> NuclearAggregator:
    """An aggregator over one socket profile, with no processes spawned."""
    return NuclearAggregator(
        profiles=[make_profile("http_flood", 8000, ProfileName.HTTP_FLOOD)],
        target_ip="127.0.0.1",
        pps=1000,
        duration=1.0,
        **kwargs,
    )


def _child_attack(**kwargs) -> AttackProfile:
    """The AttackProfile the aggregator hands to a spawned child.

    Calls the production _build_configs rather than rebuilding the same
    constructor here: a reimplementation in the test would keep passing even if
    the code under test regressed back to literals.
    """
    configs = _aggregator(**kwargs)._build_configs()
    assert len(configs) == 1
    return configs[0].attack


class TestOperatorValuesReachTheChildren:
    """The wizard asks for these numbers, so the children must run with them.

    All of these were once hardcoded literals at the aggregator call, so a run
    configured for 200 workers spawned children with 4 and printed nothing about
    the difference. A tool that reports a number it did not use is the exact
    failure this project exists to rule out, so the numbers are pinned here.
    """

    def test_workers_reach_the_child_instead_of_a_literal_four(self) -> None:
        attack = _child_attack(workers=200)
        assert attack.workers == 200

    def test_workers_at_the_model_ceiling_reach_the_child(self) -> None:
        """800 is the hard ceiling; a strike pinned to it must still run.

        The ceiling became a model bound in the same change that raised the
        operator-facing one, so a value that was legal everywhere yesterday
        but sat exactly at the new limit is the boundary worth pinning.
        """
        assert _child_attack(workers=800).workers == 800

    def test_a_non_default_worker_count_is_not_silently_replaced(self) -> None:
        """The regression that matters: a literal would pass the test above
        only if it happened to equal 200. Check a second value so no constant
        can satisfy both."""
        assert _child_attack(workers=7).workers == 7
        assert _child_attack(workers=1).workers == 1

    def test_payload_size_reaches_the_child_instead_of_a_literal_512(self) -> None:
        assert _child_attack(payload_size=1400).payload_size == 1400
        assert _child_attack(payload_size=64).payload_size == 64

    def test_keep_alive_reaches_the_child(self) -> None:
        assert _child_attack(keep_alive=True).keep_alive is True

    def test_tls_options_reach_the_child(self) -> None:
        attack = _child_attack(use_tls=True, tls_verify=False)
        assert attack.use_tls is True
        assert attack.tls_verify is False

    def test_http2_options_reach_the_child(self) -> None:
        attack = _child_attack(use_http2=True, h2_concurrency=250)
        assert attack.use_http2 is True
        assert attack.h2_concurrency == 250

    def test_http_host_reaches_the_child(self) -> None:
        attack = _child_attack(http_host="www.lab.test")
        assert attack.http_host == "www.lab.test"

    def test_a_literal_http_host_is_not_silently_ignored(self) -> None:
        """The regression that matters: a literal would pass the test above
        only if it happened to equal www.lab.test. Check a second value so
        no constant can satisfy both."""
        assert _child_attack(http_host="api.lab.test").http_host == "api.lab.test"
        assert _child_attack(http_host="lab.test:8443").http_host == "lab.test:8443"

    def test_http2_picks_the_h2_transport_for_the_http_profile(self) -> None:
        """Routing is decided in build_profiles, tuning in the aggregator. Both
        halves have to be right or the run silently uses plain HTTP/1.1."""
        profiles = build_profiles("127.0.0.1", 8000, 53, use_http2=True)
        http_profile = next(p for p in profiles if p.name == "http_flood")
        assert http_profile.transport is TransportKind.H2

    def test_build_profiles_does_not_accept_per_child_tuning(self) -> None:
        """The parameters are gone on purpose.

        NuclearProfile is frozen and has no fields for them, so accepting them
        was accepting-and-discarding. A TypeError here is the intended outcome.
        """
        for dead in ("workers", "payload_size", "keep_alive", "use_tls"):
            with pytest.raises(TypeError):
                build_profiles("127.0.0.1", 8000, 53, **{dead: 1})


class TestProbeMatchesTheProtocol:
    """A profile must be probed on the protocol it actually sends on.

    These all used a UDP datagram for everything. A UDP probe against a live
    TCP web service reports the port closed, so http_flood and slowloris were
    dropped from every nuclear run - the two profiles whose delivery the target
    can independently confirm. The run still reported a completed strike.
    """

    def test_a_live_tcp_service_is_kept(self) -> None:
        """A real bound listener, not an assumed-open well-known port."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            profiles = [
                make_profile("http_flood", port, ProfileName.HTTP_FLOOD),
            ]
            keep, skipped = filter_available_profiles(profiles, "127.0.0.1")
        finally:
            listener.close()

        assert [p.name for p in keep] == ["http_flood"]
        assert skipped == []

    def test_a_closed_tcp_port_is_still_dropped(self) -> None:
        """The fix must not make the filter accept everything."""
        profiles = [
            make_profile("http_flood", _a_closed_port(), ProfileName.HTTP_FLOOD),
            make_profile("slowloris", _a_closed_port(), ProfileName.SLOWLORIS),
        ]
        keep, skipped = filter_available_profiles(profiles, "127.0.0.1")
        assert keep == []
        assert len(skipped) == 2

    def test_slowloris_is_probed_over_tcp(self) -> None:
        """It holds a TCP connection open, so a UDP probe cannot see it."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            keep, _ = filter_available_profiles(
                [make_profile("slowloris", port, ProfileName.SLOWLORIS)],
                "127.0.0.1",
            )
        finally:
            listener.close()
        assert len(keep) == 1

    def test_icmp_still_needs_no_port(self) -> None:
        profiles = [
            make_profile("icmp_flood", None, ProfileName.ICMP_FLOOD),
        ]
        keep, skipped = filter_available_profiles(profiles, "127.0.0.1")
        assert len(keep) == 1
        assert skipped == []


class TestDatagramProfilesSurviveAClosedPort:
    """A closed port is a fact about responders, not about packets arriving.

    Six of the ten profiles were dropped together whenever nothing was bound to
    the reflector ports, so a run came back short with one line of output the
    operator had to decode. The justification the pre-flight prints - that the
    packets "would be discarded before reaching any application" - is false for
    a datagram: it arrives, is charged to the target's ingress, and is dropped
    afterwards. TCP profiles still get the probe, because for those a closed
    port really does mean nothing will ever serve the request.
    """

    def test_a_reflector_profile_is_kept_when_its_port_is_closed(self) -> None:
        keep, skipped = filter_available_profiles(
            [make_profile("dns_amplification", _a_closed_port(), ProfileName.DNS_AMPLIFICATION)],
            "127.0.0.1",
        )
        assert [p.name for p in keep] == ["dns_amplification"]
        assert skipped == []

    def test_all_four_amplification_profiles_survive(self) -> None:
        profiles = [
            make_profile("dns_amplification", _a_closed_port(), ProfileName.DNS_AMPLIFICATION),
            make_profile("ntp_amplification", _a_closed_port(), ProfileName.NTP_AMPLIFICATION),
            make_profile("cldap_amplification", _a_closed_port(), ProfileName.CLDAP_AMPLIFICATION),
            make_profile("ssdp_amplification", _a_closed_port(), ProfileName.SSDP_AMPLIFICATION),
        ]
        keep, skipped = filter_available_profiles(profiles, "127.0.0.1")
        assert len(keep) == 4
        assert skipped == []

    def test_udp_flood_survives_a_tcp_only_service_port(self) -> None:
        """The datagrams still arrive even though nothing will ever answer."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            keep, skipped = filter_available_profiles(
                [make_profile("udp_flood", port, ProfileName.UDP_FLOOD)], "127.0.0.1"
            )
        finally:
            listener.close()
        assert [p.name for p in keep] == ["udp_flood"]
        assert skipped == []

    def test_the_non_spoofed_variant_is_exempt_too(self) -> None:
        """Declining the spoofing prompt selects UDP_FLOOD_NS, not UDP_FLOOD.

        The exemption that only covered the spoofed name left the
        non-elevated path - the one most operators run - still dropping its UDP
        flood, which is the bug this whole change set was opened to fix.
        """
        keep, skipped = filter_available_profiles(
            [make_profile("udp_flood", _a_closed_port(), ProfileName.UDP_FLOOD_NS)],
            "127.0.0.1",
        )
        assert [p.name for p in keep] == ["udp_flood"]
        assert skipped == []

    def test_tcp_profiles_are_still_probed(self) -> None:
        """The exemption is for datagrams only, not a general loosening."""
        keep, skipped = filter_available_profiles(
            [make_profile("http_flood", _a_closed_port(), ProfileName.HTTP_FLOOD)],
            "127.0.0.1",
        )
        assert keep == []
        assert len(skipped) == 1


class TestPrivilegeDropIsNamed:
    """The count alone left the operator unable to tell what had gone missing."""

    @staticmethod
    def _spoofing_profile(name: str) -> NuclearProfile:
        return NuclearProfile(
            name=name,
            profile=ProfileName.DNS_AMPLIFICATION,
            transport=TransportKind.SCAPY,
            port=53,
            spoof=True,
            requires_admin=True,
        )

    def test_a_spoofing_profile_is_dropped(self) -> None:
        profiles = [self._spoofing_profile("dns_amplification"), make_profile("http_flood")]
        assert [p.name for p in _drop_privilege_profiles(profiles)] == ["http_flood"]

    def test_the_dropped_profile_is_named_in_the_output(self) -> None:
        """Naming them is the whole point; the old line said only how many."""
        profiles = [self._spoofing_profile("dns_amplification"), make_profile("http_flood")]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            _drop_privilege_profiles(profiles)
        printed = buffer.getvalue()
        assert "dns_amplification" in printed
        assert "http_flood" not in printed

    def test_nothing_is_dropped_when_every_profile_is_allowed(self) -> None:
        profiles = [make_profile("http_flood", 8000)]
        kept = _drop_privilege_profiles(profiles)
        assert kept == profiles

    def test_no_output_when_there_is_nothing_to_drop(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            _drop_privilege_profiles([make_profile("http_flood")])
        assert buffer.getvalue() == ""


class TestPreflight:
    """The probe is for profiles that need a live responder.

    These use TCP profiles because that is where the drop still applies: a
    closed port means nothing will ever serve the request. Datagram profiles
    are covered separately, and are kept.
    """

    def test_a_closed_port_is_dropped_with_a_reason(self) -> None:
        """An open port is kept, a closed one is dropped and explained.

        A real listener is bound rather than assuming a well-known port is open,
        so the test states its own premise instead of depending on whatever else
        happens to be listening when the suite runs.
        """
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        open_port = listener.getsockname()[1]
        try:
            profiles = [
                make_profile("open", open_port, ProfileName.HTTP_FLOOD),
                make_profile("closed", _a_closed_port(), ProfileName.HTTP_FLOOD),
            ]
            keep, skipped = filter_available_profiles(profiles, "127.0.0.1")
        finally:
            listener.close()

        kept = [p.name for p in keep]
        skipped_names = [name for name, _ in skipped]
        assert "open" in kept, f"an open port must be kept; skipped={skipped}"
        assert "closed" in skipped_names
        assert "closed" not in kept

    def test_a_closed_port_is_reported_with_its_address(self) -> None:
        closed = _a_closed_port()
        keep, skipped = filter_available_profiles(
            [make_profile("closed", closed, ProfileName.HTTP_FLOOD)], "127.0.0.1"
        )
        assert keep == []
        assert skipped[0][0] == "closed"
        assert f"127.0.0.1:{closed}" in skipped[0][1]
        assert "closed" in skipped[0][1]

    def test_a_portless_profile_is_never_dropped(self) -> None:
        """ICMP has no port to probe, so it must survive the pre-flight."""
        keep, skipped = filter_available_profiles(
            [make_profile("icmp_flood", port=None)], "127.0.0.1"
        )
        assert [p.name for p in keep] == ["icmp_flood"]
        assert skipped == []

    def test_the_skip_is_reported_not_silent(self) -> None:
        keep, skipped = filter_available_profiles(
            [make_profile("x", _a_closed_port(), ProfileName.HTTP_FLOOD)], "127.0.0.1"
        )
        assert skipped, "a skipped profile must come with a reason"
        assert all(reason for _, reason in skipped)

    def test_probe_against_loopback_is_decisive(self) -> None:
        """A port we are not listening on must read as closed."""
        assert probe_udp_port("127.0.0.1", _a_closed_port(), timeout=0.3) is False

    def test_probe_against_an_open_port_reads_open(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        try:
            assert probe_udp_port("127.0.0.1", port, timeout=0.3) is True
        finally:
            listener.close()

    def test_probe_against_an_unresolvable_host_is_closed(self) -> None:
        assert probe_udp_port("no-such-host.invalid", 9999, timeout=0.3) is False


# ---------------------------------------------------------------------------
# Target-side evidence
# ---------------------------------------------------------------------------
#
# Every test above asserts on what the *sender* believes it did. Those numbers
# are self-reported: a run can hand 91,367 packets to the operating system
# against a target that serves nothing and every row will look like a success.
# The tests below cover the one figure in the output that is not self-reported -
# the count the target itself recorded - and the requirement that its absence is
# stated rather than papered over.


class TestTargetEvidence:
    def _finished_aggregator(
        self, sent: int = 900, profile: ProfileName = ProfileName.HTTP_FLOOD
    ) -> NuclearAggregator:
        aggregator = make_aggregator(
            [make_profile(profile.value, profile=profile)]
        )
        aggregator._absorb(
            {
                "profile": f"nuclear-{profile.value}",
                "event": "finished",
                "success": True,
                "result": make_result(sent),
            }
        )
        return aggregator

    def _render(self, aggregator: NuclearAggregator) -> str:
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            aggregator._print_final_results()
        return buffer.getvalue()

    def test_the_target_served_count_is_shown(self) -> None:
        aggregator = self._finished_aggregator()
        aggregator._stats_before = (100, 0)
        aggregator._stats_after = (618, 3)
        output = self._render(aggregator)
        assert "requests served by target : 518" in output
        assert "errors reported by target : 3" in output

    def test_the_ratio_denominator_excludes_traffic_the_counter_cannot_see(
        self,
    ) -> None:
        """A UDP flood is invisible to an HTTP request counter.

        Putting those packets in the denominator compares two unrelated
        quantities: a run that delivered every HTTP request still reads as a low
        ratio, and the honest number gets dismissed as a bug.
        """
        aggregator = make_aggregator(
            [
                make_profile("udp_flood"),
                make_profile("http_flood", profile=ProfileName.HTTP_FLOOD),
            ]
        )
        for name, sent in (("udp_flood", 1500), ("http_flood", 160)):
            aggregator._absorb(
                {"profile": f"nuclear-{name}", "event": "started"}
            )
            aggregator._absorb(
                {
                    "profile": f"nuclear-{name}",
                    "event": "finished",
                    "success": True,
                    "result": make_result(sent),
                }
            )
        aggregator._stats_before = (0, 0)
        aggregator._stats_after = (160, 0)
        output = self._render(aggregator)
        assert "100.0% (160 of 160 addressed to this endpoint)" in output
        assert "1,500 further packets went to ports or protocols" in output

    def test_a_low_ratio_against_the_right_denominator_is_still_called_out(
        self,
    ) -> None:
        """Excluding the uncountable must not hide a genuine delivery failure."""
        aggregator = self._finished_aggregator(sent=1000)
        aggregator._stats_before = (0, 0)
        aggregator._stats_after = (100, 0)
        output = self._render(aggregator)
        assert "10.0%" in output
        assert "did not become a" in output
        assert "served request" in output

    def test_no_profile_at_this_endpoint_means_no_ratio(self) -> None:
        """A served count with nothing of ours addressed there is not a result."""
        aggregator = make_aggregator(
            [make_profile("udp_flood"), make_profile("slowloris", 9999)]
        )
        for name in ("udp_flood", "slowloris"):
            aggregator._absorb(
                {
                    "profile": f"nuclear-{name}",
                    "event": "finished",
                    "success": True,
                    "result": make_result(500),
                }
            )
        aggregator._stats_before = (0, 0)
        aggregator._stats_after = (900, 0)
        output = self._render(aggregator)
        assert "no delivery ratio can" in output
        assert "outside" in output
        assert "delivered / handed to OS" not in output

    def test_an_unreadable_target_is_said_out_loud(self) -> None:
        """The requirement: no evidence must never be presented as evidence."""
        aggregator = self._finished_aggregator()
        output = self._render(aggregator)
        assert "NOT MEASURED" in output
        assert "Nothing here confirms anything arrived" in output

    def test_an_unreadable_target_does_not_invent_a_ratio(self) -> None:
        aggregator = self._finished_aggregator()
        output = self._render(aggregator)
        assert "delivered / handed to OS" not in output

    def test_a_shrinking_counter_reads_as_zero_not_negative(self) -> None:
        """A target restart between the two reads must not produce -400 served."""
        aggregator = self._finished_aggregator()
        aggregator._stats_before = (500, 0)
        aggregator._stats_after = (100, 0)
        output = self._render(aggregator)
        assert "requests served by target : 0" in output
        assert "-400" not in output

    def test_a_single_read_does_not_claim_a_measurement(self) -> None:
        """A before without an after is an unfinished measurement, not a low one."""
        aggregator = self._finished_aggregator()
        aggregator._stats_before = (0, 0)
        aggregator._stats_after = None
        assert "NOT MEASURED" in self._render(aggregator)


class TestParentProbeAccounting:
    def test_answered_probes_are_counted_and_reported(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 4
        aggregator._probe_ok = 3
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            aggregator._print_final_results()
        output = buffer.getvalue()
        assert "75%" in output
        assert "3 of 4 probes answered" in output

    def test_no_probes_means_no_availability_claim(self) -> None:
        """Zero samples must not render as 0% availability."""
        aggregator = make_aggregator([make_profile()])
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            aggregator._print_final_results()
        assert "target availability" not in buffer.getvalue().lower()


class TestAvailabilityReportingIsNotAnOutageClaim:
    """A 0% figure must not be reported as a target that fell over.

    The regression this covers is a real run: a strike against a phone, which
    serves no HTTP, produced 0 of 84 probes answered and the report then
    asserted "The target stopped answering at least once while under load."
    An independent observer on a second machine was pinging the same phone
    throughout at 3-5ms with almost no loss, so the tool had declared an
    outage that demonstrably had not happened.

    A percentage cannot carry that distinction on its own - the same 0% means
    opposite things depending on why the probes failed - so the report has to
    say which it was, and say nothing it cannot support when it cannot tell.
    """

    @staticmethod
    def _render(aggregator) -> str:
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            aggregator._print_final_results()
        return buffer.getvalue()

    def test_refused_probes_are_not_reported_as_degradation(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 84
        aggregator._probe_ok = 0
        aggregator._probe_failures = {"ConnectError": 84}
        output = self._render(aggregator)
        assert "0%" in output
        assert "stopped answering" not in output.lower()
        assert "NOT evidence that the target failed" in output

    def test_refused_probes_say_availability_was_unmeasurable(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 84
        aggregator._probe_ok = 0
        aggregator._probe_failures = {"ConnectError": 84}
        output = self._render(aggregator)
        assert "cannot be measured" in output

    def test_answered_then_failed_is_reported_as_degradation(self) -> None:
        """Some answers followed by failures is a result, and should read as one."""
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 20
        aggregator._probe_ok = 4
        aggregator._probe_failures = {"ReadTimeout": 16}
        output = self._render(aggregator)
        assert "consistent with real degradation" in output

    def test_timeouts_alone_are_not_attributed_to_anything(self) -> None:
        """A timeout cannot separate a filtered port from a dead service."""
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 20
        aggregator._probe_ok = 0
        aggregator._probe_failures = {"ReadTimeout": 20}
        output = self._render(aggregator)
        assert "cannot distinguish a filtered port" in output
        assert "does not claim to tell those apart" in output
        assert "stopped answering" not in output.lower()

    def test_failure_reasons_are_itemised(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 30
        aggregator._probe_ok = 0
        aggregator._probe_failures = {"ConnectTimeout": 20, "ReadTimeout": 10}
        output = self._render(aggregator)
        assert "20x ConnectTimeout" in output
        assert "10x ReadTimeout" in output

    def test_full_availability_claims_nothing_about_failure(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 10
        aggregator._probe_ok = 10
        output = self._render(aggregator)
        assert "100%" in output
        assert "Probe failure reasons" not in output

    def test_refused_detection_requires_every_failure_to_be_refused(self) -> None:
        """One timeout among refusals is not evidence of an absent surface."""
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 10
        aggregator._probe_ok = 0
        aggregator._probe_failures = {"ConnectError": 9, "ReadTimeout": 1}
        assert aggregator._no_http_surface() is False

    def test_refused_detection_is_false_when_any_probe_answered(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 10
        aggregator._probe_ok = 1
        aggregator._probe_failures = {"ConnectError": 9}
        assert aggregator._no_http_surface() is False

    def test_probe_failure_reason_is_recorded_per_attempt(self) -> None:
        """alive() leaves the reason behind, and it is tallied by type."""
        aggregator = make_aggregator([make_profile()])

        class Refusing:
            last_probe_error = "ConnectError: [Errno 111] Connection refused"

            async def alive(self, timeout=None):
                return False

        aggregator._observer = Refusing()
        aggregator._probe_total = 2
        aggregator._record_probe_failure()
        aggregator._record_probe_failure()
        assert aggregator._probe_failures == {"ConnectError": 2}


class TestRefusedConnection:
    """The rule both the engine and the nuclear aggregator now share."""

    @pytest.mark.parametrize(
        "error",
        [
            "ConnectError: [Errno 111] Connection refused",
            "httpx.ConnectError",
            "connecterror: all connection attempts failed",
        ],
    )
    def test_refusals_are_recognised(self, error: str) -> None:
        from adobo.observation import refused_connection

        assert refused_connection(error) is True

    @pytest.mark.parametrize(
        "error",
        [
            "ReadTimeout: timed out",
            "ConnectTimeout: ",
            "HTTP 503 Service Unavailable",
            "",
            None,
        ],
    )
    def test_everything_else_is_not_a_refusal(self, error: str | None) -> None:
        from adobo.observation import refused_connection

        assert refused_connection(error) is False



class TestRequestShapeReachesTheChild:
    """--method/--path/--cookie/--referer/--data/--content-type must reach the
    http_flood child a nuclear strike spawns.

    The single-profile path forwards these through config_from_args; nuclear
    builds its own AttackProfiles in _build_configs, so a flag that only exists
    on that path would make a nuclear strike silently send GET /api/data while
    the operator watched for POSTs - the exact dropped-value failure
    TestOperatorValuesReachTheChildren exists to rule out.
    """

    def test_method_and_path_reach_the_child(self) -> None:
        attack = _child_attack(http_method="post", http_path="/login")
        assert attack.http_method == "post"
        assert attack.http_path == "/login"

    def test_cookie_referer_and_content_type_reach_the_child(self) -> None:
        attack = _child_attack(
            cookie_header="session=xyz",
            referer="https://lab.test/",
            content_type="application/json",
        )
        assert attack.cookie_header == "session=xyz"
        assert attack.referer == "https://lab.test/"
        assert attack.content_type == "application/json"

    def test_body_reaches_the_child(self) -> None:
        attack = _child_attack(http_method="post", http_body="a=1&b=2")
        assert attack.http_body == "a=1&b=2"

    def test_defaults_build_the_same_child_a_strike_always_built(self) -> None:
        """No shape requested -> the model defaults, byte for byte the pre-flag
        configuration."""
        attack = _child_attack()
        assert attack.http_method == "get"
        assert attack.http_path == "/api/data"
        assert attack.http_body == ""
        assert attack.cookie_header == ""

    def test_the_body_never_rides_on_a_non_http_child(self) -> None:
        """A shape that is only meaningful for http_flood must not abort a UDP
        child with a ValidationError: the model refuses a body on a GET, and a
        strike should not be able to configure one of its own children into a
        crash."""
        aggregator = NuclearAggregator(
            profiles=[
                make_profile("http_flood", 8000, ProfileName.HTTP_FLOOD),
                make_profile("udp_flood", 8000, ProfileName.UDP_FLOOD),
            ],
            target_ip="127.0.0.1",
            pps=1000,
            duration=1.0,
            http_method="post",
            http_body="a=1",
        )
        configs = aggregator._build_configs()
        shapes = {c.attack.profile: c.attack.http_body for c in configs}
        assert shapes[ProfileName.HTTP_FLOOD] == "a=1"
        assert shapes[ProfileName.UDP_FLOOD] == ""

    def test_proxy_default_scheme_reaches_the_run_config(self) -> None:
        configs = _aggregator(proxy_default_scheme="socks5")._build_configs()
        assert configs[0].proxy_default_scheme == "socks5"


class TestProfileSelection:
    """The selection parser: numbers, names, or a mix; order preserved from
    the menu; duplicates collapse; unknown tokens reported, never ignored.

    Reporting rather than ignoring is the load-bearing choice: a typo that
    silently selected nothing would run the full strike instead of the
    intended subset, which is the one failure mode worse than an error here.
    """

    def _menu(self):
        return [
            make_profile("udp_flood", 8000, ProfileName.UDP_FLOOD),
            make_profile("http_flood", 8000, ProfileName.HTTP_FLOOD),
            make_profile("slowloris", 8000, ProfileName.SLOWLORIS),
        ]

    def test_names_select_in_menu_order(self) -> None:
        selected, unknown = _parse_profile_selection(
            "slowloris,udp_flood", self._menu()
        )
        assert [p.name for p in selected] == ["udp_flood", "slowloris"]
        assert unknown == []

    def test_numbers_select_by_position(self) -> None:
        selected, unknown = _parse_profile_selection("1,3", self._menu())
        assert [p.name for p in selected] == ["udp_flood", "slowloris"]

    def test_mixed_tokens_and_duplicates_collapse(self) -> None:
        selected, unknown = _parse_profile_selection(
            "3,http_flood,3,udp_flood", self._menu()
        )
        assert [p.name for p in selected] == ["udp_flood", "http_flood", "slowloris"]
        assert unknown == []

    def test_names_are_case_insensitive(self) -> None:
        selected, _unknown = _parse_profile_selection("UDP_FLOOD", self._menu())
        assert [p.name for p in selected] == ["udp_flood"]

    def test_unknown_tokens_are_reported(self) -> None:
        selected, unknown = _parse_profile_selection("1,nope", self._menu())
        assert [p.name for p in selected] == ["udp_flood"]
        assert unknown == ["nope"]

    def test_nothing_selected_is_distinguishable_from_all(self) -> None:
        """A line of only unknowns selects nothing - the caller re-asks or
        aborts; the parser must not hand back the full list as a fallback."""
        selected, unknown = _parse_profile_selection("nope,nada", self._menu())
        assert selected == []
        assert unknown == ["nope", "nada"]
