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
        aggregator = make_aggregator([make_profile()])
        aggregator._absorb(
            {
                "profile": "nuclear-udp_flood",
                "event": "failed",
                "success": False,
                "result": None,
                "error": "no route",
            }
        )
        assert aggregator.results["nuclear-udp_flood"]["error"] == "no route"

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


class TestPreflight:
    def test_a_closed_port_is_dropped_with_a_reason(self) -> None:
        """An open port is kept, a closed one is dropped and explained.

        A real listener is bound rather than assuming a well-known port is open,
        so the test states its own premise instead of depending on whatever else
        happens to be listening when the suite runs.
        """
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        open_port = listener.getsockname()[1]
        try:
            profiles = [
                make_profile("open", open_port),
                make_profile("closed", _a_closed_port()),
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
            [make_profile("closed", closed)], "127.0.0.1"
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
            [make_profile("x", _a_closed_port())], "127.0.0.1"
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
        assert "unknown rather than inferred" in output
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
        assert aggregator._probes_all_refused() is False

    def test_refused_detection_is_false_when_any_probe_answered(self) -> None:
        aggregator = make_aggregator([make_profile()])
        aggregator._probe_total = 10
        aggregator._probe_ok = 1
        aggregator._probe_failures = {"ConnectError": 9}
        assert aggregator._probes_all_refused() is False

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

