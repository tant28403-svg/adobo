"""The claim a report makes when every probe failed.

These are contract tests over the wording, and they exist because the tool made
a false statement in a real run. A strike against a phone - which serves no
HTTP - reported "0% (0 of 84 probes answered)" and then asserted:

    The target stopped answering at least once while under load.

An independent observer on the second VM was pinging the same phone throughout
at 3-5ms with almost no loss. The target had not stopped answering anything,
and the tool had no way to know that - which is the point. What it had was a
boolean per probe, and a boolean cannot tell a collapsed target from a port
that never served anything.

The assertions below are deliberately substring checks on prose. That is
normally a smell in a test suite, but here the prose *is* the product: the
claim is the thing that reached the reader, so the claim is what has to be
verified. Changing a string here is a change to what the tool asserts, and
should be made deliberately.
"""

from __future__ import annotations

import io
import socket
from contextlib import redirect_stdout

import pytest

from adobo.observation import refused_connection


@pytest.fixture
def closed_port() -> int:
    """A loopback TCP port with nothing listening.

    Bound then released rather than hardcoded: a well-known port can be taken by
    something else on the machine running the suite, which would quietly turn a
    "target is unreachable" test into a passing no-op.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


# ---------------------------------------------------------------------------
# The shared rule
# ---------------------------------------------------------------------------


class TestRefusedConnectionRule:
    @pytest.mark.parametrize(
        "error",
        [
            "ConnectError: [Errno 111] Connection refused",
            "httpx.ConnectError",
            "connecterror: All connection attempts failed",
            "CONNECTION REFUSED",
        ],
    )
    def test_a_refusal_is_recognised(self, error: str) -> None:
        assert refused_connection(error) is True

    @pytest.mark.parametrize(
        "error",
        [
            "ReadTimeout: timed out",
            "ConnectTimeout: ",
            "HTTP 503 Service Unavailable",
            "Internal Server Error",
            "",
            None,
        ],
    )
    def test_nothing_else_counts_as_a_refusal(self, error: str | None) -> None:
        """Timeouts and 5xx are real degradation or unknown - never "no surface".

        A timeout cannot separate a filtered port from a dead service, so
        treating it as evidence of an absent HTTP surface would be as much of a
        guess as the original overclaim, just in the other direction.
        """
        assert refused_connection(error) is False

    def test_the_rule_lives_in_one_place(self) -> None:
        """Both report paths must consult the same function.

        The engine and the nuclear aggregator had drifted: the first was fixed
        to distinguish "no HTTP surface" from "target failed", the second was
        not, so the multi-profile path kept making the old false claim. Two
        copies of this rule is two things to keep in step.
        """
        import inspect

        from adobo import engine, nuclear

        assert "refused_connection" in inspect.getsource(engine)
        assert "refused_connection" in inspect.getsource(nuclear)

        # Neither may carry its own private copy of the marker list.
        for module in (engine, nuclear):
            source = inspect.getsource(module)
            assert "connection refused" not in source.lower(), (
                f"{module.__name__} defines its own marker list"
            )


# ---------------------------------------------------------------------------
# Probes must carry a reason, not just a verdict
# ---------------------------------------------------------------------------


class TestProbeFailuresCarryAReason:
    async def test_a_failed_probe_records_why(self, closed_port: int) -> None:
        from adobo.observation import TargetObserver

        observer = TargetObserver("127.0.0.1", closed_port, timeout=0.3)
        assert await observer.alive(0.3) is False
        assert observer.last_probe_error, "reason discarded"

    async def test_a_successful_probe_clears_the_reason(self) -> None:
        """The attribute describes the latest sample, not the latest failure."""
        from adobo.observation import TargetObserver

        async def answering(timeout=None):
            return {"requests": 0, "errors": 0}

        observer = TargetObserver("127.0.0.1", 9, fetch=answering)
        await observer.alive()
        assert observer.last_probe_error is None

    async def test_probe_reason_is_independent_of_the_stats_error(
        self, closed_port: int
    ) -> None:
        """Reachability and /stats payload are different questions.

        Sharing one slot would let a failed probe erase the reason the delivery
        report gives for having no target-side evidence, or vice versa.
        """
        from adobo.observation import TargetObserver

        observer = TargetObserver("127.0.0.1", closed_port, timeout=0.3)
        await observer.alive(0.3)
        assert observer.last_probe_error
        assert observer._last_error is None


# ---------------------------------------------------------------------------
# The nuclear report
# ---------------------------------------------------------------------------


def _render(aggregator) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        aggregator._print_final_results()
    return buffer.getvalue()


def _aggregator(profiles=1):
    from adobo.models import ProfileName, TransportKind
    from adobo.nuclear import NuclearAggregator, NuclearProfile

    profile = NuclearProfile(
        name="udp_flood",
        profile=ProfileName.UDP_FLOOD,
        transport=TransportKind.SOCKET,
        port=9999,
        spoof=False,
        requires_admin=False,
    )
    return NuclearAggregator([profile] * profiles, "127.0.0.1", 200, 2.0)


class TestNuclearAvailabilityWording:
    def test_refused_probes_are_not_called_degradation(self) -> None:
        """The exact false claim from the phone run must not reappear."""
        agg = _aggregator()
        agg._probe_total = 84
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectError": 84}
        output = _render(agg)
        assert "stopped answering" not in output.lower(), (
            "the tool is again asserting a target outage it cannot evidence"
        )

    def test_refused_probes_state_the_target_never_answered(self) -> None:
        agg = _aggregator()
        agg._probe_total = 84
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectError": 84}
        output = _render(agg)
        assert "no HTTP endpoint" in output
        assert "NOT evidence that the target failed" in output

    def test_a_lone_timeout_does_not_discard_overwhelming_refusals(self) -> None:
        """The real run: 82 refusals and 1 timeout out of 83 probes.

        A 100% threshold reported the fully-ambiguous branch here, so the 82
        refusals - which settle the surface question - never reached the reader.
        The surface question and the health question have different answers, and
        the report has to give both rather than collapsing them into one test.
        """
        agg = _aggregator()
        agg._probe_total = 83
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectError": 82, "ConnectTimeout": 1}
        output = _render(agg)
        assert "82 of the 83 failed probes were refused" in output
        assert "Availability cannot be measured" in output
        assert "NOT evidence that the target failed" in output
        assert "inference from the majority rather than a fact" in output

    def test_uneven_refusals_are_flagged_as_an_inference(self) -> None:
        """A minority of non-refusals must not be presented as settled fact."""
        agg = _aggregator()
        agg._probe_total = 83
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectError": 82, "ConnectTimeout": 1}
        output = _render(agg)
        assert "most likely served no HTTP endpoint" in output
        assert "1 failure(s) were not refusals" in output

    def test_uniform_refusals_are_stated_as_certain(self) -> None:
        agg = _aggregator()
        agg._probe_total = 84
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectError": 84}
        output = _render(agg)
        assert "Every probe was refused" in output
        assert "inference from the majority" not in output

    def test_surface_and_health_are_answered_separately(self) -> None:
        """A target that answered then went silent gets both readings.

        Four probes answered, so an HTTP service demonstrably existed - the
        later refusals cannot be read as "there was never a service here". The
        degradation is a separate finding and is reported as one.
        """
        agg = _aggregator()
        agg._probe_total = 20
        agg._probe_ok = 4
        agg._probe_failures = {"ConnectError": 10, "ReadTimeout": 6}
        output = _render(agg)
        assert "an HTTP service did exist" in output
        assert "Separately, the target answered 4 of 20 probes" in output
        assert "consistent with real degradation" in output
        assert "no HTTP endpoint on this port" not in output

    def test_a_service_that_existed_is_never_called_absent(self) -> None:
        """Any answered probe rules out the "never served anything" reading."""
        agg = _aggregator()
        agg._probe_total = 100
        agg._probe_ok = 1
        agg._probe_failures = {"ConnectError": 99}
        output = _render(agg)
        assert "no HTTP endpoint" not in output
        assert "an HTTP service did exist" in output

    def test_timeouts_alone_never_claim_the_port_was_accepting(self) -> None:
        """A timeout establishes silence, and silence establishes nothing.

        An earlier draft of this branch reported "no probe was refused, so the
        port was accepting connections". That inference is not available: a
        filtered port, a service that was already down, and an unreachable host
        all produce exactly the same silence. The report must say the run cannot
        tell them apart instead of picking the friendliest one.
        """
        agg = _aggregator()
        agg._probe_total = 20
        agg._probe_ok = 0
        agg._probe_failures = {"ReadTimeout": 20}
        output = _render(agg)
        assert "every failure was silence" in output
        assert "does not claim to tell those apart" in output
        assert "the port was accepting" not in output
        assert "the port was reachable" not in output

    def test_a_refusal_proves_the_host_was_alive_at_that_moment(self) -> None:
        """A RST is a real packet back, so it rules out "down the whole run"."""
        agg = _aggregator()
        agg._probe_total = 20
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectError": 10, "ReadTimeout": 10}
        output = _render(agg)
        assert "the target host was alive and its network path worked" in output
        assert "It was not down for the whole run" in output
        assert "consistent with a service that stopped accepting" in output

    def test_unrecognised_failures_claim_nothing_about_reachability(self) -> None:
        agg = _aggregator()
        agg._probe_total = 20
        agg._probe_ok = 0
        agg._probe_failures = {"SomeVendorError": 20}
        output = _render(agg)
        assert "no conclusion is drawn" in output
        assert "accepting connections" not in output

    def test_no_branch_ever_claims_a_probe_reached_a_healthy_service(self) -> None:
        """Guard: silence is never upgraded into a reachability claim.

        Walks every probe outcome the tool can record and checks that the only
        assertions about a live service come from probes that were actually
        answered. The original defect in this file was exactly this kind of
        upgrade, and a per-branch assertion does not catch it appearing in a
        branch nobody thought to test.
        """
        for total, ok, failures in (
            (84, 0, {"ConnectError": 84}),
            (83, 0, {"ConnectError": 82, "ConnectTimeout": 1}),
            (20, 0, {"ConnectError": 10, "ReadTimeout": 10}),
            (20, 0, {"ReadTimeout": 20}),
            (20, 0, {"SomeVendorError": 20}),
            (20, 4, {"ReadTimeout": 10, "ConnectError": 6}),
            (100, 1, {"ConnectError": 99}),
        ):
            agg = _aggregator()
            agg._probe_total = total
            agg._probe_ok = ok
            agg._probe_failures = failures
            output = _render(agg)
            # Scoped to the assertive form. "stopped accepting connections
            # partway through" is a hedged hypothesis about a service that
            # existed, which is a different and legitimate claim.
            assert "the port was accepting" not in output, (total, ok, failures)
            assert "the port was reachable" not in output, (total, ok, failures)
            if not ok:
                assert "an HTTP service did exist" not in output
            # The blanket "NOT evidence of failure" disclaimer is reserved for
            # the no-surface branch, where nothing ever existed to degrade. In
            # the mixed case a real change of state is a live hypothesis and the
            # disclaimer would suppress a genuine finding.
            dominates = (
                not ok
                and failures
                and sum(c for k, c in failures.items() if "refus" in k or "connecterror" in k.lower())
                / sum(failures.values())
                >= 0.95
            )
            if dominates:
                assert "NOT evidence that the target failed" in output, failures
            else:
                assert "NOT evidence that the target failed" not in output, failures

    def test_refused_count_is_summed_across_reason_types(self) -> None:
        """Two different exception names can both record a refusal.

        httpx raises ConnectError for a refused TCP connection, and a socket
        error surfacing through a different client arrives as
        ConnectionRefusedError. Both mean the same thing to this rule, so
        counting only one of them would understate the evidence.
        """
        agg = _aggregator()
        agg._probe_failures = {
            "ConnectError": 70,
            "ConnectionRefusedError": 12,
            "ReadTimeout": 5,
        }
        assert agg._refused_count() == 82

    @pytest.mark.parametrize(
        "ok,total,failures,expected",
        [
            # Strict: every failure refused.
            (0, 10, {"ConnectError": 10}, True),
            # The real run: one timeout in 83 still counts as a majority.
            (0, 83, {"ConnectError": 82, "ConnectTimeout": 1}, True),
            (0, 20, {"ConnectError": 19, "ReadTimeout": 1}, True),
            # Below the threshold: genuinely mixed, so not a surface finding.
            (0, 20, {"ConnectError": 10, "ReadTimeout": 10}, False),
            (0, 20, {"ConnectError": 18, "ReadTimeout": 2}, False),
            # Something answered, so a service existed regardless of refusals.
            (1, 20, {"ConnectError": 19}, False),
            (0, 0, {}, False),
        ],
    )
    def test_refusal_majority_threshold(
        self, ok: int, total: int, failures: dict, expected: bool
    ) -> None:
        """The relaxed threshold must not swallow genuinely mixed evidence."""
        agg = _aggregator()
        agg._probe_total = total
        agg._probe_ok = ok
        agg._probe_failures = failures
        assert agg._refusals_dominate() is expected

    def test_strict_and_relapsed_agree_on_a_uniform_run(self) -> None:
        agg = _aggregator()
        agg._probe_total = 84
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectError": 84}
        assert agg._no_http_surface() is True
        assert agg._no_http_surface() is True
        assert agg._refusals_dominate() is True

    def test_refused_probes_call_availability_unmeasurable(self) -> None:
        agg = _aggregator()
        agg._probe_total = 84
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectError": 84}
        assert "cannot be measured" in _render(agg)

    def test_partial_answers_are_reported_as_degradation(self) -> None:
        """Some answers then failures is a genuine result and reads as one."""
        agg = _aggregator()
        agg._probe_total = 20
        agg._probe_ok = 4
        agg._probe_failures = {"ReadTimeout": 16}
        assert "consistent with real degradation" in _render(agg)

    def test_timeouts_are_attributed_to_nothing(self) -> None:
        """All-timeout, nothing answered: the run states its own blindness."""
        agg = _aggregator()
        agg._probe_total = 20
        agg._probe_ok = 0
        agg._probe_failures = {"ReadTimeout": 20}
        output = _render(agg)
        assert "cannot distinguish a filtered port" in output
        assert "does not claim to tell those apart" in output
        assert "stopped answering" not in output.lower()

    def test_a_timeout_wording_does_not_leak_into_other_reasons(self) -> None:
        """The timeout explanation must not be printed for a non-timeout failure.

        A hardcoded "a timeout cannot separate a filtered port from a dead
        service" would describe a failure that never timed out, which is the
        same category of error as the original false claim: prose that asserts
        something the data does not support.
        """
        agg = _aggregator()
        agg._probe_total = 20
        agg._probe_ok = 0
        agg._probe_failures = {"ProtocolError": 20}
        output = _render(agg)
        assert "unknown rather than inferred" not in output
        assert "no conclusion is drawn" in output

    @pytest.mark.parametrize(
        "failures,expected",
        [
            ({"ReadTimeout": 3}, True),
            ({"ConnectTimeout": 3}, True),
            ({"ConnectError": 3}, False),
            ({"ProtocolError": 3}, False),
            ({}, False),
        ],
    )
    def test_timeout_detection(self, failures: dict, expected: bool) -> None:
        agg = _aggregator()
        agg._probe_failures = failures
        assert agg._probe_failures_had_timeouts() is expected

    def test_failure_reasons_are_itemised_with_counts(self) -> None:
        agg = _aggregator()
        agg._probe_total = 30
        agg._probe_ok = 0
        agg._probe_failures = {"ConnectTimeout": 20, "ReadTimeout": 10}
        output = _render(agg)
        assert "20x ConnectTimeout" in output
        assert "10x ReadTimeout" in output

    def test_perfect_availability_mentions_no_failures(self) -> None:
        agg = _aggregator()
        agg._probe_total = 10
        agg._probe_ok = 10
        assert "Probe failure reasons" not in _render(agg)

    def test_no_probes_makes_no_availability_claim(self) -> None:
        agg = _aggregator()
        assert "target availability" not in _render(agg).lower()

    @pytest.mark.parametrize(
        "ok,total,failures,expected",
        [
            (0, 10, {"ConnectError": 10}, True),
            (0, 10, {"ConnectError": 9, "ReadTimeout": 1}, False),
            (0, 10, {"ReadTimeout": 10}, False),
            (1, 10, {"ConnectError": 9}, False),
            (0, 0, {}, False),
        ],
    )
    def test_refused_requires_every_failure_to_be_a_refusal(
        self, ok: int, total: int, failures: dict, expected: bool
    ) -> None:
        """One timeout among refusals is not evidence of an absent surface."""
        agg = _aggregator()
        agg._probe_total = total
        agg._probe_ok = ok
        agg._probe_failures = failures
        assert agg._no_http_surface() is expected

    def test_failure_reason_is_tallied_by_type(self) -> None:
        """Raw exception text differs per attempt and would not sum."""
        agg = _aggregator()

        class Refusing:
            last_probe_error = "ConnectError: [Errno 111] Connection refused"

            async def alive(self, timeout=None):
                return False

        agg._observer = Refusing()
        agg._probe_total = 2
        agg._record_probe_failure()
        agg._record_probe_failure()
        assert agg._probe_failures == {"ConnectError": 2}


# ---------------------------------------------------------------------------
# Nothing anywhere still asserts an unevidenced outage
# ---------------------------------------------------------------------------


class TestNoUnevidencedOutageClaimsRemain:
    def test_no_module_asserts_the_target_stopped_answering(self) -> None:
        """The exact unsupported sentence must not exist anywhere.

        Scoped to the whole clause rather than the phrase, because "stopped
        answering" appears legitimately where probes *did* answer first and then
        did not - that is a real degradation and the report is entitled to say
        so. What must never appear is the unconditional claim, printed whenever
        availability was below 100% regardless of why it was below.
        """
        import inspect

        from adobo import engine, nuclear, report

        forbidden = "stopped answering at least once"
        for module in (engine, nuclear, report):
            source = inspect.getsource(module).lower()
            assert forbidden not in source, (
                f"{module.__name__} still contains the unsupported outage claim"
            )

    def test_availability_is_never_reported_as_unmeasured_as_zero(self) -> None:
        """Zero samples and zero success are different facts.

        A run that never probed has no availability figure. Rendering it as 0%
        would report a measurement of nothing as a measurement of nothing
        working.
        """
        agg = _aggregator()
        output = _render(agg)
        assert "0 of 0" not in output
        assert "0%" not in output
