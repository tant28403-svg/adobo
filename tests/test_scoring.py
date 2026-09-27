"""Tests for aggregation and scoring.

The score is the tool's headline output, so the tests pin down the properties
that would be embarrassing to get wrong: a perfect run must score 100, a dead
target must score 0, and a run with no data must not flatter itself.
"""

from __future__ import annotations

import pytest

from ddosim.models import ProbeResult, ProbeSummary, ResourceSample, TargetStats
from ddosim.scoring import (
    LATENCY_BUDGET_MS,
    LATENCY_CEILING_MS,
    WEIGHTS,
    grade_for,
    latency_percentiles,
    score_run,
    summarise_probes,
    summarise_resources,
)


def probe(ok: bool, latency: float | None = 20.0, error: str | None = None) -> ProbeResult:
    return ProbeResult(
        t=1.0, ok=ok, status_code=200 if ok else 503, latency_ms=latency, error=error
    )


# ---------------------------------------------------------------------------
# Weights
# ---------------------------------------------------------------------------


class TestWeights:
    def test_weights_sum_to_one(self) -> None:
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

    def test_availability_dominates(self) -> None:
        assert WEIGHTS["availability"] == max(WEIGHTS.values())

    def test_all_four_components_are_present(self) -> None:
        assert set(WEIGHTS) == {"availability", "latency", "error_rate", "headroom"}


# ---------------------------------------------------------------------------
# Latency percentiles
# ---------------------------------------------------------------------------


class TestPercentiles:
    def test_empty_input(self) -> None:
        summary = latency_percentiles([])
        assert summary.count == 0
        assert summary.p95_ms == 0.0

    def test_single_value(self) -> None:
        summary = latency_percentiles([42.0])
        assert summary.count == 1
        assert summary.p50_ms == 42.0
        assert summary.max_ms == 42.0

    def test_is_order_independent(self) -> None:
        a = latency_percentiles([5, 1, 9, 3, 7])
        b = latency_percentiles([9, 7, 5, 3, 1])
        assert a == b

    def test_mean_and_max(self) -> None:
        summary = latency_percentiles([10, 20, 30, 40])
        assert summary.mean_ms == 25.0
        assert summary.max_ms == 40.0

    def test_p95_of_a_flat_distribution(self) -> None:
        summary = latency_percentiles([100.0] * 20)
        assert summary.p95_ms == 100.0

    def test_p95_catches_the_tail(self) -> None:
        """Nearest-rank p95 of 100 samples is the 95th value, so 6 slow samples
        put ranks 95-100 in the tail."""
        summary = latency_percentiles([10.0] * 94 + [5000.0] * 6)
        assert summary.p95_ms == 5000.0
        assert summary.p50_ms == 10.0

    def test_a_single_outlier_of_twenty_lands_on_p99(self) -> None:
        """Nearest-rank on n=20 puts the 20th value at p95; document the boundary."""
        summary = latency_percentiles([10.0] * 19 + [5000.0])
        assert summary.p95_ms == 10.0
        assert summary.p99_ms == 5000.0

    def test_ignores_none_and_negative(self) -> None:
        summary = latency_percentiles([10.0, None, -5.0, 20.0])
        assert summary.count == 2

    def test_p50_does_not_exceed_p95(self) -> None:
        summary = latency_percentiles([float(v) for v in range(1, 101)])
        assert summary.p50_ms <= summary.p95_ms <= summary.p99_ms


# ---------------------------------------------------------------------------
# Probe summarisation
# ---------------------------------------------------------------------------


class TestSummariseProbes:
    def test_no_probes(self) -> None:
        summary = summarise_probes([])
        assert summary.total == 0
        assert summary.availability_pct == 0.0

    def test_all_successful(self) -> None:
        summary = summarise_probes([probe(True) for _ in range(10)])
        assert summary.availability_pct == 100.0
        assert summary.failed == 0
        assert summary.error_breakdown == {}

    def test_all_failed(self) -> None:
        summary = summarise_probes(
            [probe(False, None, "Connection refused") for _ in range(4)]
        )
        assert summary.availability_pct == 0.0
        assert summary.failed == 4

    def test_mixed_availability(self) -> None:
        summary = summarise_probes([probe(True)] * 7 + [probe(False)] * 3)
        assert summary.availability_pct == 70.0
        assert summary.succeeded == 7
        assert summary.failed == 3

    def test_errors_are_bucketed_by_cause(self) -> None:
        summary = summarise_probes(
            [
                probe(False, 5.0, "ConnectError: connection refused"),
                probe(False, 5.0, "ConnectError: connection refused"),
                probe(False, 5.0, "ReadTimeout: timed out"),
            ]
        )
        assert summary.error_breakdown == {"ConnectError": 2, "ReadTimeout": 1}

    def test_failures_without_a_message_still_bucket(self) -> None:
        summary = summarise_probes([probe(False, None, None)])
        assert summary.error_breakdown == {"unknown": 1}

    def test_latency_ignores_failed_probes_without_a_time(self) -> None:
        summary = summarise_probes(
            [probe(True, 10.0), probe(False, None, "boom")]
        )
        assert summary.latency.count == 1


# ---------------------------------------------------------------------------
# Resource summarisation
# ---------------------------------------------------------------------------


def resource(t: float, cpu: float, rss: float, threads: int = 4, sockets: int = 10) -> ResourceSample:
    return ResourceSample(
        t=t, cpu_percent=cpu, rss_mb=rss, threads=threads, open_sockets=sockets, handles=50
    )


class TestSummariseResources:
    def test_no_samples(self) -> None:
        stats = summarise_resources([])
        assert stats.sample_count == 0
        assert stats.cpu_percent_max == 0.0

    def test_peaks_and_mean(self) -> None:
        stats = summarise_resources(
            [resource(0, 10, 100), resource(1, 50, 120), resource(2, 30, 110)]
        )
        assert stats.cpu_percent_mean == 30.0
        assert stats.cpu_percent_max == 50.0
        assert stats.rss_mb_max == 120.0
        assert stats.sample_count == 3

    def test_tracks_peak_connections(self) -> None:
        stats = summarise_resources(
            [resource(0, 10, 100, sockets=5), resource(1, 10, 100, sockets=900)]
        )
        assert stats.peak_sockets == 900

    def test_p95_is_reported(self) -> None:
        stats = summarise_resources([resource(i, i * 10, 100) for i in range(10)])
        assert stats.cpu_percent_p95 >= stats.cpu_percent_mean


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


PERFECT = TargetStats(
    cpu_percent_mean=5.0,
    cpu_percent_p95=10.0,
    cpu_percent_max=10.0,
    rss_mb_max=50.0,
    peak_threads=4,
    peak_sockets=20,
    peak_handles=100,
    sample_count=10,
)

EXHAUSTED = TargetStats(
    cpu_percent_mean=99.0,
    cpu_percent_p95=100.0,
    cpu_percent_max=100.0,
    rss_mb_max=900.0,
    peak_threads=200,
    peak_sockets=800,
    peak_handles=5000,
    sample_count=10,
)


def all_ok(count: int = 20, latency: float = 10.0) -> ProbeSummary:
    return summarise_probes([probe(True, latency) for _ in range(count)])


class TestScoring:
    def test_a_completely_idle_target_scores_100(self) -> None:
        idle = TargetStats(
            cpu_percent_mean=0.0,
            cpu_percent_p95=0.0,
            cpu_percent_max=0.0,
            rss_mb_max=0.0,
            peak_threads=0,
            peak_sockets=0,
            peak_handles=0,
            sample_count=10,
        )
        score = score_run(all_ok(), idle)
        assert score.total == 100.0
        assert score.grade == "A"

    def test_a_healthy_run_still_grades_a(self) -> None:
        """Some headroom is consumed by any real service, so 100 is rare by
        design - a low-90s score for a flawless run is the honest answer."""
        score = score_run(all_ok(), PERFECT)
        assert score.total >= 99.0
        assert score.grade == "A"

    def test_dead_target_scores_0(self) -> None:
        summary = summarise_probes([probe(False, None, "refused") for _ in range(10)])
        score = score_run(summary, EXHAUSTED)
        assert score.total == 0.0
        assert score.grade == "F"

    def test_fast_failures_score_zero(self) -> None:
        """A connection refused in 1 ms must not earn full latency marks.

        This is the case that made latency look good while the target was
        completely down: the client failed fast, so its own latency was tiny.
        """
        summary = summarise_probes([probe(False, 1.0, "refused") for _ in range(10)])
        score = score_run(summary, PERFECT)
        assert score.latency == 0.0, "latency must be unmeasurable, not perfect"
        assert score.total < 15.0

    def test_timeouts_do_not_pollute_the_latency_distribution(self) -> None:
        summary = summarise_probes(
            [probe(True, 10.0)] * 9 + [probe(False, 2000.0, "ReadTimeout")]
        )
        assert summary.latency.count == 9
        assert summary.latency.p95_ms == 10.0

    def test_no_probes_scores_zero_not_a_pass(self) -> None:
        """Silence is not availability. A cancelled run must not look resilient."""
        score = score_run(ProbeSummary(), PERFECT)
        assert score.total == 0.0
        assert score.grade == "N/A"

    def test_components_are_reported(self) -> None:
        score = score_run(all_ok(), PERFECT)
        breakdown = score.as_breakdown()
        assert set(breakdown) == {"availability", "latency", "error_rate", "headroom"}
        assert all(0.0 <= v <= 100.0 for v in breakdown.values())

    def test_availability_outweighs_latency(self) -> None:
        """Losing requests must cost more than serving them slowly."""
        slow = score_run(all_ok(20, 1500.0), PERFECT)
        half_dead = score_run(
            summarise_probes([probe(True, 10.0)] * 5 + [probe(False, None, "x")] * 5),
            PERFECT,
        )
        assert half_dead.total < slow.total

    def test_headroom_only_docks_a_little(self) -> None:
        roomy = score_run(all_ok(), PERFECT)
        tight = score_run(all_ok(), EXHAUSTED)
        assert roomy.total - tight.total < 15.0, "headroom should not dominate"

    def test_latency_falls_off_between_budget_and_ceiling(self) -> None:
        at_budget = score_run(all_ok(20, LATENCY_BUDGET_MS), PERFECT)
        at_ceiling = score_run(all_ok(20, LATENCY_CEILING_MS), PERFECT)
        assert at_budget.latency == 100.0
        assert at_ceiling.latency == 0.0

    def test_latency_beyond_the_ceiling_stays_at_zero(self) -> None:
        assert score_run(all_ok(20, 60_000.0), PERFECT).latency == 0.0

    def test_error_rate_tracks_failed_probes(self) -> None:
        summary = summarise_probes([probe(True)] * 8 + [probe(False, None, "x")] * 2)
        assert score_run(summary, PERFECT).error_rate == 80.0

    def test_weights_are_echoed_into_the_score(self) -> None:
        assert score_run(all_ok(), PERFECT).weights == WEIGHTS

    def test_custom_weights_change_the_total(self) -> None:
        summary = summarise_probes([probe(True)] * 5 + [probe(False, None, "x")] * 5)
        default = score_run(summary, PERFECT)
        availability_heavy = score_run(
            summary,
            PERFECT,
            weights={
                "availability": 0.9,
                "latency": 0.05,
                "error_rate": 0.03,
                "headroom": 0.02,
            },
        )
        assert availability_heavy.total < default.total, (
            "a target that is 50% available should be punished harder when "
            "availability carries more of the score"
        )

    def test_score_is_always_in_range(self) -> None:
        for availability in range(0, 11, 2):
            summary = summarise_probes(
                [probe(True)] * availability + [probe(False, None, "x")] * (10 - availability)
            )
            for stats in (PERFECT, EXHAUSTED, TargetStats()):
                score = score_run(summary, stats)
                assert 0.0 <= score.total <= 100.0

    def test_serialises(self) -> None:
        score = score_run(all_ok(), PERFECT)
        assert score.model_dump()["grade"] == "A"


class TestGrades:
    @pytest.mark.parametrize(
        "total,expected",
        [
            (100.0, "A"),
            (90.0, "A"),
            (89.9, "B"),
            (80.0, "B"),
            (79.9, "C"),
            (70.0, "C"),
            (69.9, "D"),
            (55.0, "D"),
            (54.9, "F"),
            (0.0, "F"),
        ],
    )
    def test_bands(self, total: float, expected: str) -> None:
        assert grade_for(total) == expected

    def test_grades_are_monotonic_in_score(self) -> None:
        order = ["F", "D", "C", "B", "A"]
        grades = [grade_for(t) for t in range(0, 101, 5)]
        indices = [order.index(g) for g in grades]
        assert indices == sorted(indices)
