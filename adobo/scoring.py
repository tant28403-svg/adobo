"""Turning measurements into a verdict.

The score exists to answer one question an assessor actually asks: *did the
target stay reachable, and did it degrade gracefully or collapse?* A tool that
only reports packets-per-second is measuring itself.

**Weighting rationale.** Availability dominates (0.45) because an endpoint that
returns errors is worthless regardless of how fast the survivors respond.
Latency is next (0.25) - slow is survivable, down is not. Error rate is separate
from availability (0.20) because a target can answer 429s quickly and still be
effectively unavailable to its users. Headroom is last (0.10): it is the earliest
warning signal, but it predicts a collapse rather than measuring one.

Every component is defined at zero samples, so a run that was cancelled before
any data arrived scores 0 rather than crashing or silently scoring 100.
"""

from __future__ import annotations

import math
from typing import Iterable, Sequence

from .models import (
    Percentiles,
    ProbeResult,
    ProbeSummary,
    ResilienceScore,
    ResourceSample,
    TargetStats,
)

__all__ = [
    "WEIGHTS",
    "grade_for",
    "latency_percentiles",
    "score_run",
    "summarise_probes",
    "summarise_resources",
]

WEIGHTS: dict[str, float] = {
    "availability": 0.45,
    "latency": 0.25,
    "error_rate": 0.20,
    "headroom": 0.10,
}
"""Must sum to 1.0. Asserted at import so a typo cannot skew every score."""

assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9, "score weights must sum to 1.0"

LATENCY_BUDGET_MS = 250.0
"""Latency at or below this scores full marks. Chosen to sit just under a
typical human perception threshold for "instant" on a local network."""

LATENCY_CEILING_MS = 2000.0
"""Latency at or above this scores zero. Beyond this point a user has already
given up, so further delay earns no additional penalty."""


# --------------------------------------------------------------------------
# Aggregation helpers
# --------------------------------------------------------------------------


def latency_percentiles(values: Sequence[float]) -> Percentiles:
    """Summarise a latency distribution.

    Percentiles use nearest-rank on a sorted copy, which is exact for the small
    sample counts a short lab run produces and needs no interpolation
    convention to explain in a report.
    """
    clean = sorted(float(v) for v in values if v is not None and v >= 0)
    if not clean:
        return Percentiles(count=0)

    def at(q: float) -> float:
        index = min(len(clean) - 1, max(0, math.ceil(q * len(clean)) - 1))
        return round(clean[index], 2)

    return Percentiles(
        count=len(clean),
        mean_ms=round(sum(clean) / len(clean), 2),
        p50_ms=at(0.50),
        p95_ms=at(0.95),
        p99_ms=at(0.99),
        max_ms=round(clean[-1], 2),
    )


def summarise_probes(probes: Iterable[ProbeResult]) -> ProbeSummary:
    """Fold probe results into an availability and latency summary."""
    collected = list(probes)
    if not collected:
        return ProbeSummary()

    succeeded = sum(1 for probe in collected if probe.ok)
    failed = len(collected) - succeeded
    # Only successful probes contribute latency. A refused connection or a
    # timeout measures the client's patience, not the service's responsiveness,
    # and counting them would let a target that failed every single request score
    # full marks for latency.
    latencies = [p.latency_ms for p in collected if p.ok and p.latency_ms is not None]

    breakdown: dict[str, int] = {}
    for probe in collected:
        if probe.ok:
            continue
        # Collapse distinct exception reprs into a stable, countable key so the
        # report shows "Connection refused x412" rather than 412 separate rows.
        key = _error_bucket(probe)
        breakdown[key] = breakdown.get(key, 0) + 1

    return ProbeSummary(
        total=len(collected),
        succeeded=succeeded,
        failed=failed,
        availability_pct=round(succeeded / len(collected) * 100.0, 2),
        latency=latency_percentiles(latencies),
        error_breakdown=breakdown,
    )


def _error_bucket(probe: ProbeResult) -> str:
    raw = (probe.error or "").strip()
    if not raw:
        return "unknown"
    head = raw.split(":", 1)[0].strip()
    return head or "unknown"


def summarise_resources(samples: Iterable[ResourceSample]) -> TargetStats:
    """Fold target resource samples into a peak-and-mean summary."""
    collected = list(samples)
    if not collected:
        return TargetStats()

    cpu = [s.cpu_percent for s in collected]
    rss = [s.rss_mb for s in collected]
    ordered_cpu = sorted(cpu)
    p95_index = min(len(ordered_cpu) - 1, math.ceil(0.95 * len(ordered_cpu)) - 1)

    return TargetStats(
        cpu_percent_mean=round(sum(cpu) / len(cpu), 2),
        cpu_percent_p95=round(ordered_cpu[max(0, p95_index)], 2),
        cpu_percent_max=round(max(cpu), 2),
        rss_mb_max=round(max(rss), 2),
        peak_threads=max(s.threads for s in collected),
        peak_sockets=max(s.open_sockets for s in collected),
        peak_handles=max(s.handles for s in collected),
        sample_count=len(collected),
    )


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _latency_component(p95_ms: float, sample_count: int) -> float:
    """Linear falloff between the budget and the ceiling, clamped to 0-1.

    *sample_count* is the number of *successful* latency observations. Zero means
    nothing ever answered, so latency is unmeasurable and must score zero rather
    than defaulting to full marks.
    """
    if sample_count == 0:
        return 0.0
    if p95_ms <= LATENCY_BUDGET_MS:
        return 1.0
    if p95_ms >= LATENCY_CEILING_MS:
        return 0.0
    span = LATENCY_CEILING_MS - LATENCY_BUDGET_MS
    return _clamp01(1.0 - (p95_ms - LATENCY_BUDGET_MS) / span)


def _headroom_component(stats: TargetStats) -> float:
    """Remaining capacity, from whichever resource is closest to saturation.

    Taking the *minimum* across resources is deliberate: a target holding 90% CPU
    has no headroom left even if its memory looks fine.
    """
    if stats.sample_count == 0:
        return 0.0
    cpu = _clamp01(1.0 - (stats.cpu_percent_p95 / 100.0))
    # 512 MB RSS is treated as a comfortable ceiling for a small service.
    memory = _clamp01(1.0 - (stats.rss_mb_max / 512.0))
    socket_pressure = _clamp01(1.0 - (stats.peak_sockets / 512.0))
    return min(cpu, memory, socket_pressure)


def score_run(
    probe: ProbeSummary,
    target: TargetStats,
    *,
    weights: dict[str, float] | None = None,
) -> ResilienceScore:
    """Compute the 0-100 resilience verdict.

    A run with no probes at all cannot demonstrate resilience, so it scores 0
    with an explanatory grade rather than a flattering default.
    """
    active = dict(weights or WEIGHTS)
    if probe.total == 0:
        return ResilienceScore(
            total=0.0,
            grade="N/A",
            weights=active,
        )

    availability = _clamp01(probe.availability_pct / 100.0)
    latency = _latency_component(probe.latency.p95_ms, probe.latency.count)
    error_rate = _clamp01(1.0 - (probe.failed / probe.total))
    headroom = _headroom_component(target)

    total = (
        availability * active["availability"]
        + latency * active["latency"]
        + error_rate * active["error_rate"]
        + headroom * active["headroom"]
    )
    return ResilienceScore(
        total=round(total * 100.0, 1),
        grade=grade_for(total * 100.0),
        availability=round(availability * 100.0, 1),
        latency=round(latency * 100.0, 1),
        error_rate=round(error_rate * 100.0, 1),
        headroom=round(headroom * 100.0, 1),
        weights=active,
    )


def grade_for(total: float) -> str:
    """Letter grade from a 0-100 score.

    The bands are deliberately harsher at the top: a target that is merely
    *survivable* under load is not the same as one that is genuinely resilient.
    """
    if total >= 90:
        return "A"
    if total >= 80:
        return "B"
    if total >= 70:
        return "C"
    if total >= 55:
        return "D"
    return "F"
