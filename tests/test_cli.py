"""Tests for the single-run summary.

The summary is where a run's numbers become a claim someone acts on, so the
question these cover is not "does it print" but "does what it print survive
being read by someone who did not run it".

The specific hazard: a headline count of packets the sender handed to the
operating system reads as a result of the test, when it is only a record of the
tester's effort. The target's own count is the only figure that says anything
about the target, and its *absence* has to be visible too - otherwise an
unmeasurable run and a devastating one are the same three lines of output.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout

from ddosim.cli import summarise
from ddosim.engine import RunEngine
from ddosim.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TargetStats,
    TransportKind,
)


def _config(**kw) -> RunConfig:
    return RunConfig(
        target=Target(host="127.0.0.1", port=kw.pop("port", 9999)),
        attack=AttackProfile(
            profile=ProfileName.UDP_FLOOD,
            pps=kw.pop("pps", 1000),
            duration_seconds=kw.pop("duration", 0.2),
            payload_size=64,
            workers=1,
        ),
        transport=kw.pop("transport", TransportKind.VIRTUAL),
        **kw,
    )


def _render(result) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        summarise(type("O", (), {"result": result, "cancelled": False})())
    return buffer.getvalue()


class TestSummaryWording:
    def test_the_headline_does_not_claim_delivery(self) -> None:
        """'sent' alone invites reading it as packets that arrived."""
        outcome = RunEngine(_config()).run()
        output = _render(outcome.result)
        assert "sent to OS" in output

    def test_an_observed_target_shows_its_own_count(self) -> None:
        outcome = RunEngine(_config()).run()
        result = outcome.result.model_copy(
            update={
                "target_stats": TargetStats(
                    requests_served=250, errors_served=3, stats_observed=True
                )
            }
        )
        output = _render(result)
        assert "target served 250 requests" in output
        assert "3 errors" in output

    def test_the_two_counts_are_reconciled(self) -> None:
        """Two numbers side by side invite the reader to treat them as equals.

        The sender's 1,000 and the target's 250 are not the same measurement, so
        the ratio between them is the actual finding.
        """
        outcome = RunEngine(_config()).run()
        result = outcome.result.model_copy(
            update={
                "target_stats": TargetStats(
                    requests_served=250, stats_observed=True
                )
            }
        )
        output = _render(result)
        assert "25.0%" in output
        assert "reached the target" in output

    def test_an_unobserved_target_adds_no_delivery_claim(self) -> None:
        """A dry run or a virtual run has nothing to observe, so it says nothing."""
        outcome = RunEngine(_config()).run()
        output = _render(outcome.result)
        assert "target served" not in output
        assert "delivery" not in output

    def test_a_low_ratio_is_explained(self) -> None:
        """Otherwise a mixed UDP/HTTP run always looks like a failing flood."""
        outcome = RunEngine(_config()).run()
        result = outcome.result.model_copy(
            update={
                "target_stats": TargetStats(
                    requests_served=5, stats_observed=True
                )
            }
        )
        output = _render(result)
        assert "not counted there" in output

    def test_a_full_ratio_is_not_annotated_with_a_caveat(self) -> None:
        """The caveat is noise on a run that delivered everything it sent."""
        outcome = RunEngine(_config()).run()
        sent = outcome.result.attack.packets_sent
        result = outcome.result.model_copy(
            update={
                "target_stats": TargetStats(
                    requests_served=sent,
                    stats_observed=True,
                )
            }
        )
        output = _render(result)
        assert "not counted there" not in output
