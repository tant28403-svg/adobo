"""Tests for the policy ceilings.

The authorisation gate that used to live here is gone: it required a dated,
scoped record to be edited before the tool would send anything, including to
the loopback target in this same repository. What remains is the ceiling
clamping, which is what keeps a run inside what the machine can measure.

A test that only checked the happy path would have passed before the ceilings
existed too, so the cases here are the ones that assert a value was actually
reduced - a run that quietly ignored its limits would still send and still
report a result.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from adobo.config import LabConfig, LimitsConfig
from adobo.models import AttackProfile, ProfileName, RunConfig, Target
from adobo.safety import ClampResult, SafetyGuard, preflight


def _lab(**kw) -> LabConfig:
    return LabConfig(limits=LimitsConfig(**kw), allowed_cidrs=["127.0.0.0/8"])


def _profile(**kw) -> AttackProfile:
    defaults = dict(
        profile=ProfileName.HTTP_FLOOD,
        pps=1000,
        duration_seconds=10.0,
        payload_size=512,
        workers=4,
    )
    defaults.update(kw)
    return AttackProfile(**defaults)


# ---------------------------------------------------------------------------
# Ceilings
# ---------------------------------------------------------------------------


class TestThroughputIsNotCapped:
    """Throughput has no ceiling, so a run sends what it was asked to send.

    A pps cap only ever understated the run: the operator asked for a rate, the
    tool sent less, and the result described a smaller test than the one on
    screen. What the machine can actually send is the honest limit, and that
    shows up in the achieved figure rather than being hidden in a config file.
    """

    def test_throughput_is_left_alone_by_default(self) -> None:
        guard = SafetyGuard()
        assert guard.lab.limits.max_pps is None
        fields, notes = guard.clamp_fields(pps=2_000_000)
        assert fields["pps"] == 2_000_000
        assert notes == []

    def test_a_configured_pps_limit_is_still_honoured(self) -> None:
        """Optional means optional: an operator who sets one still gets it."""
        guard = SafetyGuard(lab=_lab(max_pps=20_000))
        fields, notes = guard.clamp_fields(pps=2_000_000)
        assert fields["pps"] == 20_000
        assert any("pps clamped" in n for n in notes)

    def test_clamp_profile_leaves_a_high_rate_alone(self) -> None:
        guard = SafetyGuard()
        result = guard.clamp_profile(_profile(pps=500_000))
        assert result.applied.pps == 500_000
        assert result.changed is False

    def test_the_summary_says_uncapped(self) -> None:
        assert "uncapped" in SafetyGuard().describe_ceilings()


class TestCeilingsClampAndReport:
    def test_payload_above_the_ceiling_is_capped(self) -> None:
        """The reported crash, in the form the clamp has to handle.

        1,900,000 was what produced a raw pydantic ValidationError. The value
        cannot be clamped after model validation, because AttackProfile refuses
        to hold it in the first place, so the model ceiling (65,507) is treated
        as a protocol bound the clamp respects too.
        """
        guard = SafetyGuard(lab=_lab(max_payload_bytes=1400))
        fields, _ = guard.clamp_fields(payload_size=1_900_000)
        assert fields["payload_size"] == 1400

    def test_workers_above_the_ceiling_are_capped(self) -> None:
        guard = SafetyGuard(lab=_lab(max_workers=200))
        fields, _ = guard.clamp_fields(workers=5000)
        assert fields["workers"] == 200

    def test_duration_above_the_ceiling_is_capped(self) -> None:
        guard = SafetyGuard(lab=_lab(max_duration_seconds=60))
        fields, _ = guard.clamp_fields(duration_seconds=600.0)
        assert fields["duration_seconds"] == 60.0

    def test_every_clamp_is_reported_in_a_note(self) -> None:
        """A capped run must never look like the run that was asked for."""
        guard = SafetyGuard(
            lab=_lab(max_pps=20_000, max_payload_bytes=1400, max_workers=200)
        )
        fields, notes = guard.clamp_fields(
            pps=2_000_000, payload_size=99_000, workers=9999
        )
        joined = " ".join(notes).lower()
        assert "pps" in joined
        assert "payload" in joined
        assert "workers" in joined
        # The note names the file holding the limit, so the operator knows
        # where the number came from.
        assert "lab.yaml" in joined
        assert fields["pps"] == 20_000
        assert fields["payload_size"] == 1400
        assert fields["workers"] == 200

    def test_a_run_inside_the_limits_is_left_alone(self) -> None:
        guard = SafetyGuard(
            lab=_lab(max_pps=20_000, max_payload_bytes=1400, max_workers=200)
        )
        fields, notes = guard.clamp_fields(pps=1000, payload_size=512, workers=4)
        assert notes == []
        assert fields["pps"] == 1000
        assert fields["payload_size"] == 512
        assert fields["workers"] == 4

    def test_ceilings_never_raise_a_value(self) -> None:
        """A run must not be able to raise its own limits."""
        guard = SafetyGuard(
            lab=_lab(max_pps=20_000, max_payload_bytes=1400, max_workers=200)
        )
        fields, notes = guard.clamp_fields(pps=10, payload_size=64, workers=1)
        assert fields["pps"] == 10
        assert fields["payload_size"] == 64
        assert fields["workers"] == 1

    def test_h2_concurrency_is_capped_at_the_model_limit(self) -> None:
        guard = SafetyGuard()
        fields, _ = guard.clamp_fields(h2_concurrency=99_999)
        assert fields["h2_concurrency"] == 1000

    def test_a_value_past_the_model_ceiling_cannot_be_constructed(self) -> None:
        """Why the clamp runs on raw fields rather than on a profile.

        pydantic rejects this before any clamp could see it, which is exactly
        the crash that prompted moving the clamp earlier. The test states that
        ordering constraint so a future refactor does not move it back.
        """
        with pytest.raises(ValidationError):
            _profile(payload_size=1_900_000)

    def test_clamping_keeps_a_wild_payload_inside_the_model(self) -> None:
        guard = SafetyGuard(lab=_lab(max_payload_bytes=1400))
        fields, notes = guard.clamp_fields(
            profile=ProfileName.HTTP_FLOOD,
            pps=1000,
            duration_seconds=10.0,
            payload_size=1_900_000,
            workers=4,
        )
        profile = AttackProfile(**fields)
        assert profile.payload_size == 1400
        assert any("payload" in n.lower() for n in notes)


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------


class TestPreflight:
    def test_preflight_returns_the_clamped_profile(self) -> None:
        config = RunConfig(
            target=Target(host="127.0.0.1", port=8000),
            attack=_profile(pps=2_000_000, payload_size=60_000),
        )
        guard = SafetyGuard(lab=_lab(max_pps=20_000, max_payload_bytes=1400))
        result = preflight(config, guard)
        assert isinstance(result, ClampResult)
        assert result.applied.pps == 20_000
        assert result.applied.payload_size == 1400

    def test_preflight_does_not_consult_any_authorisation_record(self) -> None:
        """Any target is permitted. The target is the operator's choice.

        This states the removal explicitly: a test that named an unauthorised
        target and expected a refusal would be the test for the old behaviour,
        and its absence is the point.
        """
        config = RunConfig(
            target=Target(host="192.168.9.9", port=80),
            attack=_profile(),
        )
        result = preflight(config, SafetyGuard(lab=_lab()))
        assert result.applied.pps == 1000
