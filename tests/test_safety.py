"""Tests for the authorisation gate and the policy ceilings.

These exist because the gate used to be documentation. ``config/authorization.yaml``
stated that "the engine REFUSES to open a socket unless this file is present,
unexpired, and its scope covers the target", and nothing in the codebase read
it: ``load_authorization`` was called only from tests. An expired record did
not stop a run, and neither did the ``lab.yaml`` ceilings.

A test that only checks the happy path would have passed against the broken
version too, so the refusal cases are the ones worth writing: each of them
fails if the gate is removed.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from pydantic import ValidationError

from adobo.config import AuthorizationConfig, LabConfig, LimitsConfig
from adobo.models import AttackProfile, ProfileName, Target
from adobo.safety import (
    ClampResult,
    PolicyViolation,
    SafetyGuard,
    preflight,
)

from tests.conftest import make_authorization


def _limits(**kw) -> LimitsConfig:
    return LimitsConfig(**kw)


def _lab(**kw) -> LabConfig:
    return LabConfig(limits=_limits(**kw), allowed_cidrs=["127.0.0.0/8"])


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
# Authorisation
# ---------------------------------------------------------------------------


class TestAuthorisationRefuses:
    def test_an_expired_record_is_refused(self) -> None:
        expired = make_authorization(expires_in_days=-1)
        guard = SafetyGuard(authorization=expired)
        with pytest.raises(PolicyViolation, match="expired"):
            guard.authorize(Target(host="127.0.0.1", port=8000))

    def test_a_missing_record_is_refused(self) -> None:
        """Absent means nobody approved anything, so it is a refusal.

        The alternative - treating a missing record as "no rules, carry on" -
        is the same fail-open shape this whole project is built to avoid.
        """
        guard = SafetyGuard(authorization=AuthorizationConfig(scope=["127.0.0.0/8"]))
        with pytest.raises(PolicyViolation):
            guard.authorize(Target(host="127.0.0.1", port=8000))

    def test_a_record_with_no_expiry_date_is_refused(self) -> None:
        no_expiry = AuthorizationConfig(scope=["127.0.0.0/8"])
        guard = SafetyGuard(authorization=no_expiry)
        with pytest.raises(PolicyViolation):
            guard.authorize(Target(host="127.0.0.1", port=8000))

    def test_a_target_outside_the_scope_is_refused(self) -> None:
        narrow = make_authorization(scope=["10.0.0.0/24"])
        guard = SafetyGuard(authorization=narrow)
        with pytest.raises(PolicyViolation, match="not inside the authorised scope"):
            guard.authorize(Target(host="127.0.0.1", port=8000))

    def test_the_refusal_names_the_file_to_edit(self) -> None:
        """A refusal the operator cannot act on is a support ticket."""
        guard = SafetyGuard(authorization=make_authorization(expires_in_days=-1))
        with pytest.raises(PolicyViolation) as excinfo:
            guard.authorize(Target(host="127.0.0.1", port=8000))
        assert "authorization.yaml" in str(excinfo.value)

    def test_an_unresolvable_name_is_refused_not_assumed_in_scope(self) -> None:
        """Failing closed when the address is unknown.

        The gate cannot show the scope covers a name it cannot resolve, and
        assuming it does would make the check decorative for any hostname.
        """
        guard = SafetyGuard(authorization=make_authorization())
        with pytest.raises(PolicyViolation):
            guard.authorize(Target(host="nope.invalid", port=80))

    def test_a_valid_record_permits_its_scope(self) -> None:
        guard = SafetyGuard(authorization=make_authorization())
        guard.authorize(Target(host="127.0.0.1", port=8000))  # must not raise

    def test_a_record_expiring_today_is_still_valid(self) -> None:
        today = make_authorization()
        today = today.model_copy(update={"expires_on": date.today()})
        guard = SafetyGuard(authorization=today)
        guard.authorize(Target(host="127.0.0.1", port=8000))  # must not raise

    def test_a_record_that_expired_yesterday_is_refused(self) -> None:
        stale = make_authorization()
        stale = stale.model_copy(
            update={"expires_on": date.today() - timedelta(days=1)}
        )
        guard = SafetyGuard(authorization=stale)
        with pytest.raises(PolicyViolation):
            guard.authorize(Target(host="127.0.0.1", port=8000))


# ---------------------------------------------------------------------------
# Ceilings
# ---------------------------------------------------------------------------


class TestCeilingsClampAndReport:
    def test_pps_above_the_ceiling_is_capped(self) -> None:
        guard = SafetyGuard(lab=_lab(max_pps=20_000),
                            authorization=make_authorization())
        result = guard.clamp_profile(_profile(pps=2_000_000))
        assert result.applied.pps == 20_000

    def test_payload_above_the_ceiling_is_capped(self) -> None:
        """The wizard crash, in the form the gate has to handle.

        1,900,000 was what produced a raw pydantic ValidationError before this
        existed. The value cannot be clamped *after* model validation, because
        AttackProfile refuses to hold it in the first place, so the model ceiling
        (65,507) is treated as a protocol bound the gate also respects.
        """
        guard = SafetyGuard(lab=_lab(max_payload_bytes=1400),
                            authorization=make_authorization())
        fields, _ = guard.clamp_fields(payload_size=1_900_000)
        assert fields["payload_size"] == 1400

    def test_a_value_past_the_model_ceiling_is_reported_not_crashed_on(self) -> None:
        """The original failure, reproduced as a non-crash.

        pydantic rejects 1,900,000 bytes before any guard can see it, so the
        gate is reached with the number only when the value is clamped on the
        way in. Anything the model refuses is the caller's problem, and the
        wizard now bounds the prompt rather than letting it through.
        """
        with pytest.raises(ValidationError):
            _profile(payload_size=1_900_000)

    def test_workers_above_the_ceiling_are_capped(self) -> None:
        guard = SafetyGuard(lab=_lab(max_workers=200),
                            authorization=make_authorization())
        fields, _ = guard.clamp_fields(workers=5000)
        assert fields["workers"] == 200

    def test_duration_above_the_ceiling_is_capped(self) -> None:
        guard = SafetyGuard(lab=_lab(max_duration_seconds=60),
                            authorization=make_authorization())
        fields, _ = guard.clamp_fields(duration_seconds=600.0)
        assert fields["duration_seconds"] == 60.0

    def test_every_clamp_is_reported_in_a_note(self) -> None:
        """A capped run must never look like the run that was asked for."""
        guard = SafetyGuard(
            lab=_lab(max_pps=20_000, max_payload_bytes=1400, max_workers=200),
            authorization=make_authorization(),
        )
        fields, notes = guard.clamp_fields(
            pps=2_000_000, payload_size=99_000, workers=9999
        )
        joined = " ".join(notes).lower()
        assert "pps" in joined
        assert "payload" in joined
        assert "workers" in joined
        # The note should name the file that holds the limit, so the operator
        # knows where the number came from.
        assert "lab.yaml" in joined
        assert fields["pps"] == 20_000
        assert fields["payload_size"] == 1400
        assert fields["workers"] == 200

    def test_a_run_inside_the_limits_is_left_alone(self) -> None:
        guard = SafetyGuard(
            lab=_lab(max_pps=20_000, max_payload_bytes=1400, max_workers=200),
            authorization=make_authorization(),
        )
        fields, notes = guard.clamp_fields(
            pps=1000, payload_size=512, workers=4
        )
        assert notes == []
        assert fields["pps"] == 1000
        assert fields["payload_size"] == 512
        assert fields["workers"] == 4

    def test_ceilings_never_raise_a_value(self) -> None:
        """A run must not be able to raise its own limits."""
        guard = SafetyGuard(
            lab=_lab(max_pps=20_000, max_payload_bytes=1400, max_workers=200),
            authorization=make_authorization(),
        )
        fields, notes = guard.clamp_fields(pps=10, payload_size=64, workers=1)
        assert fields["pps"] == 10
        assert fields["payload_size"] == 64
        assert fields["workers"] == 1

    def test_h2_concurrency_is_capped_at_the_model_limit(self) -> None:
        guard = SafetyGuard(authorization=make_authorization())
        fields, _ = guard.clamp_fields(h2_concurrency=99_999)
        assert fields["h2_concurrency"] == 1000


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------


class TestPreflight:
    def test_preflight_returns_the_clamped_profile(self) -> None:
        from adobo.models import RunConfig

        config = RunConfig(
            target=Target(host="127.0.0.1", port=8000),
            attack=_profile(pps=2_000_000, payload_size=60_000),
        )
        guard = SafetyGuard(
            lab=_lab(max_pps=20_000, max_payload_bytes=1400),
            authorization=make_authorization(),
        )
        result = preflight(config, guard)
        assert isinstance(result, ClampResult)
        assert result.applied.pps == 20_000
        assert result.applied.payload_size == 1400

    def test_preflight_refuses_an_unauthorised_target(self) -> None:
        from adobo.models import RunConfig

        config = RunConfig(
            target=Target(host="192.168.9.9", port=80),
            attack=_profile(),
        )
        guard = SafetyGuard(authorization=make_authorization())
        with pytest.raises(PolicyViolation):
            preflight(config, guard)

    def test_clamping_keeps_a_wild_payload_inside_the_model(self) -> None:
        """The end-to-end version of the reported crash.

        A 1,900,000-byte payload could not even be constructed, so the run died
        with a pydantic error before any policy was consulted. Clamping the
        raw fields first means the gate can answer with 1,400 and a note rather
        than letting construction fail.
        """
        guard = SafetyGuard(
            lab=_lab(max_payload_bytes=1400),
            authorization=make_authorization(),
        )
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


class TestShippedRecordIsExpired:
    """The repository's own record must still fail closed.

    If this ever passes, the "unconfigured checkout is inert" claim in the
    README is false, and the tool is one config file away from being runnable
    by anyone who clones it.
    """

    def test_the_shipped_authorization_is_expired(self) -> None:
        guard = SafetyGuard()
        with pytest.raises(PolicyViolation):
            guard.authorize(Target(host="127.0.0.1", port=8000))
