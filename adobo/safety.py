"""Policy ceilings and the network allowlist.

Two jobs, and they are deliberately different ones:

* **Ceilings** - cap the values a run asks for at the limits in
  ``config/lab.yaml``, and report every reduction so a capped run never reads
  like the run that was asked for.
* **The allowlist** - decide which addresses a run may send to at all. That
  judgement and the resolution it depends on live in :mod:`adobo.netpolicy`,
  which every transport calls from ``open()``; what is here is only the
  :class:`PolicyViolation` the refusal is raised as, and the ceiling half.

There is deliberately no authorisation gate here. There was one, backed by
``config/authorization.yaml``, and it required a date and a scope to be edited
before the tool would send a single packet - including against the loopback
lab target shipped in the same repository. That was a setup step standing
between someone and a working demo, on a tool whose whole purpose is
measurement: the authorising step produced no measurement and made the tool
harder to use without making it safer in any way that mattered, since the
target is named by the operator either way.

The allowlist is not that, and reinstating the authorisation record would not
be the same as enforcing it. An authorisation record asks *who* is asking and
makes every run pay for the answer; the allowlist asks *where* traffic may go
and is a default-deny boundary that leaves an unconfigured checkout inert.
A machine pointed at 10.0.0.0/8 is inside its lab and needs no paperwork; a
machine pointed at a name that resolves to 8.8.8.8 is not, and is refused
before a socket opens. Nothing here asks whether the operator is allowed to
name a target inside the allowlist - they are naming it deliberately.

The ceilings stay because they are what keeps a run inside what the machine
can actually measure. A run configured past them is not a stronger test, it is
a run whose numbers no longer describe the thing being tested. They are
enforced, they lower only, and they are never silent.

The legal and ethical position is unchanged and lives in the README: only
target systems you own or have written permission to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import LabConfig, load_lab_config
from .models import AttackProfile, Target


class PolicyViolation(Exception):
    """A run was refused because a configured policy does not permit it."""


@dataclass
class ClampResult:
    """What a ceiling did to a requested profile.

    *applied* is the profile the run should use; *notes* explains every change
    in the operator's own terms, so a clamped run never looks identical to the
    run that was asked for.
    """

    applied: AttackProfile
    notes: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.notes)


class SafetyGuard:
    """Clamp a run to the ceilings in ``config/lab.yaml``.

    Holds the ``LabConfig`` the ceilings come from. The allowlist on the same
    config is enforced by :mod:`adobo.netpolicy`, which needs the config and
    not the guard - it is called from transports that were constructed without
    one.
    """

    def __init__(self, lab: LabConfig | None = None) -> None:
        self.lab = lab if lab is not None else load_lab_config()

    #: Protocol bounds the model enforces, repeated here so the gate can clamp
    #: to them before the model sees a value it will reject. AttackProfile
    #: refuses anything over 65,507 bytes, and a refusal at construction time
    #: is a raw ValidationError with no mention of the policy ceiling - which is
    #: exactly the crash a 1,900,000-byte payload produced.
    MODEL_CEILINGS = {"payload_size": 65_507, "h2_concurrency": 1000}

    def clamp_fields(self, **requested: Any) -> tuple[dict[str, Any], list[str]]:
        """Cap raw requested values, before any model validates them.

        Takes loose values rather than an AttackProfile on purpose. The
        validation order matters: a value the model rejects never reaches a
        clamp applied to a profile, so the only place a ceiling can prevent the
        crash is before construction.

        Returns ``(values, notes)``. *values* holds every key that was passed,
        adjusted where needed, so it can be splatted into AttackProfile.
        """
        limits = self.lab.limits
        values: dict[str, Any] = dict(requested)
        notes: list[str] = []

        def _cap(name: str, limit: Any, source: str, unit: str = "") -> None:
            value = values.get(name)
            # A None limit means "no ceiling configured", so the requested
            # value stands. Throughput is deliberately left uncapped.
            if limit is None or not isinstance(value, (int, float)):
                return
            if value <= limit:
                return
            values[name] = limit
            shown = f"{value:,}" if isinstance(value, int) else f"{value:g}"
            cap = f"{limit:,}" if isinstance(limit, int) else f"{limit:g}"
            notes.append(f"{name} clamped from {shown} to {cap}{unit} ({source})")

        _cap("pps", limits.max_pps, "max_pps in lab.yaml")
        _cap("duration_seconds", limits.max_duration_seconds,
             "max_duration_seconds in lab.yaml", "s")
        _cap("payload_size", limits.max_payload_bytes,
             "max_payload_bytes in lab.yaml", " bytes")
        _cap("workers", limits.max_workers, "max_workers in lab.yaml")
        for name, model_limit in self.MODEL_CEILINGS.items():
            _cap(name, model_limit, "model limit")

        return values, notes

    def clamp_profile(self, profile: AttackProfile) -> ClampResult:
        """Cap an already-built *profile* at the policy ceilings.

        Only ever lowers. Kept for callers that hold a validated profile; new
        code should prefer :meth:`clamp_fields`, which runs before validation
        and can therefore prevent the crash as well as report it.
        """
        limits = self.lab.limits
        notes: list[str] = []
        updates: dict[str, Any] = {}

        # No pps clamp: throughput is not capped, so a run sends what it was
        # asked to send. See LimitsConfig for why.
        if limits.max_pps is not None and profile.pps > limits.max_pps:
            updates["pps"] = limits.max_pps
            notes.append(
                f"pps clamped from {profile.pps:,} to {limits.max_pps:,} "
                f"(max_pps in lab.yaml)"
            )

        if profile.duration_seconds > limits.max_duration_seconds:
            updates["duration_seconds"] = limits.max_duration_seconds
            notes.append(
                f"duration clamped from {profile.duration_seconds:g}s to "
                f"{limits.max_duration_seconds:g}s "
                f"(max_duration_seconds in lab.yaml)"
            )

        if profile.payload_size > limits.max_payload_bytes:
            updates["payload_size"] = limits.max_payload_bytes
            notes.append(
                f"payload clamped from {profile.payload_size:,} to "
                f"{limits.max_payload_bytes:,} bytes "
                f"(max_payload_bytes in lab.yaml)"
            )

        if profile.workers > limits.max_workers:
            updates["workers"] = limits.max_workers
            notes.append(
                f"workers clamped from {profile.workers:,} to "
                f"{limits.max_workers:,} (max_workers in lab.yaml)"
            )

        applied = profile.clamped(**updates) if updates else profile
        return ClampResult(applied=applied, notes=notes)

    def describe_ceilings(self) -> str:
        """A one-line summary, for prompts and refusal messages."""
        limits = self.lab.limits
        pps = "uncapped" if limits.max_pps is None else f"pps<={limits.max_pps:,}"
        return (
            f"{pps} duration<={limits.max_duration_seconds:g}s "
            f"payload<={limits.max_payload_bytes:,}B workers<={limits.max_workers:,}"
        )


def preflight(config: Any, guard: SafetyGuard | None = None) -> ClampResult:
    """Clamp a config to the configured ceilings.

    Returns the profile to actually run. No authorisation step: the target is
    whatever the operator named. It is not checked against ``allowed_cidrs``
    here either - this function only ever lowers values, and the allowlist
    raises rather than adjusts, which is a different kind of decision. The
    engine checks the target in :meth:`~adobo.engine.RunEngine._vet_target`
    and every transport checks it again in ``open()``.
    """
    guard = guard or SafetyGuard()
    return guard.clamp_profile(config.attack)
