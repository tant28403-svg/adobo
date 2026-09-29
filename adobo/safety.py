"""Authorisation and policy gate.

Every run passes through :class:`SafetyGuard` before a socket is opened. The
contract it enforces is the one ``config/authorization.yaml`` documents:

    The engine REFUSES to open a socket unless this file is present,
    unexpired, and its scope covers the target.

That contract was previously only written down. ``AttackProfile`` carries a
hard model ceiling (65,507 bytes, from the maximum UDP datagram) which is a
protocol limit, not a policy one; nothing read ``lab.yaml``'s ceilings, and
nothing read the authorisation record at all. So a run could be configured
past every limit the config files claimed, and a raw
``pydantic.ValidationError`` was the only thing standing between the wizard and
a crash.

Two distinct jobs, deliberately kept separate:

* :meth:`SafetyGuard.authorize` **refuses**. It is a gate, and a gate that
  sometimes lets traffic through is not a gate.
* :meth:`SafetyGuard.clamp_profile` **adjusts and reports**. A ceiling is a
  limit, and silently capping a run would make the tool report a number the
  operator did not ask for - the same class of bug as reporting a worker count
  that was never used. Every clamp is returned as a note.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from .config import LabConfig, load_authorization, load_lab_config
from .models import AttackProfile, Target


class PolicyViolation(Exception):
    """A run was refused because policy does not permit it.

    Raised rather than logged-and-continued, because the alternative is a tool
    that documents authorisation and does not perform it.
    """


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
    """Check authorisation, then clamp to the configured ceilings."""

    def __init__(
        self,
        lab: LabConfig | None = None,
        authorization: Any | None = None,
    ) -> None:
        self.lab = lab if lab is not None else load_lab_config()
        # Explicitly passed as None means "load it", so the sentinel has to be
        # distinct: callers that want *no* record pass a value that is not
        # None, and callers that want the default get the file.
        self.authorization = (
            load_authorization() if authorization is None else authorization
        )

    # -- authorisation ----------------------------------------------------

    def authorize(self, target: Target) -> None:
        """Refuse the run unless policy permits sending to *target*.

        Raises :class:`PolicyViolation` with a message that says what to fix,
        because the person hitting it is usually mid-demo and needs the file
        name and the reason, not a stack trace.
        """
        auth = self.authorization
        if auth is None:
            raise PolicyViolation(
                "No authorisation record found. config/authorization.yaml must "
                "exist before this tool will send traffic. It ships expired on "
                "purpose so an unconfigured checkout is inert - set expires_on "
                "to a future date and list the networks you are authorised to "
                "test."
            )

        if auth.is_expired():
            expires = auth.expires_on.isoformat() if auth.expires_on else "unset"
            raise PolicyViolation(
                f"Authorisation expired on {expires}. Update expires_on in "
                "config/authorization.yaml, or the run is refused. This is the "
                "gate working as intended, not a bug to work around."
            )

        if not self._in_authorization_scope(target, auth):
            raise PolicyViolation(
                f"{target.host} is not inside the authorised scope. "
                f"config/authorization.yaml covers "
                f"{', '.join(auth.scope) or '(nothing)'}. Either the target is "
                "wrong or the scope needs updating deliberately - do not widen "
                "it to make an error go away."
            )

    def _in_authorization_scope(self, target: Target, auth: Any) -> bool:
        """True when *target*'s host falls inside the authorisation scope.

        A hostname is resolved before comparison, so a target given by name is
        checked by address rather than waved through. An unresolvable name is
        refused: failing closed is the entire point of this check.
        """
        try:
            address = ipaddress.ip_address(target.host.split("%", 1)[0])
        except ValueError:
            try:
                import socket

                address = ipaddress.ip_address(
                    socket.gethostbyname(target.host.split("%", 1)[0])
                )
            except (OSError, ValueError):
                # Cannot determine what address this name resolves to, so the
                # scope cannot be shown to cover it. Refuse rather than guess.
                return False
        return any(address in network for network in auth.networks())

    # -- ceilings ---------------------------------------------------------

    #: Protocol bounds the model enforces, repeated here so the gate can clamp
    #: to them before the model sees a value it will reject. AttackProfile
    #: refuses anything over 65,507 bytes, and a refusal at construction time
    #: is a raw ValidationError with no mention of the policy ceiling - which is
    #: exactly the crash a 1,900,000-byte payload produced.
    MODEL_CEILINGS = {"payload_size": 65_507, "h2_concurrency": 1000}

    def clamp_fields(
        self, **requested: Any
    ) -> tuple[dict[str, Any], list[str]]:
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

        def _cap(name: str, limit: int, source: str, unit: str = "") -> None:
            value = values.get(name)
            if not isinstance(value, (int, float)) or value <= limit:
                return
            values[name] = limit
            shown = f"{value:,}" if isinstance(value, int) else f"{value:g}"
            cap = f"{limit:,}" if isinstance(limit, int) else f"{limit:g}"
            notes.append(
                f"{name} clamped from {shown} to {cap}{unit} ({source})"
            )

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

        if profile.pps > limits.max_pps:
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
        return (
            f"pps<={limits.max_pps:,} duration<={limits.max_duration_seconds:g}s "
            f"payload<={limits.max_payload_bytes:,}B workers<={limits.max_workers:,}"
        )


def preflight(config: Any, guard: SafetyGuard | None = None) -> ClampResult:
    """Authorise and clamp in one call. Used at the top of a run.

    Returns the profile to actually run. Raises :class:`PolicyViolation` when
    the target is not authorised.
    """
    guard = guard or SafetyGuard()
    guard.authorize(config.target)
    return guard.clamp_profile(config.attack)
