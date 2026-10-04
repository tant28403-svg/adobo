"""Socket-free transport.

Counts exactly what it is told to and sends nothing. This is what makes the
engine testable: a full run - workers, sampler, probes, scoring, reporting -
executes end to end in CI with no network, no privileges and no flakiness, and
the achieved numbers are exactly the requested numbers, so counter plumbing can
be asserted precisely.

It is also the honest mode for a dry run: ``--transport virtual`` is a real
option, not only a testing hook.
"""

from __future__ import annotations

from typing import ClassVar

from ..models import ProfileName, Target, TransportKind
from .base import Transport

__all__ = ["VirtualTransport"]


class VirtualTransport(Transport):
    """A transport that produces no packets."""

    kind: ClassVar[TransportKind] = TransportKind.VIRTUAL

    # Nothing is ever sent toward ``target``, so there is no address to check
    # against ``allowed_cidrs``. Opting out here is what keeps this transport
    # usable as the CI and dry-run mode: requiring it to resolve the target
    # would mean a run that puts no packets on the wire could still fail on a
    # hostname that does not resolve, which is a failure with no cause behind it.
    contacts_target: ClassVar[bool] = False

    def __init__(self, target: Target, profile: ProfileName) -> None:
        super().__init__(target, profile)

    def send_one(self, payload: bytes) -> None:
        self._count_attempt()
        self._count_sent(len(payload))

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["network"] = "none (counter-only)"
        return info
