"""The `allowed_cidrs` allowlist in ``config/lab.yaml``, enforced.

``config/lab.yaml`` has always described itself as "the only networks this tool
may ever send traffic to", and ``adobo.__doc__`` has always claimed the tool
"cannot target an address that is not written into an allowlist". Neither
sentence described the code: :meth:`~adobo.config.LabConfig.networks` had no
callers anywhere in the package, so the allowlist was a validated list of
strings in a config file and nothing ever compared a target against it. This
module is what makes those two sentences true.

The rule is **default deny**. A target host is resolved and every address it
resolves to is matched against the configured networks; anything outside them is
never contacted. A name that resolves to both an allowed and a disallowed
address is *not* refused outright - the disallowed addresses are dropped and the
run proceeds. The guarantee is that nothing outside the allowlist is ever sent
to, not that a name with one bad DNS record is unusable; refusing there would
break a working target because of an unrelated ``AAAA`` record. The dropped
addresses are reported in the run notes, so a name quietly losing half of them
is visible rather than silent.

A resolution failure is deliberately **not** a refusal. A name that does not
resolve is a broken target, and it is reported as one, by the transport that
needed the address, with the message and the exit path it has always had.
Turning "that hostname does not exist" into "policy denied this run" would
hide the cause behind a wall, and the default allowlist is loopback, so a typo
to a real external name is the most likely way to meet this code at all.

Enforcement happens where the address is *used*, not only where the run starts.
Every transport resolves through :func:`resolve_target` or
:func:`resolve_ipv4` inside its own ``open()``, so what was vetted is what
gets connected to. A check at startup alone would be advisory: the engine
resolved the name once, then handed the *name* to two hundred workers which
each resolved it again, and a name is not an address. Checking at the point of
use is what makes it a boundary.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from functools import lru_cache
from typing import Sequence

from .config import LabConfig, load_lab_config
from .safety import PolicyViolation

__all__ = [
    "AllowlistDecision",
    "checked_addresses",
    "decide",
    "inspect_target",
    "is_ip_literal",
    "resolve_ipv4",
    "resolve_target",
]


@lru_cache(maxsize=1)
def _shipped_lab() -> LabConfig:
    """``config/lab.yaml``, read once per process.

    Cached because this runs per *connection*, not per run: a keep-alive run
    recycles thousands of them, and re-reading and re-validating the same YAML
    each time would put file I/O on the hot path of the send loop. Operators
    edit ``lab.yaml`` between runs, not during one, and a run that started under
    one allowlist should not change its rules halfway through.
    """
    return load_lab_config()


def is_ip_literal(host: str) -> bool:
    """Whether *host* is already an address, so resolving it would accomplish nothing.

    A zone index is tolerated and stripped, so ``fe80::1%eth0`` counts as the
    address it is. :func:`socket.getaddrinfo` accepts a scoped literal on the
    platforms that have them, and rejecting one here would refuse a target the
    transport could have reached.
    """
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class AllowlistDecision:
    """What the allowlist made of one target host.

    *addresses* is everything the host resolved to; *inside* and *outside* split
    it. ``ok`` is true when nothing is outside - which includes the empty
    resolution, so an empty decision never blocks a run on its own and the
    caller can tell an unresolvable name from a permitted one by the address
    count rather than by a separate flag.
    """

    host: str
    addresses: tuple[str, ...]
    inside: tuple[str, ...]
    outside: tuple[str, ...]
    allowed_cidrs: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """True when no resolved address is outside the allowlist.

        Vacuously true for a host that resolved to nothing: see the module
        docstring on why a broken name is not a refusal.
        """
        return not self.outside

    @property
    def permitted(self) -> tuple[str, ...]:
        """The addresses a transport may actually send to, in resolution order."""
        return self.inside

    @property
    def dropped(self) -> bool:
        """True when a host resolved to at least one address outside the allowlist."""
        return bool(self.outside)

    def note(self) -> str | None:
        """One line describing what was dropped, or None when nothing was.

        Surfaces in the run notes so a name resolving partly outside the
        allowlist is visible in the result rather than quietly connecting to
        fewer addresses than the operator would expect.
        """
        if not self.outside:
            return None
        allowed = ", ".join(self.allowed_cidrs)
        return (
            f"target {self.host} resolved to {len(self.addresses)} address(es); "
            f"{', '.join(self.outside)} outside allowed_cidrs [{allowed}] and "
            f"dropped, sending only to {', '.join(self.inside)}"
        )

    def refusal(self) -> str:
        """The operator-facing refusal, naming the fix rather than just the denial."""
        allowed = ", ".join(self.allowed_cidrs)
        blocked = ", ".join(self.outside)
        return (
            f"target {self.host} resolves to {blocked}, which is outside "
            f"allowed_cidrs [{allowed}] in config/lab.yaml.\n"
            f"    Add the network to allowed_cidrs if it is a machine you own or "
            f"have written permission to test."
        )


def decide(
    host: str,
    addresses: Sequence[str],
    lab: LabConfig | None = None,
) -> AllowlistDecision:
    """Match already-resolved *addresses* against the allowlist. No I/O.

    Pure so the policy can be reasoned about and tested without a resolver or a
    config file, and so the same judgement is available to a caller that already
    has the addresses in hand.
    """
    config = lab if lab is not None else _shipped_lab()
    networks = config.networks()
    inside: list[str] = []
    outside: list[str] = []
    for raw in addresses:
        # A resolver hands back a bare address; anything it did not produce as a
        # valid address is treated as outside, because an address the policy
        # cannot parse is an address the policy cannot clear.
        try:
            address = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            outside.append(raw)
            continue
        # A v4 address is never inside a v6 network and vice versa; `in`
        # raises on a mixed comparison on some versions, so match families.
        if any(
            address.version == network.version and address in network
            for network in networks
        ):
            inside.append(raw)
        else:
            outside.append(raw)
    return AllowlistDecision(
        host=host,
        addresses=tuple(addresses),
        inside=tuple(inside),
        outside=tuple(outside),
        allowed_cidrs=tuple(config.allowed_cidrs),
    )


def checked_addresses(
    host: str,
    port: int,
    socktype: int,
    lab: LabConfig | None = None,
) -> tuple[list[socket.AddressInfo], AllowlistDecision]:
    """Resolve *host* and return only the addresses inside the allowlist.

    Returns ``(infos, decision)``. Raises :class:`PolicyViolation` when every
    resolved address is outside it, and :class:`OSError` when the name does not
    resolve - the caller decides how to word that, because a transport turns it
    into a ``TransportError`` about the target and the engine simply does not
    treat it as a policy question.

    An IP literal short-circuits the resolver. That keeps a loopback run - and
    every test in this suite, which is hermetic precisely because it never
    queries DNS - off the resolver entirely, and it cannot produce a different
    answer than asking, since the literal is already the answer.
    """
    if is_ip_literal(host):
        # Checked without the zone index, connected to with it: stripping a scope
        # from the sockaddr would hand the OS an address it cannot route to.
        bare = host.split("%", 1)[0]
        decision = decide(bare, [bare], lab)
        if not decision.ok:
            raise PolicyViolation(decision.refusal())
        family = socket.AF_INET6 if ":" in bare else socket.AF_INET
        info: socket.AddressInfo = (family, socktype, 0, "", (host, port))
        return [info], decision

    # socket.gaierror is an OSError and is deliberately not caught: a name that
    # does not resolve is a broken target, and each transport words that in its
    # own "Cannot resolve target host" TransportError. See the module docstring.
    infos = socket.getaddrinfo(host, port, type=socktype)
    if not infos:
        return [], decide(host, [], lab)

    addresses = [str(entry[4][0]) for entry in infos]
    decision = decide(host, addresses, lab)
    permitted = set(decision.permitted)
    kept = [entry for entry in infos if str(entry[4][0]) in permitted]
    if not kept:
        raise PolicyViolation(decision.refusal())
    return kept, decision


def inspect_target(
    host: str,
    port: int,
    lab: LabConfig | None = None,
) -> AllowlistDecision | None:
    """Resolve *host* and judge it, without deciding whether to send.

    For a caller that wants to *report* the allowlist's verdict rather than
    enforce it - the engine, which refuses early and readable but must not
    stop a run over a name that does not resolve.

    Returns ``None`` when the name cannot be resolved, which is not a verdict:
    that is a broken target, and the transport that needs the address reports it
    with the message it has always used. Returning a decision here would let a
    caller treat "we could not look" as "we looked and said no".

    Shares the literal short-circuit with :func:`checked_addresses` so both
    agree on what a host resolves to - a report and an enforcement that disagree
    about the same name would be worse than either being absent.
    """
    if is_ip_literal(host):
        bare = host.split("%", 1)[0]
        return decide(bare, [bare], lab)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    if not infos:
        return None
    return decide(host, [str(entry[4][0]) for entry in infos], lab)


def resolve_target(
    host: str,
    port: int,
    socktype: int,
    lab: LabConfig | None = None,
) -> tuple[list[socket.AddressInfo], AllowlistDecision]:
    """The single resolution path for a stream or datagram transport.

    Named to be called from ``open()`` and nowhere else. A transport that
    resolves a name by any other route has opted out of the allowlist without
    saying so, and that is the one mistake this module exists to prevent.
    """
    return checked_addresses(host, port, socktype, lab)


def resolve_ipv4(host: str, lab: LabConfig | None = None) -> str:
    """Resolve *host* to one IPv4 address inside the allowlist.

    For the raw-socket transports, which build a layer-3 header and need a
    dotted quad rather than an addrinfo. Both address families are resolved and
    checked even though only IPv4 can be returned, because a transport that
    could only ever send to ``127.0.0.0/8`` should not pass a check that never
    looked at the other records for the name.

    Raises :class:`PolicyViolation` when nothing permitted is an IPv4 address,
    and :class:`OSError` when the name does not resolve.
    """
    # port is unused by both callers and has no effect on the answer; 0 keeps the
    # signature honest with getaddrinfo rather than implying a service is named.
    infos, decision = checked_addresses(host, 0, socket.SOCK_DGRAM, lab)
    for entry in infos:
        if entry[0] == socket.AF_INET:
            return str(entry[4][0])
    raise OSError(
        f"target {host!r} resolved to {', '.join(decision.addresses)}, which are "
        f"inside allowed_cidrs [{', '.join(decision.allowed_cidrs)}], but none of "
        f"them is an IPv4 address and a raw packet needs one"
    )