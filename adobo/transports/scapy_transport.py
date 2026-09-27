"""Raw-socket transport via scapy.

The only module permitted to honour ``spoof_sources``: crafting a source address
is the whole point of a raw socket, and no other transport can do it.

**The capability contract is load-bearing.** ``ddosim.safety`` calls
:func:`raw_capability` before this module is ever imported for sending, and turns
``can_send``/``reason`` into a :class:`~ddosim.safety.PolicyViolation`. Keep the
returned object's two attributes named exactly that; several safety tests
assert on them.

Crafting is separated from sending on purpose. Building packets here works
anywhere, including CI and a Windows box with no Npcap, so packet construction
stays testable. Only :meth:`ScapyTransport.open` needs the privileges.
"""

from __future__ import annotations

import contextlib
import ctypes
import io
import os
import socket
import sys
import warnings
from dataclasses import dataclass
from socket import AF_INET
from typing import Any, ClassVar

from ..models import ProfileName, Target, TransportKind
from .base import Transport, TransportError

__all__ = [
    "RawCapability",
    "ScapyTransport",
    "import_scapy",
    "raw_capability",
    "scapy_available",
]

@dataclass(frozen=True, slots=True)
class RawCapability:
    """Whether raw packets can actually be sent, and why not if they cannot."""

    can_send: bool
    reason: str
    detail: str = ""

    def __bool__(self) -> bool:
        return self.can_send


# --------------------------------------------------------------------------
# Capability probing
# --------------------------------------------------------------------------


@contextlib.contextmanager
def _muted():
    """Swallow scapy's import-time chatter.

    scapy prints "No libpcap provider available" to stderr on import whenever the
    capture driver is missing. That is a normal, fully expected state here - the
    tool detects it properly and reports it itself - so letting it through would
    corrupt the wizard's prompt line.
    """
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer), contextlib.redirect_stdout(buffer):
        yield


def import_scapy() -> Any:
    """Import ``scapy.all`` with its console noise suppressed, or raise."""
    with _muted():
        import scapy.all as scapy
    return scapy


def scapy_available() -> bool:
    """True when the optional ``scapy`` extra is importable."""
    try:
        import_scapy()
    except Exception:
        return False
    return True


def _npcap_present() -> tuple[bool, str]:
    """Look for the Npcap/WinPcap capture driver on Windows.

    The DLL location is checked rather than an scapy import, because scapy
    imports cleanly without a driver and only fails at packet construction -
    far too late, and with a much less actionable message.
    """
    windir = os.environ.get("WINDIR", r"C:\Windows")
    for candidate in (
        os.path.join(windir, "System32", "Npcap", "wpcap.dll"),
        os.path.join(windir, "System32", "wpcap.dll"),
    ):
        if os.path.exists(candidate):
            return True, candidate
    return False, ""


def _is_windows_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):  # pragma: no cover - non-Windows
        return False


def _has_raw_capability_posix() -> bool:
    if not hasattr(os, "geteuid"):
        return False
    if os.geteuid() == 0:
        return True
    # Linux: CAP_NET_RAW may be granted without full root.
    try:
        import ctypes.util

        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        libc = ctypes.CDLL(libc_name, use_errno=True)
        capget = getattr(libc, "capget", None)
        capset = getattr(libc, "capset", None)
        if capget is None or capset is None:
            return False
        return True
    except Exception:  # pragma: no cover - platform dependent
        return False


def raw_capability() -> RawCapability:
    """Report whether this machine can send crafted raw packets.

    Never raises. Every failure mode is described in ``reason`` so the safety
    layer can turn it into a single actionable refusal.
    """
    if not scapy_available():
        return RawCapability(
            can_send=False,
            reason="scapy is not installed",
            detail="Install the optional extra with 'pip install -e .[raw]'.",
        )

    if sys.platform == "win32":
        found, where = _npcap_present()
        if not found:
            return RawCapability(
                can_send=False,
                reason="Npcap is not installed",
                detail="Install Npcap from https://npcap.com and restart the terminal.",
            )
        if not _is_windows_admin():
            return RawCapability(
                can_send=False,
                reason="the terminal is not running as Administrator",
                detail=(
                    f"Raw sockets need elevated rights. Npcap was found at {where}."
                ),
            )
        return RawCapability(can_send=True, reason="available", detail=where)

    if not _has_raw_capability_posix():
        return RawCapability(
            can_send=False,
            reason="the process lacks CAP_NET_RAW",
            detail="Run with sudo, or grant CAP_NET_RAW to the interpreter.",
        )
    return RawCapability(can_send=True, reason="available")


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


def _resolve_iface(scapy: Any, destination: str) -> str:
    """Pick the NIC that reaches *destination*.

    Windows has no "route to 0.0.0.0 means everything" rule, so scapy's default
    interface guess is unreliable: on a multi-homed box (a laptop with Ethernet
    and Wi-Fi, or a VM with a vEthernet adapter) it binds whichever adapter the
    enumeration happened to return first. Packets then leave the wrong NIC and
    never reach the target, which presents as a run that reports zero errors and
    zero delivered packets.

    ``conf.route.route()`` (or legacy ``scapy.route()``) asks the OS routing
    table instead, so the interface is the one the kernel would actually use.
    Resolved once per transport and reused for every packet, because the
    routing table is not consulted per send anyway.
    """
    # Modern scapy exposes the routing table via conf.route.route(); older
    # versions and test mocks expose route() directly on the module.
    route_obj = getattr(getattr(scapy, "conf", None), "route", None)
    if route_obj is not None and hasattr(route_obj, "route"):
        try:
            resolved = route_obj.route(destination)
        except Exception as exc:  # noqa: BLE001 - any failure must be actionable
            raise TransportError(
                f"No route to {destination}, so the interface to send from cannot "
                f"be determined: {exc}. Check the target address and this "
                f"machine's network configuration."
            ) from exc
    elif hasattr(scapy, "route"):
        try:
            resolved = scapy.route(destination)
        except Exception as exc:  # noqa: BLE001 - any failure must be actionable
            raise TransportError(
                f"No route to {destination}, so the interface to send from cannot "
                f"be determined: {exc}. Check the target address and this "
                f"machine's network configuration."
            ) from exc
    else:
        raise TransportError(
            f"scapy routing table not available; cannot determine egress "
            f"interface for {destination}. Check scapy installation."
        )

    iface = resolved and resolved[0]
    if not iface:
        raise TransportError(
            f"No route to {destination}: the OS routing table returned no "
            f"interface for it."
        )
    return str(iface)


class ScapyTransport(Transport):
    """Egress over raw L3/L4 sockets."""

    kind: ClassVar[TransportKind] = TransportKind.SCAPY

    def __init__(
        self,
        target: Target,
        profile: ProfileName,
        *,
        spoof_sources: bool = False,
        seed: int = 0,
    ) -> None:
        super().__init__(target, profile)
        self.spoof_sources = spoof_sources
        self.seed = seed
        self._scapy: Any = None
        self._resolved: str | None = None
        self._iface: str | None = None

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        if self._open:
            return
        capability = raw_capability()
        if not capability.can_send:
            raise TransportError(
                f"Raw packet sending is unavailable: {capability.reason}. "
                f"{capability.detail}"
            )
        try:
            scapy = import_scapy()
        except Exception as exc:  # pragma: no cover - guarded above
            raise TransportError(f"scapy is unusable: {exc}") from exc
        self._scapy = scapy

        try:
            self._resolved = socket.gethostbyname(self.target.host)
        except socket.gaierror as exc:
            raise TransportError(
                f"Cannot resolve target host {self.target.host!r}: {exc}"
            ) from exc

        # Bound to the interface, not guessed per packet. Resolved during open()
        # so an unroutable target is reported as a setup failure rather than as
        # N silent send errors discovered at the end of the run.
        self._iface = _resolve_iface(scapy, self._resolved)
        self._verify_egress(scapy)

        self._open = True

    def _verify_egress(self, scapy: Any) -> None:
        """Prove that a raw packet can actually leave this machine.

        :func:`raw_capability` answers whether the process is *allowed* a raw
        socket and whether the driver is installed. Neither proves the driver
        will accept a write, and the two faults that slip through both present
        identically: zero errors, zero packets, no explanation. An interface
        the routing table names but scapy cannot drive - the "packets leave
        the wrong NIC" case its own docstring warns about - and a driver that
        accepts the call and discards the packet are indistinguishable from a
        healthy machine by any amount of static checking.

        So one packet is actually transmitted. It goes to the same target the
        operator already aimed this run at, and it is deliberately not counted
        in the run's own counters, so the reported totals stay exactly what the
        run itself put on the wire. ``open()`` is never reached for a dry run,
        so this cannot fire when nothing was meant to be sent.
        """
        iface = self._iface
        if iface is None:  # pragma: no cover - open() always sets it first
            raise TransportError("No egress interface was resolved.")

        try:
            known = [str(name) for name in scapy.get_if_list()]
        except Exception as exc:  # noqa: BLE001 - any failure must be actionable
            raise TransportError(
                f"scapy could not enumerate this machine's interfaces, so the "
                f"interface to send from cannot be confirmed: {exc}."
            ) from exc
        if known and iface not in known:
            raise TransportError(
                f"The routing table sends to {iface!r}, but scapy cannot drive "
                f"that interface (it can see: {', '.join(known) or 'none'}). "
                f"Every packet would be dropped before leaving this machine. "
                f"Check the target address and this machine's network setup."
            )

        # Cross-platform check that the interface has an IPv4 address.
        # Modern scapy exposes ifaces via conf.ifaces; legacy uses get_if_addr.
        has_v4 = False
        ifaces = getattr(getattr(scapy, "conf", None), "ifaces", None)
        if ifaces is not None and iface in ifaces:
            try:
                ips = ifaces[iface].ips
                if any("." in ip for ip in ips):  # IPv4 contains a dot
                    has_v4 = True
            except Exception:
                pass
        if not has_v4:
            try:
                from scapy.arch import get_if_addr
                addr = get_if_addr(iface)
                if addr and addr != "0.0.0.0":
                    has_v4 = True
            except Exception:
                pass
        if not has_v4:
            raise TransportError(
                f"Interface {iface!r} has no IPv4 address, so a raw IP packet "
                f"cannot be sourced from it. Pick a target reachable over IPv4, "
                f"or fix this machine's network configuration."
            )

        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=SyntaxWarning, module="scapy")
                scapy.send(self.build_packet(b"ddosim egress probe"), iface=iface, verbose=False)
        except Exception as exc:
            self._count_error()
            raise TransportError(
                f"Raw send failed on {iface!r}: {exc}. The driver is present but "
                f"rejected the packet, so a run would send nothing and report no "
                f"error. Reinstall Npcap, or run this terminal as Administrator."
            ) from exc

    def close(self) -> None:
        # scapy owns its sockets; there is no per-transport handle to release.
        self._scapy = None
        self._resolved = None
        self._iface = None
        self._open = False

    # -- packet construction ----------------------------------------------

    def _source_address(self) -> str:
        """A plausible-looking source address for a spoofed packet.

        Only ever used when the operator has explicitly requested spoofing and
        the safety layer has confirmed raw sending is available.
        """
        if not self.spoof_sources:
            return self._resolved or self.target.host
        octets = self._resolved.split(".") if self._resolved else ["10", "0", "0", "1"]
        return ".".join(
            [octets[0], octets[1], str((int(octets[2]) + 1) % 254 + 1), "1"]
        )

    def build_packet(self, payload: bytes) -> Any:
        """Craft one packet. Requires scapy but not send privileges."""
        if self._scapy is None:
            try:
                self._scapy = import_scapy()
            except Exception as exc:
                raise TransportError(f"scapy is unusable: {exc}") from exc

        scapy = self._scapy
        destination = self._resolved or self.target.host
        source = self._source_address()
        profile = self.profile
        header: dict[str, Any]

        if profile in (ProfileName.SYN_FLOOD, ProfileName.ACK_FLOOD):
            flags = "S" if profile is ProfileName.SYN_FLOOD else "A"
            header = {
                "flags": flags,
                "sport": 1024 + (self.seed % 60000),
                "dport": self.target.port,
            }
            l4 = scapy.TCP(**header)
        elif profile is ProfileName.ICMP_FLOOD:
            header = {"type": 8, "code": 0}
            l4 = scapy.ICMP(**header)
        elif profile in (
            ProfileName.DNS_AMPLIFICATION,
            ProfileName.NTP_AMPLIFICATION,
            ProfileName.CLDAP_AMPLIFICATION,
            ProfileName.SSDP_AMPLIFICATION,
        ):
            # Amplification profiles: use target port, spoof source
            l4 = scapy.UDP(sport=40000 + (self.seed % 20000), dport=self.target.port)
        else:
            l4 = scapy.UDP(sport=40000 + (self.seed % 20000), dport=self.target.port)

        return scapy.IP(src=source, dst=destination) / l4 / payload

    # -- egress ------------------------------------------------------------

    def send_one(self, payload: bytes) -> None:
        if not self._open or self._scapy is None:
            raise TransportError("Transport is not open; call open() before sending")
        if self._iface is None:  # pragma: no cover - open() always sets it
            raise TransportError(
                "No egress interface resolved; call open() before sending"
            )
        self._count_attempt()
        try:
            packet = self.build_packet(payload)
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=SyntaxWarning, module="scapy")
                self._scapy.send(packet, iface=self._iface, verbose=False)
        except Exception as exc:
            self._count_error()
            raise TransportError(f"Raw send failed: {exc}") from exc
        self._count_sent(len(payload))

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["spoof_sources"] = self.spoof_sources
        info["iface"] = self._iface
        capability = raw_capability()
        info["raw_capable"] = capability.can_send
        info["raw_reason"] = capability.reason
        return info
