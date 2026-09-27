"""Transport selection.

One entry point, :func:`get_transport`, so nothing else in the codebase needs to
know which implementations exist. The factory re-checks the same conditions
``ddosim.safety`` already enforces: it is a second, independent gate rather than
a place where policy can be bypassed by importing a transport class directly.
A caller that skipped preflight still cannot obtain a transport that would send
raw packets or spoof a source address on an unauthorised target.
"""

from __future__ import annotations

import sys

from ..models import ProfileName, RunConfig, TransportKind
from .base import (
    SOCKET_CAPABLE_PROFILES,
    PeerUnavailable,
    Transport,
    TransportCounters,
    TransportError,
    build_payload,
    supports_profile,
)
from .scapy_transport import (
    RawCapability,
    ScapyTransport,
    import_scapy,
    raw_capability,
    scapy_available,
)
from .socket_transport import SocketTransport
from .slowloris_transport import SlowlorisTransport
from .virtual_transport import VirtualTransport

__all__ = [
    "PeerUnavailable",
    "RawCapability",
    "SOCKET_CAPABLE_PROFILES",
    "ScapyTransport",
    "SlowlorisTransport",
    "SocketTransport",
    "Transport",
    "TransportCounters",
    "TransportError",
    "VirtualTransport",
    "available_transports",
    "build_payload",
    "get_transport",
    "import_scapy",
    "linux_raw_capability",
    "raw_capability",
    "scapy_available",
    "supports_profile",
]


def linux_raw_capability() -> RawCapability:
    """Report whether this Linux machine can send raw packets via AF_INET SOCK_RAW.

    Requires either root (uid 0) or the CAP_NET_RAW capability.
    Never raises; every failure mode is described in ``reason``.
    """
    if sys.platform != "linux":
        return RawCapability(
            can_send=False,
            reason="Linux raw sockets are only available on Linux",
            detail="Use scapy transport on Windows/macOS, or run on Linux.",
        )

    # Root can always send raw
    if hasattr(sys, "geteuid") and sys.geteuid() == 0:
        return RawCapability(can_send=True, reason="running as root")

    # Check for CAP_NET_RAW via libcap
    try:
        import ctypes
        import ctypes.util

        # Capability constants
        CAP_NET_RAW = 13  # from linux/capability.h
        _LINUX_CAPABILITY_VERSION_3 = 0x20080522

        class __user_cap_header_struct(ctypes.Structure):
            _fields_ = [
                ("version", ctypes.c_uint32),
                ("pid", ctypes.c_int),
            ]

        class __user_cap_data_struct(ctypes.Structure):
            _fields_ = [
                ("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32),
            ]

        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        libc = ctypes.CDLL(libc_name, use_errno=True)

        capget = libc.capget
        capget.argtypes = [
            ctypes.POINTER(__user_cap_header_struct),
            ctypes.POINTER(__user_cap_data_struct),
        ]
        capget.restype = ctypes.c_int

        header = __user_cap_header_struct(_LINUX_CAPABILITY_VERSION_3, 0)
        data = __user_cap_data_struct()

        if capget(ctypes.byref(header), ctypes.byref(data)) == 0:
            # Check if CAP_NET_RAW is in permitted set
            if data.permitted & (1 << 13):  # CAP_NET_RAW = 13
                return RawCapability(
                    can_send=True,
                    reason="CAP_NET_RAW capability granted",
                )

        return RawCapability(
            can_send=False,
            reason="CAP_NET_RAW capability not granted",
            detail="Run with --cap-add=NET_RAW or as root.",
        )
    except Exception:
        return RawCapability(
            can_send=False,
            reason="Could not determine CAP_NET_RAW status",
            detail="Ensure libcap is installed and try again.",
        )


def get_transport(config: RunConfig) -> Transport:
    """Construct the transport named by *config*.

    Construction never opens a socket, so this is safe to call before a run
    starts and safe to call in tests. Capabilities that would require privileges
    are checked here so the failure appears at setup rather than after the
    workers have spun up.
    """
    profile = config.attack.profile

    if not supports_profile(config.transport, profile):
        raise TransportError(
            f"The {config.transport.value!r} transport cannot generate a "
            f"{profile.value!r} profile. Use --transport scapy, or choose one of: "
            + ", ".join(sorted(p.value for p in SOCKET_CAPABLE_PROFILES))
        )

    if config.transport is TransportKind.VIRTUAL:
        return VirtualTransport(config.target, profile)

    if config.transport is TransportKind.SOCKET:
        if profile is ProfileName.SLOWLORIS:
            return SlowlorisTransport(config.target, profile)
        return SocketTransport(config.target, profile)

    if config.transport is TransportKind.LINUX_RAW:
        # Import locally to avoid circular imports
        from .linux_raw_transport import LinuxRawTransport

        capability = linux_raw_capability()
        if not capability.can_send:
            raise TransportError(
                f"Linux raw sockets unavailable: {capability.reason}. "
                f"{capability.detail}"
            )
        return LinuxRawTransport(
            config.target, profile, spoof_sources=config.attack.spoof_sources,
            payload_size=config.attack.payload_size
        )

    if config.transport is TransportKind.SCAPY:
        if config.dry_run:
            # A dry run must not depend on this machine having Npcap, or preview
            # would be impossible on a laptop. Crafting alone is enough.
            return ScapyTransport(
                config.target, profile, spoof_sources=config.attack.spoof_sources
            )
        if config.attack.spoof_sources:
            capability = raw_capability()
            if not capability.can_send:
                raise TransportError(
                    "Source spoofing was requested but raw sending is "
                    f"unavailable: {capability.reason}. {capability.detail}"
                )
        return ScapyTransport(
            config.target, profile, spoof_sources=config.attack.spoof_sources
        )

    raise TransportError(f"Unknown transport {config.transport!r}")


def available_transports() -> dict[str, str]:
    """Transport name to a human-readable availability note.

    Used by ``ddosim doctor`` so the operator can see what this machine can do
    before being asked to pick.
    """
    capability = raw_capability()
    scapy_note = capability.reason if not capability.can_send else "available"
    linux_raw_cap = linux_raw_capability()
    linux_raw_note = linux_raw_cap.reason if not linux_raw_cap.can_send else "available"
    return {
        TransportKind.VIRTUAL.value: "always available (no sockets opened)",
        TransportKind.SOCKET.value: "available (standard UDP/TCP sockets)",
        TransportKind.SCAPY.value: scapy_note,
        TransportKind.LINUX_RAW.value: linux_raw_note,
    }
