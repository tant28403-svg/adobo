"""Domain models shared across the simulator.

Everything that crosses a module boundary is a typed model, so a run's
configuration, its live counters, and its final verdict all stay inspectable,
serialisable and unit-testable without opening a socket.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------


class TransportKind(str, Enum):
    """How packets leave the process."""

    SOCKET = "socket"
    """Portable default. Standard UDP/TCP sockets, no elevated rights."""

    SCAPY = "scapy"
    """Raw L3/L4 crafting via scapy. Construction is free; sending needs Npcap + Admin."""

    LINUX_RAW = "linux_raw"
    """Linux raw sockets (AF_INET SOCK_RAW). Requires CAP_NET_RAW or root.
    Non-spoofed, real source IP. Linux only, most reliable raw path.
    """

    VIRTUAL = "virtual"
    """No sockets at all. Counter-only, for hermetic tests and CI."""

    H2 = "h2"
    """HTTP/2 over TLS with multiplexed streams. Requires h2 library."""


class ProfileName(str, Enum):
    """Traffic profiles the engine knows how to generate.

    Non-spoofed variants (suffix ``_NS``) use the real source IP and work
    without elevated privileges on Linux. Spoofed variants require raw socket
    privileges and are intended for controlled reflection testing only.
    """

    UDP_FLOOD = "udp_flood"
    UDP_FLOOD_NS = "udp_flood_ns"
    SYN_FLOOD = "syn_flood"
    SYN_FLOOD_NS = "syn_flood_ns"
    ICMP_FLOOD = "icmp_flood"
    ICMP_FLOOD_NS = "icmp_flood_ns"
    ACK_FLOOD = "ack_flood"
    ACK_FLOOD_NS = "ack_flood_ns"
    DNS_AMPLIFICATION = "dns_amplification"
    NTP_AMPLIFICATION = "ntp_amplification"
    CLDAP_AMPLIFICATION = "cldap_amplification"
    SSDP_AMPLIFICATION = "ssdp_amplification"
    HTTP_FLOOD = "http_flood"
    SLOWLORIS = "slowloris"


class DefenseName(str, Enum):
    """Mitigations the target can be configured to enable."""

    NONE = "none"
    RATE_LIMIT = "rate_limit"
    CONNECTION_CAP = "connection_cap"
    WAF = "waf"
    CIRCUIT_BREAKER = "circuit_breaker"
    CHALLENGE_PAGE = "challenge_page"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Configuration models
# --------------------------------------------------------------------------


class Target(BaseModel):
    """A destination the engine is permitted to send traffic to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str = Field(min_length=1)
    port: int = Field(default=8000, ge=1, le=65535)

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.host}:{self.port}"


class AttackProfile(BaseModel):
    """User-tunable parameters for a single traffic scenario.

    These are the *requested* values. The safety layer may clamp them down to
    policy ceilings before the run starts; it never raises them.
    """

    model_config = ConfigDict(extra="forbid")

    profile: ProfileName
    pps: int = Field(default=2000, gt=0)
    duration_seconds: float = Field(default=10.0, gt=0)
    payload_size: int = Field(default=512, ge=0, le=65507)
    workers: int = Field(default=4, ge=1)
    spoof_sources: bool = False
    keep_alive: bool = False
    use_tls: bool = False
    tls_verify: bool = True
    use_http2: bool = False
    h2_concurrency: int = Field(default=100, ge=1, le=1000)

    def clamped(self, **overrides: Any) -> "AttackProfile":
        """Return a copy with fields replaced. Used by the safety layer."""
        return self.model_copy(update=overrides, deep=True)


class RunConfig(BaseModel):
    """A fully-resolved scenario, ready to execute."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(default_factory=new_run_id)
    lab_id: str = "default"
    target: Target
    attack: AttackProfile
    transport: TransportKind = TransportKind.SOCKET
    defenses: list[DefenseName] = Field(default_factory=list)
    dry_run: bool = False
    label: str = ""


# --------------------------------------------------------------------------
# Observation models
# --------------------------------------------------------------------------


class CounterSample(BaseModel):
    """One-second snapshot of what the attack side achieved."""

    model_config = ConfigDict(extra="forbid")

    t: float = Field(ge=0, description="Seconds since run start")
    attempted_pps: float = Field(ge=0)
    sent_pps: float = Field(ge=0)
    packets_sent: int = Field(ge=0)
    bytes_sent: int = Field(ge=0)
    errors: int = Field(ge=0)
    active_workers: int = Field(ge=0)


class ResourceSample(BaseModel):
    """One-second snapshot of the target process's resource usage."""

    model_config = ConfigDict(extra="forbid")

    t: float = Field(ge=0)
    cpu_percent: float = Field(default=0.0, ge=0)
    rss_mb: float = Field(default=0.0, ge=0)
    threads: int = Field(default=0, ge=0)
    open_sockets: int = Field(default=0, ge=0)
    handles: int = Field(default=0, ge=0)


class ProbeResult(BaseModel):
    """A single synthetic availability/latency probe against the target."""

    model_config = ConfigDict(extra="forbid")

    t: float = Field(ge=0)
    ok: bool
    status_code: int | None = None
    latency_ms: float | None = None
    error: str | None = None


class Percentiles(BaseModel):
    """Latency distribution summary."""

    model_config = ConfigDict(extra="forbid")

    count: int = Field(default=0, ge=0)
    mean_ms: float = 0.0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    max_ms: float = 0.0


# --------------------------------------------------------------------------
# Aggregate results
# --------------------------------------------------------------------------


class AttackStats(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transport: TransportKind
    dry_run: bool
    packets_attempted: int = 0
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    duration_actual_s: float = 0.0
    achieved_pps: float = 0.0
    spoofed_sources: bool = False

    amplification_factor: float | None = None
    """MEASURED response bytes per request byte. None when not measurable.

    Only ever set from observed counters. It is None for most amplification
    runs, because a forged source address means the reflector's reply goes to
    the victim and can never be seen from here. Do not populate it from a
    published ratio - that is what ``amplification_declared`` is for.
    """

    amplification_declared: float | None = None
    """The protocol's nominal ratio, a published constant and not a result.

    Kept separate from :attr:`amplification_factor` so a reader is never shown
    an estimate in a column headed like a measurement. Reports render it with
    an 'est' marker.
    """

    def amplification_display(self) -> str:
        """How the factor should be shown, or '-' when there is nothing to show.

        Prefers the measured value. Falls back to the declared one only when
        labelled, so an unmeasured run reads ``est 200.0x`` rather than a bare
        ``200.0x`` that reads as a result.
        """
        if self.amplification_factor is not None:
            return f"{self.amplification_factor:.1f}x"
        if self.amplification_declared is not None:
            return f"est {self.amplification_declared:.0f}x"
        return "-"


class TargetStats(BaseModel):
    """What the TARGET observed, as opposed to what the sender tried.

    The psutil fields are local-process measurements, so against a remote host
    they are necessarily empty - see ``adobo.monitor`` on why guessing them
    would be worse than omitting them. The request fields below are the remote
    case: they are read from the target's own ``/stats`` endpoint over HTTP, so
    they work regardless of where the target runs.

    Having both in one model is deliberate. ``requests_served`` is the only
    number in the whole result that is evidence of delivery, and it is measured
    on the far side rather than inferred from the sender's own counters.
    """

    model_config = ConfigDict(extra="forbid")

    cpu_percent_mean: float = 0.0
    cpu_percent_p95: float = 0.0
    cpu_percent_max: float = 0.0
    rss_mb_max: float = 0.0
    peak_threads: int = 0
    peak_sockets: int = 0
    peak_handles: int = 0
    sample_count: int = 0

    requests_served: int = 0
    """Requests the target counted during the run window. 0 if not observed."""

    errors_served: int = 0
    """Requests the target rejected or failed during the window."""

    stats_observed: bool = False
    """Whether ``/stats`` was actually read.

    Distinguishes "the target served nothing" from "we never asked". Without it
    a 0 here is indistinguishable from an unmeasured run, which is the exact
    confusion that makes a failing tool look like a healthy target.
    """

    stats_error: str | None = None
    """Why ``/stats`` could not be read, if it could not be."""

    # Note: no ``delivery_ratio`` helper lives here on purpose. Served-requests
    # over packets-handed-to-OS is only meaningful for a protocol the target
    # counts as requests; for a UDP or raw flood the target's HTTP handler never
    # sees the traffic, so the ratio would compare two unrelated quantities. That
    # condition depends on the transport, which this model does not carry, so a
    # method here could only be wrong by default. The comparison is made at the
    # point that knows the transport - see the nuclear final table, which prints
    # the caveat next to the number for the same reason.


class ProbeSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    availability_pct: float = 0.0
    latency: Percentiles = Field(default_factory=Percentiles)
    error_breakdown: dict[str, int] = Field(default_factory=dict)


class ResilienceScore(BaseModel):
    """A 0-100 verdict, broken into its weighted components.

    The weighting encodes the assumption that *staying reachable* matters more
    than being fast, and that graceful saturation is better than collapse.
    """

    model_config = ConfigDict(extra="forbid")

    total: float = 0.0
    grade: str = "N/A"
    availability: float = 0.0
    latency: float = 0.0
    error_rate: float = 0.0
    headroom: float = 0.0
    weights: dict[str, float] = Field(default_factory=dict)

    def as_breakdown(self) -> dict[str, float]:
        return {
            "availability": self.availability,
            "latency": self.latency,
            "error_rate": self.error_rate,
            "headroom": self.headroom,
        }


class RunResult(BaseModel):
    """The complete, serialisable outcome of one scenario."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    lab_id: str = "default"
    label: str = ""
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime = Field(default_factory=utcnow)
    config: RunConfig
    defenses: list[DefenseName] = Field(default_factory=list)
    attack: AttackStats = Field(default_factory=lambda: AttackStats(
        transport=TransportKind.VIRTUAL, dry_run=False
    ))
    target_stats: TargetStats = Field(default_factory=TargetStats)
    probe: ProbeSummary = Field(default_factory=ProbeSummary)
    score: ResilienceScore = Field(default_factory=ResilienceScore)
    counter_samples: list[CounterSample] = Field(default_factory=list)
    resource_samples: list[ResourceSample] = Field(default_factory=list)
    probes: list[ProbeResult] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def duration_actual_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
