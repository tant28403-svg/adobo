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

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .fingerprint import (
    DEFAULT_FINGERPRINT_KEY,
    FINGERPRINTS,
    fingerprint as resolve_persona,
    resolve_rotation,
    rotate as rotate_personas,
)
from .h2profile import (
    H2Profile,
    h2_profile as resolve_h2_profile,
    h2_profile_for_persona,
)

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

    PROXY = "proxy"
    """HTTP flood tunnelled through a rotating pool of HTTP proxies.

    Per connection, because a tunnel belongs to a connection. TCP profiles
    only: a UDP datagram has no connection to carry a tunnel, and a raw packet
    cannot be redirected through an HTTP proxy at all.
    """


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

    fingerprint: str = Field(default=DEFAULT_FINGERPRINT_KEY)
    """Which declared client identity to send. See :mod:`adobo.fingerprint`.

    A comma-separated list, following the convention ``--defenses`` already uses
    on this CLI. One key means one identity; several means the run rotates
    through them according to :attr:`fingerprint_rotation`.

    Defaults to the self-identifying lab client, and validated below so a typo
    fails here - with the list of valid keys - rather than silently falling back
    to the honest identity and producing a run that does not impersonate
    anything while appearing to.
    """

    fingerprint_rotation: str = Field(default="per_connection")
    """When to change persona: ``none``, ``per_request`` or ``per_connection``.

    ``per_connection`` is the default because a persona belongs to a connection.
    A real browser does not change its User-Agent partway through a keep-alive
    session, and one that did would be trivially wrong in a way that costs
    delivery without buying realism.
    """

    @field_validator("fingerprint")
    @classmethod
    def _fingerprint_must_exist(cls, value: str) -> str:
        keys = [part.strip() for part in value.split(",") if part.strip()]
        if not keys:
            raise ValueError(
                "fingerprint must name at least one persona; "
                f"valid keys are: {', '.join(FINGERPRINTS)}"
            )
        unknown = [key for key in keys if key not in FINGERPRINTS]
        if unknown:
            raise ValueError(
                f"unknown fingerprint {unknown[0]!r}; choose from: "
                + ", ".join(FINGERPRINTS)
            )
        return ",".join(keys)

    @field_validator("fingerprint_rotation")
    @classmethod
    def _rotation_mode_must_exist(cls, value: str) -> str:
        resolve_rotation(value)  # raises ValueError listing the valid modes
        return value

    h2_preamble: str = Field(default="auto")
    """Which HTTP/2 connection preamble to send, or ``auto`` to follow the persona.

    A persona describes the request; this describes the connection the request
    travels on. See :mod:`adobo.h2profile`.

    ``auto`` is the default and resolves to the preamble matching
    :attr:`fingerprint` when a persona is configured, and to *no change at all*
    when it is not. The second half is the important one: a run with no persona
    emits byte-for-byte what it emitted before preambles existed, and an
    impersonating run does not accidentally pair a Chrome User-Agent with a
    preamble no Chrome sends.

    Set to ``none`` to force the untouched default even when impersonating, which
    is occasionally useful for testing a detector that keys on the connection
    layer alone.
    """

    @field_validator("h2_preamble")
    @classmethod
    def _h2_preamble_must_exist(cls, value: str) -> str:
        # ``none`` is a key too, in the sense that it is a choice: "leave the
        # preamble alone". Listed separately because it is not a profile name and
        # must not appear in the "choose from" list, which lists profiles.
        if value in ("auto", "none"):
            return value
        resolve_h2_profile(value)  # raises ValueError listing the valid keys
        return value

    def persona_keys(self) -> list[str]:
        """The configured personas, in the order given."""
        return [part.strip() for part in self.fingerprint.split(",") if part.strip()]

    def impersonates(self) -> bool:
        """Whether this run presents traffic as something it is not."""
        return any(key != DEFAULT_FINGERPRINT_KEY for key in self.persona_keys())

    def persona(self, *, seed: int | None = None):
        """Resolve the persona to use, or ``None`` for the honest lab client.

        ``None`` means "send no impersonation", which is what
        ``build_payload`` expects: it reproduces the original header block byte
        for byte rather than approximating it.

        *seed* selects among the configured personas and must be supplied for
        the rotating modes. With one persona configured, every mode resolves to
        that persona - a single-entry rotation is not a rotation, and treating
        it as one would make a run nondeterministic for no benefit.

        Args:
            seed: What to vary on. ``per_request`` varies on the packet
                sequence; ``per_connection`` varies on the connection count,
                because a persona is a property of a connection.
        """
        keys = self.persona_keys()
        if not keys or keys == [DEFAULT_FINGERPRINT_KEY]:
            return None
        if len(keys) == 1 or self.fingerprint_rotation == "none":
            return resolve_persona(keys[0])
        # No seed means the caller wants the stable persona, which is what the
        # report and the transport's connection setup ask for.
        if seed is None:
            return resolve_persona(keys[0])
        return rotate_personas(keys, seed)

    def h2_profile(self) -> H2Profile | None:
        """Resolve the HTTP/2 connection preamble, or ``None`` to leave it alone.

        ``None`` is the meaningful answer, not a failure. It is what a run with no
        persona gets, and it means the transport touches nothing about the
        connection preamble so the bytes are unchanged.

        Only meaningful for HTTP/2. Other transports have no SETTINGS frame to
        change, so asking for a preamble with them is a configuration error
        rather than a no-op - see ``--h2-preamble`` validation.
        """
        if self.h2_preamble == "auto":
            persona = self.persona()
            if persona is None:
                return None
            return h2_profile_for_persona(persona.key)
        if self.h2_preamble == "none":
            return None
        return resolve_h2_profile(self.h2_preamble)

    def h2_preamble_incomplete_because(self) -> str | None:
        """Why this run's preamble is not a complete reproduction, if it is not.

        Returns ``None`` when the resolved preamble reproduces everything it
        claims. Surfaced by the report and by ``--inspect-h2`` so that a run which
        reproduces a browser's settings and its window but not its priority tree
        says which of the three it managed, rather than leaving the reader to
        assume all three.
        """
        profile = self.h2_profile()
        return profile.incomplete_because if profile else None

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
    proxy_file: str = ""
    """Path to a proxy list, for TransportKind.PROXY.

    Lives on the run config rather than the attack profile because it describes
    where egress goes, alongside ``transport``, rather than how hard the run
    pushes. Empty means no proxies, which keeps every existing call site that
    builds a RunConfig unchanged.
    """


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

    def impersonation_summary(self) -> dict[str, Any] | None:
        """What identity the run presented, or ``None`` for the honest lab client.

        Recorded in the JSON report as data rather than only as prose in ``notes``,
        so two saved runs can be compared without re-reading their text. ``None``
        and an empty dict are different answers - "presented as itself" is not the
        same claim as "presented as something else, and here is what".

        Includes the HTTP/2 preamble, because impersonation here spans two layers:
        a persona changes the request headers and, for HTTP/2, the connection
        preamble as well. Reporting only the headers would understate what was
        faked on exactly the runs where it matters most.
        """
        if not self.config.attack.impersonates():
            return None
        attack = self.config.attack
        preamble = attack.h2_profile()
        return {
            "personas": [
                key for key in attack.persona_keys()
                if key != DEFAULT_FINGERPRINT_KEY
            ],
            "rotation": attack.fingerprint_rotation,
            "h2_preamble": preamble.key if preamble else None,
            "h2_fingerprint": preamble.fingerprint() if preamble else None,
            "h2_incomplete_because": preamble.incomplete_because if preamble else None,
        }

    def to_json_dict(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        # The identity a run presented is a property of the result, not of the
        # config it was asked for - a rotating run has many personas and the
        # config only names the set. Computed here so a saved report records what
        # was actually sent rather than what was requested.
        data["impersonation"] = self.impersonation_summary()
        return data
