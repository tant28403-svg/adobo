"""Mitigations the lab target can switch on.

Each mitigation is a small, standalone, testable object. None of them know about
HTTP; :mod:`ddosim.target.app` adapts them to requests. That split is what makes
them verifiable: a rate limiter can be tested against a fake clock instead of by
sending thousands of packets at a real socket.

The classes here are the *defensive* side of the tool. They exist so a run can
measure the difference between a target that collapses and one that sheds load
gracefully - the comparison is the entire point of the exercise.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import project_path, waf_config_path
from .models import DefenseName

__all__ = [
    "CircuitBreaker",
    "ChallengeGate",
    "ConnectionCap",
    "Decision",
    "RateLimiter",
    "RequestFacts",
    "RuleMatch",
    "Verdict",
    "WafEngine",
    "WafRule",
    "WafRules",
    "load_waf_rules",
    "mitigation_for",
]


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------


class Decision(str, Enum):
    """What a mitigation decided to do with a request."""

    ALLOW = "allow"
    CHALLENGE = "challenge"
    BLOCK = "block"


class Verdict(BaseModel):
    """The outcome of evaluating every enabled mitigation against a request."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision = Decision.ALLOW
    rule_id: str = ""
    reason: str = ""
    score: int = 0
    mitigation: DefenseName | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def status_code(self) -> int:
        return {
            Decision.ALLOW: 200,
            Decision.CHALLENGE: 503,
            Decision.BLOCK: 403,
        }[self.decision]


def allow() -> Verdict:
    return Verdict(decision=Decision.ALLOW)


# --------------------------------------------------------------------------
# Request facts
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestFacts:
    """The shape of a request, reduced to what mitigations care about."""

    path: str = "/"
    method: str = "GET"
    user_agent: str | None = None
    client: str = "unknown"
    headers: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------


class RateLimiter:
    """Token bucket per client.

    Refilling per-bucket rather than keeping one global counter is the point:
    the whole behaviour under test is that a flood from one address must not
    degrade service for everyone else.
    """

    def __init__(
        self,
        rate_per_second: float = 50.0,
        burst: int = 100,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.rate = rate_per_second
        self.burst = max(1, burst)
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, client: str) -> bool:
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(client, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._buckets[client] = (tokens, now)
                return False
            self._buckets[client] = (tokens - 1.0, now)
            return True

    def tokens(self, client: str) -> float:
        with self._lock:
            tokens, _ = self._buckets.get(client, (float(self.burst), 0.0))
            return round(tokens, 2)

    def reset(self, client: str | None = None) -> None:
        with self._lock:
            if client is None:
                self._buckets.clear()
            else:
                self._buckets.pop(client, None)


# --------------------------------------------------------------------------
# Connection cap
# --------------------------------------------------------------------------


class ConnectionCap:
    """Bound the number of requests in flight simultaneously.

    Without this a threaded server will happily accept far more concurrent work
    than it can serve, queueing it all and driving latency up for everybody. With
    it, excess load is shed immediately, which is what "graceful degradation"
    looks like from the outside.
    """

    def __init__(self, limit: int = 64) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        self.limit = limit
        self._lock = threading.Lock()
        self._in_flight = 0
        self.peak = 0
        self.rejected = 0

    def acquire(self) -> bool:
        with self._lock:
            if self._in_flight >= self.limit:
                self.rejected += 1
                return False
            self._in_flight += 1
            self.peak = max(self.peak, self._in_flight)
            return True

    def release(self) -> None:
        with self._lock:
            if self._in_flight > 0:
                self._in_flight -= 1

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, *exc: object) -> None:
        self.release()


# --------------------------------------------------------------------------
# Circuit breaker
# --------------------------------------------------------------------------


class CircuitBreaker:
    """Trip after consecutive upstream failures, then stay open for a cooldown.

    Holding the breaker open briefly stops a struggling dependency being hammered
    while it is already unhealthy, which is the difference between a service that
    recovers in seconds and one that never does.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 5.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        self.failure_threshold = failure_threshold
        self.cooldown = cooldown_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self.trips = 0

    @property
    def is_open(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return False
            if self._clock() - self._opened_at >= self.cooldown:
                # Cooldown elapsed: half-open, let the next request probe.
                self._opened_at = None
                self._consecutive_failures = 0
                return False
            return True

    def allow(self) -> bool:
        return not self.is_open

    def record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if (
                self._consecutive_failures >= self.failure_threshold
                and self._opened_at is None
            ):
                self._opened_at = self._clock()
                self.trips += 1

    @property
    def state(self) -> str:
        with self._lock:
            if self._opened_at is None:
                return "closed"
            if self._clock() - self._opened_at >= self.cooldown:
                return "half-open"
            return "open"


# --------------------------------------------------------------------------
# Challenge gate
# --------------------------------------------------------------------------


class ChallengeGate:
    """Track per-client suspicion and demand a challenge past a threshold.

    Stands in for the JS challenge / CAPTCHA step a real edge product would use.
    The point is the response *behaviour*: a 503 that the client can solve, rather
    than a silent drop, so legitimate users get through.
    """

    def __init__(self, threshold: int = 5, decay_seconds: float = 30.0) -> None:
        self.threshold = max(1, threshold)
        self.decay = decay_seconds
        self._lock = threading.Lock()
        self._strikes: dict[str, tuple[int, float]] = {}
        self.served = 0

    def register_failure(self, client: str) -> int:
        now = time.monotonic()
        with self._lock:
            count, last = self._strikes.get(client, (0, now))
            if now - last > self.decay:
                count = 0
            count += 1
            self._strikes[client] = (count, now)
            return count

    def register_success(self, client: str) -> None:
        with self._lock:
            self._strikes.pop(client, None)

    def needs_challenge(self, client: str) -> bool:
        with self._lock:
            count, last = self._strikes.get(client, (0, 0.0))
            if not count:
                return False
            if time.monotonic() - last > self.decay:
                self._strikes.pop(client, None)
                return False
            return count >= self.threshold

    def strikes(self, client: str) -> int:
        with self._lock:
            return self._strikes.get(client, (0, 0.0))[0]

    def serve_challenge(self) -> Verdict:
        self.served += 1
        return Verdict(
            decision=Decision.CHALLENGE,
            rule_id="challenge-page",
            reason="client has failed to prove it is a browser recently",
            mitigation=DefenseName.CHALLENGE_PAGE,
        )


# --------------------------------------------------------------------------
# WAF rules
# --------------------------------------------------------------------------


class RuleMatch(BaseModel):
    """Static request predicates. All present conditions must hold."""

    model_config = ConfigDict(extra="forbid")

    path_prefix: str | None = None
    path_contains: str | None = None
    path_longer_than: int | None = Field(default=None, ge=0)
    method: str | None = None
    user_agent_contains: str | None = None
    user_agent_missing: bool = False
    header_present: str | None = None

    def matches(self, facts: RequestFacts) -> bool:
        if self.path_prefix is not None and not facts.path.startswith(self.path_prefix):
            return False
        if self.path_contains is not None and self.path_contains not in facts.path:
            return False
        if self.path_longer_than is not None and len(facts.path) <= self.path_longer_than:
            return False
        if self.method is not None and facts.method.upper() != self.method.upper():
            return False
        if self.user_agent_missing and facts.user_agent:
            return False
        if self.user_agent_contains is not None:
            agent = (facts.user_agent or "").lower()
            if self.user_agent_contains.lower() not in agent:
                return False
        if self.header_present is not None:
            key = self.header_present.lower()
            if not any(k.lower() == key and v for k, v in facts.headers.items()):
                return False
        return True

    def describe(self) -> str:
        parts = [
            f"{name}={value!r}"
            for name, value in self.model_dump(exclude_none=True).items()
            if value not in (False, None)
        ]
        return ", ".join(parts) or "always"


class RuleRate(BaseModel):
    """A volume threshold, evaluated per client over a rolling window."""

    model_config = ConfigDict(extra="forbid")

    requests_per_minute_over: int = Field(gt=0)

    def matches(self, request_count: int) -> bool:
        return request_count > self.requests_per_minute_over


class WafRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    description: str = ""
    enabled: bool = True
    match: RuleMatch | None = None
    rate: RuleRate | None = None
    action: Decision = Decision.BLOCK
    score: int = Field(default=5, ge=0)

    @field_validator("id")
    @classmethod
    def _unique_looking_id(cls, value: str) -> str:
        if " " in value:
            raise ValueError(f"rule id {value!r} must not contain spaces")
        return value


class WafRules(BaseModel):
    """A parsed ``waf_rules.yaml``."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    default_action: Decision = Decision.ALLOW
    challenge_threshold: int = Field(default=5, ge=1)
    block_threshold: int = Field(default=10, ge=1)
    rules: list[WafRule] = Field(default_factory=list)

    @field_validator("block_threshold")
    @classmethod
    def _block_above_challenge(cls, value: int, info) -> int:
        challenge = info.data.get("challenge_threshold")
        if challenge is not None and value <= challenge:
            raise ValueError(
                f"block_threshold ({value}) must exceed challenge_threshold "
                f"({challenge}), or requests would skip the challenge step"
            )
        return value

    def enabled_rules(self) -> list[WafRule]:
        return [rule for rule in self.rules if rule.enabled]

    def ids(self) -> list[str]:
        return [rule.id for rule in self.rules]


@dataclass(frozen=True, slots=True)
class RuleMatchResult:
    rule_id: str
    action: Decision
    score: int
    description: str


def load_waf_rules(path: str | Path | None = None) -> WafRules:
    """Load ``waf_rules.yaml``, falling back to an empty rule set.

    An absent file means "no WAF rules", not an error: a target with the WAF
    enabled and no rules loaded is a legitimate - if useless - configuration, and
    failing to boot would be worse.
    """
    target_path = project_path(path) if path else waf_config_path()
    if not target_path.exists():
        return WafRules()
    with target_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{target_path} must contain a YAML mapping at the top level")
    return WafRules.model_validate(raw)


# --------------------------------------------------------------------------
# WAF engine
# --------------------------------------------------------------------------


class WafEngine:
    """Score requests against the rule set and decide allow/challenge/block.

    Scores accumulate rather than short-circuiting, so several weak signals can
    combine into a block. A single strong signal still wins immediately, because
    waiting for more evidence on an obvious traversal attempt only wastes work.
    """

    def __init__(
        self,
        rules: WafRules | None = None,
        *,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rules = rules or WafRules()
        self.window = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._history: dict[str, deque[float]] = {}
        self.matched: dict[str, int] = {}

    def record(self, client: str) -> int:
        """Note a request and return the client's count inside the window."""
        now = self._clock()
        with self._lock:
            events = self._history.setdefault(client, deque())
            events.append(now)
            cutoff = now - self.window
            while events and events[0] < cutoff:
                events.popleft()
            return len(events)

    def evaluate(self, facts: RequestFacts) -> Verdict:
        """Score a request and decide.

        Decision procedure, kept deliberately predictable because it has to be
        explainable in a report:

        1. Every enabled rule whose ``match`` and ``rate`` conditions hold
           contributes its score.
        2. The total selects a band: at or above ``block_threshold`` blocks, at
           or above ``challenge_threshold`` challenges, otherwise allow.
        3. A rule may *escalate* but never de-escalate. A rule that declares
           ``block`` escalates on its own once it is individually serious - its
           score alone reaches ``challenge_threshold``. A low-scoring rule
           cannot short-circuit the bands, so a noisy signature cannot take a
           target down by itself.
        """
        active = self.rules.enabled_rules()
        rate_rules = [rule for rule in active if rule.rate is not None]
        # Counted once per request, not once per rate rule, so a request cannot
        # inflate its own rate by matching several volume thresholds.
        request_count = self.record(facts.client) if rate_rules else 0

        matched: list[RuleMatchResult] = []
        for rule in active:
            if rule.match is not None and not rule.match.matches(facts):
                continue
            if rule.rate is not None and not rule.rate.matches(request_count):
                continue
            if rule.match is None and rule.rate is None:
                continue
            matched.append(
                RuleMatchResult(
                    rule_id=rule.id,
                    action=rule.action,
                    score=rule.score,
                    description=rule.description,
                )
            )

        if not matched:
            return Verdict(decision=self.rules.default_action, score=0)

        score = sum(hit.score for hit in matched)
        strongest = max(matched, key=lambda hit: hit.score)

        with self._lock:
            for hit in matched:
                self.matched[hit.rule_id] = self.matched.get(hit.rule_id, 0) + 1

        if score >= self.rules.block_threshold:
            decision = Decision.BLOCK
        elif score >= self.rules.challenge_threshold:
            decision = Decision.CHALLENGE
        else:
            decision = Decision.ALLOW

        if decision is not Decision.BLOCK and any(
            hit.action is Decision.BLOCK
            and hit.score >= self.rules.challenge_threshold
            for hit in matched
        ):
            decision = Decision.BLOCK

        if decision is Decision.ALLOW:
            return Verdict(decision=Decision.ALLOW, score=score)

        return Verdict(
            decision=decision,
            rule_id=strongest.rule_id,
            reason=self._reason(strongest, matched, score),
            score=score,
            mitigation=DefenseName.WAF,
        )

    @staticmethod
    def _reason(
        strongest: RuleMatchResult, matched: list[RuleMatchResult], score: int
    ) -> str:
        parts = [f"{hit.rule_id} (+{hit.score})" for hit in matched]
        detail = ", ".join(parts)
        if strongest.description:
            detail += f" - {strongest.description}"
        return f"score {score}: {detail}"

    def reset(self) -> None:
        with self._lock:
            self._history.clear()
            self.matched.clear()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "rules_loaded": len(self.rules.rules),
                "rules_enabled": len(self.rules.enabled_rules()),
                "tracked_clients": len(self._history),
                "matches": dict(self.matched),
            }


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------


def mitigation_for(
    defense: DefenseName,
    *,
    waf_rules: WafRules | None = None,
    rate_per_second: float = 50.0,
    burst: int = 100,
    connection_limit: int = 64,
    failure_threshold: int = 5,
    cooldown_seconds: float = 5.0,
    challenge_threshold: int = 5,
) -> Any | None:
    """Construct the mitigation object for a defense, or None for ``NONE``."""
    if defense is DefenseName.NONE:
        return None
    if defense is DefenseName.RATE_LIMIT:
        return RateLimiter(rate_per_second, burst)
    if defense is DefenseName.CONNECTION_CAP:
        return ConnectionCap(connection_limit)
    if defense is DefenseName.WAF:
        return WafEngine(waf_rules)
    if defense is DefenseName.CIRCUIT_BREAKER:
        return CircuitBreaker(failure_threshold, cooldown_seconds)
    if defense is DefenseName.CHALLENGE_PAGE:
        return ChallengeGate(challenge_threshold)
    raise ValueError(f"Unhandled defense {defense!r}")


def describe_defenses(defenses: Iterable[DefenseName]) -> list[str]:
    return [d.value for d in defenses]
