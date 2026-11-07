"""The lab target's app glue: defenses driven through real requests.

The defense *rules* are pure objects; what had no coverage at all was the
adaptation layer - ``create_app``'s middleware deciding which defense sees
which request, the exempt paths that keep the instrumentation measurable, and
the counters a run's delivery figure relies on. These tests drive the real app
over FastAPI's TestClient, so a rule that works in isolation but is wired in
the wrong order fails here.

The challenge-gate ordering test is the reason this file exists: the gate sat
AFTER the WAF it depends on for its strike accounting, which made it
unreachable through the live path - every client it should have challenged was
flat 403'd by the WAF one line earlier, forever.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from adobo.defenses import RuleMatch, WafRule, WafRules
from adobo.models import DefenseName
from adobo.target.app import TargetSettings, create_app


def _client(settings: TargetSettings, **client_kw) -> TestClient:
    return TestClient(create_app(settings), **client_kw)


def _blocking_rules() -> WafRules:
    """One rule whose score alone reaches the block band (threshold 10)."""
    return WafRules(
        rules=[
            WafRule(
                id="block-evil-bot",
                description="test rule: block the evil-bot agent",
                match=RuleMatch(user_agent_contains="evil-bot"),
                score=10,
            )
        ]
    )


class TestBaseline:
    def test_the_target_serves_and_counts(self) -> None:
        client = _client(TargetSettings())
        assert client.get("/healthz").status_code == 200
        assert client.get("/api/data").status_code == 200
        stats = client.get("/stats").json()
        assert stats["requests"] == 1, "only /api/data counts: /healthz and /stats are exempt"
        assert stats["errors"] == 0

    def test_exempt_paths_never_enter_the_counters(self) -> None:
        """The instrumentation must not measure itself: probes hitting
        /healthz would otherwise inflate the served count a delivery ratio is
        computed from."""
        client = _client(TargetSettings())
        client.get("/healthz")
        first = client.get("/stats").json()["requests"]
        client.get("/healthz")
        second = client.get("/stats").json()["requests"]
        assert first == second == 0


class TestRateLimit:
    def test_load_past_the_burst_is_shed(self) -> None:
        settings = TargetSettings(
            defenses=[DefenseName.RATE_LIMIT], rate_per_second=0.5, burst=5
        )
        client = _client(settings)
        statuses = [client.get("/api/data").status_code for _ in range(8)]
        assert statuses[:5] == [200] * 5, "the burst is admitted"
        assert 429 in statuses, "past the burst, load is shed"

    def test_the_health_probe_survives_a_spent_burst(self) -> None:
        """Availability measurement must not be shed by the mitigation it is
        measuring - /healthz is exempt precisely for this."""
        settings = TargetSettings(
            defenses=[DefenseName.RATE_LIMIT], rate_per_second=0.5, burst=2
        )
        client = _client(settings)
        for _ in range(5):
            client.get("/api/data")
        assert client.get("/healthz").status_code == 200


class TestWaf:
    def test_a_matching_user_agent_is_blocked(self) -> None:
        settings = TargetSettings(
            defenses=[DefenseName.WAF], waf_rules=_blocking_rules()
        )
        client = _client(settings)
        blocked = client.get("/api/data", headers={"User-Agent": "evil-bot/1.0"})
        assert blocked.status_code == 403
        allowed = client.get("/api/data", headers={"User-Agent": "Mozilla/5.0"})
        assert allowed.status_code == 200

    def test_a_blocked_request_is_counted_as_an_error(self) -> None:
        settings = TargetSettings(
            defenses=[DefenseName.WAF], waf_rules=_blocking_rules()
        )
        client = _client(settings)
        client.get("/api/data", headers={"User-Agent": "evil-bot/1.0"})
        assert client.get("/stats").json()["errors"] == 1


class TestCircuitBreaker:
    def test_repeated_failures_open_the_circuit(self) -> None:
        settings = TargetSettings(
            defenses=[DefenseName.CIRCUIT_BREAKER],
            failure_threshold=3,
            cooldown_seconds=60.0,
        )
        # raise_server_exceptions=False: the app's own exception is the failure
        # the breaker exists to record, and the test wants the 500, not a raise.
        client = _client(settings, raise_server_exceptions=False)
        for _ in range(3):
            client.get("/api/flaky?fail=true")
        healthy = client.get("/api/flaky")
        assert healthy.status_code == 503
        assert "circuit_open" in healthy.text


class TestChallengeGate:
    def test_a_waf_denied_client_is_challenged_not_flat_403d(self) -> None:
        """The ordering regression, as behaviour.

        The gate's strikes come from WAF denials, so with the gate behind the
        WAF every challenged client was 403'd one line earlier, forever. With
        the gate first, the client earns a solvable 503 after the threshold.
        """
        settings = TargetSettings(
            defenses=[DefenseName.WAF, DefenseName.CHALLENGE_PAGE],
            waf_rules=_blocking_rules(),
            challenge_threshold=2,
        )
        client = _client(settings)
        for _ in range(2):
            assert client.get("/api/data", headers={"User-Agent": "evil-bot/1.0"}).status_code == 403
        challenged = client.get("/api/data", headers={"User-Agent": "evil-bot/1.0"})
        assert challenged.status_code == 503
        assert "challenge" in challenged.text.lower()

    def test_a_clean_client_is_never_challenged(self) -> None:
        settings = TargetSettings(
            defenses=[DefenseName.WAF, DefenseName.CHALLENGE_PAGE],
            waf_rules=_blocking_rules(),
            challenge_threshold=2,
        )
        app = create_app(settings)
        client = TestClient(app)
        for _ in range(5):
            assert client.get("/api/data").status_code == 200
        assert app.state.settings.challenge.served == 0
