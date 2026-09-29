"""Shared fixtures.

Every test in this suite is hermetic: it uses literal IP addresses (so no DNS
is ever queried) and tmp_path for any run artefact (so real output is never
touched).

The one thing tests do *not* rely on is the repository's own
``config/authorization.yaml``, which ships expired on purpose. A test that
depended on editing that file to make itself pass would be testing the wrong
thing, and would silently stop testing anything if the guard were removed. So
the authorisation record is supplied per-test instead, and
``tests/test_safety.py`` covers the refusal paths on their own.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from adobo.config import AuthorizationConfig
from adobo.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TransportKind,
)
from adobo.safety import SafetyGuard


def make_authorization(
    scope: list[str] | None = None,
    expires_in_days: int = 30,
) -> AuthorizationConfig:
    """An authorisation record that permits *scope*, valid for a month."""
    return AuthorizationConfig(
        operator="test",
        issuer="test",
        reference="TEST",
        scope=scope if scope is not None else ["127.0.0.0/8"],
        issued_on=date.today(),
        expires_on=date.today() + timedelta(days=expires_in_days),
    )


@pytest.fixture
def authorization() -> AuthorizationConfig:
    """A valid, in-scope record for loopback."""
    return make_authorization()


@pytest.fixture
def guard(authorization: AuthorizationConfig) -> SafetyGuard:
    """A guard that permits loopback, so a test is not blocked by policy."""
    return SafetyGuard(authorization=authorization)


@pytest.fixture
def make_run_config():
    def _make(
        *,
        host: str = "127.0.0.1",
        port: int = 8000,
        transport: TransportKind = TransportKind.SOCKET,
        dry_run: bool = False,
        spoof_sources: bool = False,
        pps: int = 100,
        duration: float = 2.0,
        payload_size: int = 128,
        workers: int = 1,
        profile: ProfileName = ProfileName.UDP_FLOOD,
    ) -> RunConfig:
        return RunConfig(
            target=Target(host=host, port=port),
            attack=AttackProfile(
                profile=profile,
                pps=pps,
                duration_seconds=duration,
                payload_size=payload_size,
                workers=workers,
                spoof_sources=spoof_sources,
            ),
            transport=transport,
            dry_run=dry_run,
        )

    return _make
