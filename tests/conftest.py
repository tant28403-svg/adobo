"""Shared fixtures.

Every test in this suite is hermetic: it uses literal IP addresses (so no DNS
is ever queried) and tmp_path for any run artefact (so real output is never
touched).
"""

from __future__ import annotations

import pytest

from adobo.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TransportKind,
)


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
