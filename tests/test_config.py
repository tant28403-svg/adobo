"""Tests for configuration loading.

Includes checks against the *shipped* config files, so a bad edit to
config/lab.yaml is caught rather than discovered mid-demo.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from adobo.config import (
    AuthorizationConfig,
    LabConfig,
    LimitsConfig,
    MeasurementConfig,
    PathsConfig,
    load_authorization,
    load_lab_config,
    project_path,
)
from adobo.models import Target


# ---------------------------------------------------------------------------
# Shipped configuration
# ---------------------------------------------------------------------------


class TestShippedConfig:
    def test_lab_yaml_loads(self) -> None:
        config = load_lab_config()
        assert config.lab_id == "adobo"
        assert config.limits.max_pps == 20_000

    def test_lab_yaml_is_loopback_only_by_default(self) -> None:
        """The out-of-the-box posture must not permit touching the LAN."""
        config = load_lab_config()
        for network in config.networks():
            assert network.is_loopback, f"default allowlist leaks {network}"

    def test_lab_yaml_allowlist_is_minimal(self) -> None:
        config = load_lab_config()
        assert set(config.allowed_cidrs) == {"127.0.0.0/8", "::1/128"}

    def test_lab_yaml_target_is_loopback(self) -> None:
        config = load_lab_config()
        assert config.target.host == "127.0.0.1"

    def test_shipped_authorisation_is_expired(self) -> None:
        auth = load_authorization()
        assert auth is not None
        assert auth.is_expired()

    def test_shipped_authorisation_scopes_loopback_only(self) -> None:
        auth = load_authorization()
        assert auth is not None
        for network in auth.networks():
            assert network.is_loopback

    def test_lab_yaml_ceiling_is_sane(self) -> None:
        limits = load_lab_config().limits
        assert 0 < limits.max_pps <= 1_000_000
        assert 0 < limits.max_duration_seconds <= 3600
        assert 0 < limits.max_payload_bytes <= 65_507
        assert 0 < limits.max_workers <= 256


# ---------------------------------------------------------------------------
# LabConfig
# ---------------------------------------------------------------------------


class TestLabConfig:
    def test_networks_parses_to_ip_networks(self) -> None:
        config = LabConfig(allowed_cidrs=["10.0.0.0/8", "192.168.1.0/24"])
        networks = config.networks()
        assert networks[0] == ipaddress.ip_network("10.0.0.0/8")
        assert networks[1] == ipaddress.ip_network("192.168.1.0/24")

    def test_host_bits_are_tolerated(self) -> None:
        config = LabConfig(allowed_cidrs=["192.168.1.15/24"])
        assert config.networks() == (ipaddress.ip_network("192.168.1.0/24"),)

    def test_missing_file_falls_back_to_defaults(self, tmp_path: Path) -> None:
        config = load_lab_config(tmp_path / "absent.yaml")
        assert config.lab_id == "adobo"
        assert config.limits.max_pps == 20_000

    def test_non_mapping_yaml_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "lab.yaml"
        bad.write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_lab_config(bad)

    def test_empty_yaml_falls_back_to_defaults(self, tmp_path: Path) -> None:
        empty = tmp_path / "lab.yaml"
        empty.write_text("", encoding="utf-8")
        assert load_lab_config(empty).lab_id == "adobo"

    def test_unknown_key_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            LabConfig.model_validate({"lab_id": "x", "typoed_key": 1})

    @pytest.mark.parametrize("value", [0, -1])
    def test_limits_must_be_positive(self, value: int) -> None:
        with pytest.raises(ValueError):
            LimitsConfig(max_pps=value)


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


class TestMeasurement:
    def test_intervals_convert_to_seconds(self) -> None:
        m = MeasurementConfig(
            sample_interval_ms=1000, probe_interval_ms=250, probe_timeout_ms=1500
        )
        assert m.sample_interval_s == 1.0
        assert m.probe_interval_s == 0.25
        assert m.probe_timeout_s == 1.5

    def test_non_positive_intervals_rejected(self) -> None:
        with pytest.raises(ValueError):
            MeasurementConfig(probe_interval_ms=0)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


class TestPaths:
    def test_relative_paths_resolve_against_project_root(self) -> None:
        resolved = PathsConfig(log_dir="logs").log_path()
        assert resolved.is_absolute()
        assert resolved.name == "logs"

    def test_absolute_paths_are_preserved(self, tmp_path: Path) -> None:
        paths = PathsConfig(log_dir=str(tmp_path / "abs"))
        assert paths.log_path() == tmp_path / "abs"

    def test_ensure_dirs_creates_all_output_directories(self, tmp_path: Path) -> None:
        paths = PathsConfig(
            log_dir=str(tmp_path / "l"),
            report_dir=str(tmp_path / "r"),
            results_dir=str(tmp_path / "res"),
            audit_log=str(tmp_path / "l" / "audit.jsonl"),
        )
        paths.ensure_dirs()
        assert paths.log_path().is_dir()
        assert paths.report_path().is_dir()
        assert paths.results_path().is_dir()

    def test_project_path_helper_handles_both_forms(self) -> None:
        assert project_path("logs").is_absolute()
        assert project_path("C:/tmp/x").is_absolute()


# ---------------------------------------------------------------------------
# AuthorizationConfig
# ---------------------------------------------------------------------------


class TestAuthorizationConfig:
    def test_expiry_calculation(self) -> None:
        from datetime import date, timedelta

        today = date.today()
        expired = AuthorizationConfig(expires_on=today - timedelta(days=1))
        valid = AuthorizationConfig(expires_on=today + timedelta(days=1))
        assert expired.is_expired()
        assert not valid.is_expired()
        assert valid.days_remaining() == 1

    def test_absent_expiry_is_treated_as_expired(self) -> None:
        assert AuthorizationConfig().is_expired()

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert load_authorization(tmp_path / "absent.yaml") is None

    def test_blank_scope_entry_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be blank"):
            AuthorizationConfig(scope=["  "])

    def test_non_cidr_scope_entry_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="not a valid CIDR"):
            AuthorizationConfig(scope=["example.com"])

    def test_networks_parses_scope(self) -> None:
        auth = AuthorizationConfig(scope=["127.0.0.0/8", "10.0.0.0/8"])
        assert len(auth.networks()) == 2


class TestTargetModel:
    def test_port_bounds(self) -> None:
        with pytest.raises(ValueError):
            Target(host="127.0.0.1", port=0)
        with pytest.raises(ValueError):
            Target(host="127.0.0.1", port=70_000)

    def test_target_is_hashable_and_frozen(self) -> None:
        target = Target(host="127.0.0.1", port=80)
        assert {target, Target(host="127.0.0.1", port=80)} == {target}
        with pytest.raises(ValueError):
            target.port = 90  # type: ignore[misc]
