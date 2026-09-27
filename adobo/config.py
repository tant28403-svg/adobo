"""YAML-backed configuration loading and validation.

Three files drive the tool, all optional-but-recommended and all overridable by
path:

    config/lab.yaml            policy: allowlist, ceilings, measurement cadence
    config/authorization.yaml  written authorisation record (fails closed)
    config/waf_rules.yaml      mitigation rule set (parsed by ddosim.defenses)

Nothing here opens a socket. Loading a config is a pure, testable operation.
"""

from __future__ import annotations

import ipaddress
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import paths
from .models import Target

# --------------------------------------------------------------------------
# Locations
# --------------------------------------------------------------------------
#
# Resolution lives in ddosim.paths, which knows whether we are running from a
# source tree or a PyInstaller bundle. Do not reintroduce Path(__file__).parent
# here: under a onefile build that points at the temp extraction directory, and
# config would silently fail to load.

LAB_CONFIG_NAME = "lab.yaml"
AUTHORIZATION_CONFIG_NAME = "authorization.yaml"
WAF_CONFIG_NAME = "waf_rules.yaml"


def project_path(relative: str | Path) -> Path:
    """Resolve a config-relative path against the ddosim home directory."""
    candidate = Path(relative)
    if candidate.is_absolute():
        return candidate
    return paths.home() / candidate


def config_path(name: str) -> Path:
    """Resolve a file inside the config directory."""
    return paths.config_file(name)


# --------------------------------------------------------------------------
# lab.yaml
# --------------------------------------------------------------------------


class LimitsConfig(BaseModel):
    """Hard ceilings. Runs are clamped down to these, never above."""

    model_config = ConfigDict(extra="forbid")

    max_pps: int = Field(default=20_000, gt=0)
    max_duration_seconds: float = Field(default=60.0, gt=0)
    max_payload_bytes: int = Field(default=1400, gt=0)
    max_workers: int = Field(default=8, gt=0)


class MeasurementConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample_interval_ms: int = Field(default=1000, gt=0)
    probe_interval_ms: int = Field(default=250, gt=0)
    probe_path: str = "/healthz"
    probe_timeout_ms: int = Field(default=1500, gt=0)

    @property
    def sample_interval_s(self) -> float:
        return self.sample_interval_ms / 1000.0

    @property
    def probe_interval_s(self) -> float:
        return self.probe_interval_ms / 1000.0

    @property
    def probe_timeout_s(self) -> float:
        return self.probe_timeout_ms / 1000.0


class PathsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    log_dir: str = "logs"
    report_dir: str = "reports"
    results_dir: str = "results"
    audit_log: str = "logs/audit.jsonl"

    def log_path(self) -> Path:
        return project_path(self.log_dir)

    def report_path(self) -> Path:
        return project_path(self.report_dir)

    def results_path(self) -> Path:
        return project_path(self.results_dir)

    def audit_path(self) -> Path:
        return project_path(self.audit_log)

    def ensure_dirs(self) -> None:
        for directory in (self.log_path(), self.report_path(), self.results_path()):
            directory.mkdir(parents=True, exist_ok=True)


class LabConfig(BaseModel):
    """Top-level `lab.yaml`."""

    model_config = ConfigDict(extra="forbid")

    lab_id: str = "default"
    allowed_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.0/8"])
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    target: Target = Field(default_factory=lambda: Target(host="127.0.0.1", port=8000))
    measurement: MeasurementConfig = Field(default_factory=MeasurementConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)

    @field_validator("allowed_cidrs")
    @classmethod
    def _must_be_parseable(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("allowed_cidrs must not be empty: an empty allowlist disables the tool")
        for entry in value:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"allowed_cidrs entry {entry!r} is not a valid CIDR: {exc}") from exc
        return value

    def networks(self) -> tuple[Any, ...]:
        return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in self.allowed_cidrs)


def load_lab_config(path: str | Path | None = None) -> LabConfig:
    """Load `lab.yaml`. Falls back to conservative defaults if absent."""
    target_path = project_path(path) if path else config_path(LAB_CONFIG_NAME)
    if not target_path.exists():
        return LabConfig()
    with target_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{target_path} must contain a YAML mapping at the top level")
    return LabConfig.model_validate(raw)


# --------------------------------------------------------------------------
# authorization.yaml
# --------------------------------------------------------------------------


class AuthorizationConfig(BaseModel):
    """Written authorisation record. The engine refuses to run without one."""

    model_config = ConfigDict(extra="forbid")

    operator: str = "unassigned"
    issuer: str = "unassigned"
    reference: str = "NONE"
    scope: list[str] = Field(default_factory=list)
    issued_on: date | None = None
    expires_on: date | None = None
    notes: str = ""

    @field_validator("scope")
    @classmethod
    def _entries_must_be_parseable(cls, value: list[str]) -> list[str]:
        for entry in value:
            candidate = entry.strip()
            if not candidate:
                raise ValueError("authorization scope entries must not be blank")
            try:
                ipaddress.ip_network(candidate, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"authorization scope entry {entry!r} is not a valid CIDR: {exc}"
                ) from exc
        return value

    def networks(self) -> tuple[Any, ...]:
        return tuple(ipaddress.ip_network(entry.strip(), strict=False) for entry in self.scope)

    def is_expired(self, today: date | None = None) -> bool:
        if self.expires_on is None:
            return True
        return self.expires_on < (today or date.today())

    def days_remaining(self, today: date | None = None) -> int:
        if self.expires_on is None:
            return 0
        return (self.expires_on - (today or date.today())).days


def load_authorization(path: str | Path | None = None) -> AuthorizationConfig | None:
    """Load `authorization.yaml`, or return None when it is absent."""
    target_path = (
        project_path(path) if path else config_path(AUTHORIZATION_CONFIG_NAME)
    )
    if not target_path.exists():
        return None
    with target_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{target_path} must contain a YAML mapping at the top level")
    return AuthorizationConfig.model_validate(raw)


# --------------------------------------------------------------------------
# waf_rules.yaml
# --------------------------------------------------------------------------
# Parsed by ddosim.defenses, which owns the rule model. Only the location lives
# here so every config file has exactly one resolver.


def waf_config_path() -> Path:
    return config_path(WAF_CONFIG_NAME)
