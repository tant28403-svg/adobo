"""Tests for filesystem layout resolution.

The frozen/fallback branches are simulated by patching the detection helpers
rather than by building a real bundle, so these stay fast and hermetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adobo import paths
from adobo.config import project_path


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestDetection:
    def test_not_frozen_under_pytest(self) -> None:
        assert paths.is_frozen() is False

    def test_executable_path_is_none_when_not_frozen(self) -> None:
        assert paths.executable_path() is None

    def test_frozen_requires_both_attributes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(paths.sys, "frozen", True, raising=False)
        assert paths.is_frozen() is False, "sys.frozen alone is not enough"
        monkeypatch.setattr(paths.sys, "_MEIPASS", "/tmp/bundle", raising=False)
        assert paths.is_frozen() is True

    def test_frozen_uses_executable_directory_not_meipass(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The whole point: never resolve against the temp extraction dir."""
        monkeypatch.setattr(paths.sys, "frozen", True, raising=False)
        monkeypatch.setattr(paths.sys, "_MEIPASS", str(tmp_path / "MEI12345"), raising=False)
        monkeypatch.setattr(
            paths.sys, "executable", str(tmp_path / "adobo.exe"), raising=False
        )

        assert paths.executable_path() == tmp_path / "adobo.exe"
        assert paths.resolve_home() == tmp_path

    def test_source_root_is_absolute(self) -> None:
        assert paths.source_root().is_absolute()
        assert (paths.source_root() / "adobo").is_dir()

    def test_fallback_root_is_absolute(self) -> None:
        assert paths.fallback_root().is_absolute()


# ---------------------------------------------------------------------------
# Resolution precedence
# ---------------------------------------------------------------------------


class TestResolution:
    def test_explicit_override_wins(self, tmp_path: Path) -> None:
        assert paths.resolve_home(tmp_path) == tmp_path

    def test_override_is_expanded_and_absolute(self, tmp_path: Path) -> None:
        resolved = paths.resolve_home(str(tmp_path / "." ))
        assert resolved.is_absolute()
        assert resolved == tmp_path

    def test_env_var_is_honoured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(paths.HOME_ENV_VAR, str(tmp_path))
        assert paths.resolve_home() == tmp_path
        assert paths.home() == tmp_path

    def test_override_beats_env_var(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(paths.HOME_ENV_VAR, str(tmp_path / "from-env"))
        assert paths.resolve_home(tmp_path) == tmp_path

    def test_unwritable_env_var_is_not_silently_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A misconfigured DDOSIM_HOME must fail loudly, not fall through."""
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("occupied", encoding="utf-8")
        monkeypatch.setenv(paths.HOME_ENV_VAR, str(blocker))
        assert paths.resolve_home() == blocker

    def test_unwritable_candidates_fall_through(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        calls: list[Path] = []

        def _deny(path: Path) -> bool:
            calls.append(path)
            return False

        monkeypatch.setattr(paths, "_is_writable", _deny)
        assert paths.resolve_home() == paths.fallback_root()
        assert len(calls) > 1, "should have tried more than one candidate"

    def test_home_is_writable_in_this_checkout(self) -> None:
        assert paths.home().is_dir()
        assert paths._is_writable(paths.home())


# ---------------------------------------------------------------------------
# Well-known locations
# ---------------------------------------------------------------------------


class TestLocations:
    def test_every_location_sits_under_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(paths.HOME_ENV_VAR, str(tmp_path))
        for location in (
            paths.config_dir(),
            paths.logs_dir(),
            paths.reports_dir(),
            paths.results_dir(),
            paths.audit_path(),
        ):
            assert location.is_relative_to(tmp_path)

    def test_config_file_is_inside_config_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(paths.HOME_ENV_VAR, str(tmp_path))
        assert paths.config_file("lab.yaml") == tmp_path / "config" / "lab.yaml"

    def test_project_path_delegates_to_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(paths.HOME_ENV_VAR, str(tmp_path))
        assert project_path("logs/audit.jsonl") == tmp_path / "logs" / "audit.jsonl"

    def test_project_path_preserves_absolute(self, tmp_path: Path) -> None:
        absolute = tmp_path / "elsewhere"
        assert project_path(absolute) == absolute
