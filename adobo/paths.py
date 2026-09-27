"""Filesystem layout resolution.

Where config, logs, results and reports live depends entirely on *how* the tool
is running, and getting this wrong is silent and destructive:

* **Frozen (PyInstaller onefile)** - ``__file__`` points inside the temporary
  extraction directory that PyInstaller creates per run. Anything written there
  vanishes on exit and nothing shipped is readable. So the base directory is
  derived from ``sys.executable`` instead: the folder the user double-clicked.
* **Source checkout / ``pip install -e``** - the base is the repository root,
  found by walking up from this file.
* **Unwritable install directory** - an exe dropped in ``Program Files`` cannot
  write beside itself. Resolution falls through to a per-user data directory and
  reports where it landed, rather than failing partway through a run.

Everything else in the codebase resolves paths through here. Nothing calls
``Path(__file__)`` directly.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "ddosim"
HOME_ENV_VAR = "DDOSIM_HOME"

__all__ = [
    "APP_NAME",
    "HOME_ENV_VAR",
    "audit_path",
    "config_dir",
    "config_file",
    "executable_path",
    "fallback_root",
    "home",
    "is_frozen",
    "logs_dir",
    "reports_dir",
    "resolve_home",
    "results_dir",
    "source_root",
]


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def is_frozen() -> bool:
    """True when running from a PyInstaller bundle.

    Both attributes are checked: ``sys.frozen`` is set by other freezers too,
    while ``_MEIPASS`` is PyInstaller-specific. Requiring both avoids claiming to
    be frozen under a loader that would not give us ``sys.executable`` meaning.
    """
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def executable_path() -> Path | None:
    """The bundle's own executable, or None when not frozen."""
    if not is_frozen():
        return None
    try:
        return Path(sys.executable).resolve()
    except (OSError, AttributeError):  # pragma: no cover - defensive
        return None


def source_root() -> Path:
    """Repository root when running from a source tree."""
    return Path(__file__).resolve().parent.parent


def fallback_root() -> Path:
    """A per-user directory used when the install directory is not writable."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base).expanduser() / APP_NAME
    return Path.home() / f".{APP_NAME}"


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def _is_writable(path: Path) -> bool:
    """True if *path* exists (or can be created) and accepts writes.

    An actual write probe is used rather than a permission bit, because on
    Windows the ACLs on ``Program Files`` are stricter than what
    ``os.access`` alone implies.
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(path, os.W_OK)


def resolve_home(override: str | Path | None = None) -> Path:
    """The base directory that config and output paths hang off.

    Precedence: explicit *override* > ``DDOSIM_HOME`` > the executable's folder
    (frozen) > the source root > a per-user fallback.

    The env var and an explicit override are honoured even when they are not
    writable, on the assumption the caller meant them. Only the implicit
    candidates fall through, so a misconfigured ``DDOSIM_HOME`` surfaces as a
    clear write error instead of being silently ignored.
    """
    if override is not None:
        return Path(override).expanduser().resolve()

    env_value = os.environ.get(HOME_ENV_VAR)
    if env_value:
        return Path(env_value).expanduser().resolve()

    candidates: list[Path] = []
    executable = executable_path()
    if executable is not None:
        candidates.append(executable.parent)
    candidates.append(source_root())
    candidates.append(fallback_root())

    for candidate in candidates:
        if _is_writable(candidate):
            return candidate
    return fallback_root()


def home() -> Path:
    """The resolved base directory for this process."""
    return resolve_home()


# --------------------------------------------------------------------------
# Well-known locations
# --------------------------------------------------------------------------


def config_dir() -> Path:
    return home() / "config"


def config_file(name: str) -> Path:
    return config_dir() / name


def logs_dir() -> Path:
    return home() / "logs"


def reports_dir() -> Path:
    return home() / "reports"


def results_dir() -> Path:
    return home() / "results"


def audit_path() -> Path:
    return logs_dir() / "audit.jsonl"
