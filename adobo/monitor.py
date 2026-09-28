"""Sample the target process's resource usage while a run is in flight.

Saturation is invisible from the attack side alone. A sender can report a steady
100k pps while the target has been dead for the last thirty seconds, so a run
that never samples the target cannot tell "handled it" from "dropped everything
on the floor". These samples are what make the resilience score meaningful.

Scope and honesty about limits
------------------------------
psutil can only inspect processes on the local machine, so this samples the
*local* target - the one ``adobo`` can start itself. Against a remote host there
is no honest way to read its CPU or RSS, and inventing plausible numbers would
corrupt the score. In that case sampling is skipped and the result carries a
note saying so, rather than a row of zeroes that look like an idle target.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Protocol

from .models import ResourceSample

try:  # pragma: no cover - exercised implicitly by the availability check
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard dependency
    psutil = None  # type: ignore[assignment]

__all__ = ["ResourceMonitor", "TargetProcess", "psutil_available"]


def psutil_available() -> bool:
    return psutil is not None


class TargetProcess(Protocol):
    """The subset of ``psutil.Process`` this module relies on.

    Declared so the monitor can be tested against a stub instead of by spawning
    real processes and racing on their counters.
    """

    def cpu_percent(self, interval: float | None = ...) -> float: ...
    def memory_info(self) -> Any: ...
    def num_threads(self) -> int: ...
    def num_fds(self) -> int: ...
    def num_handles(self) -> int: ...
    def is_running(self) -> bool: ...


class ResourceMonitor:
    """Periodically snapshot a process into :class:`ResourceSample` rows.

    Not a thread: the engine drives it from its existing async sampler loop, so
    there is one scheduler to reason about rather than two.
    """

    def __init__(
        self,
        process: TargetProcess | None,
        *,
        interval_s: float = 1.0,
        clock: Any = time.monotonic,
    ) -> None:
        self._process = process
        self.interval_s = max(0.05, interval_s)
        self._clock = clock
        self._started_at = clock()
        self._last_at: float | None = None
        self._samples: list[ResourceSample] = []
        self.unavailable_reason: str | None = None

        if process is None:
            self.unavailable_reason = (
                "no local target process to sample; resource figures are absent "
                "for this run rather than guessed"
            )

    @property
    def available(self) -> bool:
        return self._process is not None

    @property
    def samples(self) -> list[ResourceSample]:
        return list(self._samples)

    def sample(self) -> ResourceSample | None:
        """Take one snapshot, or return None if sampling is not possible.

        A failure to read the process is not fatal to the run: losing visibility
        is unfortunate, aborting the measurement because of it would be worse.
        The sample is skipped and the reason recorded.
        """
        if self._process is None:
            return None
        now = self._clock()
        elapsed = now - self._started_at
        try:
            sample = ResourceSample(
                t=round(elapsed, 3),
                cpu_percent=_cpu_percent(self._process),
                rss_mb=_rss_mb(self._process),
                threads=int(_safe(self._process.num_threads, 0)),
                open_sockets=int(_safe(self._process.num_fds, 0)),
                handles=int(_safe(self._process.num_handles, 0)),
            )
        except Exception as exc:  # process died, access denied, race on exit
            self.unavailable_reason = f"resource sampling stopped: {exc}"
            self._process = None
            return None
        self._last_at = now
        self._samples.append(sample)
        return sample


def _safe(getter: Any, default: int = 0) -> int:
    """Read a counter, tolerating one the platform does not have.

    Windows has no ``num_fds``; POSIX has no ``num_handles``. Those absences are
    structural, so they report 0 and the sample stays complete.

    Anything else - a dead process, a permission error - is *not* tolerated.
    Swallowing it would emit a row of zeroes that reads as "the target was idle",
    which is the exact misreading the unavailability note exists to prevent.
    """
    try:
        value = getter()
    except (AttributeError, NotImplementedError):
        return default
    return int(value or 0)


def _cpu_percent(process: TargetProcess) -> float:
    try:
        value = process.cpu_percent(interval=None)
    except AttributeError:  # pragma: no cover - only a partial stub
        return 0.0
    return max(0.0, float(value or 0.0))


def _rss_mb(process: TargetProcess) -> float:
    info = process.memory_info()
    rss = getattr(info, "rss", 0)
    return round(rss / (1024 * 1024), 3) if rss else 0.0


def process_for_pid(pid: int | None) -> TargetProcess | None:
    """Wrap a PID, or return None if it cannot be inspected.

    Returning None rather than raising keeps the engine's startup path simple:
    an uninspectable target downgrades the report, it does not abort the run.
    """
    if pid is None or psutil is None:
        return None
    try:
        process = psutil.Process(pid)
        process.is_running()  # verify before promising anything
    except Exception:
        return None
    return process  # type: ignore[return-value]
