"""Tests for the resource monitor.

The monitor is tested against a stub process rather than a real one. Spawning
processes to assert on their counters would be slow and racy, and the whole
point of the stub is that the awkward cases (a process that dies mid-run, a
platform with no ``num_fds``) are easy to reproduce deliberately.
"""

from __future__ import annotations

import pytest

from adobo.monitor import ResourceMonitor, process_for_pid, psutil_available


class StubProcess:
    """A controllable stand-in for ``psutil.Process``.

    ``absent`` simulates a platform that has no such counter (AttributeError),
    which is what Windows does for num_fds. ``broken`` simulates a process that
    has gone away (OSError). The two must not be conflated, so the stub keeps
    them distinct.
    """

    def __init__(self, *, cpu=12.5, rss=64 * 1024 * 1024, threads=4, fds=7, handles=9):
        self._cpu = cpu
        self._rss = rss
        self._threads = threads
        self._fds = fds
        self._handles = handles
        self.cpu_calls: list[float | None] = []
        self.absent: set[str] = set()
        self.broken: set[str] = set()

    def _maybe_raise(self, name: str) -> None:
        if name in self.absent:
            raise AttributeError(name)
        if name in self.broken:
            raise OSError(f"{name} unavailable")

    def cpu_percent(self, interval=None):
        self._maybe_raise("cpu_percent")
        self.cpu_calls.append(interval)
        return self._cpu

    def memory_info(self):
        self._maybe_raise("memory_info")
        return type("Mem", (), {"rss": self._rss})()

    def num_threads(self):
        self._maybe_raise("num_threads")
        return self._threads

    def num_fds(self):
        self._maybe_raise("num_fds")
        return self._fds

    def num_handles(self):
        self._maybe_raise("num_handles")
        return self._handles

    def is_running(self):
        return True


class FakeClock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestSampling:
    def test_sample_records_every_field(self) -> None:
        monitor = ResourceMonitor(StubProcess(), clock=FakeClock())
        sample = monitor.sample()
        assert sample is not None
        assert sample.cpu_percent == 12.5
        assert sample.rss_mb == 64.0
        assert sample.threads == 4
        assert sample.open_sockets == 7
        assert sample.handles == 9

    def test_t_is_measured_from_the_monitor_start(self) -> None:
        clock = FakeClock()
        monitor = ResourceMonitor(StubProcess(), clock=clock)
        clock.advance(2.5)
        assert monitor.sample().t == 2.5

    def test_samples_accumulate(self) -> None:
        monitor = ResourceMonitor(StubProcess(), clock=FakeClock())
        monitor.sample()
        monitor.sample()
        assert len(monitor.samples) == 2

    def test_cpu_is_sampled_without_blocking(self) -> None:
        """interval=None keeps a sample from costing a whole second."""
        process = StubProcess()
        ResourceMonitor(process, clock=FakeClock()).sample()
        assert process.cpu_calls == [None]

    def test_cpu_is_clamped_to_zero(self) -> None:
        """psutil can report a small negative value on some platforms."""
        monitor = ResourceMonitor(StubProcess(cpu=-3.0), clock=FakeClock())
        assert monitor.sample().cpu_percent == 0.0

    def test_zero_rss_is_reported_as_zero(self) -> None:
        monitor = ResourceMonitor(StubProcess(rss=0), clock=FakeClock())
        assert monitor.sample().rss_mb == 0.0

    def test_samples_property_returns_a_copy(self) -> None:
        monitor = ResourceMonitor(StubProcess(), clock=FakeClock())
        monitor.sample()
        monitor.samples.clear()
        assert len(monitor.samples) == 1, "callers must not be able to erase the record"


class TestPlatformDifferences:
    def test_missing_fds_reports_zero_not_a_lost_row(self) -> None:
        """Windows has no num_fds; the sample should still be complete."""
        process = StubProcess()
        process.absent.add("num_fds")
        sample = ResourceMonitor(process, clock=FakeClock()).sample()
        assert sample is not None and sample.open_sockets == 0

    def test_missing_handles_reports_zero(self) -> None:
        process = StubProcess()
        process.absent.add("num_handles")
        sample = ResourceMonitor(process, clock=FakeClock()).sample()
        assert sample is not None and sample.handles == 0

    def test_a_platform_missing_fds_does_not_stop_sampling(self) -> None:
        process = StubProcess()
        process.absent.add("num_fds")
        monitor = ResourceMonitor(process, clock=FakeClock())
        assert monitor.sample() is not None
        assert monitor.sample() is not None
        assert monitor.unavailable_reason is None


class TestFailureHandling:
    def test_a_dead_process_stops_sampling_without_raising(self) -> None:
        """Losing visibility is bad; aborting the measurement over it is worse."""
        process = StubProcess()
        process.broken.add("memory_info")
        monitor = ResourceMonitor(process, clock=FakeClock())
        assert monitor.sample() is None
        assert "resource sampling stopped" in monitor.unavailable_reason

    def test_a_permission_error_also_stops_sampling(self) -> None:
        process = StubProcess()
        process.broken.add("num_threads")
        monitor = ResourceMonitor(process, clock=FakeClock())
        assert monitor.sample() is None
        assert monitor.unavailable_reason

    def test_no_further_samples_after_a_failure(self) -> None:
        process = StubProcess()
        process.broken.add("memory_info")
        monitor = ResourceMonitor(process, clock=FakeClock())
        monitor.sample()
        assert monitor.sample() is None
        assert monitor.samples == []

    def test_the_error_message_survives_into_the_notes(self) -> None:
        """A silent zero column would read as 'the target was idle'."""
        process = StubProcess()
        process.broken.add("memory_info")
        monitor = ResourceMonitor(process, clock=FakeClock())
        monitor.sample()
        assert monitor.unavailable_reason
        assert "memory_info" in monitor.unavailable_reason


class TestNoTarget:
    def test_absent_process_is_unavailable(self) -> None:
        monitor = ResourceMonitor(None)
        assert monitor.available is False
        assert monitor.sample() is None
        assert monitor.unavailable_reason

    def test_the_reason_says_figures_were_not_guessed(self) -> None:
        assert "guessed" in ResourceMonitor(None).unavailable_reason

    def test_no_process_yields_no_samples(self) -> None:
        assert ResourceMonitor(None).samples == []


class TestProcessLookup:
    def test_our_own_pid_is_inspectable(self) -> None:
        import os

        assert process_for_pid(os.getpid()) is not None

    def test_a_bogus_pid_returns_none(self) -> None:
        assert process_for_pid(2**31 - 1) is None

    def test_no_pid_returns_none(self) -> None:
        assert process_for_pid(None) is None

    def test_psutil_is_available_in_this_environment(self) -> None:
        assert psutil_available() is True
