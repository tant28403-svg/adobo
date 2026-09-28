"""Tests for reading the target's own counters.

Without these, a run against a remote host has no target-side evidence at all,
and the only number in the result is the sender's own packet count. These tests
pin down the behaviour that makes the difference meaningful:

* a failed read is reported as unobserved, never as zero;
* the reported figure is a delta across the window, not an absolute;
* a shrinking counter reads as zero, because a restarted target must not be
  reported as having served negative requests.
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from adobo.observation import TargetObserver


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StatsHandler(BaseHTTPRequestHandler):
    """Serves a mutable request/error pair, standing in for the lab target."""

    requests = 0
    errors = 0
    requests_path = "/stats"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        if self.path != self.requests_path:
            self.send_error(404)
            return
        body = json.dumps(
            {"status": "ok", "requests": self.requests, "errors": self.errors}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def stats_server():
    """A real HTTP server on loopback serving /stats, plus its mutable state."""
    handler = type("Handler", (_StatsHandler,), {"requests": 0, "errors": 0})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, handler
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def closed_port() -> int:
    """A port with nothing listening, for the unreachable-target case."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestRead:
    async def test_it_returns_the_targets_own_counters(self, stats_server) -> None:
        server, handler = stats_server
        handler.requests = 41
        handler.errors = 2
        observer = TargetObserver("127.0.0.1", server.server_address[1])
        assert await observer.read() == (41, 2)

    async def test_an_unreachable_target_is_unobserved_not_zero(
        self, closed_port: int
    ) -> None:
        """The distinction that makes the figure worth reporting.

        Zero would mean "the target served nothing". Unobserved means "we could
        not ask". Collapsing them makes an unmeasurable run look like a
        devastating one, or vice versa.
        """
        observer = TargetObserver("127.0.0.1", closed_port, timeout=0.3)
        assert await observer.read() is None

    async def test_a_failed_read_records_why(self, closed_port: int) -> None:
        """A report of 'no evidence' without a reason cannot be acted on."""
        observer = TargetObserver("127.0.0.1", closed_port, timeout=0.3)
        await observer.read()
        assert observer._last_error

    async def test_a_payload_without_counters_is_unobserved(self) -> None:
        async def fetch(timeout: float | None = None) -> dict:
            return {"status": "ok"}

        observer = TargetObserver("127.0.0.1", 1, fetch=fetch)
        assert await observer.read() is None
        assert "missing request counters" in (observer._last_error or "")

    async def test_a_non_numeric_counter_is_unobserved(self) -> None:
        async def fetch(timeout: float | None = None) -> dict:
            return {"requests": "many", "errors": 0}

        observer = TargetObserver("127.0.0.1", 1, fetch=fetch)
        assert await observer.read() is None

    async def test_a_404_is_unobserved(self, closed_port: int) -> None:
        """A target that does not serve /stats at all, e.g. a third-party host."""
        s = ThreadingHTTPServer(("127.0.0.1", 0), _NoStatsHandler)
        thread = threading.Thread(target=s.serve_forever, daemon=True)
        thread.start()
        try:
            observer = TargetObserver("127.0.0.1", s.server_address[1], timeout=1.0)
            assert await observer.read() is None
        finally:
            s.shutdown()
            s.server_close()


class _NoStatsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_error(404)

    def log_message(self, *args: object) -> None:
        pass


class TestWindow:
    def test_it_reports_the_delta_not_the_absolute(self) -> None:
        """The target may have been serving before the run began.

        An absolute count would attribute someone else's requests to this run.
        """
        observer = TargetObserver("127.0.0.1", 1)
        stats = observer.window_sync((10_000, 5), (10_750, 9))
        assert stats.requests_served == 750
        assert stats.errors_served == 4

    def test_a_complete_window_is_observed(self) -> None:
        observer = TargetObserver("127.0.0.1", 1)
        assert observer.window_sync((0, 0), (5, 0)).stats_observed is True

    def test_a_missing_read_is_not_observed(self) -> None:
        observer = TargetObserver("127.0.0.1", 1)
        assert observer.window_sync(None, (5, 0)).stats_observed is False

    def test_a_missing_closing_read_is_not_observed(self) -> None:
        """Half a measurement is not a measurement, and must not read as zero."""
        observer = TargetObserver("127.0.0.1", 1)
        stats = observer.window_sync((0, 0), None)
        assert stats.stats_observed is False
        assert stats.requests_served == 0

    def test_an_unobserved_window_carries_a_reason(self) -> None:
        observer = TargetObserver("127.0.0.1", 1)
        assert observer.window_sync(None, None).stats_error

    def test_a_restarted_target_reads_as_zero_not_negative(self) -> None:
        """Counters reset when a target restarts mid-run.

        Without the clamp the report says the target served -400 requests, which
        is not a number anything can mean.
        """
        observer = TargetObserver("127.0.0.1", 1)
        stats = observer.window_sync((500, 10), (100, 0))
        assert stats.requests_served == 0
        assert stats.errors_served == 0

    def test_the_sync_alias_is_the_same_function(self) -> None:
        """Callers written against the async name must get the sync behaviour."""
        observer = TargetObserver("127.0.0.1", 1)
        assert observer.window((0, 0), (3, 1)).requests_served == 3


class TestAlive:
    async def test_a_responding_target_is_alive(self, stats_server) -> None:
        server, _ = stats_server
        observer = TargetObserver("127.0.0.1", server.server_address[1])
        assert await observer.alive() is True

    async def test_an_unreachable_target_is_not_alive(self, closed_port: int) -> None:
        observer = TargetObserver("127.0.0.1", closed_port, timeout=0.3)
        assert await observer.alive(0.3) is False

    async def test_unavailability_is_not_an_error(self, closed_port: int) -> None:
        """A target that is down is the measurement, not a fault in the prober."""
        observer = TargetObserver("127.0.0.1", closed_port, timeout=0.3)
        assert await observer.alive(0.3) is False

    async def test_a_failure_records_why(self, closed_port: int) -> None:
        """The reason is kept, because a boolean cannot report one.

        Callers have to distinguish a target that collapsed from a port that
        never served anything, and both arrive here as plain False.
        """
        observer = TargetObserver("127.0.0.1", closed_port, timeout=0.3)
        assert observer.last_probe_error is None, "no sample taken yet"
        assert await observer.alive(0.3) is False
        assert observer.last_probe_error
        assert observer.last_probe_error.split(":")[0].strip()

    async def test_success_clears_the_previous_failure(self, stats_server) -> None:
        """The attribute must describe the latest sample, not the latest failure."""
        server, _ = stats_server
        observer = TargetObserver("127.0.0.1", server.server_address[1])
        await observer.alive()
        assert observer.last_probe_error is None

    async def test_a_failure_does_not_disturb_the_stats_error(self, closed_port: int) -> None:
        """read() and alive() track different things and must not share state.

        _last_error describes the /stats payload; last_probe_error describes
        reachability. Conflating them would let a probe overwrite the reason the
        delivery report gives for having no target-side evidence.
        """
        observer = TargetObserver("127.0.0.1", closed_port, timeout=0.3)
        assert await observer.alive(0.3) is False
        assert observer.last_probe_error
        assert observer._last_error is None
