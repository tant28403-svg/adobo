"""Tests for deadlines, cancellation and the escalation ladder.

The stop guarantee is the most safety-critical behaviour in the tool, so these
tests assert it at every layer rather than only the happy path. The escalation
layer calls ``os._exit``, which would kill the test runner, so
``adobo.cancellation._hard_exit`` is always monkeypatched before it can fire.
"""

from __future__ import annotations

import threading
import time

import pytest

from adobo.cancellation import (
    CancelReason,
    CancellationToken,
    GracePeriod,
    RunController,
    install_signal_handlers,
    remove_signal_handlers,
    run_watchdog,
)


# ---------------------------------------------------------------------------
# CancellationToken
# ---------------------------------------------------------------------------


class TestCancellationToken:
    def test_starts_uncancelled(self) -> None:
        token = CancellationToken()
        assert token.cancelled is False
        assert token.reason is CancelReason.NONE
        assert token.requested_at is None

    def test_first_cancel_wins(self) -> None:
        token = CancellationToken()
        assert token.cancel(CancelReason.DEADLINE, "first") is True
        token.cancel(CancelReason.WATCHDOG, "second")
        assert token.reason is CancelReason.DEADLINE
        assert token.message == "first"

    def test_hard_stop_supersedes_graceful(self) -> None:
        """'I mean it' must survive a later bookkeeping reason overwriting it."""
        token = CancellationToken()
        token.cancel(CancelReason.USER_GRACEFUL)
        token.cancel(CancelReason.USER_HARD, "forced")
        assert token.reason is CancelReason.USER_HARD
        assert token.message == "forced"

    def test_hard_stop_does_not_downgrade_to_later_graceful(self) -> None:
        token = CancellationToken()
        token.cancel(CancelReason.USER_HARD)
        token.cancel(CancelReason.USER_GRACEFUL)
        assert token.reason is CancelReason.USER_HARD

    def test_only_the_first_call_reports_true(self) -> None:
        token = CancellationToken()
        assert token.cancel(CancelReason.DEADLINE) is True
        assert token.cancel(CancelReason.DEADLINE) is False

    def test_wait_returns_immediately_once_cancelled(self) -> None:
        token = CancellationToken()
        token.cancel(CancelReason.DEADLINE)
        assert token.wait(5.0) is True

    def test_wait_times_out_while_running(self) -> None:
        assert CancellationToken().wait(0.05) is False

    def test_wait_wakes_another_thread(self) -> None:
        token = CancellationToken()
        woke = threading.Event()

        def waiter() -> None:
            token.wait(5.0)
            woke.set()

        thread = threading.Thread(target=waiter, daemon=True)
        thread.start()
        time.sleep(0.05)
        token.cancel(CancelReason.USER_GRACEFUL)
        assert woke.wait(2.0) is True
        thread.join(timeout=1.0)

    def test_requested_at_records_the_first_moment(self) -> None:
        token = CancellationToken()
        assert token.requested_at is None
        token.cancel(CancelReason.DEADLINE)
        first = token.requested_at
        time.sleep(0.02)
        token.cancel(CancelReason.USER_HARD)
        assert token.requested_at == first

    def test_describe_is_serialisable(self) -> None:
        token = CancellationToken()
        token.cancel(CancelReason.DEADLINE, "elapsed")
        described = token.describe()
        assert described["cancelled"] is True
        assert described["reason"] == "deadline"
        assert described["elapsed_s"] is not None

    def test_reset_re_arms(self) -> None:
        token = CancellationToken()
        token.cancel(CancelReason.DEADLINE)
        token.reset()
        assert token.cancelled is False
        assert token.reason is CancelReason.NONE

    def test_concurrent_cancels_leave_a_single_reason(self) -> None:
        token = CancellationToken()
        reasons = [
            CancelReason.DEADLINE,
            CancelReason.USER_GRACEFUL,
            CancelReason.WATCHDOG,
            CancelReason.ERROR,
        ]
        barrier = threading.Barrier(len(reasons))

        def racer(reason: CancelReason) -> None:
            barrier.wait()
            token.cancel(reason)

        threads = [
            threading.Thread(target=racer, args=(r,)) for r in reasons
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2.0)
        assert token.cancelled is True
        assert token.reason in reasons


# ---------------------------------------------------------------------------
# CancelReason
# ---------------------------------------------------------------------------


class TestCancelReason:
    @pytest.mark.parametrize(
        "reason,expected",
        [
            (CancelReason.NONE, False),
            (CancelReason.DEADLINE, False),
            (CancelReason.USER_GRACEFUL, True),
            (CancelReason.USER_HARD, True),
            (CancelReason.WATCHDOG, True),
            (CancelReason.ABANDONED, True),
            (CancelReason.ERROR, True),
        ],
    )
    def test_is_cancel(self, reason: CancelReason, expected: bool) -> None:
        assert reason.is_cancel is expected

    def test_a_met_deadline_is_not_a_cancellation(self) -> None:
        """Finishing on time is success, and must not exit 130."""
        assert CancelReason.DEADLINE.is_cancel is False


# ---------------------------------------------------------------------------
# RunController
# ---------------------------------------------------------------------------


class TestRunController:
    def test_before_start_there_is_no_deadline(self) -> None:
        controller = RunController(5.0)
        assert controller.deadline is None
        assert controller.elapsed == 0.0
        assert controller.remaining == 5.0

    def test_deadline_is_start_plus_duration(self) -> None:
        controller = RunController(5.0)
        controller.start()
        assert controller.deadline is not None
        assert 4.9 <= controller.remaining <= 5.0

    def test_does_not_stop_before_the_deadline(self) -> None:
        controller = RunController(5.0)
        controller.start()
        assert controller.should_stop() is False

    def test_stops_once_the_deadline_passes(self) -> None:
        controller = RunController(0.15)
        controller.start()
        time.sleep(0.25)
        assert controller.should_stop() is True

    def test_expiry_records_the_deadline_reason(self) -> None:
        controller = RunController(0.1)
        controller.start()
        time.sleep(0.2)
        controller.should_stop()
        assert controller.token.reason is CancelReason.DEADLINE

    def test_remaining_never_goes_negative(self) -> None:
        controller = RunController(0.05)
        controller.start()
        time.sleep(0.15)
        assert controller.remaining == 0.0
        assert controller.overran is True

    def test_first_interrupt_is_graceful(self) -> None:
        controller = RunController(60.0)
        controller.start()
        controller.on_user_interrupt()
        assert controller.token.reason is CancelReason.USER_GRACEFUL
        assert controller.should_stop() is True

    def test_second_interrupt_inside_the_window_is_hard(self) -> None:
        controller = RunController(60.0)
        controller.start()
        controller.on_user_interrupt()
        controller.on_user_interrupt()
        assert controller.token.reason is CancelReason.USER_HARD

    def test_slow_second_interrupt_stays_graceful(self) -> None:
        """A double-tap after a pause must not force a hard stop."""
        controller = RunController(60.0, grace=GracePeriod(second_signal_seconds=0.1))
        controller.start()
        controller.on_user_interrupt()
        time.sleep(0.2)
        controller.on_user_interrupt()
        assert controller.token.reason is CancelReason.USER_GRACEFUL

    def test_force_is_always_hard(self) -> None:
        controller = RunController(60.0)
        controller.start()
        controller.on_user_force()
        assert controller.token.reason is CancelReason.USER_HARD

    def test_abandonment_waits_out_the_join_grace(self) -> None:
        controller = RunController(60.0, grace=GracePeriod(join_grace_s=0.1))
        controller.start()
        controller.on_user_force()
        assert controller.should_mark_abandoned is False
        time.sleep(0.15)
        assert controller.should_mark_abandoned is True

    def test_escalation_waits_out_its_own_window(self) -> None:
        controller = RunController(
            60.0, grace=GracePeriod(join_grace_s=0.05, escalate_after_s=0.2)
        )
        controller.start()
        controller.on_user_force()
        time.sleep(0.1)
        assert controller.should_escalate is False
        time.sleep(0.2)
        assert controller.should_escalate is True

    def test_graceful_stop_never_escalates(self) -> None:
        controller = RunController(60.0, grace=GracePeriod(escalate_after_s=0.0))
        controller.start()
        controller.on_user_interrupt()
        time.sleep(0.05)
        assert controller.should_escalate is False

    def test_running_stop_never_escalates(self) -> None:
        controller = RunController(60.0, grace=GracePeriod(escalate_after_s=0.0))
        controller.start()
        time.sleep(0.05)
        assert controller.should_escalate is False
        assert controller.should_mark_abandoned is False

    def test_describe_is_serialisable(self) -> None:
        controller = RunController(3.0)
        controller.start()
        described = controller.describe()
        assert described["duration_s"] == 3.0
        assert "cancellation" in described


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------


class TestWatchdog:
    def test_calls_back_once_the_join_grace_expires(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        controller = RunController(60.0, grace=GracePeriod(join_grace_s=0.1))
        controller.start()
        controller.on_user_force()
        watchdog = run_watchdog(
            controller, lambda: calls.append("abandoned"), poll_interval=0.02
        )
        try:
            time.sleep(0.35)
        finally:
            watchdog.stop()
        assert calls == ["abandoned"], "should fire exactly once, not repeatedly"

    def test_stays_quiet_while_the_run_is_healthy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("adobo.cancellation._hard_exit", lambda *a: None)
        calls: list[str] = []
        controller = RunController(0.2)
        controller.start()
        watchdog = run_watchdog(
            controller, lambda: calls.append("abandoned"), poll_interval=0.02
        )
        try:
            time.sleep(0.5)
        finally:
            watchdog.stop()
        assert calls == []

    def test_escalates_only_after_its_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exits: list[int] = []
        monkeypatch.setattr(
            "adobo.cancellation._hard_exit", lambda code=130: exits.append(code)
        )
        controller = RunController(
            60.0, grace=GracePeriod(join_grace_s=0.02, escalate_after_s=0.08)
        )
        controller.start()
        controller.on_user_force()
        watchdog = run_watchdog(controller, lambda: None, poll_interval=0.02)
        try:
            deadline = time.monotonic() + 2.0
            while not exits and time.monotonic() < deadline:
                time.sleep(0.02)
        finally:
            watchdog.stop()
        assert exits == [130], "should escalate to a hard exit exactly once"

    def test_stop_is_idempotent(self) -> None:
        controller = RunController(60.0)
        controller.start()
        watchdog = run_watchdog(controller, lambda: None, poll_interval=0.05)
        watchdog.stop()
        watchdog.stop()
        assert watchdog.alive is False

    def test_watchdog_is_a_daemon(self) -> None:
        controller = RunController(60.0)
        controller.start()
        watchdog = run_watchdog(controller, lambda: None, poll_interval=0.05)
        try:
            assert watchdog.thread.daemon is True
        finally:
            watchdog.stop()


# ---------------------------------------------------------------------------
# Signal wiring
# ---------------------------------------------------------------------------


class TestSignalHandlers:
    def test_installation_is_a_no_op_off_the_main_thread(self) -> None:
        """signal.signal only works on the main thread, and must degrade quietly.

        Checked from a genuinely spawned thread rather than assumed, because
        pytest happens to drive this suite from the main thread.
        """
        result: dict[int, object] = {}

        def attempt() -> None:
            result.update(install_signal_handlers(RunController(1.0)))

        thread = threading.Thread(target=attempt)
        thread.start()
        thread.join(timeout=2.0)
        assert result == {}

    def test_round_trip_on_the_main_thread(self) -> None:
        import signal

        assert threading.current_thread() is threading.main_thread()
        previous = signal.getsignal(signal.SIGINT)
        installed = install_signal_handlers(RunController(1.0))
        try:
            assert signal.SIGINT in installed
            assert signal.getsignal(signal.SIGINT) is not previous
        finally:
            remove_signal_handlers(installed)
        assert signal.getsignal(signal.SIGINT) is previous

    def test_registers_sigbreak_on_windows(self) -> None:
        import signal

        installed = install_signal_handlers(RunController(1.0))
        try:
            if hasattr(signal, "SIGBREAK"):
                assert signal.SIGBREAK in installed
        finally:
            remove_signal_handlers(installed)

    def test_sigint_reaches_the_controller(self) -> None:
        import signal

        if threading.current_thread() is not threading.main_thread():
            pytest.skip("signal delivery requires the main thread")
        controller = RunController(60.0)
        installed = install_signal_handlers(controller)
        try:
            signal.raise_signal(signal.SIGINT)
        finally:
            remove_signal_handlers(installed)
        assert controller.token.reason is CancelReason.USER_GRACEFUL

    def test_restore_tolerates_a_bogus_handler(self) -> None:
        import signal

        remove_signal_handlers({signal.SIGINT: "not-a-handler"})
