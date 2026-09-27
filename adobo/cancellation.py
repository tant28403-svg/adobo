"""Run lifecycle control: deadlines, cooperative cancellation, and escalation.

A traffic generator that will not stop is worse than no tool at all, so
stopping is treated as a first-class requirement with five independent layers
rather than a single best-effort check:

    1. Deadline       Every worker compares ``monotonic()`` against a deadline
                      on each batch, so a run ends on time with no signal.
    2. Graceful stop  The first Ctrl+C sets the cancel event. Workers finish the
                      batch in flight, the result is finalised and scored, the
                      audit trail records a cancelled ``run_end``.
    3. Hard stop      A second Ctrl+C within the grace window, or a single
                      Ctrl+Break, skips the join waits but still writes the
                      partial result and the audit entry.
    4. Watchdog       If workers have not joined within ``join_grace_s`` the
                      watchdog escalates and the run is marked ``abandoned``.
    5. Last resort    ``os._exit`` after ``escalate_after_s``.

**What layers 4 and 5 can and cannot promise.** CPython cannot kill a thread
that is blocked inside a kernel ``sendto`` on a full socket buffer. Layers 1-3
bound the overshoot to roughly one batch, because a worker can only check the
flag between batches. Layers 4-5 exist for the case where that assumption
breaks: they stop the *process*, which is the only true guarantee available from
inside Python. The socket transports minimise the odds by giving every socket a
send timeout and a small ``SO_SNDBUF``.

The audit trail is written ``run_start`` *before* any socket is opened, so even
an ``os._exit`` leaves a valid record of who ran what against what. That is the
reason escalation is safe.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from types import FrameType

__all__ = [
    "CancelReason",
    "CancellationToken",
    "GracePeriod",
    "RunController",
    "Watchdog",
    "install_signal_handlers",
    "remove_signal_handlers",
    "run_watchdog",
]


class CancelReason(str, Enum):
    """Why a run stopped."""

    NONE = "none"
    DEADLINE = "deadline"
    USER_GRACEFUL = "user_interrupt"
    USER_HARD = "user_force"
    WATCHDOG = "watchdog_timeout"
    ABANDONED = "abandoned"
    ERROR = "error"

    @property
    def is_cancel(self) -> bool:
        return self not in (CancelReason.NONE, CancelReason.DEADLINE)


@dataclass(frozen=True, slots=True)
class GracePeriod:
    """Timing windows for the escalation ladder.

    Defaults are tuned for a person standing at a keyboard: a second Ctrl+C
    within three seconds is a deliberate "I mean it", and five seconds of
    non-response after that is long enough for a stuck ``sendto`` to hit its own
    two second socket timeout but short enough not to feel like a hang.
    """

    second_signal_seconds: float = 3.0
    join_grace_s: float = 5.0
    escalate_after_s: float = 20.0


# --------------------------------------------------------------------------
# Cancellation token
# --------------------------------------------------------------------------


@dataclass
class CancellationToken:
    """A thread-safe, one-way stop signal that records why it fired.

    Deliberately monotonic: once cancelled it stays cancelled, and the reason is
    upgraded (graceful -> hard) but never downgraded, so the audit trail always
    reflects the most serious thing that happened.
    """

    _event: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _reason: CancelReason = field(default=CancelReason.NONE, repr=False)
    _requested_at: float | None = field(default=None, repr=False)
    _message: str = field(default="", repr=False)

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> CancelReason:
        with self._lock:
            return self._reason

    @property
    def message(self) -> str:
        with self._lock:
            return self._message

    @property
    def requested_at(self) -> float | None:
        with self._lock:
            return self._requested_at

    def cancel(self, reason: CancelReason, message: str = "") -> bool:
        """Request cancellation. Returns True if this call was the first.

        The first request wins the reason, except that a hard stop always
        supersedes a graceful one, since "I meant it" is more urgent
        information than "please stop soon".
        """
        with self._lock:
            already_set = self._event.is_set()
            supersedes = (
                reason is CancelReason.USER_HARD
                and self._reason is CancelReason.USER_GRACEFUL
            )
            if not already_set or supersedes:
                self._reason = reason
                self._message = message
                if self._requested_at is None:
                    self._requested_at = time.monotonic()
            if not already_set:
                self._event.set()
            return not already_set

    def wait(self, timeout: float | None = None) -> bool:
        """Block until cancelled or *timeout*. True if cancelled."""
        return self._event.wait(timeout)

    def reset(self) -> None:
        """Re-arm. Only safe before any worker has started observing it."""
        with self._lock:
            self._event.clear()
            self._reason = CancelReason.NONE
            self._requested_at = None
            self._message = ""

    def describe(self) -> dict[str, object]:
        with self._lock:
            return {
                "cancelled": self._event.is_set(),
                "reason": self._reason.value,
                "message": self._message,
                "elapsed_s": (
                    round(time.monotonic() - self._requested_at, 3)
                    if self._requested_at is not None
                    else None
                ),
            }


# --------------------------------------------------------------------------
# Run controller
# --------------------------------------------------------------------------


class RunController:
    """Owns a run's deadline and its cancellation token.

    Workers poll :meth:`should_stop` once per batch; nothing blocks on the token,
    so there is no lock in the hot path and no chance of a worker deadlocking
    against the cancellation logic.
    """

    def __init__(
        self,
        duration_seconds: float,
        *,
        grace: GracePeriod | None = None,
    ) -> None:
        self.grace = grace or GracePeriod()
        self.token = CancellationToken()
        self._duration = duration_seconds
        self._started_at: float | None = None
        self._first_signal_at: float | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._started_at = time.monotonic()

    @property
    def started_at(self) -> float | None:
        return self._started_at

    @property
    def deadline(self) -> float | None:
        if self._started_at is None:
            return None
        return self._started_at + self._duration

    @property
    def elapsed(self) -> float:
        if self._started_at is None:
            return 0.0
        return time.monotonic() - self._started_at

    @property
    def remaining(self) -> float:
        deadline = self.deadline
        if deadline is None:
            return self._duration
        return max(0.0, deadline - time.monotonic())

    @property
    def overran(self) -> bool:
        deadline = self.deadline
        return deadline is not None and time.monotonic() > deadline

    # -- stopping ----------------------------------------------------------

    def should_stop(self) -> bool:
        """Whether a worker should stop after its current batch.

        The deadline is checked here as well as on the token so that a run ends
        on time even if no signal ever arrives - the common case by far.
        """
        if self.token.cancelled:
            return True
        deadline = self.deadline
        if deadline is not None and time.monotonic() >= deadline:
            self.token.cancel(
                CancelReason.DEADLINE,
                f"duration of {self._duration}s elapsed",
            )
            return True
        return False

    def request_stop(self, reason: CancelReason, message: str = "") -> bool:
        return self.token.cancel(reason, message)

    def on_user_interrupt(self) -> None:
        """Handle one Ctrl+C, escalating to a hard stop on a rapid second press."""
        if self._first_signal_at is None:
            self._first_signal_at = time.monotonic()
            self.token.cancel(
                CancelReason.USER_GRACEFUL,
                "interrupted by the operator; stopping after the current batch",
            )
            return

        if time.monotonic() - self._first_signal_at <= self.grace.second_signal_seconds:
            self.token.cancel(
                CancelReason.USER_HARD,
                "second interrupt within "
                f"{self.grace.second_signal_seconds:g}s; forcing an immediate stop",
            )
        else:
            # A slow second press restarts the grace rather than escalating, so
            # an accidental double-tap after a pause does not force a hard stop.
            self._first_signal_at = time.monotonic()
            self.token.cancel(
                CancelReason.USER_GRACEFUL,
                "interrupted again; stopping after the current batch",
            )

    def on_user_force(self) -> None:
        """Handle Ctrl+Break, which on Windows means 'stop now' unconditionally."""
        self.token.cancel(
            CancelReason.USER_HARD, "Ctrl+Break pressed; forcing an immediate stop"
        )

    @property
    def should_escalate(self) -> bool:
        """True once a hard stop has had ``escalate_after_s`` to take effect."""
        if self.token.reason is not CancelReason.USER_HARD:
            return False
        requested = self.token.requested_at
        if requested is None:
            return False
        return (time.monotonic() - requested) >= self.grace.escalate_after_s

    @property
    def should_mark_abandoned(self) -> bool:
        """True when a hard stop has outlived the join grace period."""
        if not self.token.cancelled:
            return False
        requested = self.token.requested_at
        if requested is None:
            return False
        return (time.monotonic() - requested) >= self.grace.join_grace_s

    def describe(self) -> dict[str, object]:
        return {
            "duration_s": self._duration,
            "elapsed_s": round(self.elapsed, 3),
            "remaining_s": round(self.remaining, 3),
            "overran": self.overran,
            "cancellation": self.token.describe(),
        }


# --------------------------------------------------------------------------
# Watchdog
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Watchdog:
    """Handle for a running escalation thread."""

    thread: threading.Thread
    stop_event: threading.Event

    def stop(self, timeout: float = 1.0) -> None:
        """Ask the watchdog to finish. Never joins indefinitely."""
        self.stop_event.set()
        self.thread.join(timeout=timeout)

    @property
    def alive(self) -> bool:
        return self.thread.is_alive()


def run_watchdog(
    controller: RunController,
    on_abandoned,
    *,
    poll_interval: float = 0.25,
) -> Watchdog:
    """Start a daemon thread that escalates if a run will not stop.

    *on_abandoned* is called once, when the join grace period is exceeded, so
    the caller can record ``abandoned`` in the audit trail before the process is
    torn down.
    """
    finished = threading.Event()
    abandoned_fired = threading.Event()
    escalated = threading.Event()

    def loop() -> None:
        while not finished.wait(poll_interval):
            if not controller.token.cancelled:
                continue
            if controller.should_mark_abandoned and not abandoned_fired.is_set():
                abandoned_fired.set()
                try:
                    on_abandoned()
                except Exception:  # pragma: no cover - reporting must not mask
                    pass
            # Latched, because escalation is a once-per-process event. With
            # os._exit the call never returns, so the latch is invisible in
            # production - but relying on that hides the invariant, and anything
            # that made _hard_exit recoverable would re-enter on every poll.
            if controller.should_escalate and not escalated.is_set():
                escalated.set()
                _hard_exit()

    thread = threading.Thread(target=loop, name="ddosim-watchdog", daemon=True)
    thread.start()
    return Watchdog(thread=thread, stop_event=finished)


def _hard_exit(code: int = 130) -> None:
    """Terminate immediately, bypassing interpreter cleanup.

    This is the last of the five layers. It is abrupt by design: cleanup code
    that runs during shutdown could itself block, which is the precise failure
    this layer exists to escape. The audit trail is already on disk.
    """
    sys.stderr.write(
        "\n[ddosim] Workers did not stop in time. Terminating the process now.\n"
        "          The audit trail in logs/audit.jsonl is complete up to run_start.\n"
    )
    sys.stderr.flush()
    os._exit(code)


# --------------------------------------------------------------------------
# Signal wiring
# --------------------------------------------------------------------------


def install_signal_handlers(controller: RunController) -> dict[int, object]:
    """Route Ctrl+C and Ctrl+Break into *controller*.

    Returns the previous handlers so they can be restored. If the process is not
    on the main thread - which is how the tests run - installation is skipped and
    an empty mapping returned, because ``signal.signal`` only works there.
    """
    if threading.current_thread() is not threading.main_thread():
        return {}

    previous: dict[int, object] = {}

    def _sigint(_signum: int, _frame: FrameType | None) -> None:
        controller.on_user_interrupt()

    previous[signal.SIGINT] = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _sigint)

    # Ctrl+Break is the reliable "stop now" on a Windows console. SIGTERM gets
    # the same treatment so a supervisor's timeout is a graceful stop, not a
    # surprise hard kill.
    sigbreak = getattr(signal, "SIGBREAK", None)
    if sigbreak is not None:
        previous[sigbreak] = signal.getsignal(sigbreak)
        signal.signal(sigbreak, lambda *_args: controller.on_user_force())

    sigterm = getattr(signal, "SIGTERM", None)
    if sigterm is not None:
        previous[sigterm] = signal.getsignal(sigterm)
        signal.signal(sigterm, lambda *_args: controller.on_user_interrupt())

    return previous


def remove_signal_handlers(previous: dict[int, object]) -> None:
    """Restore handlers captured by :func:`install_signal_handlers`."""
    if threading.current_thread() is not threading.main_thread():
        return
    for signum, handler in previous.items():
        try:
            signal.signal(signum, handler)  # type: ignore[arg-type]
        except (OSError, ValueError, TypeError):  # pragma: no cover - defensive
            pass
