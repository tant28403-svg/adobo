"""Tests for the run engine.

Runs here use the VIRTUAL transport, so the numbers are exact and no packet ever
leaves the process: a 1000 pps / 2 s run must report 2000 sent, not "about 2000".
That determinism is what makes the pacing, aggregation and cancellation logic
assertable at all.

Wall-clock assertions are deliberately loose. They exist to prove the engine
*stops when it says it will*, not to benchmark the machine.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import pytest

from adobo.cancellation import CancelReason, GracePeriod, RunController
from adobo.engine import (
    EngineHooks,
    RunEngine,
    RunOutcome,
    TARGET_PLAIN,
    TARGET_TLS_H2,
    TARGET_UNKNOWN,
)
from adobo.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TransportKind,
)
from adobo.scoring import score_run
from adobo.transports import TransportCounters

TARGET = Target(host="127.0.0.1", port=8000)


def make_config(
    *,
    duration: float = 0.5,
    pps: int = 1000,
    workers: int = 2,
    payload_size: int = 64,
    transport: TransportKind = TransportKind.VIRTUAL,
    dry_run: bool = False,
    profile: ProfileName = ProfileName.UDP_FLOOD,
) -> RunConfig:
    return RunConfig(
        target=TARGET,
        attack=AttackProfile(
            profile=profile,
            pps=pps,
            duration_seconds=duration,
            payload_size=payload_size,
            workers=workers,
        ),
        transport=transport,
        dry_run=dry_run,
    )


def make_engine(config: RunConfig, **kwargs) -> RunEngine:
    return RunEngine(config, **kwargs)


@pytest.fixture(autouse=True)
def _no_clamping(monkeypatch):
    """Run these tests at the values they ask for.

    The engine caps a run to the lab.yaml ceilings, which would quietly lower
    the duration and payload some of these tests rely on. The guard is replaced
    with permissive limits so each test measures the engine rather than the
    policy. Ceiling behaviour has its own tests in test_safety.py.
    """
    from adobo.config import LabConfig, LimitsConfig
    from adobo.safety import SafetyGuard

    def permissive(self, lab=None):
        object.__setattr__(
            self,
            "lab",
            lab
            or LabConfig(
                limits=LimitsConfig(
                    max_pps=10_000_000,
                    max_duration_seconds=3600,
                    max_payload_bytes=65_507,
                    max_workers=1000,
                )
            ),
        )

    monkeypatch.setattr(SafetyGuard, "__init__", permissive)


# ---------------------------------------------------------------------------
# Running to the deadline
# ---------------------------------------------------------------------------


class TestDeadline:
    def test_stops_on_its_own_within_a_tolerance(self) -> None:
        started = time.monotonic()
        outcome = make_engine(make_config(duration=0.4)).run()
        elapsed = time.monotonic() - started
        assert elapsed < 1.5, f"run overran badly: {elapsed:.2f}s"
        assert outcome.reason is CancelReason.DEADLINE
        assert outcome.cancelled is False
        assert outcome.exit_code == 0

    def test_meeting_the_deadline_is_not_a_cancellation(self) -> None:
        outcome = make_engine(make_config(duration=0.3)).run()
        assert outcome.reason is CancelReason.DEADLINE
        assert "cancel" not in " ".join(outcome.result.notes).lower()

    def test_paces_the_requested_rate(self) -> None:
        """1000 pps for 1s should be ~1000 packets, and the VIRTUAL transport is
        exact, so a wide band still catches gross pacing errors."""
        outcome = make_engine(make_config(duration=1.0, pps=1000)).run()
        sent = outcome.result.attack.packets_sent
        assert 800 <= sent <= 1200, f"expected ~1000 packets, got {sent}"

    def test_pps_scales_with_the_request(self) -> None:
        slow = make_engine(make_config(duration=0.5, pps=200)).run()
        fast = make_engine(make_config(duration=0.5, pps=2000)).run()
        assert fast.result.attack.packets_sent > slow.result.attack.packets_sent * 3

    def test_rate_is_shared_across_workers(self) -> None:
        """Total pps is the sum, so worker count must not multiply the rate."""
        one = make_engine(make_config(duration=0.6, pps=600, workers=1)).run()
        four = make_engine(make_config(duration=0.6, pps=600, workers=4)).run()
        one_rate = one.result.attack.achieved_pps
        four_rate = four.result.attack.achieved_pps
        assert 0.5 < four_rate / one_rate < 2.0, (
            f"worker count changed the aggregate rate: {one_rate} vs {four_rate}"
        )

    def test_records_how_long_it_actually_ran(self) -> None:
        outcome = make_engine(make_config(duration=0.4)).run()
        actual = outcome.result.attack.duration_actual_s
        assert 0.3 <= actual <= 1.2

    def test_achieved_pps_is_derived_from_the_actual_duration(self) -> None:
        outcome = make_engine(make_config(duration=0.5, pps=1000)).run()
        attack = outcome.result.attack
        assert attack.achieved_pps == round(
            attack.packets_sent / attack.duration_actual_s, 2
        )


# ---------------------------------------------------------------------------
# Counter aggregation
# ---------------------------------------------------------------------------


class TestCounters:
    def test_counts_survive_worker_exit(self) -> None:
        """The regression that retired workers must not lose their totals."""
        outcome = make_engine(make_config(duration=0.5, workers=3)).run()
        assert outcome.result.attack.packets_attempted > 0
        assert outcome.result.attack.packets_sent == outcome.result.attack.packets_attempted

    def test_attempted_is_never_below_sent(self) -> None:
        outcome = make_engine(make_config(duration=0.5)).run()
        attack = outcome.result.attack
        assert attack.packets_attempted >= attack.packets_sent

    def test_bytes_track_payload_size(self) -> None:
        outcome = make_engine(make_config(duration=0.4, payload_size=100)).run()
        attack = outcome.result.attack
        assert attack.bytes_sent == attack.packets_sent * 100

    def test_virtual_transport_reports_no_errors(self) -> None:
        outcome = make_engine(make_config(duration=0.3)).run()
        assert outcome.result.attack.errors == 0

    def test_emits_at_least_one_counter_sample(self) -> None:
        """A run shorter than the sample interval must still produce a series."""
        outcome = make_engine(make_config(duration=0.15)).run()
        assert len(outcome.result.counter_samples) >= 1

    def test_samples_are_ordered_and_monotonic_in_time(self) -> None:
        outcome = make_engine(make_config(duration=0.6)).run()
        times = [s.t for s in outcome.result.counter_samples]
        assert times == sorted(times)

    def test_final_sample_totals_match_the_run(self) -> None:
        outcome = make_engine(make_config(duration=0.6)).run()
        last = outcome.result.counter_samples[-1]
        assert last.packets_sent == outcome.result.attack.packets_sent

    def test_reported_worker_count_is_plausible(self) -> None:
        outcome = make_engine(make_config(duration=0.6, workers=3)).run()
        counts = {s.active_workers for s in outcome.result.counter_samples}
        assert counts <= {0, 1, 2, 3}


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


class TestCancellation:
    def test_graceful_cancel_stops_the_run_early(self) -> None:
        controller = RunController(30.0)
        config = make_config(duration=30.0, pps=2000)
        engine = make_engine(config, controller=controller)

        def canceller() -> None:
            time.sleep(0.3)
            controller.on_user_interrupt()

        thread = threading.Thread(target=canceller, daemon=True)
        thread.start()
        started = time.monotonic()
        outcome = engine.run()
        elapsed = time.monotonic() - started
        thread.join(timeout=2.0)

        assert elapsed < 5.0, "a 30s run cancelled at 0.3s should stop promptly"
        assert outcome.cancelled is True
        assert outcome.reason is CancelReason.USER_GRACEFUL
        assert outcome.exit_code == 130

    def test_hard_cancel_is_recorded(self) -> None:
        controller = RunController(30.0)
        engine = make_engine(make_config(duration=30.0), controller=controller)

        def canceller() -> None:
            time.sleep(0.2)
            controller.on_user_interrupt()
            controller.on_user_interrupt()  # second press inside the window

        thread = threading.Thread(target=canceller, daemon=True)
        thread.start()
        outcome = engine.run()
        thread.join(timeout=2.0)
        assert outcome.reason is CancelReason.USER_HARD

    def test_force_break_is_hard(self) -> None:
        controller = RunController(30.0)
        engine = make_engine(make_config(duration=30.0), controller=controller)

        def breaker() -> None:
            time.sleep(0.2)
            controller.on_user_force()

        thread = threading.Thread(target=breaker, daemon=True)
        thread.start()
        outcome = engine.run()
        thread.join(timeout=2.0)
        assert outcome.reason is CancelReason.USER_HARD

    def test_cancelled_run_still_reports_what_it_sent(self) -> None:
        """Partial data is the point of a graceful stop, not a loss."""
        controller = RunController(30.0)
        engine = make_engine(make_config(duration=30.0, pps=2000), controller=controller)

        def canceller() -> None:
            time.sleep(0.3)
            controller.on_user_interrupt()

        thread = threading.Thread(target=canceller, daemon=True)
        thread.start()
        outcome = engine.run()
        thread.join(timeout=2.0)
        assert outcome.result.attack.packets_sent > 0

    def test_cancellation_is_noted_in_the_result(self) -> None:
        controller = RunController(30.0)
        engine = make_engine(make_config(duration=30.0), controller=controller)
        threading.Timer(0.2, controller.on_user_interrupt).start()
        outcome = engine.run()
        assert any("cancel" in note.lower() for note in outcome.result.notes)

    def test_run_with_a_stuck_worker_is_marked_abandoned(self) -> None:
        """Layer 4: a worker that ignores the stop must be surfaced, not hidden."""
        controller = RunController(
            30.0, grace=GracePeriod(join_grace_s=0.1, escalate_after_s=60.0)
        )
        engine = make_engine(make_config(duration=30.0), controller=controller)

        # A worker that blocks in send and ignores the deadline entirely.
        started = threading.Event()

        def stuck() -> None:
            started.set()
            time.sleep(30.0)

        thread = threading.Thread(target=stuck, daemon=True, name="adobo-worker-stuck")
        engine._start_workers = lambda: [thread]  # type: ignore[method-assign]
        thread.start()
        assert started.wait(2.0)

        abandoned: list[bool] = []
        engine.set_abandon_hook(lambda: abandoned.append(True))
        controller.request_stop(CancelReason.USER_HARD, "test")

        outcome = engine.run()

        assert abandoned == [True], "abandon hook should have fired"
        assert outcome.abandoned is True
        assert any("Abandoned" in note for note in outcome.result.notes)


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class TestFailureHandling:
    """A target the transport cannot open at all.

    Two separate mechanisms are being avoided here, both of which used to be
    reached by aiming at an unresolvable name. The safety gate now refuses a
    name it cannot resolve (correct - it cannot show the scope covers the
    target). And a *resolvable* host that merely refuses connections is
    ``PeerUnavailable``, which the engine treats as the lab's central
    observation rather than a fault, so it never reaches the worker-error hook.

    A missing raw capability is used instead: it fails in transport
    construction, which is the path these tests are about, and it is chosen
    here because it is deterministic on every platform.
    """

    @staticmethod
    def _unopenable(config: RunConfig) -> RunConfig:
        return config.model_copy(
            update={"transport": TransportKind.LINUX_RAW}
        )

    def _unreachable(self, config: RunConfig) -> RunConfig:
        return self._unopenable(config)

    def test_unresolvable_target_does_not_hang(self) -> None:
        config = make_config(duration=0.3, transport=TransportKind.SOCKET)
        config = self._unreachable(config)
        started = time.monotonic()
        outcome = make_engine(config).run()
        assert time.monotonic() - started < 5.0
        assert outcome.reason is CancelReason.ERROR
        assert outcome.cancelled is True

    def test_worker_errors_are_surfaced_as_notes(self) -> None:
        config = make_config(duration=0.2, transport=TransportKind.SOCKET)
        config = self._unreachable(config)
        outcome = make_engine(config).run()
        assert any("error" in note.lower() for note in outcome.result.notes)

    def test_worker_error_hook_is_called(self) -> None:
        seen: list[BaseException] = []
        config = make_config(duration=0.2, transport=TransportKind.SOCKET)
        config = self._unreachable(config)
        engine = make_engine(config, hooks=EngineHooks(on_worker_error=seen.append))
        engine.run()
        assert seen, "the CLI needs to be able to report transport failures"

    def test_result_is_still_built_after_a_failure(self) -> None:
        config = make_config(duration=0.2, transport=TransportKind.SOCKET)
        config = self._unreachable(config)
        outcome = make_engine(config).run()
        assert outcome.result.run_id
        # The result records the transport that was attempted, so a failure is
        # still attributable to a specific transport rather than to "a run".
        assert outcome.result.attack.transport is TransportKind.LINUX_RAW


class TestDeadTargetIsMeasuredNotAborted:
    """A target that is already down must produce a measurement, not an error.

    Before this behaviour, a refused connection aborted the run before any
    probes were taken, so a resilience lab could never report 'the target fell
    over'. Now the run proceeds, the prober measures the target's availability
    as zero, and the result notes explain that nothing was delivered because the
    target was already down.
    """

    @staticmethod
    def closed_tcp_port() -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def _config_for_dead_tcp(self, duration: float = 0.5) -> RunConfig:
        port = self.closed_tcp_port()
        return make_config(
            duration=duration,
            transport=TransportKind.SOCKET,
            profile=ProfileName.HTTP_FLOOD,
        ).model_copy(update={"target": Target(host="127.0.0.1", port=port)})

    def test_a_refused_tcp_target_is_measured_not_aborted(self) -> None:
        config = self._config_for_dead_tcp(0.5)
        outcome = make_engine(
            config,
            controller=RunController(0.5),
            sample_interval_s=0.1,
            probe_interval_s=0.1,
            probe_timeout_s=0.3,
        ).run()

        # The run must finish on the deadline, not abort early.
        assert outcome.reason is CancelReason.DEADLINE
        assert outcome.cancelled is False
        assert outcome.abandoned is False

        # The prober must have taken measurements (even if all failed).
        assert outcome.result.probe.total > 0
        assert outcome.result.probe.availability_pct == 0.0

        # The result must explain that nothing was sent because the target was down.
        notes = " ".join(outcome.result.notes)
        assert "not accepting traffic" in notes.lower()
        assert "already down" in notes.lower()

    def test_setup_time_is_not_charged_to_the_run_duration(self) -> None:
        """The connect timeout must happen *before* the controller's clock starts.

        If setup consumed the run's budget, a 0.5 s run with a 1.0 s connect
        timeout would finish with zero probes and claim the deadline was met.
        """
        config = self._config_for_dead_tcp(0.5)
        engine = make_engine(
            config,
            controller=RunController(0.5),
            sample_interval_s=0.1,
            probe_interval_s=0.1,
            probe_timeout_s=0.3,
        )
        started = time.monotonic()
        outcome = engine.run()
        wall = time.monotonic() - started

        # Wall time may be slightly more than the deadline (grace, join), but the
        # *run* elapsed time must equal the deadline, not the connect timeout.
        # The run's started_at (UTC) should be within a second of the wall clock
        # start, confirming setup happened before the clock.
        assert abs(outcome.result.started_at.timestamp() - time.time()) < 2.0
        # The controller's reported elapsed should be the deadline, not the
        # connect timeout. Allow a small margin for shutdown overhead.
        assert 0.45 < outcome.result.attack.duration_actual_s < 1.0
        # The prober must have run and taken at least one measurement.
        assert outcome.result.probe.total > 0

    def test_no_workers_are_started_when_the_target_is_already_refusing(
        self,
    ) -> None:
        """Workers would only rediscover the same failure at connect cost."""
        config = self._config_for_dead_tcp(0.5)
        engine = make_engine(
            config,
            controller=RunController(0.5),
            sample_interval_s=0.1,
            probe_interval_s=0.1,
            probe_timeout_s=0.3,
        )
        outcome = engine.run()

        # No packets were sent.
        assert outcome.result.attack.packets_sent == 0
        # The note must state that explicitly.
        notes = " ".join(outcome.result.notes)
        assert "no packets were delivered" in notes.lower()


class TestAllWorkersDeadStopsTheRunEarly:
    """A run whose every worker has died before the deadline is a shell.

    Two h3 errors each costing a connect timeout were what the operator saw -
    [RUNNING] rows, zero counters, "0/2 profile contributing" - while the
    engine idled to the clock, because worker deaths never stop a run by
    design. They still do not (one worker dying leaves the others working),
    but the *last* one out while the deadline is still far away declares it.
    """

    def _engine(self, monkeypatch, duration: float = 1.0, workers: int = 2):
        from adobo.transports import TransportError, TransportCounters

        monkeypatch.setattr("adobo.engine.get_transport", lambda config: _DyingTransport())
        config = make_config(duration=duration, workers=workers)
        return make_engine(config), duration

    def test_the_run_stops_with_an_error_well_before_the_deadline(
        self, monkeypatch
    ) -> None:
        engine = self._engine(monkeypatch)[0]
        started = time.monotonic()
        outcome = engine.run()
        elapsed = time.monotonic() - started
        assert outcome.reason is CancelReason.ERROR
        assert elapsed < 0.6, f"the run idled past its last live worker: {elapsed:.2f}s"
        # Nothing was ever going to be sent, and the result says so directly.
        assert outcome.result.attack.packets_sent == 0

    def test_the_note_carries_the_count_and_the_deadline(self, monkeypatch) -> None:
        engine = self._engine(monkeypatch)[0]
        outcome = engine.run()
        joined = " ".join(outcome.result.notes)
        assert "all 2 worker threads exited" in joined
        assert "before the deadline" in joined
        assert "TransportError" in joined


class _DyingTransport:
    """A transport that opens but on which every send fails identically."""

    connections_opened = 0

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def request_stop(self) -> None:  # pragma: no cover - interface completeness
        pass

    def snapshot(self) -> TransportCounters:
        return TransportCounters()

    def send_one(self, _payload: Any) -> None:
        from adobo.transports import TransportError

        raise TransportError("connect refused")


class TestTheProbeSpeaksTheTargetScheme:
    """Probes and /stats must speak the scheme the target accepts.

    The prober used to inherit the profile's TLS flag verbatim - h2/h3 runs
    imply it - and so probed a plaintext website over https://host:80: every
    probe refused, "0% availability" described a live site, and the /stats
    reading ended 'ConnectError: ' with nothing after the colon. Verification
    asks the port once, at run start, and only a definite plain answer flips.
    """

    def _tls_config(self) -> RunConfig:
        return make_config(duration=0.3, transport=TransportKind.VIRTUAL).model_copy(
            update={
                "attack": AttackProfile(
                    profile=ProfileName.HTTP_FLOOD,
                    pps=500,
                    duration_seconds=0.3,
                    payload_size=64,
                    use_tls=True,
                )
            }
        )

    def _engine(self, config: RunConfig, detect_to: str, monkeypatch) -> RunEngine:
        monkeypatch.setattr(
            "adobo.engine.detect_target_protocol",
            lambda host, port, timeout=2.0: detect_to,
        )
        return make_engine(config)

    def test_a_plain_target_flips_to_plain_and_says_so(self, monkeypatch) -> None:
        engine = self._engine(self._tls_config(), TARGET_PLAIN, monkeypatch)
        outcome = engine.run()
        assert engine._probe_tls is False
        joined = " ".join(outcome.result.notes)
        assert "plain HTTP" in joined
        assert "8000" in joined  # the port it actually probed is named

    def test_a_tls_target_keeps_the_claimed_scheme(self, monkeypatch) -> None:
        engine = self._engine(self._tls_config(), TARGET_TLS_H2, monkeypatch)
        outcome = engine.run()
        assert engine._probe_tls is True
        joined = " ".join(outcome.result.notes)
        assert "refused a TLS handshake" not in joined

    def test_a_silent_target_keeps_the_claimed_scheme(self, monkeypatch) -> None:
        """'unknown' is not 'plain': the flip needs positive evidence."""
        engine = self._engine(self._tls_config(), TARGET_UNKNOWN, monkeypatch)
        outcome = engine.run()
        assert engine._probe_tls is True


class TestSleepUntilStopReturnsPromptlyOnCancel:

    """_sleep_until_stop must not poll in slices; it must wait on the event.

    The old implementation sliced the wait into 50 ms chunks via
    asyncio.to_thread, which meant twenty thread round-trips per second per
    task. On a loaded machine that starved the prober and delayed cancellation
    observability. The new implementation waits once on the token with the
    remaining interval clipped to the deadline, so a cancel is observed
    immediately and the thread hand-off cost is constant.
    """

    def test_sleep_returns_true_immediately_after_cancel(self) -> None:
        from adobo.cancellation import RunController

        controller = RunController(1.0)
        controller.start()
        engine = make_engine(make_config(duration=0.5))
        engine.controller = controller

        import asyncio

        async def run() -> None:
            # Cancel immediately, then sleep. The wait must return True at once.
            controller.request_stop(CancelReason.USER_GRACEFUL, "test")
            assert await engine._sleep_until_stop(10.0) is True

        asyncio.run(run())

    def test_sleep_returns_false_if_not_cancelled_and_time_remains(self) -> None:
        controller = RunController(1.0)
        controller.start()
        engine = make_engine(make_config(duration=0.5))
        engine.controller = controller

        import asyncio

        async def run() -> None:
            # Sleep a tiny bit; should return False (not cancelled, time left).
            assert await engine._sleep_until_stop(0.01) is False

        asyncio.run(run())

    def test_sleep_respects_the_deadline_not_just_the_token(self) -> None:
        """The deadline is not signalled by the token, so the wait must clip to it."""
        controller = RunController(0.1)  # very short deadline
        controller.start()
        engine = make_engine(make_config(duration=0.5))
        engine.controller = controller

        import asyncio

        async def run() -> None:
            # The interval is 1.0 s, but the deadline is 0.1 s. The wait must
            # clip to the deadline and return True when the deadline passes.
            #
            # The upper bound is loose on purpose. What is being proved is that
            # the wait ends near the 0.1 s deadline rather than running out the
            # full 1.0 s interval; anything under a second proves that. A tight
            # bound measured real scheduling delay, so it failed intermittently
            # when the suite loaded the machine and never indicated a fault.
            start = time.monotonic()
            result = await engine._sleep_until_stop(1.0)
            elapsed = time.monotonic() - start
            assert result is True
            assert 0.08 < elapsed < 0.6

        asyncio.run(run())


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


class TestDryRun:
    def test_sends_nothing(self) -> None:
        outcome = make_engine(make_config(duration=0.2, dry_run=True)).run()
        assert outcome.result.attack.packets_sent == 0
        assert outcome.result.attack.dry_run is True

    def test_still_completes_on_time(self) -> None:
        started = time.monotonic()
        make_engine(make_config(duration=0.3, dry_run=True)).run()
        assert time.monotonic() - started < 2.0

    def test_is_noted_in_the_result(self) -> None:
        outcome = make_engine(make_config(duration=0.2, dry_run=True)).run()
        assert any("dry run" in note.lower() for note in outcome.result.notes)

    def test_runs_without_authorisation_being_checked(self) -> None:
        """Authorization is a safety-layer concern; the engine must not re-ask."""
        outcome = make_engine(make_config(duration=0.2, dry_run=True)).run()
        assert outcome.exit_code == 0


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


class TestProbePolicy:
    def test_virtual_transport_runs_no_probes(self) -> None:
        outcome = make_engine(make_config(duration=0.3)).run()
        assert outcome.result.probes == []

    def test_dry_run_runs_no_probes(self) -> None:
        outcome = make_engine(make_config(duration=0.3, dry_run=True)).run()
        assert outcome.result.probes == []

    def test_probe_disabling_is_noted(self) -> None:
        outcome = make_engine(make_config(duration=0.2)).run()
        assert any("Probes disabled" in note for note in outcome.result.notes)

    def test_probes_can_be_forced_off(self) -> None:
        config = make_config(duration=0.2, transport=TransportKind.SOCKET)
        config = config.model_copy(update={"target": Target(host="127.0.0.1", port=9)})
        engine = make_engine(config, enable_probes=False)
        outcome = engine.run()
        assert outcome.result.probes == []


# ---------------------------------------------------------------------------
# Result assembly
# ---------------------------------------------------------------------------


class TestResult:
    def test_run_id_is_carried_through(self) -> None:
        config = make_config(duration=0.2)
        outcome = make_engine(config).run()
        assert outcome.result.run_id == config.run_id

    def test_result_serialises_to_json(self) -> None:
        outcome = make_engine(make_config(duration=0.2)).run()
        payload = outcome.result.to_json_dict()
        assert payload["run_id"] == outcome.result.run_id
        assert payload["attack"]["transport"] == "virtual"

    def test_timestamps_bracket_the_run(self) -> None:
        outcome = make_engine(make_config(duration=0.2)).run()
        assert outcome.result.finished_at >= outcome.result.started_at

    def test_duration_actual_is_derived(self) -> None:
        outcome = make_engine(make_config(duration=0.2)).run()
        assert outcome.result.duration_actual_s >= 0.15

    def test_transport_and_profile_are_recorded(self) -> None:
        outcome = make_engine(make_config(duration=0.2)).run()
        assert outcome.result.config.attack.profile is ProfileName.UDP_FLOOD
        assert outcome.result.attack.transport is TransportKind.VIRTUAL

    def test_label_and_defenses_survive(self) -> None:
        config = make_config(duration=0.2)
        config = config.model_copy(update={"label": "baseline run"})
        outcome = make_engine(config).run()
        assert outcome.result.label == "baseline run"

    def test_spoofing_flag_is_recorded(self) -> None:
        config = make_config(duration=0.2)
        config.attack.spoof_sources = True
        outcome = make_engine(config).run()
        assert outcome.result.attack.spoofed_sources is True

    def test_scoring_can_be_applied_to_the_result(self) -> None:
        outcome = make_engine(make_config(duration=0.2)).run()
        score = score_run(outcome.result.probe, outcome.result.target_stats)
        assert 0.0 <= score.total <= 100.0
        assert score.weights


# ---------------------------------------------------------------------------
# Target-side observation
# ---------------------------------------------------------------------------
#
# The sender's packet count cannot distinguish "the target served it" from "the
# target refused it" from "the host is down". These tests cover the one path
# that can, and - just as importantly - the cases where reading the target
# would be meaningless and must not be attempted.


class TestTargetObservation:
    def test_a_virtual_run_reports_the_target_as_unobserved(self) -> None:
        """Nothing is on the wire, so a delivery figure of zero would be a lie.

        Reporting zero would read as "the target served nothing" when the truth
        is that nothing was ever sent.
        """
        outcome = make_engine(make_config(duration=0.2)).run()
        assert outcome.result.target_stats.stats_observed is False

    def test_a_dry_run_reports_the_target_as_unobserved(self) -> None:
        outcome = make_engine(
            make_config(duration=0.2, dry_run=True, transport=TransportKind.SOCKET)
        ).run()
        assert outcome.result.target_stats.stats_observed is False

    def test_a_dry_run_puts_nothing_on_the_wire(self) -> None:
        """Nothing sent means nothing to observe, and nothing to claim.

        A dry run starts no workers, so every counter is zero. The important
        property for this module is the second one: with no traffic there is no
        evidence to read, so reporting the target as unobserved is the only
        honest outcome.
        """
        outcome = make_engine(
            make_config(duration=0.2, dry_run=True, transport=TransportKind.SOCKET)
        ).run()
        stats = outcome.result.attack
        assert stats.packets_sent == 0
        assert stats.dry_run is True
        assert outcome.result.target_stats.stats_observed is False

    def test_observation_can_be_turned_off(self) -> None:
        """Nuclear mode's children rely on this.

        Ten children each reading /stats would apply ten times the intended probe
        load to an already-saturated target, and all ten would lose the race to
        answer.
        """
        engine = make_engine(
            make_config(duration=0.2, transport=TransportKind.SOCKET),
            observe_target=False,
        )
        assert engine._should_observe_target() is False

    def test_observation_is_on_by_default_for_a_real_transport(self) -> None:
        engine = make_engine(
            make_config(duration=0.2, transport=TransportKind.SOCKET)
        )
        assert engine._should_observe_target() is True

    def test_an_unreadable_target_is_reported_with_its_reason(self) -> None:
        """An unreachable target must not be reported as a served-request count."""
        closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        config = make_config(duration=0.2, transport=TransportKind.SOCKET)
        config = config.model_copy(
            update={"target": Target(host="127.0.0.1", port=port)}
        )
        outcome = make_engine(config).run()
        stats = outcome.result.target_stats
        assert stats.stats_observed is False
        assert stats.stats_error

    def test_a_served_request_count_reaches_the_result(self) -> None:
        """End to end: a real run against a real target must yield real evidence."""
        import json
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = json.dumps(
                    {"status": "ok", "requests": 500, "errors": 1}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = make_config(duration=0.3, transport=TransportKind.SOCKET)
            config = config.model_copy(
                update={
                    "target": Target(host="127.0.0.1", port=server.server_address[1])
                }
            )
            outcome = make_engine(config).run()
        finally:
            server.shutdown()
            server.server_close()

        stats = outcome.result.target_stats
        assert stats.stats_observed is True
        assert stats.requests_served == 0, "no HTTP flood ran, so nothing was served"


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


class TestHooks:
    def test_tick_hook_receives_progress(self) -> None:
        ticks: list[object] = []
        engine = make_engine(
            make_config(duration=0.4), hooks=EngineHooks(on_tick=ticks.append)
        )
        engine.run()
        assert ticks, "the live display needs progress updates"
        assert all(hasattr(t, "counters") for t in ticks)

    def test_snapshot_availability_is_100_when_nothing_was_probed(self) -> None:
        from adobo.engine import RunSnapshot
        from adobo.transports import TransportCounters

        snapshot = RunSnapshot(
            elapsed=1.0,
            remaining=0.0,
            counters=TransportCounters(),
            active_workers=1,
        )
        assert snapshot.availability_pct() == 100.0
        assert snapshot.achieved_pps() == 0.0

    def test_snapshot_availability_reflects_failures(self) -> None:
        from adobo.engine import RunSnapshot
        from adobo.transports import TransportCounters

        snapshot = RunSnapshot(
            elapsed=1.0,
            remaining=0.0,
            counters=TransportCounters(),
            active_workers=1,
            probe_totals=(10, 6),
        )
        assert snapshot.availability_pct() == 60.0


# ---------------------------------------------------------------------------
# Test-facing surface
# ---------------------------------------------------------------------------


class TestOutcomeShape:
    def test_exit_code_zero_on_success(self) -> None:
        outcome = make_engine(make_config(duration=0.2)).run()
        assert isinstance(outcome, RunOutcome)
        assert outcome.exit_code == 0

    def test_exit_code_130_on_cancel(self) -> None:
        controller = RunController(30.0)
        engine = make_engine(make_config(duration=30.0), controller=controller)
        threading.Timer(0.2, controller.on_user_interrupt).start()
        assert engine.run().exit_code == 130

    def test_measurement_config_is_honoured(self) -> None:
        class Measurement:
            sample_interval_s = 0.15
            probe_interval_s = 0.05
            probe_path = "/healthz"
            probe_timeout_s = 0.4

        engine = RunEngine.from_config(
            make_config(duration=0.5), lab_measurement=Measurement()
        )
        assert engine.sample_interval_s == 0.15
        assert engine.probe_timeout_s == 0.4
        engine.run()

    def test_explicit_kwargs_beat_measurement_config(self) -> None:
        class Measurement:
            sample_interval_s = 0.15
            probe_interval_s = 0.05
            probe_path = "/healthz"
            probe_timeout_s = 0.4

        engine = RunEngine.from_config(
            make_config(duration=0.3),
            lab_measurement=Measurement(),
            sample_interval_s=0.05,
        )
        assert engine.sample_interval_s == 0.05

    def test_batch_size_is_at_least_one(self) -> None:
        engine = make_engine(make_config(duration=0.1), batch=0)
        assert engine.batch == 1
