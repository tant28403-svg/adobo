"""The run engine: workers, sampling, probing, and guaranteed shutdown.

Concurrency shape, and why:

* **Sender workers** are plain threads. They poll
  :meth:`RunController.should_stop` once per batch and hold no locks, so
  cancellation can never contend with them. Pacing uses a per-worker absolute
  schedule rather than a shared token bucket, which keeps rate control
  independent per worker and lock-free.
* **The sampler and the prober** are asyncio tasks, because both are
  I/O-shaped and both must be cancellable instantly. The prober uses
  ``httpx.AsyncClient``; the sampler uses psutil, whose calls are short enough to
  run inline.

Each worker owns its own transport: a socket is not a safe concurrent-write
target, and one closed or blocked socket would otherwise stall every other worker
through a shared handle. The engine therefore aggregates counters across
worker transports rather than reading a single one.

Every exit path - clean deadline, graceful cancel, hard cancel, worker crash -
goes through one ``finally``, so the result is written and the audit trail closed
exactly once. That single funnel is what stops a half-finished run from leaving
a dangling ``run_start`` in the trail.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from .cancellation import (
    CancelReason,
    RunController,
    Watchdog,
    install_signal_handlers,
    remove_signal_handlers,
    run_watchdog,
)
from .models import (
    AttackStats,
    CounterSample,
    ProbeResult,
    ProfileName,
    ResourceSample,
    RunConfig,
    RunResult,
    TargetStats,
    TransportKind,
    new_run_id,
    utcnow,
)
from .monitor import ResourceMonitor, process_for_pid
from .observation import TargetObserver, refused_connection
from .proxies import ProxyListError, shared_pool
from .safety import SafetyGuard
from .transports import (
    PeerUnavailable,
    Transport,
    TransportCounters,
    TransportError,
    build_payload,
    get_transport,
)

__all__ = [
    "DEFAULT_BATCH",
    "EngineHooks",
    "RunEngine",
    "RunOutcome",
    "RunSnapshot",
]

DEFAULT_BATCH = 50
"""Packets between cancellation checks.

Small enough that a hard stop lands within a few milliseconds, large enough that
per-batch bookkeeping is not the dominant cost.
"""


def _read_once(coro: Any) -> Any:
    """Run a single short coroutine to completion from synchronous code.

    Used only for the opening ``/stats`` reading, which must happen before the
    workers start and so cannot be a task inside the samplers loop. It is one
    isolated call bounded by the observer's own timeout, not work on the run's
    hot path, so spinning up a loop for it is acceptable.
    """
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Progress reporting
# --------------------------------------------------------------------------


@dataclass(slots=True)
class RunSnapshot:
    """A read-only view of a run in flight, for the live display."""

    elapsed: float
    remaining: float
    counters: TransportCounters
    active_workers: int
    last_probe: ProbeResult | None = None
    probe_totals: tuple[int, int] = (0, 0)
    cancel_reason: CancelReason = CancelReason.NONE
    amplification_factor: float | None = None

    def achieved_pps(self) -> float:
        return self.counters.sent / self.elapsed if self.elapsed > 0 else 0.0

    def availability_pct(self) -> float:
        total, ok = self.probe_totals
        return (ok / total * 100.0) if total else 100.0


@dataclass(slots=True)
class EngineHooks:
    """Optional callbacks, so the CLI can render progress without coupling here."""

    on_tick: Callable[[RunSnapshot], None] | None = None
    on_worker_error: Callable[[BaseException], None] | None = None


@dataclass(slots=True)
class RunOutcome:
    """What a completed run produced, and how it ended."""

    result: RunResult
    cancelled: bool
    reason: CancelReason
    abandoned: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        """130 is the conventional shell code for "terminated by interrupt"."""
        return 130 if self.cancelled else 0


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class RunEngine:
    """Executes one :class:`RunConfig` and returns a :class:`RunOutcome`.

    :meth:`run` puts the config through :class:`~adobo.safety.SafetyGuard`
    before anything is opened, so the CLI, the wizard and any future entry
    point are all capped by the same check.
    """

    def __init__(
        self,
        config: RunConfig,
        *,
        hooks: EngineHooks | None = None,
        controller: RunController | None = None,
        sample_interval_s: float = 1.0,
        probe_interval_s: float = 0.25,
        probe_path: str = "/healthz",
        probe_timeout_s: float = 1.5,
        batch: int = DEFAULT_BATCH,
        enable_probes: bool = True,
        target_pid: int | None = None,
        observe_target: bool = True,
        guard: SafetyGuard | None = None,
    ) -> None:
        self.config = config
        # Injectable so tests can supply permissive ceilings without weakening
        # the production path: the default reads config/lab.yaml.
        self._guard = guard
        self.hooks = hooks or EngineHooks()
        self.controller = controller or RunController(config.attack.duration_seconds)
        self.sample_interval_s = sample_interval_s
        self.probe_interval_s = probe_interval_s
        self.probe_path = probe_path
        self.probe_timeout_s = probe_timeout_s
        self.batch = max(1, batch)
        self.enable_probes = enable_probes
        self.monitor = ResourceMonitor(
            process_for_pid(target_pid), interval_s=sample_interval_s
        )

        self._counter_samples: list[CounterSample] = []
        self._resource_samples: list[ResourceSample] = []
        self._probes: list[ProbeResult] = []

        # Ceiling adjustments made by the safety gate. Reported in the summary
        # so a clamped run never reads like the run that was asked for.
        self._policy_notes: list[str] = []

        # Target-side observation. Kept apart from the monitor because that one
        # needs psutil and therefore only works locally, while this works over
        # HTTP and so measures a remote target too. Between them, a run has some
        # evidence from the target's side rather than none.
        self._observer = TargetObserver(
            config.target.host, config.target.port
        )
        self._observe_target_enabled = observe_target
        self._stats_before: tuple[int, int] | None = None
        self._stats_after: tuple[int, int] | None = None
        self._observer_grace_s = 1.0
        self._close_read_timeout_s = 10.0

        self._transport_lock = threading.Lock()
        self._worker_transports: list[Transport] = []
        self._retired = TransportCounters()
        self._active_workers = 0
        self._last_attempted = 0
        self._sample_last_time = time.monotonic()
        self._worker_errors: list[BaseException] = []
        self._peer_unavailable: str | None = None
        self._setup_error: str | None = None
        # Set when the prober could not run at all, as distinct from running and
        # failing. The two produce different reports: one has no availability
        # figure, the other has a figure that says the target was down.
        self._probe_unavailable: str | None = None
        # What actually probed, recorded rather than assumed. The disclosure note
        # reads this, because deriving it from the transport kind is how the note
        # came to claim HTTP/3 probing for a run that had used the TCP prober.
        self._probe_protocol: str | None = None
        self._abandoned = False
        self._abandon_hook: Callable[[], None] | None = None

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        config: RunConfig,
        *,
        lab_measurement: Any = None,
        **kwargs: Any,
    ) -> "RunEngine":
        """Build an engine, taking measurement cadence from ``lab.yaml``."""
        if lab_measurement is not None:
            kwargs.setdefault("sample_interval_s", lab_measurement.sample_interval_s)
            kwargs.setdefault("probe_interval_s", lab_measurement.probe_interval_s)
            kwargs.setdefault("probe_path", lab_measurement.probe_path)
            kwargs.setdefault("probe_timeout_s", lab_measurement.probe_timeout_s)
        return cls(config, **kwargs)

    def set_abandon_hook(self, hook: Callable[[], None]) -> None:
        """Called once if the run cannot be stopped within the join grace."""
        self._abandon_hook = hook

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> RunOutcome:
        """Execute the scenario to completion or to cancellation.

        Cancellation is not an error: a stopped run produces a result. Genuine
        faults are re-raised, but only after the audit trail has been closed.
        """
        # Ceilings, before anything is opened, so a run never goes out past
        # what the config permits.
        if not self.config.dry_run:
            self._apply_safety_gate()

        # The opening /stats reading is the first thing that happens, ahead of
        # `started`, so it is setup rather than part of the run. It has to be
        # taken before the workers start for two reasons: once the flood is
        # running the target is saturated and the read queues behind the traffic
        # being generated, timing out and losing the measurement entirely; and
        # charging it to the run would eat a dead target's whole budget on a
        # target that cannot answer at all. Against a live target it costs about
        # a millisecond.
        if self._should_observe_target():
            self._stats_before = _read_once(self._observer.read())

        started = utcnow()
        previous_handlers = install_signal_handlers(self.controller)
        watchdog = run_watchdog(self.controller, self._mark_abandoned)

        workers: list[threading.Thread] = []
        fatal: BaseException | None = None

        try:
            # Setup happens *before* the clock starts. Opening a transport can
            # block for up to the connect timeout, and charging that to the run
            # would let a slow or dead target consume the whole duration before
            # a single packet is sent - leaving a result with no measurements
            # from a run that was supposed to last ten seconds.
            ready = True
            if not self.config.dry_run:
                ready = self._validate_transport()

            if not ready:
                # Refuse early rather than letting every worker fail identically.
                self.controller.request_stop(
                    CancelReason.ERROR, "the transport could not be opened"
                )

            # The opening /stats reading was taken at the very top of run(), ahead
            # of the clock and the workers, so the measurement window is the run
            # itself and the load never competes for the request.
            self.controller.start()
            if not self.config.dry_run and ready and not self._peer_unavailable:
                # When the target is already refusing connections there is
                # nothing to deliver, and letting every worker rediscover that
                # with its own connect timeout would add that timeout to the end
                # of every run against a dead target. The prober still runs, so
                # the result is a measurement of the target being down.
                workers = self._start_workers()

            asyncio.run(self._run_samplers())
        except BaseException as exc:  # noqa: BLE001 - re-raised after cleanup
            fatal = exc
            self.controller.request_stop(CancelReason.ERROR, str(exc))
        finally:
            # Tell every worker to wind down *before* waiting on any of them.
            # close() is only reached once a worker's own loop has returned, so
            # a transport that paces itself by sleeping would otherwise have to
            # finish its whole sleep interval before noticing the deadline.
            self._stop_workers()
            self._join_workers(workers)
            self._drain_transports()
            watchdog.stop()
            remove_signal_handlers(previous_handlers)

        outcome = self._build_outcome(started)
        if fatal is not None:
            raise fatal
        return outcome

    def _apply_safety_gate(self) -> None:
        """Clamp the run to the configured ceilings.

        There is no authorisation step: the target is the one the operator
        named. Clamps are applied to the config in place and recorded, so the
        summary reports the values that were actually used rather than the ones
        that were requested.
        """
        guard = self._guard or SafetyGuard()
        result = guard.clamp_profile(self.config.attack)
        if result.changed:
            self.config = self.config.model_copy(
                update={"attack": result.applied}
            )
            self._policy_notes.extend(result.notes)

    def _validate_transport(self) -> bool:
        """Open and immediately close one transport to fail fast.

        Cheaper than discovering an unresolvable target or missing Npcap from N
        identical worker errors a moment later.

        A target that refuses the connection is *not* treated as a failure to
        open: that is the lab's central observation, not a fault on this machine,
        so the run continues and the prober measures it. Only a genuine local
        fault - missing Npcap, an unusable interface - stops the run here.
        """
        try:
            probe = get_transport(self.config)
            probe.open()
            probe.close()
        except PeerUnavailable as exc:
            self._peer_unavailable = str(exc)
            return True
        except TransportError as exc:
            import logging
            logging.error(f"Transport validation failed for {self.config.attack.profile.value}: {exc}")
            self._setup_error = str(exc)
            self._record_worker_error(exc)
            return False
        return True

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _start_workers(self) -> list[threading.Thread]:
        threads: list[threading.Thread] = []
        for index in range(self.config.attack.workers):
            thread = threading.Thread(
                target=self._worker_loop,
                args=(index,),
                name=f"adobo-worker-{index}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        return threads

    def _worker_loop(self, index: int) -> None:
        try:
            transport = get_transport(self.config)
            transport.open()
        except PeerUnavailable:
            return
        except TransportError as exc:
            self._record_worker_error(exc)
            return

        with self._transport_lock:
            self._worker_transports.append(transport)
            self._active_workers += 1
        try:
            # A transport may own its pacing instead of using send_one. It is
            # handed the *per-worker* rate, the same figure _pump derives, so
            # total offered load is pps regardless of worker count. Previously
            # this passed payload_size, which a rate-named parameter then turned
            # into a connection count 25x higher than intended.
            #
            # The attack profile comes along too. A self-paced transport has to
            # build the payload itself, and it cannot: the generic path builds
            # it in _pump and hides that behind send_one, so a transport taking
            # over the loop had no way to learn the payload size or the
            # keep-alive flag it was meant to be sending.
            if hasattr(transport, 'worker_loop'):
                attack = self.config.attack
                transport.worker_loop(
                    index,
                    attack.pps / max(1, attack.workers),
                    attack,
                )
            else:
                self._pump(transport, index)
        except TransportError as exc:
            self._record_worker_error(exc)
        except Exception as exc:  # noqa: BLE001 - a crash must not hang the run
            self._record_worker_error(exc)
        finally:
            transport.close()
            with self._transport_lock:
                self._active_workers -= 1
                self._retired = self._retired + transport.snapshot()
                if transport in self._worker_transports:
                    self._worker_transports.remove(transport)

    def _pump(self, transport: Transport, index: int) -> None:
        """Pace packets to the configured rate until asked to stop.

        The requested pps is the *total* across workers, so each worker sends at
        ``pps / workers``. Sleeps are computed from an absolute schedule so that
        error handling and sleep overhead do not accumulate into drift.
        """
        profile = self.config.attack
        per_worker_pps = max(1.0, profile.pps / max(1, profile.workers))
        interval = 1.0 / per_worker_pps
        next_send = time.monotonic()
        sequence = index * 1_000_000

        # Whether a persona actually varies is decided once per worker, not per
        # packet. Asking it per packet would split a string and walk a list for
        # every packet of a run that may issue hundreds of thousands of them -
        # the same class of mistake commit 0ca8c1d removed from the raw path.
        # With a single persona configured, which is the common case, this is
        # one comparison per run and the send path below never rotates.
        rotates = (
            len(profile.persona_keys()) > 1 and profile.fingerprint_rotation != "none"
        )
        # per_connection varies on the transport's connection count and
        # per_request on the packet sequence. The distinction is not cosmetic: a
        # persona is a property of a connection, so rotating it mid-keep-alive
        # would claim an identity the connection was never established with.
        per_connection = profile.fingerprint_rotation == "per_connection"

        while not self.controller.should_stop():
            for _ in range(self.batch):
                if self.controller.should_stop():
                    return
                sequence += 1
                persona = (
                    profile.persona(
                        seed=transport.connections_opened if per_connection else sequence
                    )
                    if rotates
                    else profile.persona()
                )
                transport.send_one(
                    build_payload(
                        profile.profile,
                        profile.payload_size,
                        target=self.config.target,
                        seed=sequence,
                        keep_alive=profile.keep_alive,
                        fingerprint=persona,
                    )
                )
            next_send += interval * self.batch
            now = time.monotonic()
            if next_send > now:
                # Wake early on cancel rather than sleeping out the interval.
                self.controller.token.wait(min(next_send - now, 0.2))
            else:
                # Fell behind, e.g. a saturated socket. Resync rather than
                # sending without sleeping, which would turn a degraded run
                # into an unbounded burst.
                next_send = now

    def _record_worker_error(self, exc: BaseException) -> None:
        self._worker_errors.append(exc)
        if self.hooks.on_worker_error is not None:
            self.hooks.on_worker_error(exc)

    def _mark_abandoned(self) -> None:
        if self._abandoned:
            return
        self._abandoned = True
        self.controller.request_stop(
            CancelReason.ABANDONED,
            "workers did not stop within the grace period; the process is being torn down",
        )
        if self._abandon_hook is not None:
            try:
                self._abandon_hook()
            except Exception:  # pragma: no cover - reporting must not mask
                pass

    def _stop_workers(self) -> None:
        """Signal every live transport to wind down.

        A transport whose worker loop paces itself has no other way to learn
        that the deadline has passed: ``close()`` runs in the worker's own
        ``finally``, so a loop sleeping between sends would sleep out the full
        interval first. The join grace is shorter than that, so the worker was
        abandoned mid-sleep and the run reported nothing for a profile that had
        been sending throughout.
        """
        with self._transport_lock:
            transports = list(self._worker_transports)
        for transport in transports:
            try:
                transport.request_stop()
            except Exception:  # pragma: no cover - defensive
                pass

    def _join_workers(self, workers: list[threading.Thread]) -> None:
        """Wait for every worker against one shared deadline.

        Joining each with the full grace in turn would make the grace scale with
        the worker count - four workers meant four times the documented wait, and
        a caller timing the run to that budget would be surprised. The deadline
        is shared so the grace means what it says.
        """
        if not workers:
            return
        deadline = time.monotonic() + self.controller.grace.join_grace_s
        for worker in workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            self._mark_abandoned()

    def _drain_transports(self) -> None:
        with self._transport_lock:
            transports = list(self._worker_transports)
        for transport in transports:
            try:
                transport.close()
            except Exception:  # pragma: no cover - defensive
                pass

    def total_counters(self) -> TransportCounters:
        """Sum every worker's counters, live and already-retired.

        Workers are removed from the live list when they finish, so the retired
        accumulator is what makes the totals still correct once they have all
        exited - which is exactly when the run's stats are read.
        """
        with self._transport_lock:
            live = [t.snapshot() for t in self._worker_transports]
            retired = self._retired
        return TransportCounters(
            attempted=retired.attempted + sum(s.attempted for s in live),
            sent=retired.sent + sum(s.sent for s in live),
            bytes=retired.bytes + sum(s.bytes for s in live),
            errors=retired.errors + sum(s.errors for s in live),
        )

    # ------------------------------------------------------------------
    # Sampling and probing
    # ------------------------------------------------------------------

    def _probes_enabled(self) -> bool:
        # A virtual transport has no peer to probe, and a dry run has no packets
        # to have caused any degradation. Either way the numbers would be noise.
        return (
            self.enable_probes
            and not self.config.dry_run
            and self.config.transport is not TransportKind.VIRTUAL
        )

    def _should_observe_target(self) -> bool:
        """Whether reading the target's own counters can say anything.

        Skipped for a dry run and for the virtual transport, because neither
        puts anything on the wire. Reading ``/stats`` there would cost a request
        and report a delivery figure of zero, which reads as "the target served
        nothing" when the truth is that nothing was ever sent.

        Nuclear mode turns it off per child. Ten profiles would otherwise each
        read ``/stats`` against one already-saturated target, adding ten times
        the intended probe load and losing all ten races; the parent takes one
        reading for the run as a whole instead.
        """
        if not self._observe_target_enabled:
            return False
        return not self.config.dry_run and self.config.transport is not TransportKind.VIRTUAL

    async def _run_samplers(self) -> None:
        # The closing /stats reading is taken here, as a task alongside the run,
        # rather than awaited around it. Waiting on it externally cost real
        # wall-clock time: a target that does not serve /stats refused the
        # connection for the full timeout, which added seconds to every deadline.
        # Instrumentation that can delay the thing it measures is not
        # instrumentation, so this now runs concurrently and the run's duration
        # does not depend on the target answering at all.
        done = asyncio.Event()
        observer = asyncio.create_task(
            self._observe_target(done), name="adobo-target-stats"
        )
        tasks: list[asyncio.Task[None]] = [
            asyncio.create_task(self._sample_counters(), name="adobo-sampler")
        ]
        if self._probes_enabled():
            tasks.append(
                asyncio.create_task(self._probe_availability(), name="adobo-prober")
            )
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:  # pragma: no cover - outer cancellation
            raise
        finally:
            done.set()
            # Let the observer take its closing reading before cancelling it.
            # Cancelling straight after done.set() throws the read away, which
            # leaves the run with a 'before' figure and no 'after' - and the
            # window is then silently unmeasurable. The grace is short and only
            # ever spent when 'before' succeeded, so a live target answers in
            # about a millisecond and an unresponsive one is bounded here.
            try:
                await asyncio.wait_for(
                    asyncio.shield(observer), timeout=self._close_read_timeout_s + 1.0
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
            except Exception:  # noqa: BLE001 - a failed read is reported, not raised
                pass
            if not observer.done():
                observer.cancel()
            await asyncio.gather(observer, return_exceptions=True)
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _observe_target(self, done: asyncio.Event) -> None:
        """Take the closing /stats reading once the run is over.

        The opening reading is taken by :meth:`run` before the workers start, so
        the window brackets the run and the load is not competing for the
        request. By the time this fires the workers have been joined and the
        target is free again, so the read is prompt.
        """
        if not self._should_observe_target() or self._stats_before is None:
            return
        await done.wait()
        # Long budget on purpose: the target is still draining the requests the
        # flood already delivered, and a closing read taken too early would
        # undercount them - which is the delivery figure itself.
        self._stats_after = await self._observer.read(timeout=self._close_read_timeout_s)

    async def _sleep_until_stop(self, interval: float) -> bool:
        """Sleep up to *interval*, waking early on cancel or at the deadline.

        Returns True if the controller asked to stop.

        This waits on the cancellation token rather than polling it in slices.
        ``threading.Event.wait`` returns the instant the event is set, so a
        cancel is already observed with no polling - but each poll costs an
        ``asyncio.to_thread`` round trip, and at 50 ms slices that is twenty
        thread hand-offs a second per task. On a loaded machine those
        hand-offs were measurably delaying the prober, which cost availability
        samples on short runs. The timeout is clipped to the time left before
        the deadline so the run still ends on time even though the deadline does
        not set the event by itself.
        """
        if self.controller.should_stop():
            return True
        remaining = min(interval, self.controller.remaining)
        if remaining <= 0:
            return self.controller.should_stop()
        if await asyncio.to_thread(self.controller.token.wait, remaining):
            return True
        return self.controller.should_stop()

    async def _sample_counters(self) -> None:
        last_sent = 0
        while not self.controller.should_stop():
            if await self._sleep_until_stop(self.sample_interval_s):
                break
            now = time.monotonic()
            self._emit_counter_sample(now, last_sent)
            last_sent = self._counter_samples[-1].packets_sent
            self.monitor.sample()
        # Always emit a closing sample. Without this a run shorter than the
        # sample interval would produce no time series at all, and the report
        # would show an empty chart for a perfectly healthy one-second run.
        self._emit_counter_sample(time.monotonic(), last_sent)
        self.monitor.sample()

    def _emit_counter_sample(self, now: float, last_sent: int) -> None:
        """Append one rate sample, expressed as a delta from the previous one."""
        delta = now - self._sample_last_time
        if delta <= 0:
            delta = 1e-9
        counters = self.total_counters()
        self._counter_samples.append(
            CounterSample(
                t=round(self.controller.elapsed, 3),
                attempted_pps=round(
                    (counters.attempted - self._last_attempted) / delta, 1
                ),
                sent_pps=round((counters.sent - last_sent) / delta, 1),
                packets_sent=counters.sent,
                bytes_sent=counters.bytes,
                errors=counters.errors,
                active_workers=self._active_workers,
            )
        )
        self._last_attempted = counters.attempted
        self._sample_last_time = now
        self._emit_snapshot()

    async def _probe_availability(self) -> None:
        """Probe the target's monitoring path for the whole run.

        The client is built and the first probe issued before any sleep, so even
        a one-second run yields a measurement. Probing first and sleeping after
        means the prober can never be starved by a short deadline and leave the
        report claiming an unmeasured run scored well.
        """
        if self.config.transport is TransportKind.H3:
            await self._probe_availability_h3()
            return
        self._probe_protocol = "http/1.1"
        timeout = httpx.Timeout(self.probe_timeout_s)
        async with httpx.AsyncClient(timeout=timeout) as client:
            while not self.controller.should_stop():
                result = await self._single_probe(client)
                self._probes.append(result)
                self._emit_snapshot()
                if await self._sleep_until_stop(self.probe_interval_s):
                    return

    async def _probe_availability_h3(self) -> None:
        """Probe over HTTP/3, in the same protocol the run is generating.

        An h3 run probed over HTTP/1.1 on TCP asks a question the target cannot
        answer. Windows blackholes that connection rather than refusing it, so the
        probe times out, availability reads 0%, and a target that served every
        request scores 0/100. Measured, not hypothesised: the h3 end-to-end run
        reported `availability 0.0%` and `resilience 0.0 / 100` against a target
        that had answered 1,200 requests.

        Records nothing when aioquic is absent. An empty probe list already means
        "unmeasured" in the report, and inventing failing probes would convert a
        missing dependency into a claim about the target.
        """
        from .transports.http3_transport import aioquic_available, h3_probe

        if not aioquic_available():
            self._probe_unavailable = (
                "aioquic is not installed, so no HTTP/3 probe could be made and "
                "availability is unmeasured for this run."
            )
            return

        self._probe_protocol = "h3"
        tls_verify = getattr(self.config.attack, "tls_verify", True)
        while not self.controller.should_stop():
            probe = await h3_probe(
                self.config.target.host,
                self.config.target.port,
                self.probe_path,
                timeout=self.probe_timeout_s,
                tls_verify=tls_verify,
            )
            self._probes.append(
                ProbeResult(
                    t=round(self.controller.elapsed, 3),
                    ok=probe.ok,
                    status_code=probe.status_code,
                    latency_ms=probe.latency_ms,
                    error=probe.error,
                )
            )
            self._emit_snapshot()
            if await self._sleep_until_stop(self.probe_interval_s):
                return

    async def _single_probe(self, client: Any) -> ProbeResult:
        t = round(self.controller.elapsed, 3)
        url = (
            f"http://{self.config.target.host}:{self.config.target.port}"
            f"{self.probe_path}"
        )
        started = time.monotonic()
        try:
            response = await client.get(url)
        except Exception as exc:  # noqa: BLE001 - any failure is a failed probe
            return ProbeResult(
                t=t,
                ok=False,
                latency_ms=round((time.monotonic() - started) * 1000, 2),
                error=f"{type(exc).__name__}: {exc}",
            )
        latency = round((time.monotonic() - started) * 1000, 2)
        return ProbeResult(
            t=t,
            ok=response.status_code < 500,
            status_code=response.status_code,
            latency_ms=latency,
            error=None if response.status_code < 400 else f"HTTP {response.status_code}",
        )

    def _emit_snapshot(self) -> None:
        if self.hooks.on_tick is None:
            return
        ok = sum(1 for probe in self._probes if probe.ok)
        
        # Calculate amplification factor for this snapshot
        amp_factor = self._calculate_amplification_factor(self.total_counters())
        
        self.hooks.on_tick(
            RunSnapshot(
                elapsed=round(self.controller.elapsed, 1),
                remaining=round(self.controller.remaining, 1),
                counters=self.total_counters(),
                active_workers=self._active_workers,
                last_probe=self._probes[-1] if self._probes else None,
                probe_totals=(len(self._probes), ok),
                cancel_reason=self.controller.token.reason,
                amplification_factor=amp_factor,
            )
        )

    # ------------------------------------------------------------------
    # Result assembly
    # ------------------------------------------------------------------

    def _build_outcome(self, started: Any) -> RunOutcome:
        from .scoring import score_run, summarise_probes, summarise_resources

        reason = self.controller.token.reason
        cancelled = reason.is_cancel
        # The monitor is the only source of resource samples, so read them back
        # from it rather than maintaining a second copy in the engine.
        self._resource_samples = self.monitor.samples
        target_stats = summarise_resources(self._resource_samples)

        # Fold in what the target itself counted over the run window. Merged
        # rather than replacing: the psutil fields and the request counters come
        # from different mechanisms and one is often unavailable when the other
        # is not - a local target has no /stats worth reading if it is not the lab
        # app, and a remote one has no psutil.
        observed = self._observer.window_sync(self._stats_before, self._stats_after)
        if observed.stats_observed or target_stats.sample_count == 0:
            target_stats = TargetStats(
                cpu_percent_mean=target_stats.cpu_percent_mean,
                cpu_percent_p95=target_stats.cpu_percent_p95,
                cpu_percent_max=target_stats.cpu_percent_max,
                rss_mb_max=target_stats.rss_mb_max,
                peak_threads=target_stats.peak_threads,
                peak_sockets=target_stats.peak_sockets,
                peak_handles=target_stats.peak_handles,
                sample_count=target_stats.sample_count,
                requests_served=observed.requests_served,
                errors_served=observed.errors_served,
                stats_observed=observed.stats_observed,
                stats_error=observed.stats_error,
            )

        probe_summary = summarise_probes(self._probes)
        result = RunResult(
            run_id=self.config.run_id or new_run_id(),
            lab_id=self.config.lab_id,
            label=self.config.label,
            started_at=started,
            finished_at=utcnow(),
            config=self.config,
            defenses=list(self.config.defenses),
            attack=self._attack_stats(),
            target_stats=target_stats,
            probe=probe_summary,
            score=score_run(probe_summary, target_stats),
            counter_samples=list(self._counter_samples),
            resource_samples=list(self._resource_samples),
            probes=list(self._probes),
            notes=self._notes(reason, cancelled),
        )
        return RunOutcome(
            result=result,
            cancelled=cancelled,
            reason=reason,
            abandoned=self._abandoned,
        )

    def _attack_stats(self) -> AttackStats:
        counters = self.total_counters()
        duration_actual = round(self.controller.elapsed, 3)

        return AttackStats(
            transport=self.config.transport,
            dry_run=self.config.dry_run,
            packets_attempted=counters.attempted,
            packets_sent=counters.sent,
            bytes_sent=counters.bytes,
            errors=counters.errors,
            duration_actual_s=duration_actual,
            achieved_pps=round(counters.sent / max(duration_actual, 1e-9), 2),
            spoofed_sources=self.config.attack.spoof_sources,
            amplification_factor=self._calculate_amplification_factor(counters),
            amplification_declared=self._declared_amplification(
                self.config.attack.profile
            ),
        )

    def _calculate_amplification_factor(self, counters: TransportCounters) -> float | None:
        """Observed amplification, or None when it is not measurable.

        This previously returned a constant looked up from the profile name -
        40x for DNS, 200x for NTP, 70x for CLDAP, 30x for SSDP - while ignoring
        the ``counters`` argument it was handed. The result was a run
        reporting "200.0x" beside a sent count of zero, and nothing in the
        report distinguished a published figure from a measured one.

        A factor is a ratio of two observed quantities: response bytes divided
        by request bytes. Both have to be real. So the only value produced here
        is one derived from the counters, and when nothing came back the answer
        is None.

        None is the *normal* answer for a real amplification run, and that is
        physics rather than a gap in the measurement. Amplification requires a
        forged source address, so the reflector replies to the victim and the
        response is never visible from the sending host. The declared protocol
        ratio is reported separately as
        :attr:`~adobo.models.AttackStats.amplification_declared`, labelled as
        a nominal figure, so a reader can never mistake it for a result.
        """
        return counters.measured_amplification

    @staticmethod
    def _declared_amplification(profile: ProfileName) -> float | None:
        """The protocol's *nominal* ratio - a constant, never a measurement.

        Published maxima (NTP monlist 556x, for instance) assume a reflector
        that is configured to answer maximally and a target on a link with no
        loss. Neither holds here, so this is surfaced as an estimate and kept
        out of :attr:`AttackStats.amplification_factor`.
        """
        return {
            ProfileName.DNS_AMPLIFICATION: 40.0,
            ProfileName.NTP_AMPLIFICATION: 200.0,
            ProfileName.CLDAP_AMPLIFICATION: 70.0,
            ProfileName.SSDP_AMPLIFICATION: 30.0,
        }.get(profile)

    def _target_lacks_http_surface(self) -> bool:
        """True when every probe failed by refusing the connection.

        Delegates the rule itself to :func:`adobo.observation.refused_connection`
        so the engine's report and the nuclear aggregator cannot drift apart on
        what counts as evidence of a target having no HTTP service.
        """
        if not self._probes:
            return False
        for probe in self._probes:
            if probe.ok:
                return False
            if not refused_connection(probe.error):
                return False
        return True

    def _impersonation_note(self) -> str | None:
        """Disclose that this run presented traffic as a browser.

        Returns the note, or ``None`` when nothing was impersonated.

        This is not decoration. The tool's whole result is a claim about how a
        target behaved under load, and a run that presents itself as Chrome
        produces a different number than one that presents itself as the lab
        client - against a WAF, dramatically so, since the WAF may admit one and
        challenge the other. A resilience score printed without saying which
        identity was used would let two runs that exercised different code paths
        be read as comparable, which is the same class of defect this codebase
        has repeatedly fixed elsewhere: an amplification ratio reported as a
        measurement when it was a published constant, an availability figure
        rendered as 0% when it was never measured.

        Silence is the signal. ``lab_default`` produces no note at all, so a
        reader can tell "this run impersonated nothing" from "this run
        impersonated something and the tool did not say".
        """
        attack = self.config.attack
        if not attack.impersonates():
            return None
        keys = [key for key in attack.persona_keys() if key != "lab_default"]
        names = ", ".join(keys)
        plural = "s were" if len(keys) > 1 else " was"
        mode = attack.fingerprint_rotation
        scope = (
            "one per connection"
            if mode == "per_connection"
            else "one per request" if mode == "per_request" else "fixed for the run"
        )
        return (
            f"Client impersonation: {len(keys)} persona{plural} used ({names}), "
            f"{scope}. Traffic was presented as those browsers, so delivery and "
            f"availability figures describe a client the target was not actually "
            f"dealing with. Compare against a lab_default run to separate the "
            f"target's behaviour from the identity it was shown."
        )

    def _rapid_reset_note(self) -> str | None:
        """Disclose what a Rapid Reset run was testing, and which figures to read.

        Returns the note, or ``None`` for any other profile.

        Three things have to be said, and each is a figure that would otherwise
        be read as a failure:

        * The target's served-request count stays near zero *by design*. Being
          cancelled before the handler runs is what the profile does, so "392
          requests sent, 0 served" is the correct result and not a broken run.
        * Delivery percentage and any amplification factor are therefore not
          measurable, rather than measured and found to be zero.
        * pps here means open-and-cancel pairs per second, not completed
          requests, and each pair is only a few tens of bytes of framing. 5,000
          pps of this is a much heavier load on the target than 5,000 pps of
          http_flood, so the number is not comparable across profiles.

        Also states the expected outcome, because "nothing happened" is the
        success case here and reads as a failed test otherwise. This is a
        regression test for a published CVE, and a patched server absorbing it
        is the answer the operator wants.
        """
        if self.config.attack.profile is not ProfileName.RAPID_RESET:
            return None
        return (
            "HTTP/2 Rapid Reset (CVE-2023-44487): each request was cancelled "
            "immediately after its headers were sent, so this tested whether the "
            "target applies the stream-reset limits that patch introduced. The "
            "target's served-request count staying near zero is expected - being "
            "cancelled is what the profile does - and delivery and amplification "
            "are unmeasurable here rather than zero. Read the reset count above as "
            "what was sent, and the target's CPU and memory plus the probe "
            "results as what it cost. A patched target absorbs this and nothing "
            "happens, which is the passing result; a target that slows, drops "
            "probes or answers GOAWAY has shown the gap. This profile always "
            "speaks HTTP/2 over TLS, so certificate verification applies and a "
            "self-signed target needs --tls-no-verify."
        )

    def _h3_note(self) -> str | None:
        """Disclose that this run spoke HTTP/3, and what that costs in figures.

        Returns the note, or ``None`` for any other transport.

        Two things have to be said, and both are the kind of thing that reads as
        a working number if it is left out.

        The transport is QUIC over UDP, so a target's defenses ran on a different
        code path than in a TCP run - per-connection state, protocol detection
        and any QUIC-specific limit are all in play.

        And there is no received-bytes figure. A UDP datagram is not
        acknowledged, so nothing on this path can count what arrived; any such
        number would be invented. It is absent rather than zero-as-in-nothing-was-
        sent, and the delivery and amplification figures below are correspondingly
        weaker than they would be for an HTTP/1.1 run against the same target.

        The *sent* bytes are counted, and counted from the datagram endpoint, so
        they include QUIC and QPACK framing where the HTTP/1.1 path counts payload
        only. Each figure is honest about what it measures; they are not
        interchangeable.

        Availability *is* measured for an h3 run - the prober speaks HTTP/3, the
        same protocol the load used - so the figure is meaningful where a TCP
        probe against a QUIC-only target would have timed out and reported 0% for
        a machine that was serving fine.
        """
        if self.config.transport is not TransportKind.H3:
            return None
        if self._probe_protocol == "h3":
            probed = (
                "Availability was measured over HTTP/3, the same protocol as the "
                "load, so the figure is meaningful here rather than the 0% a TCP "
                "probe against a QUIC-only target produces."
            )
        elif self._probe_unavailable is not None:
            probed = self._probe_unavailable
        else:
            # The transport is h3 but nothing recorded probing over it. Stating
            # what actually happened is the only honest option; guessing would
            # put "measured over HTTP/3" next to a figure that was not.
            probed = (
                "No HTTP/3 probe was made, so the availability figure below came "
                "from another protocol and is not comparable to a QUIC target."
            )
        return (
            "HTTP/3 over QUIC: requests were sent over UDP with no TCP handshake, "
            "so the target's defenses ran on a different path than a TCP run and "
            "the figures below are not directly comparable to one. No received-bytes "
            "or amplification figure is reported, because UDP is not acknowledged "
            "and nothing on this path can count what arrived - those values are "
            "absent, not zero. Bytes sent are counted at the datagram endpoint and "
            f"so include QUIC and header framing, unlike the payload-only count an "
            f"HTTP/1.1 run reports. {probed}"
        )

    def _proxy_note(self) -> str | None:
        """Disclose that this run's egress was distributed across a proxy pool.

        Returns the note, or ``None`` when the run did not use proxies.

        For the same reason as :meth:`_impersonation_note`: a run through a
        thousand proxies and a run from one address exercise entirely different
        target code, because per-IP rate limits, connection caps and reputation
        blocking only exist in the second case. A resilience score that does not
        say which one produced it invites the reader to compare them directly,
        and the comparison is meaningless.

        Silence is the signal. A direct run produces no note at all, so "this run
        did not rotate" is distinguishable from "this run rotated and the tool did
        not say".

        Reports the *distinct* proxies reached rather than the hand-outs. A pool
        of one handed out 10,000 times also reports 10,000 hand-outs and would
        read as a working rotation while being the exact single-source run this
        feature exists to avoid.
        """
        if self.config.transport is not TransportKind.PROXY:
            return None
        try:
            pool = shared_pool(self.config.proxy_file or None)
        except ProxyListError as exc:
            # Setup failed before any transport existed, so this is only
            # reachable if the list disappeared between construction and here.
            return f"Proxy list could not be read: {exc}"

        size = len(pool)
        reached = pool.distinct_used
        scope = (
            "one proxy per connection"
            if self.config.attack.keep_alive
            else "one proxy per request"
        )
        coverage = (
            f"every proxy in the pool was used ({reached} of {size})"
            if reached >= size
            else (
                f"only {reached} of {size} proxies were reached - the run ended "
                f"before rotating through the list, so this measures a smaller "
                f"set of source addresses than the pool holds"
            )
        )
        return (
            f"Proxy rotation: {scope}, {coverage} ({pool.used:,} connections "
            f"tunnelled). Traffic arrived from those source addresses rather "
            f"than this machine's, so per-IP rate limiting and connection caps "
            f"were in play. Compare against a --transport socket run to separate "
            f"the target's behaviour from the number of distinct sources."
        )

    def _h2_preamble_note(self) -> str | None:
        """Disclose what this run's HTTP/2 connection layer reproduced.

        Returns the note, or ``None`` when no preamble was configured.

        Separate from :meth:`_impersonation_note` because the two answer different
        questions and have different reach. The impersonation note fires for HTTP
        and HTTP/2 alike; this one can only fire for HTTP/2, and it has to be
        candid about *how much* was reproduced rather than that something was.
        Two of the three profiles cannot send the whole connection preamble -
        h2 will not emit Firefox's priority tree, and it always adds settings a
        browser omits - so a note that said only "preamble applied" would overstate
        it. The profile's own ``incomplete_because`` carries the measured detail
        and is reproduced here rather than summarised, so the report carries the
        same words ``--inspect-h2`` shows.
        """
        profile = self.config.attack.h2_profile()
        if profile is None:
            return None
        note = (
            f"HTTP/2 connection preamble: {profile.label} "
            f"({profile.fingerprint()})."
        )
        if profile.incomplete_because:
            note += f" Incomplete: {profile.incomplete_because}"
        return note

    def _notes(self, reason: CancelReason, cancelled: bool) -> list[str]:
        notes: list[str] = []
        if reason is CancelReason.DEADLINE:
            notes.append(f"Stopped on the {self.config.attack.duration_seconds}s deadline.")
        elif cancelled:
            notes.append(
                f"Run cancelled ({reason.value}): "
                f"{self.controller.token.message or 'no further detail'}"
            )
        if self._abandoned:
            notes.append(
                "Abandoned: a worker did not stop within "
                f"{self.controller.grace.join_grace_s}s. Counters may be incomplete."
            )
        # Ceiling adjustments come first: they change what the rest of the
        # numbers describe, so they belong above anything derived from them.
        notes.extend(self._policy_notes)
        if self._setup_error:
            # Stated first and separately: when setup fails, nothing was ever
            # sent, so every figure below is zero for a reason that has nothing
            # to do with the target. Read as a resilience result it would be
            # deeply misleading.
            notes.append(
                f"The transport could not be opened, so no packets were sent "
                f"and nothing below measures the target: {self._setup_error}"
            )
        if self._worker_errors:
            first = self._worker_errors[0]
            notes.append(
                f"{len(self._worker_errors)} worker error(s); first was "
                f"{type(first).__name__}: {first}"
            )
        if self._peer_unavailable:
            notes.append(
                f"The target was not accepting traffic when the run started "
                f"({self._peer_unavailable}). No packets were delivered, so the "
                f"figures below describe a target that was already down rather "
                f"than one that fell over under load."
            )
        if self.config.dry_run:
            notes.append("Dry run: no packets were sent.")
        # Placed next to the keep-alive note because both qualify how the
        # figures below should be read, and both are absent when they do not
        # apply - the report stays as quiet as it was before personas existed.
        impersonation = self._impersonation_note()
        if impersonation is not None:
            notes.append(impersonation)
        preamble = self._h2_preamble_note()
        if preamble is not None:
            notes.append(preamble)
        h3 = self._h3_note()
        if h3 is not None:
            notes.append(h3)
        proxy = self._proxy_note()
        if proxy is not None:
            notes.append(proxy)
        rapid = self._rapid_reset_note()
        if rapid is not None:
            notes.append(rapid)
        if self.config.attack.keep_alive:
            notes.append(
                "Keep-alive enabled: delivery figures may overcount if the target "
                "closes connections between requests, because a local sendall() "
                "can succeed after the peer has closed."
            )
        if not self._probes_enabled() and not self.config.dry_run:
            notes.append("Probes disabled for this run.")
        elif self._probes_enabled() and not self._probes:
            # The prober is enabled but recorded nothing, so there is no
            # availability figure to read. Say so rather than let the report
            # show an empty probe table that looks like an omission.
            notes.append(
                "Availability was not measured: the run ended before the first "
                "probe completed. Availability figures are absent rather than "
                "assumed good."
            )
        if self._probes_enabled() and self._target_lacks_http_surface():
            notes.append(
                f"Every probe to {self.config.target.host}:{self.config.target.port}"
                f"{self.probe_path} was refused. The target served no HTTP "
                f"endpoint there, so the 0% availability above records that the "
                f"prober had nothing to talk to - it does not show a target that "
                f"failed under load. Against a target with no HTTP surface, "
                f"availability is unmeasurable and the packet counters are "
                f"sender-side only: they are what this process handed to the "
                f"kernel, not proof of arrival."
            )
        if self.monitor.unavailable_reason:
            # Said explicitly rather than left as absent columns, so a reader can
            # tell "the target was idle" from "we could not see the target".
            notes.append(
                f"Resource figures unavailable: {self.monitor.unavailable_reason}."
            )
        return notes
