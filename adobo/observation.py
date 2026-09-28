"""Read what the TARGET observed, from the target itself.

The gap this closes
-------------------
``adobo.monitor`` samples CPU and RSS through psutil, which only works on a
local process. Against a remote host it can only report that the figures are
unavailable - correctly, since inventing them would corrupt the score. The
consequence was that a remote run had *no* target-side evidence at all, leaving
the sender's own packet count as the only number in the result.

That is not a measurement. A sender counts what it handed to the operating
system, which says nothing about whether a single packet arrived: the target
may be refusing them, the middlebox may be dropping them, or the host may be
down entirely, and all three look identical from here. The target's own request
counter distinguishes them, and the lab target already exposes one at
``/stats``.

So this module reads that endpoint before and after a run and reports the
difference. The gap between what the sender handed over and what the target
counted *is* the measurement - it is where "it did nothing" stops being a guess.

Why the difference, and not the absolute value
---------------------------------------------
The target may have been serving traffic before the run started, so an absolute
count would attribute someone else's requests to this run. Only the delta
across the window belongs to the run.

``/stats`` is in the lab target's ``DEFAULT_EXEMPT_PATHS``, so it bypasses the
rate limiter and WAF. That is a correctness requirement, not a convenience: if
the mitigation being tested could block the instrumentation, every run would
end up measuring the mitigation blocking its own measurement.

Honest failure
--------------
When the endpoint cannot be read, this reports ``stats_observed=False`` with the
reason. It never falls back to zero-as-if-measured, because an unobserved run
and an observed-but-idle target must not look alike - that ambiguity is exactly
what made the previous reports unreadable.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Protocol

from .models import TargetStats

__all__ = [
    "TargetObservation",
    "TargetObserver",
    "STATS_PATH",
    "NO_HTTP_SURFACE_MARKERS",
    "refused_connection",
]

STATS_PATH = "/stats"


# Text that means "nothing is listening on that port" rather than "the target was
# reachable and then failed". Matched case-insensitively against the recorded
# error, which carries the exception type name.
NO_HTTP_SURFACE_MARKERS = ("connection refused", "connecterror")
"""Deliberately narrow. See :func:`refused_connection`."""


def refused_connection(error: str | None) -> bool:
    """True when an error records a *refused* connection.

    Two very different situations produce an identical 0% availability, and
    reporting them the same way is how a report ends up claiming an outage that
    never happened:

    * the target exposes no HTTP endpoint, so the prober asked a question it was
      never going to get an answer to, and
    * the target answered and then failed, which is a real measurement.

    Only a refused connection distinguishes them. A timeout is deliberately not
    treated as evidence of either: a filtered port, a silent host and a service
    that never responds are indistinguishable from the client, so claiming to
    know which it was would be a guess dressed as a finding.

    Lives here rather than in either caller because both the engine's report and
    the nuclear aggregator need the same distinction, and a second copy of this
    rule is a second thing to keep in step with the first.
    """
    if not error:
        return False
    lowered = error.lower()
    return any(marker in lowered for marker in NO_HTTP_SURFACE_MARKERS)


class TargetObservation(Protocol):
    """The subset of the target's ``/stats`` payload this module relies on."""

    requests: int
    errors: int


class _HttpStats:
    """Fetches ``/stats`` over HTTP.

    Declared as a class rather than a function so a test can substitute a stub
    without a network, and so the reason for a failure can be carried through as
    a string instead of an exception type the caller has to know.
    """

    def __init__(self, host: str, port: int, *, path: str, timeout: float) -> None:
        self._url = f"http://{host}:{port}{path}"
        self._timeout = timeout

    async def get(self, timeout: float | None = None) -> dict[str, Any]:
        import httpx

        effective = self._timeout if timeout is None else timeout
        async with httpx.AsyncClient(timeout=httpx.Timeout(effective)) as client:
            response = await client.get(self._url)
            response.raise_for_status()
            return response.json()


class TargetObserver:
    """Reads the target's own request counters either side of a run.

    The default timeout is deliberately short. A target that does not serve
    ``/stats`` refuses the connection in roughly the timeout's worth of time, and
    this read is not free to be slow: it happens during a live run, so a long
    timeout would either delay the run or leave the caller waiting on evidence
    that is never coming. A ``/stats`` read from a live lab target is about a
    millisecond, so 0.5s is already generous.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        path: str = STATS_PATH,
        timeout: float = 0.5,
        fetch: Callable[[float | None], Awaitable[dict[str, Any]]] | None = None,
    ) -> None:
        self._url = f"http://{host}:{port}{path}"
        self._timeout = timeout
        self._last_error: str | None = None
        # Why the most recent alive() sample failed, or None if it succeeded or
        # has not run. Separate from _last_error, which belongs to read() and is
        # about the /stats payload rather than about reachability.
        self.last_probe_error: str | None = None
        if fetch is not None:
            self._fetch = fetch  # type: ignore[assignment]
        else:
            client = _HttpStats(host, port, path=path, timeout=timeout)
            self._fetch = client.get  # type: ignore[assignment]

    async def read(self, timeout: float | None = None) -> tuple[int, int] | None:
        """Return the target's raw (requests, errors), or None if unreadable.

        *timeout* overrides the instance default. The closing read of a run
        deliberately allows longer than the opening one: the target is still
        working through a backlog of requests the flood already delivered, and
        reading too early would undercount them. Undercounting here is not a
        cosmetic rounding error - it is the delivery figure, and reporting fewer
        requests served than the target actually handled would make a working
        flood look like a failing one. The cost is bounded and is paid after the
        run is over, so it cannot distort what is being measured.

        Never raises. A target that is down, slow, or not running the lab app
        is an expected condition for a stress test, and the caller's correct
        response is to report the absence of evidence - not to abort a run that
        is otherwise proceeding normally.
        """
        try:
            payload = await self._fetch(timeout)
        except Exception as exc:  # noqa: BLE001 - any failure means "unobserved"
            self._last_error = f"{type(exc).__name__}: {exc}"
            return None
        try:
            return int(payload["requests"]), int(payload["errors"])
        except (KeyError, TypeError, ValueError) as exc:
            self._last_error = f"/stats payload missing request counters: {exc}"
            return None

    async def alive(self, timeout: float | None = None) -> bool:
        """True if the target answered its liveness path just now.

        Used as an availability sample during a run, where the question is
        whether the target is still responding rather than what it has counted.
        Never raises: an unreachable target is a failed sample, which is the
        measurement, not an error in the measuring.

        The reason for the most recent failure is left on
        :attr:`last_probe_error`. A boolean cannot distinguish "the target
        collapsed" from "there was never an HTTP service here", and a report
        that has to choose between those two readings is guessing unless it kept
        the reason. Success clears it, so the attribute always describes the
        latest sample rather than the latest failure.
        """
        try:
            await self._fetch(timeout)
        except Exception as exc:  # noqa: BLE001 - unavailability is the datum
            self.last_probe_error = f"{type(exc).__name__}: {exc}"
            return False
        self.last_probe_error = None
        return True

    def window_sync(
        self, before: tuple[int, int] | None, after: tuple[int, int] | None
    ) -> TargetStats:
        """Build the target-side portion of a result from two readings.

        Synchronous, and does no I/O: both readings were taken earlier by
        :meth:`read`, and this only differences them. Keeping it free of I/O is
        what stops an unobservable target from costing anything at result-assembly
        time.

        Returns a :class:`TargetStats` carrying only the request fields; the
        psutil resource fields stay at their defaults because this path is
        remote-capable and those are not (see ``adobo.monitor``).
        """
        if before is None or after is None:
            return TargetStats(
                stats_observed=False,
                stats_error=self._last_error
                or "target /stats could not be read before and after the run",
            )
        return TargetStats(
            requests_served=max(0, after[0] - before[0]),
            errors_served=max(0, after[1] - before[1]),
            stats_observed=True,
        )

    # Retained under its original name for callers that were written against the
    # async form; identical behaviour, since it no longer awaits anything.
    window = window_sync
