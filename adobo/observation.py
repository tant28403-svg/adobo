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
    "explain_http_error",
    "refused_connection",
]

STATS_PATH = "/stats"


# Text that means "nothing is listening on that port" rather than "the target was
# reachable and then failed". Matched case-insensitively against the recorded
# error, which carries the exception type name.
NO_HTTP_SURFACE_MARKERS = ("refused", "connecterror")
"""Deliberately narrow. See :func:`refused_connection`.

"refused" covers the spellings that actually reach here - the errno text
"[Errno 111] Connection refused", and the bare exception name
ConnectionRefusedError, which contains no space and so would be missed by a
marker written as "connection refused". "connecterror" is separate because
httpx wraps a refused connect in ConnectError, which never says "refused".

Neither word appears in a timeout or a 5xx, so nothing here can be reached by
the failure modes that must *not* be treated as evidence of an absent service.
"""


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


def explain_http_error(exc: BaseException, url: str) -> str:
    """Name the failure AND where it happened, for empty-bellied exceptions.

    ``reason: ConnectError: `` - type name, colon, nothing - is what an
    operator is shown when the exception's ``str()`` is empty, and a reader
    cannot tell a scheme mismatch (TLS into a plaintext port, the case that
    produced it) from a dead target from it. When the detail is empty the
    connection itself becomes the detail: what was connected to, and over
    which scheme. The probe failure-reason *matching* still keys off the
    exception type name, which survives either branch.
    """
    detail = str(exc).strip()
    if detail:
        return f"{type(exc).__name__}: {detail}"
    return f"{type(exc).__name__} (no detail from the server) when connecting to {url}"


class TargetObservation(Protocol):
    """The subset of the target's ``/stats`` payload this module relies on."""

    requests: int
    errors: int


class _HttpStats:
    """Fetches ``/stats`` over HTTP or HTTPS.

    Declared as a class rather than a function so a test can substitute a stub
    without a network, and so the reason for a failure can be carried through as
    a string instead of an exception type the caller has to know.

    *tls* follows the attack: a run that speaks TLS to the target must read its
    counters over TLS too, because a plaintext read against a TLS-only port
    never answers - and an unobserved run is exactly the ambiguity this module
    exists to eliminate. *verify* follows the run's certificate decision, so a
    lab target with a self-signed certificate is readable instead of failing
    the handshake on a check the operator already declined.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        path: str,
        timeout: float,
        tls: bool = False,
        verify: bool = True,
        host_header: str = "",
    ) -> None:
        scheme = "https" if tls else "http"
        self._url = f"{scheme}://{host}:{port}{path}"
        self._timeout = timeout
        self._verify = verify
        self._headers = {"Host": host_header} if host_header else None
        """The Host the attack presents, when one was configured.

        httpx would otherwise derive Host from the URL - the IP - and on a
        CDN-fronted target that lands on the edge's catch-all instead of the
        site whose counters this reader exists to see. Note that TLS
        *verification* still checks the URL host (the IP); a certificate that
        only names the domain verifies only when the run's verify answer is
        off or the target is addressed by name.
        """

    async def get(self, timeout: float | None = None) -> dict[str, Any]:
        import httpx

        effective = self._timeout if timeout is None else timeout
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(effective), verify=self._verify
        ) as client:
            response = await client.get(self._url, headers=self._headers)
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
        tls: bool = False,
        verify: bool = True,
        host_header: str = "",
    ) -> None:
        scheme = "https" if tls else "http"
        self._url = f"{scheme}://{host}:{port}{path}"
        self._timeout = timeout
        self._last_error: str | None = None
        # Why the most recent alive() sample failed, or None if it succeeded or
        # has not run. Separate from _last_error, which belongs to read() and is
        # about the /stats payload rather than about reachability.
        self.last_probe_error: str | None = None
        if fetch is not None:
            self._fetch = fetch  # type: ignore[assignment]
        else:
            client = _HttpStats(
                host,
                port,
                path=path,
                timeout=timeout,
                tls=tls,
                verify=verify,
                host_header=host_header,
            )
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
            self._last_error = explain_http_error(exc, self._url)
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

        **Any HTTP response counts as an answer** - including a 3xx redirect or
        a WAF's 403. The previous version called ``raise_for_status()`` on the
        fetch, so a 308-to-somewhere or a 403 was counted as a *failure*, and a
        target that had answered 138 times read as "0%, none was refused" - the
        opposite of what the transcript showed. A refused connection, a
        timeout, or silence is what a failed sample means now; a status code,
        whatever it is, is the service speaking.

        The reason for the most recent sample is left on
        :attr:`last_probe_error`: ``None`` after a 2xx/3xx answer, ``HTTP 403``
        (the status that answered) after a 4xx/5xx, or the connection failure
        text. Callers render that distinction rather than collapsing all three.
        """
        try:
            await self._fetch(timeout)
        except Exception as exc:  # noqa: BLE001 - unavailability is the datum
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status is not None:
                # httpx raises HTTPStatusError with the response attached when
                # the fetch is configured to reject non-2xx. The status is the
                # target answering, which is what this method measures.
                self.last_probe_error = f"HTTP {status}"
                return True
            self.last_probe_error = explain_http_error(exc, self._url)
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
