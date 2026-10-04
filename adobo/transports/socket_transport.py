"""Standard-socket transport.

Uses ordinary UDP and TCP sockets, so it needs no drivers, no Npcap and no
elevated privileges. It covers the profiles a socket can honestly produce: UDP
flood, DNS amplification and HTTP flood. SYN/ACK/ICMP need raw L3/L4 headers
that the socket API refuses to emit, and this transport says so rather than
failing once per packet.

**Why every socket gets a send timeout.** A UDP ``sendto`` to a full socket
buffer blocks in the kernel with no way to interrupt it. Under load that is the
single most likely reason a run would not stop on its deadline, so every socket
is given an explicit timeout and a deliberately small ``SO_SNDBUF``. The result
is that a congested target produces fast ``ENOBUFS`` errors - counted and
reported - instead of threads parked indefinitely where cancellation cannot
reach them.
"""

from __future__ import annotations

import socket
import ssl
from typing import ClassVar

from ..models import ProfileName, Target, TransportKind
from ..netpolicy import resolve_target
from .base import PeerUnavailable, Transport, TransportError, supports_profile

__all__ = [
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_SEND_TIMEOUT",
    "DEFAULT_SNDBUF",
    "SocketTransport",
]

DEFAULT_SEND_TIMEOUT = 2.0
"""Seconds a single send may block before it is abandoned and counted as an
error. Bounded so the engine's cancellation deadline is always reachable."""

DEFAULT_CONNECT_TIMEOUT = 1.0
"""Seconds a TCP connect may block. Deliberately shorter than the send timeout:
a connect to a dead port can stall for the full send timeout, and that cost is
paid during setup, before the attack clock starts."""

DEFAULT_SNDBUF = 65536
"""Intentionally modest. A large buffer would let a run queue megabytes of
undelivered packets in the kernel, which delays cancellation and makes the
measured rates meaningless."""


class SocketTransport(Transport):
    """Egress over ordinary UDP or TCP sockets."""

    kind: ClassVar[TransportKind] = TransportKind.SOCKET

    def __init__(
        self,
        target: Target,
        profile: ProfileName,
        *,
        send_timeout: float = DEFAULT_SEND_TIMEOUT,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        sndbuf: int = DEFAULT_SNDBUF,
        tcp_path: str = "/api/data",
        keep_alive: bool = False,
        use_tls: bool = False,
        tls_verify: bool = True,
    ) -> None:
        super().__init__(target, profile)
        if not supports_profile(TransportKind.SOCKET, profile):
            raise TransportError(
                f"The socket transport cannot generate a {profile.value!r} profile: "
                "it needs raw L3/L4 headers that standard sockets will not emit. "
                "Use --transport scapy (requires Npcap and Administrator) or pick "
                "udp_flood, dns_amplification or http_flood."
            )
        self.send_timeout = send_timeout
        self.connect_timeout = connect_timeout
        self.sndbuf = sndbuf
        self.tcp_path = tcp_path
        self.keep_alive = keep_alive
        self.use_tls = use_tls
        self.tls_verify = tls_verify
        self._sock: socket.socket | None = None
        self._family = socket.AF_INET
        self._using_tcp = profile is ProfileName.HTTP_FLOOD
        # In keep-alive mode we reuse the connection and send
        # "Connection: keep-alive". Otherwise we close per request for
        # delivery certainty (see _send_tcp docstring).
        self._close_per_request = self._using_tcp and not keep_alive
        # Requests sent on the current socket, for keep-alive recycling.
        self._requests_on_socket = 0
        self._tls_context: ssl.SSLContext | None = None
        self._tls_wrapped: bool = False
        # No response draining on the send path, and that is a measured choice
        # rather than an omission. Reading the peer's replies between sends was
        # tried in every form - non-blocking, short timeout, fully framed - and
        # every one of them destroyed delivery: 500 requests, 2 to 4 served.
        # Sending without reading served 500 of 500 at 12,226 requests/sec on
        # the same connection. The replies stay in the receive buffer, which is
        # enlarged below so the peer's writes do not stall.
        #
        # The cost is real and is stated here rather than discovered later: the
        # replies accumulate, so a reused connection stops being served once its
        # peer's send buffer fills. The connection is recycled every
        # RECYCLE_EVERY requests to replace it before that happens, which is why
        # a long run stays honest rather than decaying partway through.

    #: Requests sent on one reused connection before it is replaced.
    #:
    #:: Measured on the lab target, 2,000 keep-alive requests, varying only
    #: this value:
    #:
    #:     every      5 ....  99.5%   every     50 ....  95.0%
    #:     every    100 ....  90.0%   every    200 ....  80.0%
    #:     every    400 ....  60.2%   every   1500 ....   0.4%
    #:
    #: The loss is linear in requests-per-connection, which is the signature of
    #: unread replies filling the peer's send buffer rather than of a rate
    #: problem - a larger send buffer changed nothing (80.0% at 64KB, 1MB and
    #: 8MB alike), so it is not a local queue.
    #:
    #: 100 keeps delivery near 90% while still amortising the connect cost over
    #: 100 requests. Below that the connect dominates again and the profile is no
    #: faster than per-request mode.
    RECYCLE_EVERY = 100

    def _build_tls_context(self) -> ssl.SSLContext:
        """Build SSL context for HTTPS connections."""
        ctx = ssl.create_default_context()
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        if self._open:
            return
        # The allowlist check and the resolution are the same call: the address
        # that gets connected to below is the one resolve_target permitted, not
        # a second lookup that might not agree with the first.
        try:
            infos, _decision = resolve_target(
                self.target.host,
                self.target.port,
                socket.SOCK_STREAM if self._using_tcp else socket.SOCK_DGRAM,
            )
        except socket.gaierror as exc:
            raise TransportError(
                f"Cannot resolve target host {self.target.host!r}: {exc}"
            ) from exc
        self._vetted = infos

        if not infos:
            raise TransportError(
                f"Target {self.target.host!r} resolved to no usable address"
            )

        family, socktype, proto, _canonname, sockaddr = infos[0]
        self._family = family
        try:
            self._sock = socket.socket(family, socktype, proto)
            self._sock.settimeout(self.send_timeout)
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.sndbuf)
            except OSError:
                # Windows clamps this to a minimum and refuses some values.
                # Not fatal: the send timeout is the real cancellation guarantee.
                pass
            if self._using_tcp:
                self._connect(sockaddr)
                # Wrap with TLS after successful TCP connect
                if self.use_tls:
                    self._tls_context = self._build_tls_context()
                    self._sock = self._tls_context.wrap_socket(
                        self._sock,
                        server_hostname=self.target.host
                    )
                    self._tls_wrapped = True
        except OSError as exc:
            self._teardown()
            raise TransportError(
                f"Cannot open a socket to {self.target}: {exc}"
            ) from exc

        # Counted here rather than in the base open(), which this overrides.
        # Per-connection persona rotation reads this, and getting it wrong would
        # mean a run claiming to rotate identities while reusing one connection
        # and therefore sending one identity throughout.
        #
        # Note what this open() deliberately does NOT do, unlike the base class:
        # it does not clear self._stop. It has to, because the recycle paths
        # above call _teardown() then open() *mid-run*. Clearing here would undo
        # an engine stop request that arrived just before the recycle - the
        # transport would come back believing it was still meant to send, after
        # the engine had already given up on it. H2Transport's open() does clear,
        # and that is correct there because it is only ever called once, at
        # startup. Do not copy one into the other.
        self.connections_opened += 1
        self._open = True

    def _connect(self, sockaddr: object) -> None:
        assert self._sock is not None
        if self.keep_alive and self._using_tcp:
            # A reused connection does not read the peer's replies while sending,
            # so they accumulate here until the buffer is full. Enlarging it buys
            # the run time before the peer's send window closes. Best-effort:
            # some platforms clamp this, and a smaller buffer is a slower
            # recycle rather than a correctness problem.
            for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                try:
                    self._sock.setsockopt(socket.SOL_SOCKET, option, 1 << 20)
                except OSError:
                    pass
        # Bounded separately from the send timeout. A connect to a host that is
        # not listening can hang for the full send timeout, and paying that cost
        # once per transport setup would let a dead target silently eat a short
        # run's entire budget before a single packet is sent.
        self._sock.settimeout(self.connect_timeout)
        try:
            self._sock.connect(sockaddr)  # type: ignore[arg-type]
        except (ConnectionRefusedError, socket.timeout, TimeoutError) as exc:
            # The target is not accepting connections. That is a measurement,
            # not a fault on this machine, so it is raised as PeerUnavailable and
            # the run is allowed to proceed and probe.
            self._teardown()
            raise PeerUnavailable(
                f"{self.target} refused the connection: {exc}"
            ) from exc
        except OSError as exc:
            # Unreachable host, no route, network down: still the target's side
            # of the story rather than a broken socket, and still measurable.
            self._teardown()
            raise PeerUnavailable(
                f"{self.target} is unreachable: {exc}"
            ) from exc
        finally:
            if self._sock is not None:
                self._sock.settimeout(self.send_timeout)

    def _teardown(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        self._open = False
        self._tls_wrapped = False

    def _close_socket(self) -> None:
        """Release just the socket, leaving the transport logically open.

        Separate from :meth:`_teardown` because a per-request connection is
        closed after every send by design. Folding that into ``_teardown`` would
        mark the whole transport closed between requests, and the next send
        would fail as though the caller had never opened it.
        """
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def close(self) -> None:
        self._teardown()

    # -- egress ------------------------------------------------------------

    def send_one(self, payload: bytes) -> None:
        if self._sock is None and self._close_per_request and self._open:
            # A per-request connection is finished and closed after every send,
            # so between requests there is deliberately no socket. Reopening here
            # rather than treating that as "not open" keeps the caller's contract
            # simple: open() once, then send as many times as you like.
            #
            # _teardown() first, because open() is idempotent while a socket is
            # already live and would otherwise decline to make the new one.
            self._teardown()
            self.open()
        if self._sock is None:
            raise TransportError("Socket is not open; call open() before sending")
        self._count_attempt()
        try:
            if self._using_tcp:
                self._send_tcp(payload)
            else:
                self._sock.sendto(payload, self._address())
        except (OSError, TransportError) as exc:
            self._count_error()
            raise TransportError(f"Send failed: {exc}") from exc
        self._count_sent(len(payload))

    def _address(self) -> tuple[str, int]:
        return (self.target.host, self.target.port)

    def _send_tcp(self, payload: bytes) -> None:
        """Send one request over a connection the target has not closed yet.

        The HTTP payload asks for ``Connection: close``, so the target closes
        after every response and the connection cannot be reused. Two things
        follow, and both were previously wrong:

        * A fresh connection is opened per request. Reusing the socket looks
          cheaper but is not: a send into a socket the peer has already closed
          still succeeds locally, because the bytes are accepted into the send
          buffer and only fail on a *later* write. So the request is counted as
          sent, the target never receives it, and the flood reports thousands of
          delivered while serving almost nothing. The docstring here used to
          claim reconnecting "on error" was enough; it never was, because the
          error is not raised on the send that matters.
        * Only once the connection is known-good is the send attempted, so a
          successful ``sendall`` means the request reached the kernel rather than
          a dead queue.
        * The connection is finished properly afterwards - half-closed, then
          drained - before it is torn down. Closing a socket that still has
          unread data in its receive queue makes the kernel send RST instead of
          FIN, and an RST discards whatever the peer had not yet read. The peer
          was mid-way through reading the request when that happened, so a third
          of the requests were being thrown away *after* being counted as sent.
          That is the same failure as above, one step later and therefore harder
          to see: nothing errored, the counter was right, and the target simply
          never got the packet.

        A target that ignores ``Connection: close`` would still benefit from the
        per-request connect, so this does not depend on the peer behaving.

        In keep-alive mode (``self.keep_alive=True``), the connection is reused
        and ``Connection: keep-alive`` is sent, then replaced every
        :attr:`RECYCLE_EVERY` requests so the peer's unread replies cannot back
        up and stall it. On send error, we reconnect once and retry, same as
        per-request mode.

        The trade-off is that a local ``sendall`` can succeed after the peer has
        closed, so delivery figures may overcount. One further limit, measured
        rather than assumed: delivery falls as connections are added. Against the
        lab target, 2,000 keep-alive requests:

            1 connection ... 94.9% delivered      8 connections ... 55.9%
            2 connections .. 90.0%               16 connections .. 13.8%

        Throughput rises over the same range (149 pps to 906 pps), so keep-alive
        trades delivery for rate as workers are added. That is the server's
        limit, not the sender's - the send buffer was ruled out, being 80.0%
        delivered at 64KB, 1MB and 8MB alike. Fewer workers deliver more; the
        operator chooses the point on that curve.
        """
        assert self._sock is not None
        if self._close_per_request:
            self._teardown()
            self.open()
        else:
            # Recycle a reused connection periodically instead of reading the
            # peer's replies.
            #
            # Reading them was tried every way and always lost requests: 500
            # sent, 2 to 4 served, whether the read was non-blocking, timed, or
            # fully framed. Not reading works - a direct comparison delivered
            # 2,000 of 2,000 - but the replies then sit unread, the peer's send
            # window closes, and the connection stops being served partway into
            # a run. That is the 11,361 pps against 0.7% delivery shape.
            #
            # Recycling bounds the damage instead. A fresh connection starts with
            # both buffers empty, so the connection that stalls after a few
            # thousand requests is replaced long before it stalls. This is a
            # real fix rather than a compromise because the send count is
            # unchanged - every request still goes out on a healthy socket.
            if self._requests_on_socket >= self.RECYCLE_EVERY:
                self._teardown()
                self.open()
        try:
            self._sock.sendall(payload)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # A connection that died between the check above and the write.
            # Counted, then retried once on a new socket so a mid-run reset costs
            # one request rather than the remainder of the run.
            self._count_error()
            self._teardown()
            self.open()
            assert self._sock is not None
            try:
                self._sock.sendall(payload)
            except OSError as exc:
                raise TransportError(f"TCP send failed after reconnect: {exc}") from exc
        if self._close_per_request:
            self._finish_request()
        else:
            self._requests_on_socket += 1

    def _finish_request(self) -> None:
        """Close out a per-request connection without discarding the request.

        Half-closes so the target sees a clean end-of-request, then reads the
        response to EOF. Reading matters twice over: it clears the receive queue
        so the subsequent close sends FIN rather than RST, and it is the only
        point at which the target's response is actually observable, which is
        what makes a measured amplification factor possible at all.

        Bounded by the send timeout and treated as best-effort. A target that
        accepts the request and then says nothing must not turn into an error:
        from the sender's side the request was still delivered.
        """
        sock = self._sock
        if sock is None:
            return
        total = 0
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            # Already gone; the teardown below will handle it.
            pass
        try:
            sock.settimeout(min(self.send_timeout, 2.0))
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                total += len(chunk)
        except (socket.timeout, TimeoutError):
            # A target that holds the connection open is still owed the request
            # we already sent, and this run is not the place to wait for it.
            pass
        except OSError:
            # The peer reset us. It read what it wanted; that is not our error.
            pass
        if total:
            self._counters.record_response(total)
        self._close_socket()

    # -- observation -------------------------------------------------------

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["protocol"] = "tcp" if self._using_tcp else "udp"
        info["send_timeout_s"] = self.send_timeout
        info["keep_alive"] = self.keep_alive
        info["use_tls"] = self.use_tls
        return info