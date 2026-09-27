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
from typing import ClassVar

from ..models import ProfileName, Target, TransportKind
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
        self._sock: socket.socket | None = None
        self._family = socket.AF_INET
        self._using_tcp = profile is ProfileName.HTTP_FLOOD
        # Every HTTP payload this transport builds declares ``Connection:
        # close``, so the target will hang up after each response and the socket
        # cannot be reused. Connecting per request is what makes a successful
        # send mean anything.
        self._close_per_request = self._using_tcp

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        if self._open:
            return
        try:
            infos = socket.getaddrinfo(
                self.target.host,
                self.target.port,
                type=socket.SOCK_STREAM if self._using_tcp else socket.SOCK_DGRAM,
            )
        except socket.gaierror as exc:
            raise TransportError(
                f"Cannot resolve target host {self.target.host!r}: {exc}"
            ) from exc

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
        except OSError as exc:
            self._teardown()
            raise TransportError(
                f"Cannot open a socket to {self.target}: {exc}"
            ) from exc

        self._open = True

    def _connect(self, sockaddr: object) -> None:
        assert self._sock is not None
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
        """
        assert self._sock is not None
        if self._close_per_request:
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
        return info
