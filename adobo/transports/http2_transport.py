"""HTTP/2 transport using the h2 library.

Provides true multiplexed HTTP/2 over TLS with flow control.
One connection, many concurrent streams — the throughput multiplier.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import h2.config
import h2.connection
import h2.events
import h2.errors

from ..models import ProfileName, Target, TransportKind
from .base import PeerUnavailable, Transport, TransportError, supports_profile

if TYPE_CHECKING:
    from ..engine import RunController

__all__ = ["H2Transport"]

DEFAULT_H2_CONCURRENCY = 100
"""Streams per connection. Equivalent to keep-alive concurrency multiplier."""

DEFAULT_SEND_TIMEOUT = 2.0
DEFAULT_CONNECT_TIMEOUT = 1.0
DEFAULT_STREAM_TIMEOUT = 10.0  # Per-stream timeout
DEFAULT_DRAIN_TIMEOUT = 30.0  # Max time to drain all streams


@dataclass
class StreamState:
    """Track a single HTTP/2 stream's lifecycle."""
    stream_id: int
    state: str = "idle"  # idle -> headers_sent -> headers_received -> data_receiving -> done
    started_at: float = 0.0
    response_bytes: int = 0


class H2Transport(Transport):
    """HTTP/2 over TLS with multiplexed streams."""

    kind: TransportKind = TransportKind.H2

    def __init__(
        self,
        target: Target,
        profile: ProfileName,
        *,
        send_timeout: float = DEFAULT_SEND_TIMEOUT,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        concurrency: int = DEFAULT_H2_CONCURRENCY,
        tls_verify: bool = True,
        tcp_path: str = "/api/data",
    ) -> None:
        super().__init__(target, profile)
        if not supports_profile(TransportKind.H2, profile):
            raise TransportError(
                f"HTTP/2 transport only supports http_flood profile, got {profile.value!r}"
            )
        self.send_timeout = send_timeout
        self.connect_timeout = connect_timeout
        self.concurrency = concurrency
        self.tls_verify = tls_verify
        self.tcp_path = tcp_path
        self.stream_timeout = DEFAULT_STREAM_TIMEOUT
        self.drain_timeout = DEFAULT_DRAIN_TIMEOUT

        self._sock: socket.socket | None = None
        self._conn: h2.connection.H2Connection | None = None
        self._streams: dict[int, StreamState] = {}
        self._next_stream_id = 1
        self._window = 65535  # Initial flow control window
        self._local_window = 65535  # Local flow control window
        self._remote_window = 65535  # Remote flow control window (what we can send)
        self._external_stop = False  # Engine cancellation flag

    def _build_tls_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2'])
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def open(self) -> None:
        if self._open:
            return
        try:
            # TCP connect
            raw_sock = socket.create_connection(
                (self.target.host, self.target.port),
                timeout=self.connect_timeout
            )
            raw_sock.settimeout(self.send_timeout)

            # TLS with ALPN
            ctx = self._build_tls_context()
            self._sock = ctx.wrap_socket(
                raw_sock,
                server_hostname=self.target.host
            )
            negotiated = self._sock.selected_alpn_protocol()
            if negotiated != 'h2':
                raise TransportError(
                    f"ALPN negotiation failed: server offered {negotiated!r}, expected h2"
                )

            # HTTP/2 connection
            config = h2.config.H2Configuration(
                client_side=True,
                header_encoding='utf-8',
            )
            self._conn = h2.connection.H2Connection(config=config)
            self._conn.initiate_connection()
            self._sock.sendall(self._conn.data_to_send())

            # Wait for SETTINGS acknowledged
            self._await_settings_ack()

        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
            self._teardown()
            raise TransportError(f"Cannot open HTTP/2 connection to {self.target}: {exc}") from exc

        self._open = True

    def _await_settings_ack(self) -> None:
        """Block until server acknowledges our initial SETTINGS."""
        deadline = time.monotonic() + self.send_timeout
        while True:
            if time.monotonic() > deadline:
                raise TransportError("Timeout waiting for SETTINGS ack")
            data = self._sock.recv(65535)
            if not data:
                raise TransportError("Server closed connection during SETTINGS")
            events = self._conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.SettingsAcknowledged):
                    return
            self._sock.sendall(self._conn.data_to_send())

    def _teardown(self) -> None:
        if self._sock is not None:
            try:
                if self._conn:
                    # Graceful GOAWAY
                    self._conn.close_connection(error_code=h2.errors.ErrorCodes.NO_ERROR)
                    self._sock.sendall(self._conn.data_to_send())
                self._sock.close()
            finally:
                self._sock = None
                self._conn = None
                self._streams.clear()
        self._open = False

    def close(self) -> None:
        self._teardown()

    def send_one(self, payload: bytes) -> None:
        """Send one HTTP/2 request on a new stream."""
        if not self._open or not self._conn or not self._sock:
            raise TransportError("Transport not open")

        # Respect concurrency limit
        while len(self._streams) >= self.concurrency:
            self._drain_responses()
            if self._should_stop_external():
                return

        # Check local flow control window before opening new stream
        if self._local_window < 16384:  # Less than 16KB available
            self._drain_responses()
            # If still low, wait a bit
            if self._local_window < 16384:
                time.sleep(0.01)
                self._drain_responses()

        stream_id = self._conn.get_next_available_stream_id()
        headers = [
            (':method', 'GET'),
            (':path', self.tcp_path),
            (':authority', self.target.host),
            (':scheme', 'https'),
            ('user-agent', 'adobo-h2-flood'),
        ]

        self._conn.send_headers(stream_id, headers, end_stream=True)
        self._streams[stream_id] = StreamState(
            stream_id=stream_id,
            state="headers_sent",
            started_at=time.monotonic()
        )
        self._count_attempt()
        self._sock.sendall(self._conn.data_to_send())

        # Try to get response immediately
        self._drain_responses()

    def _drain_responses(self) -> None:
        """Read and process incoming frames."""
        if not self._sock or not self._conn:
            return
        try:
            self._sock.settimeout(0.01)  # Non-blocking poll
            data = self._sock.recv(65535)
            if not data:
                # Connection closed by peer
                self._teardown()
                return
            events = self._conn.receive_data(data)
            for event in events:
                self._handle_event(event)
        except socket.timeout:
            pass
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            self._teardown()
        finally:
            self._sock.settimeout(self.send_timeout)

        # Check for stream timeouts
        self._check_stream_timeouts()

        # Send any pending frames (WINDOW_UPDATE, etc.)
        if self._conn:
            self._sock.sendall(self._conn.data_to_send())

    def _handle_event(self, event: h2.events.Event) -> None:
        if isinstance(event, h2.events.ResponseReceived):
            # Headers received, stream is active
            if event.stream_id in self._streams:
                self._streams[event.stream_id].state = "headers_received"

        elif isinstance(event, h2.events.DataReceived):
            # Response body data
            if event.stream_id in self._streams:
                stream = self._streams[event.stream_id]
                stream.response_bytes += len(event.data)
                stream.state = "data_receiving"
                # Acknowledge flow control
                self._conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )

        elif isinstance(event, h2.events.StreamEnded):
            # Response complete
            if event.stream_id in self._streams:
                stream = self._streams.pop(event.stream_id)
                stream.state = "done"
                self._count_sent(1)  # Count the request as sent

        elif isinstance(event, h2.events.WindowUpdated):
            # Flow control window opened
            if event.stream_id == 0:
                # Connection-level window update
                self._remote_window += event.delta
            else:
                # Stream-level window update
                pass  # h2 handles stream-level internally

        elif isinstance(event, h2.events.RemoteSettingsChanged):
            # Server sent new SETTINGS
            pass  # h2 handles automatically

        elif isinstance(event, (h2.events.ConnectionTerminated, h2.events.GoawayReceived)):
            self._teardown()

        elif isinstance(event, h2.events.RstStreamReceived):
            # Server reset stream - remove from tracking
            if event.stream_id in self._streams:
                self._streams.pop(event.stream_id, None)

    def _check_stream_timeouts(self) -> None:
        """Check for and clean up timed-out streams."""
        now = time.monotonic()
        timed_out = []
        for stream_id, stream in self._streams.items():
            if now - stream.started_at > self.stream_timeout:
                timed_out.append(stream_id)
        for stream_id in timed_out:
            # Send RST_STREAM for timed out stream
            try:
                if self._conn and self._open:
                    self._conn.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
                    self._sock.sendall(self._conn.data_to_send())
            except Exception:
                pass
            self._streams.pop(stream_id, None)

    def _drain_responses(self) -> None:
        """Read and process incoming frames."""
        if not self._sock or not self._conn:
            return
        try:
            self._sock.settimeout(0.01)  # Non-blocking poll
            data = self._sock.recv(65535)
            if not data:
                # Connection closed by peer
                self._teardown()
                return
            events = self._conn.receive_data(data)
            for event in events:
                self._handle_event(event)
        except socket.timeout:
            pass
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            self._teardown()
        finally:
            self._sock.settimeout(self.send_timeout)

        # Check for stream timeouts
        self._check_stream_timeouts()

        # Send any pending frames (WINDOW_UPDATE, etc.)
        if self._conn:
            self._sock.sendall(self._conn.data_to_send())

    def _drain_all(self) -> None:
        """Wait for all in-flight streams to complete."""
        deadline = time.monotonic() + self.drain_timeout
        while self._streams:
            if time.monotonic() > deadline:
                # Force close remaining streams
                for stream_id in list(self._streams.keys()):
                    try:
                        if self._conn and self._open:
                            self._conn.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
                    except Exception:
                        pass
                break
            self._drain_responses()
            if self._should_stop_external():
                # Send RST_STREAM for remaining streams
                for stream_id in list(self._streams.keys()):
                    try:
                        if self._conn and self._open:
                            self._conn.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
                    except Exception:
                        pass
                break

    def _should_stop_external(self) -> bool:
        """Check if engine requested stop."""
        return self._external_stop

    def request_stop(self) -> None:
        """Called by engine to request graceful stop."""
        self._external_stop = True

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info.update({
            "protocol": "h2",
            "concurrency": self.concurrency,
            "tls_verify": self.tls_verify,
        })
        return info