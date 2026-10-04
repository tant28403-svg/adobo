"""HTTP/2 transport using the h2 library.

Provides true multiplexed HTTP/2 over TLS with flow control.
One connection, many concurrent streams — the throughput multiplier.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

import h2.config
import h2.connection
import h2.events
import h2.errors

from ..fingerprint import Fingerprint
from ..h2profile import H2Profile, DEFAULT_PSEUDO_HEADER_ORDER
from ..models import ProfileName, Target, TransportKind
from ..netpolicy import resolve_target
from .base import PeerUnavailable, Transport, TransportError, supports_profile

if TYPE_CHECKING:
    from ..engine import RunController

__all__ = ["H2Transport", "H2ErrorCode"]

DEFAULT_H2_CONCURRENCY = 100
"""Streams per connection. Equivalent to keep-alive concurrency multiplier."""

DEFAULT_SEND_TIMEOUT = 2.0
DEFAULT_CONNECT_TIMEOUT = 1.0
DEFAULT_STREAM_TIMEOUT = 10.0  # Per-stream timeout
DEFAULT_DRAIN_TIMEOUT = 30.0  # Max time to drain all streams


class H2ErrorCode(IntEnum):
    """HTTP/2 error codes (RFC 7540 Section 7)."""
    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xA
    ENHANCE_YOUR_CALM = 0xB
    INADEQUATE_SECURITY = 0xC
    HTTP_1_1_REQUIRED = 0xD


@dataclass
class StreamState:
    """Track a single HTTP/2 stream's lifecycle."""
    stream_id: int
    state: str = "idle"  # idle -> headers_sent -> headers_received -> data_receiving -> done
    started_at: float = 0.0
    response_bytes: int = 0
    rst_received: bool = False
    rst_error_code: int | None = None


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
        fingerprint: Fingerprint | None = None,
        h2_profile: H2Profile | None = None,
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
        self._persona = fingerprint
        """Persona to present, or ``None`` for the self-identifying default.

        Held here rather than read from the payload because this transport
        builds its own HTTP/2 header block and ignores the bytes the engine hands
        to ``send_one``. A persona set per request could not be honoured by a
        multiplexed connection anyway: every stream on one connection shares one
        identity, which is the same reason ``per_request`` rotation cannot apply
        to HTTP/2.
        """
        self._h2_profile = h2_profile
        """Connection preamble to present, or ``None`` to leave h2's defaults.

        ``None`` is the default and is load-bearing: it means this transport
        touches nothing about the connection preamble, so a run with no persona
        configured emits byte-for-byte what it emitted before preambles existed.
        Not ``H2_PROFILES["h2_library"]``, because naming a profile would make it
        reachable by a typo and would imply the default is a chosen identity
        rather than the absence of one.
        """

        self._sock: socket.socket | None = None
        self._conn: h2.connection.H2Connection | None = None
        self._streams: dict[int, StreamState] = {}
        self._next_stream_id = 1
        self._window = 65535  # Initial flow control window
        self._local_window = 65535  # Local flow control window
        self._remote_window = 65535  # Remote flow control window (what we can send)
        self._goaway_received = False
        self._goaway_error_code: int | None = None
        self._goaway_last_stream_id: int | None = None
        self._ping_outstanding: bool = False
        self._last_ping_time: float = 0
        self._ping_rtt: float = 0.0

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
            # Connect to the address the allowlist permitted rather than to the
            # name. create_connection() would resolve the name itself, and a name
            # is not an address - it could come back as something else between
            # the check and the connect. Handed an IP literal it performs no DNS
            # lookup at all, so what is dialled is what was vetted. SNI and
            # certificate validation still use the name, below.
            infos, _decision = resolve_target(
                self.target.host,
                self.target.port,
                socket.SOCK_STREAM,
            )
            self._vetted = infos
            # Rebuilt as a 2-tuple rather than passed through: an AF_INET6
            # sockaddr is (host, port, flowinfo, scopeid) and create_connection
            # rejects anything that is not exactly (host, port). Passing
            # infos[0][4] straight through broke every IPv6 target.
            _family, _socktype, _proto, _canon, sockaddr = infos[0]
            raw_sock = socket.create_connection(
                (sockaddr[0], self.target.port),
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

            # Must precede initiate_connection(): that call is what serialises
            # local_settings into the single SETTINGS frame, and it is the only
            # point at which those values can be influenced. See the ordering
            # constraints documented on H2Profile.apply - calling
            # update_settings() here instead would emit frames ahead of the
            # PRI * HTTP/2.0 magic and produce a preface the peer rejects.
            if self._h2_profile is not None:
                self._h2_profile.apply(self._conn)

            self._conn.initiate_connection()

            # After initiating, for the same reason: increment_flow_control_window
            # emits immediately, and anything emitted before the magic is a
            # malformed preface.
            if self._h2_profile is not None:
                increment = self._h2_profile.window_increment()
                if increment:
                    self._conn.increment_flow_control_window(increment)

            self._sock.sendall(self._conn.data_to_send())

            # Wait for SETTINGS acknowledged
            self._await_settings_ack()

        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
            self._teardown()
            raise TransportError(f"Cannot open HTTP/2 connection to {self.target}: {exc}") from exc

        # This open() overrides the base method, so it must do what the base
        # does. Without the clear, a transport closed after one run and opened
        # for the next would come back already flagged as stopping and exit its
        # send loop immediately - reporting a clean zero, which is
        # indistinguishable from a run that worked. The scapy transport had this
        # exact defect and it is covered by a test there; this is the same fix.
        self._stop.clear()
        self.connections_opened += 1
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
        # Pseudo-header order is a fingerprint signal in its own right, and it is
        # the one component of the preamble that lives here rather than in
        # open(): it is decided per stream, not per connection.
        #
        # RFC 9113 requires pseudo-headers to precede ordinary headers and every
        # name to be lowercase, and the h2 library enforces both - but it fixes
        # no order *among* the pseudo-headers, so this is where the choice is
        # made. That is why this transport cannot reuse an HTTP/1.1 header block
        # verbatim, and why a persona's canonical-case names are lowercased here
        # rather than stored twice in both cases where the two copies could drift.
        pseudo_values = {
            ':method': 'GET',
            ':path': self.tcp_path,
            ':authority': self.target.host,
            ':scheme': 'https',
        }
        order = (
            self._h2_profile.pseudo_header_order
            if self._h2_profile is not None
            else DEFAULT_PSEUDO_HEADER_ORDER
        )
        headers: list[tuple[str, str]] = [
            (name, pseudo_values[name]) for name in order
        ]
        #
        # With no persona the identity stays the self-identifying
        # "adobo-h2-flood", which is unchanged from before personas existed. This
        # transport builds its own headers and ignores the payload the engine
        # hands it, so the persona arrives at construction instead.
        if self._persona is not None:
            headers.extend(
                (name.lower(), value) for name, value in self._persona.headers
            )
        else:
            headers.append(('user-agent', 'adobo-h2-flood'))

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
            # Guarded because both handlers above tear the connection down, which
            # sets _sock to None - so a peer that closes mid-drain would otherwise
            # turn a clean disconnect into an AttributeError raised from the
            # finally block, replacing the teardown with a traceback. That masks
            # the real cause and propagates out of send_one, where the engine counts
            # it as a worker error rather than as the connection ending.
            if self._sock is not None:
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

        elif isinstance(event, h2.events.ConnectionTerminated):
            # Connection terminated by peer
            self._teardown()

        elif isinstance(event, h2.events.GoawayReceived):
            # Server sent GOAWAY
            self._goaway_received = True
            self._goaway_error_code = event.error_code
            self._goaway_last_stream_id = event.last_stream_id
            self._teardown()

        elif isinstance(event, h2.events.RstStreamReceived):
            # Server reset stream
            if event.stream_id in self._streams:
                stream = self._streams.pop(event.stream_id, None)
                if stream:
                    stream.rst_received = True
                    stream.rst_error_code = event.error_code

        elif isinstance(event, h2.events.PingReceived):
            # Server sent PING - we should respond with PING_ACK
            # h2 handles this automatically, but we can track it
            pass

        elif isinstance(event, h2.events.PingAckReceived):
            # Our PING was acknowledged - calculate RTT
            if self._ping_outstanding:
                self._ping_rtt = time.monotonic() - self._last_ping_time
                self._ping_outstanding = False

        elif isinstance(event, h2.events.AlternativeServiceAvailable):
            # Server offered alternative service (ALTSVC)
            pass  # Could be used for connection migration

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
        """Whether the engine has asked this transport to wind down.

        Reads the base class's stop event rather than a private flag. It used to
        keep its own ``_external_stop`` boolean, which meant ``request_stop``
        overrode the base method without setting the event the base class's
        ``stopping`` property reads - so any base-class code added later would
        have seen a transport that was not stopping. The scapy transport had the
        same defect and it was fixed there; this is the same fix.
        """
        return self.stopping

    def request_stop(self) -> None:
        """Called by engine to request graceful stop.

        Now delegates to the base implementation instead of replacing it, so
        ``stopping`` and the event stay in agreement.
        """
        super().request_stop()

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info.update({
            "protocol": "h2",
            "concurrency": self.concurrency,
            "tls_verify": self.tls_verify,
            "goaway_received": self._goaway_received,
            "goaway_error_code": self._goaway_error_code,
            "goaway_last_stream_id": self._goaway_last_stream_id,
            "ping_rtt": self._ping_rtt,
        })
        return info