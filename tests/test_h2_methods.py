"""POST and HEAD over the HTTP/2 transport.

The h2 transport builds its own header block and ignores the HTTP/1.1 bytes
the engine hands it, so request-shape options need their own path here - and
their own proof. These tests drive the real ``open()``/``send_one()`` against
a socket whose far end is a genuine server-mode h2 connection, then assert on
the frames the server actually received. Asserting on received frames rather
than on h2's client-side API means a change in *what goes on the wire* fails
here, which is the thing a run's delivery figure depends on.

The byte-compat rule carries over from the HTTP/1.1 work: with every option at
its default, the header block and the framing (HEADERS with END_STREAM, no
DATA) are exactly what the transport always sent.
"""

from __future__ import annotations

import socket

import h2.config
import h2.connection
import pytest

from adobo.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TransportKind,
)
from adobo.transports import get_transport
from adobo.transports.http2_transport import H2Transport
from adobo.transports.rapid_reset_transport import RapidResetTransport

TARGET = Target(host="127.0.0.1", port=443)


class _PeerSocket:
    """A socket whose far end is a real server-mode h2 connection.

    ``recv`` raises ``socket.timeout`` when the peer has nothing queued, which
    is the transport's normal no-data poll path - a stub returning b"" there
    would read as "peer closed" and tear the connection down.
    """

    def __init__(self) -> None:
        self.sent = bytearray()
        self.closed = False
        self.events: list = []
        self._peer = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        self._peer.initiate_connection()
        self._pending = bytearray(self._peer.data_to_send())

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)
        for event in self._peer.receive_data(bytes(data)):
            self.events.append(event)
            if isinstance(event, h2.events.DataReceived):
                # A real server acks body bytes as its application consumes
                # them; without this the client's send window never reopens
                # and the chunked-body path would (correctly) wait forever.
                self._peer.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
        self._pending.extend(self._peer.data_to_send())

    def recv(self, size: int) -> bytes:
        if not self._pending:
            raise socket.timeout
        chunk = bytes(self._pending[:size])
        del self._pending[:size]
        return chunk

    def selected_alpn_protocol(self) -> str:
        return "h2"

    def close(self) -> None:
        self.closed = True

    def shutdown(self, _how: int) -> None:
        pass


class _RecordingContext:
    """An SSL context whose ``wrap_socket`` hands the peer socket straight back."""

    def __init__(self, recorder: _PeerSocket) -> None:
        self._recorder = recorder

    def wrap_socket(self, sock, server_hostname=None):  # noqa: ANN001, ARG002
        return self._recorder


def _drive(monkeypatch, **kw) -> tuple[H2Transport, _PeerSocket]:
    from adobo.transports import http2_transport as module

    recorder = _PeerSocket()
    monkeypatch.setattr(module.socket, "create_connection", lambda *a, **k: recorder)
    monkeypatch.setattr(
        H2Transport, "_build_tls_context", lambda self: _RecordingContext(recorder)
    )
    # The transport is returned unopened: the test's ``with`` block owns the
    # lifecycle, and a second open() against an already-drained peer would
    # time out waiting for a SETTINGS ack that was consumed the first time.
    return H2Transport(TARGET, ProfileName.HTTP_FLOOD, **kw), recorder


def headers_of(recorder: _PeerSocket, stream_id: int) -> list[tuple[str, str]]:
    event = next(
        e for e in recorder.events
        if isinstance(e, h2.events.RequestReceived) and e.stream_id == stream_id
    )
    return event.headers


def events_for(recorder: _PeerSocket, stream_id: int, kind: type) -> list:
    return [
        e for e in recorder.events
        if isinstance(e, kind) and e.stream_id == stream_id
    ]


# ---------------------------------------------------------------------------
# Header block
# ---------------------------------------------------------------------------


class TestHeaderBlock:
    def test_default_block_is_unchanged(self) -> None:
        transport = H2Transport(TARGET, ProfileName.HTTP_FLOOD)
        assert transport._build_stream_headers() == [
            (":method", "GET"),
            (":path", "/api/data"),
            (":authority", "127.0.0.1"),
            (":scheme", "https"),
            ("user-agent", "adobo-h2-flood"),
        ]

    def test_post_declares_method_type_and_length(self) -> None:
        transport = H2Transport(
            TARGET, ProfileName.HTTP_FLOOD, method="post", body="a=1&b=2"
        )
        headers = transport._build_stream_headers()
        assert (":method", "POST") in headers
        assert ("content-type", "application/x-www-form-urlencoded") in headers
        assert ("content-length", "7") in headers

    def test_head_declares_the_method(self) -> None:
        transport = H2Transport(TARGET, ProfileName.HTTP_FLOOD, method="head")
        assert (":method", "HEAD") in transport._build_stream_headers()

    def test_path_and_custom_content_type(self) -> None:
        transport = H2Transport(
            TARGET,
            ProfileName.HTTP_FLOOD,
            method="post",
            body="{}",
            content_type="application/json",
            tcp_path="/login",
        )
        headers = transport._build_stream_headers()
        assert (":path", "/login") in headers
        assert ("content-type", "application/json") in headers

    def test_identity_headers_follow_the_persona_block(self) -> None:
        transport = H2Transport(
            TARGET,
            ProfileName.HTTP_FLOOD,
            method="post",
            body="a=1",
            cookie_header="session=xyz",
            referer="https://lab.test/",
        )
        headers = dict(transport._build_stream_headers())
        assert headers["referer"] == "https://lab.test/"
        assert headers["cookie"] == "session=xyz"
        # and they precede the content headers in the ordered list
        ordered = [name for name, _ in transport._build_stream_headers()]
        assert ordered.index("referer") < ordered.index("content-type")
        assert ordered.index("cookie") < ordered.index("content-type")

    def test_no_stray_headers_when_options_are_unset(self) -> None:
        transport = H2Transport(TARGET, ProfileName.HTTP_FLOOD)
        names = [name for name, _ in transport._build_stream_headers()]
        assert "referer" not in names
        assert "cookie" not in names
        assert "content-length" not in names


# ---------------------------------------------------------------------------
# Construction-time refusals
# ---------------------------------------------------------------------------


class TestValidation:
    def test_bad_method_is_refused(self) -> None:
        from adobo.transports.base import TransportError

        with pytest.raises(TransportError, match="get, post, head"):
            H2Transport(TARGET, ProfileName.HTTP_FLOOD, method="delete")

    def test_a_body_requires_post(self) -> None:
        from adobo.transports.base import TransportError

        with pytest.raises(TransportError, match="requires the post method"):
            H2Transport(TARGET, ProfileName.HTTP_FLOOD, method="head", body="a=1")


# ---------------------------------------------------------------------------
# Frames on the wire
# ---------------------------------------------------------------------------


class TestWire:
    def test_get_ends_at_headers_like_it_always_did(self, monkeypatch) -> None:
        transport, recorder = _drive(monkeypatch)
        with transport:
            transport.send_one(b"ignored")
        event = next(
            e for e in recorder.events if isinstance(e, h2.events.RequestReceived)
        )
        assert event.stream_ended is not None, "END_STREAM rides the HEADERS"
        assert events_for(recorder, event.stream_id, h2.events.DataReceived) == []

    def test_post_body_arrives_as_data_and_ends_the_stream(self, monkeypatch) -> None:
        transport, recorder = _drive(monkeypatch, method="post", body="a=1&b=2")
        with transport:
            transport.send_one(b"ignored")
        event = next(
            e for e in recorder.events if isinstance(e, h2.events.RequestReceived)
        )
        assert dict(event.headers)[":method"] == "POST"
        assert dict(event.headers)["content-length"] == "7"
        assert event.stream_ended is None, "HEADERS must not close a POST with a body"
        data = b"".join(
            e.data for e in events_for(recorder, event.stream_id, h2.events.DataReceived)
        )
        assert data == b"a=1&b=2"
        ended = events_for(recorder, event.stream_id, h2.events.StreamEnded)
        assert ended, "the final DATA frame must carry END_STREAM"

    def test_an_empty_post_is_complete_at_headers(self, monkeypatch) -> None:
        transport, recorder = _drive(monkeypatch, method="post")
        with transport:
            transport.send_one(b"ignored")
        event = next(
            e for e in recorder.events if isinstance(e, h2.events.RequestReceived)
        )
        assert dict(event.headers)["content-length"] == "0"
        assert event.stream_ended is not None
        assert events_for(recorder, event.stream_id, h2.events.DataReceived) == []

    def test_head_ends_at_headers(self, monkeypatch) -> None:
        transport, recorder = _drive(monkeypatch, method="head")
        with transport:
            transport.send_one(b"ignored")
        event = next(
            e for e in recorder.events if isinstance(e, h2.events.RequestReceived)
        )
        assert dict(event.headers)[":method"] == "HEAD"
        assert event.stream_ended is not None
        assert events_for(recorder, event.stream_id, h2.events.DataReceived) == []

    def test_a_body_larger_than_the_window_is_chunked(self, monkeypatch) -> None:
        """The default h2 flow-control window is 64 KiB; a 70 KiB body must
        leave in clamped DATA frames, not raise FlowControlError."""
        body = "F" * 70_000
        transport, recorder = _drive(monkeypatch, method="post", body=body)
        with transport:
            transport.send_one(b"ignored")
        event = next(
            e for e in recorder.events if isinstance(e, h2.events.RequestReceived)
        )
        assert dict(event.headers)["content-length"] == "70000"
        data_events = events_for(recorder, event.stream_id, h2.events.DataReceived)
        assert len(data_events) > 1, "the body went out in more than one DATA frame"
        assert b"".join(e.data for e in data_events) == body.encode()
        assert events_for(recorder, event.stream_id, h2.events.StreamEnded)


# ---------------------------------------------------------------------------
# rapid_reset keeps its CVE shape; the factory wires the shape through
# ---------------------------------------------------------------------------


class TestWiring:
    def test_rapid_reset_pins_get_even_when_post_is_configured(self) -> None:
        transport = RapidResetTransport(
            TARGET, ProfileName.RAPID_RESET, method="post", body="a=1"
        )
        assert transport._method == "get"
        assert transport._encoded_body == b""

    def test_the_factory_wires_the_request_shape(self) -> None:
        config = RunConfig(
            target=Target(host="127.0.0.1", port=443),
            attack=AttackProfile(
                profile=ProfileName.HTTP_FLOOD,
                use_http2=True,
                http_method="post",
                http_path="/login",
                http_body="a=1&b=2",
                cookie_header="session=xyz",
                referer="https://lab.test/",
            ),
            transport=TransportKind.H2,
        )
        transport = get_transport(config)
        assert isinstance(transport, H2Transport)
        assert transport._method == "post"
        assert transport.tcp_path == "/login"
        assert transport._encoded_body == b"a=1&b=2"
        assert transport._cookie_header == "session=xyz"
        assert transport._referer == "https://lab.test/"

    def test_the_factory_wires_the_shape_through_the_proxy_h2_transport(
        self, tmp_path
    ) -> None:
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("socks5://127.0.0.1:1080\n", encoding="utf-8")
        config = RunConfig(
            target=Target(host="127.0.0.1", port=443),
            attack=AttackProfile(
                profile=ProfileName.HTTP_FLOOD,
                use_http2=True,
                http_method="head",
                http_path="/healthz",
            ),
            transport=TransportKind.PROXY,
            proxy_file=str(proxy_file),
        )
        from adobo.transports.proxy_transport import ProxyH2Transport

        transport = get_transport(config)
        assert isinstance(transport, ProxyH2Transport)
        assert transport._method == "head"
        assert transport.tcp_path == "/healthz"
