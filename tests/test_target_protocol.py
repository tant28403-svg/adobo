"""Tests for detect_target_protocol(), the ask-the-target probe.

The wizard used to offer HTTP/2, HTTP/3 and rapid_reset without ever asking
the target whether it speaks TLS on the port the operator named. Against a
plaintext website every choice beyond those questions' defaults could only
end in workers that open nothing. These tests pin what the verdicts are and
what produces them, using fake sockets so no test reaches a real network.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any

import pytest

from adobo.engine import (
    TARGET_CLOSED,
    TARGET_PLAIN,
    TARGET_TLS,
    TARGET_TLS_H2,
    TARGET_UNKNOWN,
    detect_target_protocol,
)


class _FakeSocket:
    """The slice a `with socket:` block plus a send/recv cycle needs."""

    def __init__(self, response: bytes = b"") -> None:
        self._buffer = response
        self.sent: bytearray = bytearray()
        self.settimeouts: list[float] = []
        self.closed = False

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *_a: Any) -> None:
        self.close()

    def settimeout(self, value: float) -> None:
        self.settimeouts.append(value)

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, _n: int) -> bytes:
        chunk, self._buffer = self._buffer[:512], self._buffer[512:]
        return chunk

    def close(self) -> None:
        self.closed = True


class _FakeTlsSock(_FakeSocket):
    """The wrapped socket detect() sees inside `with ctx.wrap_socket(...)`."""

    def __init__(self, alpn: str) -> None:
        super().__init__()
        self._alpn = alpn

    def version(self) -> str:
        return "TLSv1.3"

    def selected_alpn_protocol(self) -> str:
        return self._alpn


class _FakeSslContext:
    """A context whose wrap either completes or refuses, per test.

    The detection builds ``ssl.SSLContext(PROTOCOL_TLS_CLIENT)`` directly -
    an unverified context, so a self-signed target still yields a verdict -
    and the fake listens on that constructor.
    """

    def __init__(self, wrapped: _FakeTlsSock | None, refused: Exception | None) -> None:
        self._wrapped = wrapped
        self._refused = refused
        self.alpn_offered: list[list[str]] = []
        self.check_hostname = True
        self.verify_mode: Any = None

    def set_alpn_protocols(self, protocols: list[str]) -> None:
        self.alpn_offered.append(protocols)

    def wrap_socket(self, sock: Any, server_hostname: str | None = None) -> _FakeTlsSock:
        if self._refused is not None:
            raise self._refused
        assert self._wrapped is not None
        return self._wrapped


def _patch(monkeypatch, sockets: list[_FakeSocket], context: _FakeSslContext) -> None:
    calls: list[tuple[str, int]] = []

    def _connect(_address: tuple[str, int], timeout: float) -> _FakeSocket:
        calls.append(_address)
        assert sockets, "the test driver asked for more sockets than were scripted"
        return sockets.pop(0)

    monkeypatch.setattr(socket, "create_connection", _connect)
    monkeypatch.setattr(
        "adobo.engine.ssl.SSLContext", lambda *a, **k: context
    )
    return calls


def test_a_tls_handshake_that_negotiates_h2_reads_tls_h2(monkeypatch) -> None:
    tls_sock = _FakeTlsSock("h2")
    _patch(
        monkeypatch,
        [tls_sock],
        _FakeSslContext(wrapped=tls_sock, refused=None),
    )
    assert detect_target_protocol("198.51.100.7", 443) == TARGET_TLS_H2
    assert tls_sock.sent == bytearray()  # the handshake is the probe's work


def test_a_tls_handshake_without_h2_reads_tls(monkeypatch) -> None:
    tls_sock = _FakeTlsSock("http/1.1")
    _patch(
        monkeypatch,
        [tls_sock],
        _FakeSslContext(wrapped=tls_sock, refused=None),
    )
    assert detect_target_protocol("198.51.100.7", 443) == TARGET_TLS


def test_a_refused_handshake_with_an_http_answer_reads_plain(monkeypatch) -> None:
    # Fresh sockets per phase: the TLS attempt (refused) and the plain GET.
    refused_socket = _FakeSocket()
    plain_socket = _FakeSocket(b"HTTP/1.1 301 Moved Permanently\r\n\r\n")
    context = _FakeSslContext(
        wrapped=None, refused=ssl.SSLError("wrong version number")
    )
    calls = _patch(monkeypatch, [refused_socket, plain_socket], context)
    assert detect_target_protocol("198.51.100.7", 80) == TARGET_PLAIN
    # A refused ClientHello must not be followed by a plain GET on the same
    # socket: the server is mid-read and the answer would be garbage.
    assert refused_socket.sent == bytearray()
    assert plain_socket.sent.startswith(b"GET / HTTP/1.1")
    # The plain probe is addressed to the same host:port, because the question
    # is about this port's protocol, not about any other service on the host.
    assert calls == [("198.51.100.7", 80), ("198.51.100.7", 80)]


def test_a_refused_handshake_with_silence_reads_unknown(monkeypatch) -> None:
    refused_socket = _FakeSocket()
    silent_socket = _FakeSocket(b"")  # recv returns b"" immediately: no answer
    context = _FakeSslContext(wrapped=None, refused=ssl.SSLError("handshake"))
    _patch(monkeypatch, [refused_socket, silent_socket], context)
    assert detect_target_protocol("198.51.100.7", 80) == TARGET_UNKNOWN


def test_a_refused_connect_reads_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *a, **k: (_ for _ in ()).throw(OSError("refused")),
    )
    assert detect_target_protocol("198.51.100.7", 81) == TARGET_CLOSED
