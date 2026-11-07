"""SOCKS proxy support: list parsing, the handshakes, and the tunnel dispatch.

The handshakes are tested against a scripted socket rather than a live SOCKS
server: every reply a real server can send is a handful of well-defined bytes,
so feeding those bytes in and asserting on the bytes out exercises exactly the
code a live server would, without a network dependency in CI. The live path is
covered by :class:`TestTunnelDispatch`, which runs a full
``connect_tunnel`` -> ``socks_connect`` pass over the same scripted socket,
the same composition the proxy transport and the health check use.

The byte-level assertions exist because the wire format is the contract. A
reordered greeting or a missing NUL terminator is not a stylistic difference -
it is a server that reads garbage and refuses, and the operator would see a
"proxy refused" for a proxy that works everywhere else.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from adobo.models import RunConfig, Target
from adobo.proxies import ProxyListError, parse_proxy
from adobo.transports.proxy_transport import (
    ProxyConnectionError,
    connect_tunnel,
)
from adobo.transports.socks import SOCKSError, socks_connect


class ScriptedSocket:
    """A socket that replays canned replies and records what was sent.

    ``recv`` honours the caller's byte count the way a real socket does: a
    queued reply longer than *n* is returned in pieces, which is what makes
    ``_read_exact``'s short-read handling actually exercised rather than
    assumed.
    """

    def __init__(self, replies: list[bytes]) -> None:
        self.replies = list(replies)
        self.sent: list[bytes] = []
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int) -> bytes:
        if not self.replies:
            return b""  # peer closed
        chunk = self.replies[0][:n]
        self.replies[0] = self.replies[0][n:]
        if not self.replies[0]:
            self.replies.pop(0)
        return chunk

    def close(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# List parsing
# ---------------------------------------------------------------------------


class TestParsing:
    def test_explicit_socks5_prefix(self) -> None:
        proxy = parse_proxy("socks5://1.2.3.4:1080")
        assert proxy.scheme == "socks5" and proxy.is_socks

    def test_socks4a_collapses_to_socks4(self) -> None:
        assert parse_proxy("socks4a://1.2.3.4:1080").scheme == "socks4"

    def test_socks5h_collapses_to_socks5(self) -> None:
        """The h marks remote DNS, which the CONNECT already does here."""
        assert parse_proxy("socks5h://1.2.3.4:1080").scheme == "socks5"

    def test_bare_line_defaults_to_http(self) -> None:
        assert parse_proxy("1.2.3.4:8080").scheme == "http"

    def test_default_scheme_tags_bare_lines(self) -> None:
        proxy = parse_proxy("1.2.3.4:1080", default_scheme="socks5")
        assert proxy.scheme == "socks5"

    def test_an_explicit_prefix_beats_the_default(self) -> None:
        proxy = parse_proxy("http://1.2.3.4:8080", default_scheme="socks5")
        assert proxy.scheme == "http"

    def test_unknown_scheme_is_refused_by_name(self) -> None:
        with pytest.raises(ProxyListError, match="ftp"):
            parse_proxy("ftp://1.2.3.4:21")

    def test_credentials_survive_with_a_scheme(self) -> None:
        proxy = parse_proxy("socks5://user:hunter2@1.2.3.4:1080")
        assert proxy.username == "user" and proxy.password == "hunter2"

    def test_label_carries_the_scheme_for_socks(self) -> None:
        assert parse_proxy("socks5://1.2.3.4:1080").label() == "socks5://1.2.3.4:1080"
        assert parse_proxy("1.2.3.4:8080").label() == "1.2.3.4:8080"
        assert (
            parse_proxy("socks4://u@1.2.3.4:1080").label() == "socks4://u@1.2.3.4:1080"
        )

    def test_run_config_validates_the_default_scheme(self) -> None:
        with pytest.raises(ValidationError, match="http, socks4, socks5"):
            RunConfig(
                target=Target(host="127.0.0.1", port=80),
                proxy_default_scheme="gopher",
            )


# ---------------------------------------------------------------------------
# SOCKS5 handshake
# ---------------------------------------------------------------------------


def proxy(scheme: str = "socks5", **kw):
    return parse_proxy(f"{scheme}://127.0.0.1:1080", **kw)


class TestSocks5:
    def test_no_auth_success_with_an_ip_target(self) -> None:
        sock = ScriptedSocket([
            b"\x05\x00",                      # method selection: no auth
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x1f\x90",  # CONNECT granted
        ])
        socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=3)
        assert sock.sent[0] == b"\x05\x01\x00"
        assert sock.sent[1] == b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"

    def test_domain_target_uses_atyp_three(self) -> None:
        sock = ScriptedSocket([
            b"\x05\x00",
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x1f\x90",
        ])
        socks_connect(sock, proxy(), "lab.internal", 8080, timeout=3)
        assert sock.sent[1] == b"\x05\x01\x00\x03\x0clab.internal\x1f\x90"

    def test_credentials_are_negotiated_and_sent(self) -> None:
        sock = ScriptedSocket([
            b"\x05\x02",                       # username/password chosen
            b"\x01\x00",                       # auth accepted
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x1f\x90",
        ])
        socks_connect(
            sock,
            parse_proxy("socks5://user:pass@127.0.0.1:1080"),
            "127.0.0.1",
            80,
            timeout=3,
        )
        assert sock.sent[1] == b"\x01\x04user\x04pass"

    def test_rejected_credentials_name_the_failure(self) -> None:
        sock = ScriptedSocket([b"\x05\x02", b"\x01\x01"])
        with pytest.raises(SOCKSError, match="rejected the username/password"):
            socks_connect(
                sock, parse_proxy("socks5://u:p@127.0.0.1:1080"),
                "127.0.0.1", 80, timeout=3,
            )

    def test_unacceptable_methods_when_no_credentials_were_offered(self) -> None:
        sock = ScriptedSocket([b"\x05\xff"])
        with pytest.raises(SOCKSError, match="credentials are required"):
            socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=3)

    def test_an_unoffered_method_is_refused(self) -> None:
        sock = ScriptedSocket([b"\x05\x80"])
        with pytest.raises(SOCKSError, match="not offered"):
            socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=3)

    def test_connect_refusal_names_the_reply(self) -> None:
        sock = ScriptedSocket([
            b"\x05\x00",
            b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00",
        ])
        with pytest.raises(SOCKSError, match="connection refused by the target"):
            socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=3)

    def test_wrong_version_is_refused(self) -> None:
        sock = ScriptedSocket([b"\x04\x00"])
        with pytest.raises(SOCKSError, match="not SOCKS5"):
            socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=3)

    def test_a_mid_reply_close_is_an_error_not_silence(self) -> None:
        sock = ScriptedSocket([b"\x05\x00", b"\x05"])
        with pytest.raises(SOCKSError, match="closed the connection mid-handshake"):
            socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=3)

    def test_the_bound_address_is_drained(self) -> None:
        """Bytes left after the handshake would prepend themselves to the
        caller's first request on a keep-alive tunnel."""
        sock = ScriptedSocket([
            b"\x05\x00",
            b"\x05\x00\x00\x03\x09localhost\x1f\x90",
        ])
        socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=3)
        assert sock.replies == [], "the reply's bound address must be consumed"

    def test_unknown_address_type_in_the_reply(self) -> None:
        sock = ScriptedSocket([b"\x05\x00", b"\x05\x00\x00\x09" + b"\x00" * 18])
        with pytest.raises(SOCKSError, match="unknown address type"):
            socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=3)

    def test_timeout_is_applied(self) -> None:
        sock = ScriptedSocket([b"\x05\x00", b"\x05\x00\x00\x01" + b"\x00" * 6])
        socks_connect(sock, proxy(), "127.0.0.1", 80, timeout=1.5)
        assert sock.timeout == 1.5


# ---------------------------------------------------------------------------
# SOCKS4 / 4a handshake
# ---------------------------------------------------------------------------


class TestSocks4:
    def test_ip_target_connect(self) -> None:
        sock = ScriptedSocket([b"\x00\x5a" + b"\x00" * 6])
        socks_connect(sock, proxy("socks4"), "127.0.0.1", 80, timeout=3)
        assert sock.sent[0] == b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00"

    def test_domain_target_uses_the_4a_form(self) -> None:
        sock = ScriptedSocket([b"\x00\x5a" + b"\x00" * 6])
        socks_connect(sock, proxy("socks4"), "lab.internal", 8080, timeout=3)
        assert sock.sent[0] == b"\x04\x01\x1f\x90\x00\x00\x00\x01\x00lab.internal\x00"

    def test_credentials_travel_in_the_userid(self) -> None:
        """SOCKS4 has no password field; user:pass is the convention the
        authenticated endpoints in public lists actually use."""
        sock = ScriptedSocket([b"\x00\x5a" + b"\x00" * 6])
        socks_connect(
            sock, parse_proxy("socks4://u:p@127.0.0.1:1080"),
            "127.0.0.1", 80, timeout=3,
        )
        assert b"u:p\x00" in sock.sent[0]

    def test_refusal_names_the_reply_code(self) -> None:
        sock = ScriptedSocket([b"\x00\x5b" + b"\x00" * 6])
        with pytest.raises(SOCKSError, match="rejected or failed"):
            socks_connect(sock, proxy("socks4"), "127.0.0.1", 80, timeout=3)

    def test_ipv6_target_is_refused_with_direction(self) -> None:
        sock = ScriptedSocket([])
        with pytest.raises(SOCKSError, match="use a socks5 proxy"):
            socks_connect(sock, proxy("socks4"), "::1", 80, timeout=3)


# ---------------------------------------------------------------------------
# Dispatch through connect_tunnel, as the transport and health check call it
# ---------------------------------------------------------------------------


class TestTunnelDispatch:
    def test_a_socks_proxy_goes_through_the_socks_handshake(self) -> None:
        sock = ScriptedSocket([
            b"\x05\x00",
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x1f\x90",
        ])
        connect_tunnel(sock, proxy(), "127.0.0.1", 80, timeout=3)
        assert sock.sent[1].startswith(b"\x05\x01\x00"), "a SOCKS CONNECT went out"

    def test_an_http_proxy_still_sends_connect(self) -> None:
        sock = ScriptedSocket([b"HTTP/1.1 200 Connection established\r\n\r\n"])
        connect_tunnel(sock, parse_proxy("1.2.3.4:8080"), "example.com", 80, timeout=3)
        assert sock.sent[0].startswith(b"CONNECT example.com:80")

    def test_a_socks_failure_wraps_as_proxy_refusal_and_closes(self) -> None:
        sock = ScriptedSocket([b"\x05\xff"])
        with pytest.raises(ProxyConnectionError, match="failed the socks5 handshake"):
            connect_tunnel(sock, proxy(), "127.0.0.1", 80, timeout=3)
        assert sock.closed, "a failed handshake must not leave a half-open socket"

    def test_health_check_reaches_a_socks_proxy_through_the_real_path(self, monkeypatch) -> None:
        """The health check must exercise the same scheme dispatch a run does,
        so it cannot drift into testing a code path the flood never takes."""
        import socket as socket_module

        from adobo.proxies import ProxyPool

        sock = ScriptedSocket([
            b"\x05\x00",
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x1f\x90",
        ])
        monkeypatch.setattr(
            socket_module, "create_connection", lambda *a, **kw: sock
        )
        pool = ProxyPool([proxy()])
        alive, dead = pool.health_check("203.0.113.7", 80, timeout=3)
        assert [p.endpoint for p in alive] == ["127.0.0.1:1080"]
        assert dead == []
        assert b"\x05\x01\x00" in sock.sent[-1]
