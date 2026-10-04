"""Tests for proxy rotation.

The load-bearing test here is :class:`TestAgainstARealProxy`, which runs the
transport against an HTTP proxy implemented in this file and a real target
server. Everything else checks the parts that can be checked in isolation: how a
list is parsed, how the rotation is scheduled, what happens when a proxy refuses.

The reason for the real thing is specific. A CONNECT tunnel is a handshake with
ordering requirements - request, response, then TLS, then traffic - and a mock
that returns a canned ``200`` for anything would pass while the transport sent
the tunnel request after the TLS wrap, or reused a socket that was never
read from. The bytes either come out the far end of a socket or they do not.

Every proxy here is loopback. Nothing in this file contacts a network.
"""

from __future__ import annotations

import base64
import socket
import threading
import time

import pytest

from adobo.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TransportKind,
)
from adobo.proxies import (
    Proxy,
    ProxyListError,
    ProxyPool,
    load_proxies,
    parse_proxy,
    shared_pool,
)
from adobo.transports import ProxyTransport, get_transport, supports_profile
from adobo.transports.base import TransportError
from adobo.transports.proxy_transport import (
    ProxyConnectionError,
    ProxyH2Transport,
    connect_tunnel,
)


# ---------------------------------------------------------------------------
# A real HTTP proxy, and a real target, on loopback
# ---------------------------------------------------------------------------


class ProxyServer:
    """A minimal CONNECT proxy, enough for the handshake under test.

    Forwards the tunnelled bytes to the requested target unchanged, which is what
    makes it useful: the test can assert on what actually arrived at the target
    rather than on what the client believes it sent.

    ``fail_with`` turns it into a refusing proxy, and ``require_auth`` into an
    authenticating one, so the error paths are exercised against a peer that
    really sends the status code rather than against a stubbed return value.
    """

    def __init__(
        self,
        *,
        fail_with: int = 0,
        require_auth: str | None = None,
        silent: bool = False,
        hangup: bool = False,
    ) -> None:
        self.fail_with = fail_with
        self.require_auth = require_auth
        # hangup=True closes the connection before answering at all, which is a
        # different failure from silent=True (which holds it open) and must not
        # be treated as an empty-but-usable tunnel.
        self.hangup = hangup
        # silent=True accepts the TCP connection and never answers, which is how
        # a black-holed proxy behaves and which must time out rather than hang.
        self.silent = silent
        self.requests: list[tuple[str, str | None]] = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1:{self.port}"

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(client,), daemon=True
            ).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(5.0)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            first = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = first.split(" ")
            authority = parts[1] if len(parts) > 1 else ""

            authorization = None
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"proxy-authorization:"):
                    authorization = line.split(b":", 1)[1].strip().decode("latin-1")
            self.requests.append((first, authorization))

            if self.hangup:
                return

            if self.silent:
                # Hold the connection open and say nothing at all, which is what
                # a black-holed proxy does. Returning here instead would close
                # the socket and the client would see an immediate EOF, which is
                # a different failure path (see the hangup test).
                time.sleep(10.0)
                return
            if self.require_auth and authorization != self.require_auth:
                client.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"x\"\r\n\r\n"
                )
                client.close()
                return
            if self.fail_with:
                client.sendall(
                    f"HTTP/1.1 {self.fail_with} Nope\r\n\r\n".encode("ascii")
                )
                client.close()
                return

            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            host, _, port = authority.rpartition(":")
            try:
                upstream = socket.create_connection(
                    (host, int(port)), timeout=5.0
                )
            except OSError:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                client.close()
                return
            _pump(client, upstream)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until either side closes."""
    done = threading.Event()

    def _copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while not done.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            done.set()

    threads = [
        threading.Thread(target=_copy, args=(a, b), daemon=True),
        threading.Thread(target=_copy, args=(b, a), daemon=True),
    ]
    for thread in threads:
        thread.start()
    done.wait(10.0)
    for sock in (a, b):
        try:
            sock.close()
        except OSError:
            pass


class TargetServer:
    """Counts accepted TCP connections and the request lines that arrived."""

    def __init__(self) -> None:
        self.connections = 0
        self.requests: list[str] = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(
                target=self._handle, args=(client,), daemon=True
            ).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(5.0)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            self.requests.append(head.split(b"\r\n", 1)[0].decode("latin-1"))
            client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


def _pool(*endpoints: str) -> ProxyPool:
    return ProxyPool(parse_proxy(e) for e in endpoints)


def _transport(proxy: ProxyServer, target_port: int, **kw) -> ProxyTransport:
    return ProxyTransport(
        Target(host="127.0.0.1", port=target_port),
        ProfileName.HTTP_FLOOD,
        pool=_pool(proxy.endpoint),
        send_timeout=5.0,
        connect_timeout=5.0,
        **kw,
    )


# ---------------------------------------------------------------------------
# Parsing the list
# ---------------------------------------------------------------------------


class TestParseProxy:
    def test_host_and_port(self) -> None:
        proxy = parse_proxy("203.0.113.7:8080")
        assert (proxy.host, proxy.port) == ("203.0.113.7", 8080)
        assert proxy.needs_auth is False

    def test_credentials(self) -> None:
        proxy = parse_proxy("user:secret@203.0.113.7:8080")
        assert proxy.username == "user"
        assert proxy.password == "secret"

    def test_a_password_may_contain_an_at_sign(self) -> None:
        """Split on the last '@', or the credential is silently truncated.

        The failure is a 407 that looks exactly like a wrong password, and the
        operator has no way to tell it from one.
        """
        proxy = parse_proxy("user:p@ss@203.0.113.7:8080")
        assert proxy.password == "p@ss"
        assert proxy.host == "203.0.113.7"

    def test_username_without_a_password(self) -> None:
        """The credential is `user:`, not `user`. Asserted on the header that
        actually goes out, since that is what the proxy checks."""
        proxy = parse_proxy("user@203.0.113.7:8080")
        assert proxy.username == "user"
        expected = "Basic " + base64.b64encode(b"user:").decode()
        assert proxy.authorization() == expected

    def test_http_scheme_is_accepted_and_ignored(self) -> None:
        assert parse_proxy("http://203.0.113.7:8080").host == "203.0.113.7"
        assert parse_proxy("https://203.0.113.7:8080").port == 8080

    def test_a_non_http_scheme_is_refused_by_name(self) -> None:
        """`socks5://1.2.3.4:1080` read as a host becomes a connection to a host
        literally called `socks5`, and the operator has no way to guess why."""
        with pytest.raises(ProxyListError, match="socks5"):
            parse_proxy("socks5://203.0.113.7:1080")

    def test_bracketed_ipv6(self) -> None:
        proxy = parse_proxy("[2001:db8::1]:8080")
        assert proxy.host == "2001:db8::1"
        assert proxy.port == 8080
        assert proxy.endpoint == "[2001:db8::1]:8080"

    def test_a_bare_ipv6_literal_is_refused_as_ambiguous(self) -> None:
        with pytest.raises(ProxyListError, match=r"\[address\]:port"):
            parse_proxy("2001:db8::1:8080")

    def test_a_missing_port_is_refused(self) -> None:
        with pytest.raises(ProxyListError, match="no port"):
            parse_proxy("203.0.113.7")

    def test_an_out_of_range_port_is_refused(self) -> None:
        with pytest.raises(ProxyListError, match="out of range"):
            parse_proxy("203.0.113.7:70000")

    def test_a_non_numeric_port_is_refused(self) -> None:
        with pytest.raises(ProxyListError, match="not a number"):
            parse_proxy("203.0.113.7:http")

    def test_authorization_is_basic_and_absent_when_open(self) -> None:
        expected = "Basic " + base64.b64encode(b"u:p").decode()
        assert parse_proxy("u:p@1.2.3.4:80").authorization() == expected
        assert parse_proxy("1.2.3.4:80").authorization() is None


class TestLoadProxies:
    def test_comments_and_blanks_are_skipped(self, tmp_path) -> None:
        path = tmp_path / "p.txt"
        path.write_text(
            "# a purchased list\n\n203.0.113.1:80\n  \n203.0.113.2:80  # us-east\n",
            encoding="utf-8",
        )
        proxies = load_proxies(path)
        assert [p.host for p in proxies] == ["203.0.113.1", "203.0.113.2"]

    def test_a_missing_file_is_an_empty_list_not_an_error(self, tmp_path) -> None:
        """A missing list is the operator's to fix; it is not a crash.

        Failing the run with a traceback for a file that may simply not be
        written yet would be a worse answer than running without proxies.
        """
        assert load_proxies(tmp_path / "absent.txt") == []

    def test_a_bad_line_names_its_line_number(self, tmp_path) -> None:
        path = tmp_path / "p.txt"
        path.write_text("203.0.113.1:80\nbroken\n", encoding="utf-8")
        with pytest.raises(ProxyListError, match=r"p\.txt:2"):
            load_proxies(path)

    def test_duplicates_are_dropped(self, tmp_path) -> None:
        """A duplicate halves the apparent pool size, which is the number an
        operator reads to judge whether the test is worth running."""
        path = tmp_path / "p.txt"
        path.write_text("203.0.113.1:80\n203.0.113.1:80\n", encoding="utf-8")
        assert len(load_proxies(path)) == 1

    def test_the_same_proxy_twice_with_different_credentials_is_kept(
        self, tmp_path
    ) -> None:
        path = tmp_path / "p.txt"
        path.write_text("1.2.3.4:80\na:b@1.2.3.4:80\n", encoding="utf-8")
        assert len(load_proxies(path)) == 2


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


class TestProxyPool:
    def test_rotation_is_round_robin(self) -> None:
        pool = _pool("1.1.1.1:80", "2.2.2.2:80", "3.3.3.3:80")
        assert [pool.next().host for _ in range(6)] == [
            "1.1.1.1", "2.2.2.2", "3.3.3.3", "1.1.1.1", "2.2.2.2", "3.3.3.3",
        ]

    def test_consecutive_hand_outs_differ(self) -> None:
        """The whole point: request n and request n-1 come from different IPs."""
        pool = _pool("1.1.1.1:80", "2.2.2.2:80")
        assert pool.next() is not pool.next()

    def test_threads_never_receive_the_same_proxy_twice_in_a_row(self) -> None:
        """itertools.cycle would pass this in one thread and fail it in many.

        `next()` on a shared cycle is not atomic, so N workers would each get the
        same element and skip others. Since the feature is "the next request
        comes from somewhere else", that failure is invisible in the counters.
        """
        pool = _pool("1.1.1.1:80", "2.2.2.2:80", "3.3.3.3:80", "4.4.4.4:80")
        seen: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            local = [pool.next().host for _ in range(200)]
            with lock:
                seen.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(seen) == 1600
        assert pool.used == 1600

    def test_distinct_used_is_not_the_hand_out_count(self) -> None:
        """A pool of one handed out 10,000 times must not read as rotation."""
        pool = _pool("1.1.1.1:80")
        for _ in range(100):
            pool.next()
        assert pool.used == 100
        assert pool.distinct_used == 1

    def test_an_empty_pool_is_refused(self) -> None:
        with pytest.raises(ProxyListError):
            ProxyPool([])

    def test_shared_pool_returns_one_rotation_per_list(self, tmp_path) -> None:
        """Every worker draws from one rotation.

        A pool per worker would still touch every proxy, but each worker's first
        requests would come from the top of the list - and that synchronised
        opening burst is exactly what a per-IP connection cap catches. If the two
        calls returned different objects, request 0 and request 1 would both come
        from proxy #1.
        """
        path = tmp_path / "p.txt"
        path.write_text("203.0.113.1:80\n203.0.113.2:80\n", encoding="utf-8")
        first = shared_pool(path)
        second = shared_pool(path)
        assert first is second

        assert first.next().host == "203.0.113.1"
        assert second.next().host == "203.0.113.2"


# ---------------------------------------------------------------------------
# The transport, against real proxies on loopback
# ---------------------------------------------------------------------------


class TestAgainstARealProxy:
    """The bytes either come out the far end of a socket or they do not."""

    def test_a_request_reaches_the_target_through_the_proxy(self) -> None:
        proxy, target = ProxyServer(), TargetServer()
        try:
            transport = _transport(proxy, target.port)
            transport.open()
            transport.send_one(b"GET /api/data HTTP/1.1\r\nHost: x\r\n\r\n")
            transport.close()
        finally:
            proxy.close()
            target.close()

        assert proxy.requests[0][0] == (
            "CONNECT 127.0.0.1:%d HTTP/1.1" % target.port
        )
        assert target.requests == ["GET /api/data HTTP/1.1"]

    def test_the_target_sees_an_origin_form_request(self) -> None:
        """Not an absolute URI. The tunnel keeps the bytes identical to a direct
        run, which is what keeps --fingerprint and --h2-preamble meaning what
        they mean."""
        proxy, target = ProxyServer(), TargetServer()
        try:
            transport = _transport(proxy, target.port)
            transport.open()
            transport.send_one(b"GET /api/data HTTP/1.1\r\nHost: x\r\n\r\n")
            transport.close()
        finally:
            proxy.close()
            target.close()

        assert not target.requests[0].startswith("GET http://")

    def test_credentials_are_sent_and_the_tunnel_opens(self) -> None:
        expected = "Basic " + base64.b64encode(b"u:p").decode()
        proxy = ProxyServer(require_auth=expected)
        target = TargetServer()
        try:
            transport = ProxyTransport(
                Target(host="127.0.0.1", port=target.port),
                ProfileName.HTTP_FLOOD,
                pool=_pool(f"u:p@{proxy.endpoint}"),
                send_timeout=5.0,
                connect_timeout=5.0,
            )
            transport.open()
            transport.close()
        finally:
            proxy.close()
            target.close()

        assert proxy.requests[0][1] == expected

    def test_a_rejected_tunnel_raises_rather_than_sending(self) -> None:
        """The run must not fall back to sending from the local address.

        That fallback would produce a run reporting distributed egress while
        actually generating exactly the single-source traffic the operator was
        trying to avoid, and every counter would look normal.
        """
        proxy = ProxyServer(fail_with=403)
        target = TargetServer()
        try:
            transport = _transport(proxy, target.port)
            with pytest.raises(ProxyConnectionError, match="403"):
                transport.open()
        finally:
            proxy.close()
            target.close()

        assert target.requests == []

    def test_a_407_names_credentials_rather_than_the_password(self) -> None:
        proxy = ProxyServer(require_auth="Basic something-else")
        try:
            with pytest.raises(ProxyConnectionError) as info:
                connect_tunnel(
                    _connected(proxy.endpoint), parse_proxy("user:hunter2@x:1"),
                    "127.0.0.1", 9, 5.0,
                )
        finally:
            proxy.close()
        assert "407" in str(info.value)
        assert "hunter2" not in str(info.value)

    def test_a_proxy_that_hangs_up_is_refused(self) -> None:
        """An empty response is not a tunnel.

        A proxy that closes without answering must be treated as a refusal: the
        alternative is treating it as a usable connection, and the first send
        then fails somewhere far away with a message about the target.
        """
        proxy = ProxyServer(hangup=True)
        try:
            with pytest.raises(ProxyConnectionError):
                connect_tunnel(
                    _connected(proxy.endpoint), parse_proxy("x:1"),
                    "127.0.0.1", 9, 2.0,
                )
        finally:
            proxy.close()

    def test_a_silent_proxy_times_out_rather_than_hanging(self) -> None:
        """A black-holed proxy must cost the connect timeout, not the run.

        Unbounded here would park every worker inside open() and the run would
        stop on its join grace with nothing sent and no explanation.
        """
        proxy = ProxyServer(silent=True)
        target = TargetServer()
        try:
            transport = ProxyTransport(
                Target(host="127.0.0.1", port=target.port),
                ProfileName.HTTP_FLOOD,
                pool=_pool(proxy.endpoint),
                send_timeout=5.0,
                connect_timeout=0.4,
            )
            with pytest.raises(ProxyConnectionError, match="did not answer"):
                transport.open()
        finally:
            proxy.close()
            target.close()

    def test_each_connection_takes_the_next_proxy(self) -> None:
        """Per-connection rotation, which is what per-request rotation means
        when keep-alive is off."""
        proxies = [ProxyServer() for _ in range(3)]
        target = TargetServer()
        try:
            transport = ProxyTransport(
                Target(host="127.0.0.1", port=target.port),
                ProfileName.HTTP_FLOOD,
                pool=_pool(*[p.endpoint for p in proxies]),
                send_timeout=5.0,
                connect_timeout=5.0,
            )
            # keep_alive is off, so each send opens a fresh connection - which is
            # what makes the next proxy the one that gets used.
            transport.open()
            for _ in range(6):
                transport.send_one(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            transport.close()
        finally:
            for proxy in proxies:
                proxy.close()
            target.close()

        used = [len(p.requests) for p in proxies]
        # Every proxy used, and evenly. The absolute count is higher than the
        # number of sends because SocketTransport opens a connection in both
        # send_one() and _send_tcp() in per-request mode (socket_transport.py
        # :373), so each request costs two tunnels. That redundancy predates
        # this feature and is left alone; what matters here is that the pool is
        # spread rather than pinned to the first proxy.
        assert all(n > 0 for n in used), f"a proxy was skipped: {used}"
        assert len(set(used)) == 1, f"rotation was uneven: {used}"

    def test_a_run_against_a_proxy_reports_rotation(self) -> None:
        """The note is the disclosure, and silence has to mean "no proxies"."""
        from adobo.engine import RunEngine

        proxy, target = ProxyServer(), TargetServer()
        try:
            config = RunConfig(
                target=Target(host="127.0.0.1", port=target.port),
                attack=AttackProfile(
                    profile=ProfileName.HTTP_FLOOD,
                    pps=20,
                    duration_seconds=0.4,
                    payload_size=128,
                    workers=1,
                ),
                transport=TransportKind.PROXY,
                proxy_file=_write_list(proxy.endpoint),
            )
            outcome = RunEngine(config).run()
        finally:
            proxy.close()
            target.close()

        notes = outcome.result.notes
        assert any("Proxy rotation" in n for n in notes), notes
        assert any("one proxy per request" in n for n in notes), notes

    def test_a_direct_run_says_nothing_about_proxies(self) -> None:
        """Silence is the signal, so a direct run must have no proxy note."""
        from adobo.engine import RunEngine

        config = RunConfig(
            target=Target(host="127.0.0.1", port=9),
            attack=AttackProfile(
                profile=ProfileName.UDP_FLOOD,
                pps=100,
                duration_seconds=0.2,
                payload_size=128,
                workers=1,
            ),
            transport=TransportKind.VIRTUAL,
        )
        outcome = RunEngine(config).run()
        assert not any("Proxy" in n for n in outcome.result.notes)


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


class TestProxyRefusals:
    def test_a_udp_profile_cannot_be_proxied(self) -> None:
        """It would have to send from the local address and report rotation."""
        assert supports_profile(TransportKind.PROXY, ProfileName.UDP_FLOOD) is False
        with pytest.raises(TransportError, match="http_flood"):
            ProxyTransport(
                Target(host="127.0.0.1", port=80),
                ProfileName.UDP_FLOOD,
                pool=_pool("1.1.1.1:80"),
            )

    def test_an_empty_list_fails_at_setup_not_per_worker(self) -> None:
        """One clear error, rather than N identical ones from N workers."""
        config = RunConfig(
            target=Target(host="127.0.0.1", port=80),
            attack=AttackProfile(profile=ProfileName.HTTP_FLOOD, workers=8),
            transport=TransportKind.PROXY,
            proxy_file=_write_list(),
        )
        with pytest.raises(ProxyListError, match="no proxies"):
            get_transport(config)

    def test_a_missing_list_fails_at_setup(self) -> None:
        config = RunConfig(
            target=Target(host="127.0.0.1", port=80),
            attack=AttackProfile(profile=ProfileName.HTTP_FLOOD),
            transport=TransportKind.PROXY,
            proxy_file="definitely-absent-proxies.txt",
        )
        with pytest.raises(ProxyListError, match="no proxies"):
            get_transport(config)

    def test_the_h2_proxy_transport_exists_and_refuses_bad_profiles(self) -> None:
        transport = ProxyH2Transport(
            Target(host="127.0.0.1", port=443),
            ProfileName.HTTP_FLOOD,
            pool=_pool("1.1.1.1:80"),
            concurrency=10,
        )
        assert transport.kind is TransportKind.PROXY
        assert transport.pool is not None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write_list(*endpoints: str) -> str:
    """Write a proxy list into a temp file and return its path."""
    import tempfile
    from pathlib import Path

    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, encoding="utf-8"
    )
    handle.write("\n".join(endpoints) + ("\n" if endpoints else ""))
    handle.close()
    return str(Path(handle.name))


def _connected(endpoint: str) -> socket.socket:
    host, _, port = endpoint.rpartition(":")
    sock = socket.create_connection((host, int(port)), timeout=5.0)
    return sock