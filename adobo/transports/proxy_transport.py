"""HTTP proxy transport - egress that rotates across a pool of proxies.

Subclasses :class:`~adobo.transports.socket_transport.SocketTransport` and
changes exactly one thing: where the TCP connection goes. Everything after the
connect - payload construction, persona rotation, keep-alive recycling, counters,
cancellation - is inherited, so a proxied run reports the same way a direct one
does and there is no second implementation to drift.

**Why CONNECT rather than absolute-form request URIs.** An HTTP proxy supports
two ways to carry a request: rewrite the request line to an absolute URI
(``GET http://host/path``), or tunnel with ``CONNECT`` and then speak ordinary
origin-form requests down the tunnel. Absolute-form would mean rewriting the
request the payload builder produces, for every profile and every persona. The
tunnel keeps the bytes on the wire identical to a direct run, so
``--fingerprint`` and ``--h2-preamble`` keep meaning what they mean now, and a
proxied run differs from a direct one *only* in the source address - which is
the entire thing being tested.

**Why the target is never resolved by the proxy path.** ``CONNECT`` carries the
target's *name*, not its address, so the proxy does the lookup. That is
deliberate: resolving here and sending an address would make the proxy's view of
the target irrelevant, and a proxy that cannot reach the target is a fact about
the proxy, not about the run.
"""

from __future__ import annotations

import socket
from typing import ClassVar

from ..models import ProfileName, Target, TransportKind
from ..proxies import Proxy, ProxyPool
from .base import TransportError, supports_profile
from .http2_transport import H2Transport
from .socket_transport import SocketTransport

__all__ = [
    "ProxyH2Transport",
    "ProxyTransport",
    "connect_tunnel",
]

#: Longest CONNECT response this will buffer. A 200 response with a large
#: header block from a chatty proxy must not be able to grow this without bound;
#: anything past it is a proxy misbehaving rather than a tunnel worth keeping.
_MAX_RESPONSE_BYTES = 16_384

#: Status codes worth naming, because the operator has to be able to tell a bad
#: password from a blocked port from a proxy that does not support CONNECT.
_STATUS_HINTS = {
    400: "the proxy rejected the CONNECT request",
    403: "the proxy refused to forward to this target",
    405: "the proxy does not support CONNECT",
    407: "the proxy requires credentials, or the ones supplied were rejected",
    502: "the proxy could not reach the target",
    503: "the proxy is unavailable or overloaded",
    504: "the proxy timed out reaching the target",
}


class ProxyConnectionError(TransportError):
    """A proxy refused the tunnel, or did not answer one.

    Kept distinct from ``PeerUnavailable`` on purpose. A peer refusing the
    connection is the lab's central observation and the engine deliberately lets
    the run continue so the prober can measure a target that is already down.
    A proxy refusing is a property of the proxy list: if it were treated as a
    dead target, the run would stop and report "target down" for what is a dead
    proxy, which would be a measurement of nothing.
    """


def connect_tunnel(
    sock: socket.socket,
    proxy: Proxy,
    target_host: str,
    target_port: int,
    timeout: float,
) -> None:
    """Establish a CONNECT tunnel to *target_host* through *proxy*.

    Raises :class:`ProxyConnectionError` on any non-2xx response, on a
    connection that closes before answering, and on a response that never
    terminates. Credentials are never included in an error message - a refused
    tunnel is exactly when a password is most likely to end up pasted into a
    bug report.
    """
    authority = target_host if ":" not in target_host else f"[{target_host}]"
    request = (
        f"CONNECT {authority}:{target_port} HTTP/1.1\r\n"
        f"Host: {authority}:{target_port}\r\n"
    )
    authorization = proxy.authorization()
    if authorization:
        request += f"Proxy-Authorization: {authorization}\r\n"
    request += "\r\n"

    sock.settimeout(timeout)
    try:
        sock.sendall(request.encode("ascii"))
        response = _read_response(sock)
    except socket.timeout as exc:
        sock.close()
        raise ProxyConnectionError(
            f"proxy {proxy.label()} did not answer a CONNECT within {timeout:g}s"
        ) from exc
    except OSError as exc:
        sock.close()
        raise ProxyConnectionError(
            f"proxy {proxy.label()} failed during CONNECT: {exc}"
        ) from exc

    status, _reason = _parse_status(response)
    if status is None:
        sock.close()
        raise ProxyConnectionError(
            f"proxy {proxy.label()} sent a response that was not an HTTP status "
            f"line: {response[:60]!r}"
        )
    if not 200 <= status < 300:
        sock.close()
        hint = _STATUS_HINTS.get(status, "")
        detail = f": {hint}" if hint else ""
        raise ProxyConnectionError(
            f"proxy {proxy.label()} refused a tunnel to "
            f"{authority}:{target_port} with HTTP {status}{detail}"
        )


def _read_response(sock: socket.socket) -> bytes:
    """Read until the end of the response header block, bounded."""
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            # Closed before the header block ended. Treated as a refusal rather
            # than an empty tunnel, because a tunnel that returns nothing at all
            # is indistinguishable from a proxy that hung up.
            break
        buffer.extend(chunk)
        if len(buffer) > _MAX_RESPONSE_BYTES:
            break
    return bytes(buffer)


def _parse_status(response: bytes) -> tuple[int | None, str]:
    """The status code and reason from an HTTP response line."""
    line = response.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
    parts = line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return None, line
    try:
        return int(parts[1]), parts[2] if len(parts) > 2 else ""
    except ValueError:  # pragma: no cover - guarded by isdigit above
        return None, line


class _ProxyRouting:
    """The pool shared by both proxy transports.

    A mixin rather than duplicated fields, because a run constructs many
    transports - one per worker - and they must all draw from *one* rotation.
    A pool per worker would mean each worker walks the whole list independently,
    so the run would still touch every proxy, but the rotation would restart
    from the top on every worker and the first N requests of each worker would
    arrive from the same few addresses. That defeats the point of a pool: the
    opening burst is what a per-IP defense would catch.
    """

    def __init__(
        self,
        target: Target,
        profile: ProfileName,
        *,
        pool: ProxyPool,
        **kw,
    ) -> None:
        # **kw forwarded deliberately: keep_alive, use_tls, sndbuf, concurrency,
        # h2_profile and the rest belong to the concrete transport underneath,
        # and this mixin has no opinion about any of them. Swallowing them would
        # silently drop keep_alive - turning a per-request run into a single
        # long-lived tunnel through one proxy, which is the opposite of what was
        # asked for and would report as rotation.
        super().__init__(target, profile, **kw)  # type: ignore[call-arg]
        self.pool = pool
        self.proxy_in_use: Proxy | None = None

    def _connect_endpoint(self) -> tuple[str, int]:
        proxy = self.pool.next()
        # Recorded before the connect so a failure still names which proxy was
        # tried. Without it, a run against a dead proxy list reports N identical
        # errors naming the target and no indication of which endpoint was at
        # fault.
        self.proxy_in_use = proxy
        return (proxy.host, proxy.port)

    def _after_connect(self) -> None:
        if self.proxy_in_use is None:  # pragma: no cover - open() sets it first
            raise TransportError("no proxy was selected for this connection")
        assert self._sock is not None
        connect_tunnel(
            self._sock,
            self.proxy_in_use,
            self.target.host,
            self.target.port,
            self.connect_timeout,
        )

    def describe(self) -> dict[str, object]:
        info = super().describe()  # type: ignore[misc]
        info["proxy"] = self.proxy_in_use.label() if self.proxy_in_use else None
        info["proxy_pool"] = len(self.pool)
        return info


class ProxyTransport(_ProxyRouting, SocketTransport):
    """HTTP flood through a rotating pool of HTTP proxies."""

    kind: ClassVar[TransportKind] = TransportKind.PROXY

    def __init__(self, target: Target, profile: ProfileName, *, pool: ProxyPool, **kw) -> None:
        if not supports_profile(TransportKind.PROXY, profile):
            raise TransportError(
                f"The proxy transport cannot generate a {profile.value!r} "
                f"profile: a UDP datagram has no connection to carry a tunnel "
                f"and a raw packet cannot be redirected through an HTTP proxy. "
                f"Use --profile http_flood with --transport proxy."
            )
        super().__init__(target, profile, pool=pool, **kw)


class ProxyH2Transport(_ProxyRouting, H2Transport):
    """HTTP/2 through a rotating pool of HTTP proxies.

    The tunnel is established before the TLS handshake for the same reason it is
    in :class:`ProxyTransport`: the ALPN negotiation and certificate check must
    happen with the *target* on the other end, and wrapping before CONNECT would
    make the proxy the TLS peer.
    """

    kind: ClassVar[TransportKind] = TransportKind.PROXY

    def __init__(self, target: Target, profile: ProfileName, *, pool: ProxyPool, **kw) -> None:
        super().__init__(target, profile, pool=pool, **kw)