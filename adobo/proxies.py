"""Proxy pools for rotating egress.

**What this changes about a run.** Without a proxy, every request in a run
leaves from one address, so the only defenses a target can apply are per-IP
ones - rate limiting, connection caps, reputation blocking. A target that
shrugs off 5,000 requests/second from a single address can still collapse under
10,000 addresses at 500 each. This module exists to make that second scenario
reachable from one machine.

**Rotation is per connection, and that is not a simplification.** A proxy is
bound to a TCP connection: the tunnel is established once and carries every byte
that follows, so "use a different proxy" and "use a different connection" are
the same operation. With ``--keep-alive`` off - the default - the transport
opens a connection per request, which means a different proxy per request. Turn
keep-alive on and the proxy is held for the transport's ``RECYCLE_EVERY``
requests instead, so rotation becomes every hundredth request. That is the only
knob, and it is the knob that already existed.

**Only TCP can be proxied.** A UDP datagram has no connection to attach a tunnel
to, and a raw packet is addressed by IP and cannot be redirected through an HTTP
proxy at all. So the proxy transport serves HTTP flood and nothing else, and
says so rather than accepting the profile and silently sending from the local
address - which is the worst possible outcome, because the run would report
distributed egress while actually producing exactly what it always produced.
"""

from __future__ import annotations

import base64
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

__all__ = [
    "Proxy",
    "ProxyListError",
    "ProxyPool",
    "load_proxies",
    "parse_proxy",
    "require_proxies",
    "shared_pool",
]

DEFAULT_PROXY_FILE = "proxies.txt"
"""Where :func:`load_proxies` looks when given no path, relative to the adobo
home directory like every other config path in the tool."""

_MAX_PORT = 65535


class ProxyListError(ValueError):
    """A proxy list could not be read or a line in it could not be understood.

    Distinct from a transport error because it happens before a run starts and
    is the operator's file, not the network: every message here names the line
    number so the bad entry can be found without counting from the top.
    """


@dataclass(frozen=True)
class Proxy:
    """One upstream proxy.

    Frozen because a pool hands the same instance to every worker thread, and a
    transport that could mutate the proxy it was handed could do so while another
    thread was reading it.
    """

    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @property
    def needs_auth(self) -> bool:
        return bool(self.username)

    @property
    def endpoint(self) -> str:
        return f"{_bracket(self.host)}:{self.port}"

    def authorization(self) -> str | None:
        """The ``Proxy-Authorization`` value, or None when the proxy is open.

        Basic auth, which is what every HTTP proxy that supports credentials
        accepts. Encoded here rather than in the transport so the credential
        handling is in one place and can be checked once.
        """
        if not self.needs_auth:
            return None
        raw = f"{self.username}:{self.password or ''}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def label(self) -> str:
        """How to name this proxy in output. Never includes credentials."""
        if self.needs_auth:
            return f"{self.username}@{self.endpoint}"
        return self.endpoint

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.label()


def _bracket(host: str) -> str:
    """Wrap an IPv6 literal in brackets so ``host:port`` stays parseable."""
    return f"[{host}]" if ":" in host else host


def parse_proxy(line: str) -> Proxy:
    """Parse one proxy entry.

    Accepted, in the order they are peeled off::

        [scheme://][user:pass@]host:port

    A scheme of ``http`` or ``https`` is accepted and ignored - both mean the
    same thing to us, since we CONNECT and then speak TLS ourselves. Any other
    scheme is refused by name rather than treated as a hostname, because
    ``socks5://1.2.3.4:1080`` parsed as a host would produce a connection to a
    host literally called ``socks5``, and the operator would spend a while
    wondering why.
    """
    text = line.strip()
    if not text:
        raise ProxyListError("empty proxy entry")

    scheme = ""
    if "://" in text:
        scheme, _, text = text.partition("://")
        scheme = scheme.lower()
        if scheme not in ("http", "https"):
            raise ProxyListError(
                f"unsupported proxy scheme {scheme!r}: only http and https "
                f"proxies are supported"
            )

    username: str | None = None
    password: str | None = None
    # The credential separator is the *last* '@', so a password containing '@'
    # survives. Splitting on the first one truncates it silently and produces a
    # 407 that looks like wrong credentials.
    if "@" in text:
        credentials, _, text = text.rpartition("@")
        if ":" in credentials:
            username, _, password = credentials.partition(":")
        else:
            username = credentials
        if not username:
            raise ProxyListError("proxy entry has an empty username")

    host, port_text, bracket = _split_host_port(text)
    if not host:
        raise ProxyListError(f"proxy entry has no host: {line.strip()!r}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ProxyListError(
            f"proxy port {port_text!r} is not a number in {line.strip()!r}"
        ) from exc
    if not 1 <= port <= _MAX_PORT:
        raise ProxyListError(
            f"proxy port {port} is out of range in {line.strip()!r}"
        )

    return Proxy(host=host, port=port, username=username, password=password)


def _split_host_port(text: str) -> tuple[str, str, bool]:
    """Split ``host:port``, honouring bracketed IPv6 literals.

    A bare IPv6 literal with no brackets is ambiguous - ``::1:8080`` has three
    colons - so it is rejected here with a message that says what to do, rather
    than being read as the host ``::1:`` on port ``8080``.
    """
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise ProxyListError(f"unclosed '[' in proxy entry {text!r}")
        host = text[1:end]
        rest = text[end + 1:]
        if not rest.startswith(":"):
            raise ProxyListError(
                f"bracketed IPv6 proxy {text!r} has no port after the ']'"
            )
        return host, rest[1:], True

    host, sep, port = text.rpartition(":")
    if not sep:
        raise ProxyListError(f"proxy entry has no port: {text!r}")
    if ":" in host:
        raise ProxyListError(
            f"ambiguous IPv6 proxy {text!r}: write it as [address]:port"
        )
    return host, port, False


def load_proxies(path: str | Path | None = None) -> list[Proxy]:
    """Read a proxy list, one entry per line.

    Blank lines and ``#`` comments are skipped, so a list can be annotated -
    which matters when the list is a few thousand purchased endpoints and the
    only way to know which region a line belongs to is what someone wrote next
    to it.

    Returns an empty list when *path* is None or does not exist: a missing file
    is a configuration the operator can fix, and failing the run at startup with
    a stack trace for it would be a worse answer than running without proxies
    would be. Callers that require proxies must check ``len()`` themselves -
    :func:`require_proxies` does.
    """
    if path is None:
        from . import paths

        target = paths.home() / DEFAULT_PROXY_FILE
    else:
        from .config import project_path

        target = project_path(path)

    if not target.exists():
        return []

    proxies: list[Proxy] = []
    seen: set[tuple[str, int, str | None]] = set()
    with target.open("r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                proxy = parse_proxy(line)
            except ProxyListError as exc:
                raise ProxyListError(
                    f"{target}:{number}: {exc}"
                ) from exc
            key = (proxy.host, proxy.port, proxy.username)
            if key in seen:
                # A duplicate in a purchased list is common and harmless. It
                # would halve the apparent pool size, which is the number an
                # operator reads to judge whether the test is worth running.
                continue
            seen.add(key)
            proxies.append(proxy)
    return proxies


def require_proxies(path: str | Path | None) -> list[Proxy]:
    """Load a proxy list and insist it is not empty."""
    proxies = load_proxies(path)
    if not proxies:
        raise ProxyListError(
            f"no proxies found in {path or DEFAULT_PROXY_FILE}. One proxy per "
            f"line, as host:port or user:pass@host:port."
        )
    return proxies


_POOLS: dict[tuple[str, float], ProxyPool] = {}
_POOLS_LOCK = threading.Lock()


def shared_pool(path: str | Path | None) -> ProxyPool:
    """The one pool for a proxy list, shared by every transport in the process.

    The engine builds one transport per worker and each calls ``get_transport``
    with the same config, so a pool constructed per call would restart the
    rotation from the top on every worker. Every proxy would still be used, but
    the opening burst - the first N requests of each of the 200 workers - would
    all come from the same handful of addresses, and *that* is precisely what a
    per-IP rate limiter or connection cap catches. A distributed run that opens
    with a synchronised stampede is not a distributed run.

    Keyed on path and mtime so editing the list between runs builds a new pool,
    and so two different lists in one process never share a rotation.
    """
    proxies = require_proxies(path)
    first = proxies[0]
    from .config import project_path

    resolved = project_path(path) if path is not None else None
    try:
        stamp = resolved.stat().st_mtime if resolved is not None else 0.0
    except OSError:
        stamp = 0.0
    key = (f"{first.endpoint}:{len(proxies)}", stamp)
    with _POOLS_LOCK:
        pool = _POOLS.get(key)
        if pool is None:
            pool = ProxyPool(proxies)
            _POOLS[key] = pool
    return pool


class ProxyPool:
    """A round-robin pool, safe to share across worker threads.

    An index rather than :class:`itertools.cycle` because ``cycle`` is not
    thread-safe: ``next()`` on a shared cycle from N workers would return the
    same element to several of them and skip others, and since the point is that
    request *n* comes from a different address than request *n-1*, that
    failure is invisible in the counters and fatal to the feature.

    The lock is per connection, not per packet, so the contention is on the same
    operation that already does a TCP handshake.
    """

    def __init__(self, proxies: Iterable[Proxy]) -> None:
        self._proxies = tuple(proxies)
        if not self._proxies:
            raise ProxyListError("a proxy pool needs at least one proxy")
        self._index = 0
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._proxies)

    def __iter__(self) -> Iterator[Proxy]:
        return iter(self._proxies)

    def next(self) -> Proxy:
        """The next proxy in rotation."""
        with self._lock:
            proxy = self._proxies[self._index % len(self._proxies)]
            self._index += 1
        return proxy

    @property
    def used(self) -> int:
        """How many proxies have been handed out. Never exceeds the pool size
        on a single pass, but grows across passes - which is what makes a run
        reportable as having actually rotated rather than merely been configured
        to."""
        with self._lock:
            return self._index

    @property
    def distinct_used(self) -> int:
        """How many distinct proxies have been handed out.

        This is the honest version of "did we rotate": ``used`` counts every
        hand-out, so a pool of one proxy handed out 10,000 times also reports
        10,000 and would read as a successful rotation. A run that reached only
        a fraction of its list is worth knowing about before its results are
        quoted.
        """
        with self._lock:
            return min(self._index, len(self._proxies))

    def describe(self) -> dict[str, object]:
        return {
            "proxies": len(self._proxies),
            "authenticated": sum(1 for p in self._proxies if p.needs_auth),
            "handed_out": self.used,
        }