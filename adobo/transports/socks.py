"""SOCKS4/4a and SOCKS5 client handshakes, in pure Python.

**Why this exists as a hand-written module rather than a PySocks import.** The
core of this tool is deliberately pure Python so it runs unmodified on Termux,
where compiling an extra C-extension dependency for a protocol whose wire
format fits in one screen is a poor trade. The handshake is small, fully
specified, and testable against a scripted socket, which is exactly the kind
of thing that should be owned rather than imported.

**What a successful handshake leaves behind.** On return from
:func:`socks_connect`, *sock* is a tunnel whose far end is the target: the
caller then speaks HTTP (and wraps TLS, if any) exactly as it would on a
direct connection. Nothing else about the connection changes, which is why the
proxy transport can treat CONNECT and SOCKS as interchangeable steps.

**Framing discipline.** Every read is bounded by an exact byte count, because
a reply shorter than the spec is a server that hung up mid-handshake and must
be reported as such, not a silent zero-byte "success". Every field parsed is
range-checked where the spec allows a value, and the SOCKS5 CONNECT reply's
bound-address is drained even though it is unused - leaving bytes in the
socket would corrupt whatever the caller sends next on a keep-alive tunnel.

**Auth.** SOCKS5 offers no-auth and username/password (RFC 1929), offering the
latter only when the proxy line carried credentials - a server that demands
auth we did not offer is refused with its method number named. SOCKS4 has no
password field, so the userid carries the username, or ``user:pass`` when a
password is configured: both conventions exist in the wild and the first is
what PySocks sent, which is what the lists this replaces were formatted for.
"""

from __future__ import annotations

import ipaddress
import socket
import struct

from .base import TransportError

__all__ = [
    "SOCKSError",
    "socks_connect",
]

#: Longest reply the handshakes will read in one step. A SOCKS5 reply is at
#: most 4 + 1 + 16 + 2 = 262 bytes and a SOCKS4 reply is 8, so anything past
#: this is a server misbehaving, and reads stay bounded regardless.
_MAX_REPLY_BYTES = 512

_SOCKS5_VERSION = 0x05
_SOCKS5_CMD_CONNECT = 0x01
_SOCKS5_METHOD_NO_AUTH = 0x00
_SOCKS5_METHOD_USERNAME_PASSWORD = 0x02
_SOCKS5_METHOD_UNACCEPTABLE = 0xFF
_SOCKS5_ATYP_IPV4 = 0x01
_SOCKS5_ATYP_DOMAIN = 0x03
_SOCKS5_ATYP_IPV6 = 0x04

_SOCKS5_REPLIES = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused by the target",
    0x06: "TTL expired",
    0x07: "command not supported by the proxy",
    0x08: "address type not supported by the proxy",
}

_SOCKS4_GRANTED = 0x5A
_SOCKS4_REPLIES = {
    0x5A: "granted",
    0x5B: "request rejected or failed",
    0x5C: "the proxy could not reach identd on this client",
    0x5D: "the proxy's identd check disagreed with the request",
}


class SOCKSError(TransportError):
    """A SOCKS server refused a handshake step or sent a malformed reply.

    A subclass of :class:`~adobo.transports.base.TransportError`, so the proxy
    transport's retry-and-mark-dead loop treats a dead SOCKS proxy exactly like
    a dead HTTP one: retried through other proxies, never misread as the target
    being down.
    """


def socks_connect(
    sock: socket.socket,
    proxy,
    target_host: str,
    target_port: int,
    timeout: float,
) -> None:
    """Run the handshake for *proxy*'s scheme; the tunnel then reaches the target.

    Raises :class:`SOCKSError` for every refusal and every malformed reply.
    Never closes *sock* - the caller owns the socket's lifetime, matching how
    :func:`~adobo.transports.proxy_transport.connect_tunnel` treats CONNECT.
    """
    if proxy.scheme == "socks5":
        _socks5_connect(sock, proxy, target_host, target_port, timeout)
    elif proxy.scheme == "socks4":
        _socks4_connect(sock, proxy, target_host, target_port, timeout)
    else:  # pragma: no cover - parse_proxy refuses other schemes earlier
        raise SOCKSError(f"unsupported proxy scheme {proxy.scheme!r}")


def _send_all(sock: socket.socket, data: bytes, label: str) -> None:
    try:
        sock.sendall(data)
    except socket.timeout as exc:
        raise SOCKSError(f"timed out sending {label}") from exc
    except OSError as exc:
        raise SOCKSError(f"failed sending {label}: {exc}") from exc


def _read_exact(sock: socket.socket, count: int, label: str) -> bytes:
    """Read exactly *count* bytes or raise.

    A short read is a server that hung up mid-reply. That must be an error and
    not silence, because a zero-byte reply read as "no bytes yet" would make a
    dead proxy indistinguishable from a working one.
    """
    chunks = bytearray()
    try:
        while len(chunks) < count:
            chunk = sock.recv(min(count - len(chunks), _MAX_REPLY_BYTES))
            if not chunk:
                break
            chunks.extend(chunk)
    except socket.timeout as exc:
        raise SOCKSError(f"timed out reading {label}") from exc
    except OSError as exc:
        raise SOCKSError(f"failed reading {label}: {exc}") from exc
    if len(chunks) < count:
        raise SOCKSError(
            f"proxy closed the connection mid-handshake, while reading {label}"
        )
    return bytes(chunks)


# ---------------------------------------------------------------------------
# SOCKS5 (RFC 1928), with RFC 1929 username/password auth
# ---------------------------------------------------------------------------


def _socks5_connect(sock, proxy, host, port, timeout) -> None:
    sock.settimeout(timeout)
    methods = (
        bytes([_SOCKS5_METHOD_USERNAME_PASSWORD])
        if proxy.needs_auth
        else bytes([_SOCKS5_METHOD_NO_AUTH])
    )
    greeting = bytes([_SOCKS5_VERSION, len(methods)]) + methods
    _send_all(sock, greeting, "the method greeting")

    reply = _read_exact(sock, 2, "the method selection")
    version, method = reply[0], reply[1]
    if version != _SOCKS5_VERSION:
        raise SOCKSError(
            f"proxy answered the greeting with version {version}, not SOCKS5"
        )
    if method == _SOCKS5_METHOD_UNACCEPTABLE:
        detail = "credentials are required" if not proxy.needs_auth else "none were acceptable"
        raise SOCKSError(
            f"proxy accepts none of the offered auth methods ({detail})"
        )
    if method == _SOCKS5_METHOD_USERNAME_PASSWORD:
        _socks5_auth(sock, proxy)
    elif method != _SOCKS5_METHOD_NO_AUTH:
        raise SOCKSError(
            f"proxy chose auth method 0x{method:02x}, which was not offered"
        )

    request = bytes([_SOCKS5_VERSION, _SOCKS5_CMD_CONNECT, 0x00]) + _socks5_address(
        host, port
    )
    _send_all(sock, request, "the CONNECT request")

    head = _read_exact(sock, 4, "the CONNECT reply")
    version, code, _reserved, atyp = head[0], head[1], head[2], head[3]
    if version != _SOCKS5_VERSION:
        raise SOCKSError(
            f"proxy answered the CONNECT with version {version}, not SOCKS5"
        )
    if code != 0x00:
        reason = _SOCKS5_REPLIES.get(code, f"reply code 0x{code:02x}")
        raise SOCKSError(f"proxy refused the CONNECT: {reason}")
    _drain_bound_address(sock, atyp)


def _socks5_auth(sock, proxy) -> None:
    """RFC 1929 subnegotiation. Runs inside the tunnel, so its version is 1."""
    username = (proxy.username or "").encode("ascii", "replace")
    password = (proxy.password or "").encode("ascii", "replace")
    if len(username) > 255 or len(password) > 255:
        raise SOCKSError("SOCKS5 username and password are limited to 255 bytes")
    _send_all(
        sock,
        bytes([0x01, len(username)]) + username + bytes([len(password)]) + password,
        "the auth exchange",
    )
    reply = _read_exact(sock, 2, "the auth reply")
    if reply[0] != 0x01:
        raise SOCKSError(
            f"proxy answered auth with version {reply[0]}, not the RFC 1929 subnegotiation"
        )
    if reply[1] != 0x00:
        raise SOCKSError("proxy rejected the username/password credentials")


def _socks5_address(host: str, port: int) -> bytes:
    """The ATYP + address + port triple, choosing the type the target needs."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            raw = host.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SOCKSError(
                f"target host {host!r} is not an IP or an ASCII name, so it "
                "cannot be carried in a SOCKS5 CONNECT"
            ) from exc
        if len(raw) > 255:
            raise SOCKSError("target hostname exceeds the 255-byte SOCKS5 limit")
        return bytes([_SOCKS5_ATYP_DOMAIN, len(raw)]) + raw + struct.pack(">H", port)
    if ip.version == 4:
        return bytes([_SOCKS5_ATYP_IPV4]) + ip.packed + struct.pack(">H", port)
    return bytes([_SOCKS5_ATYP_IPV6]) + ip.packed + struct.pack(">H", port)


def _drain_bound_address(sock, atyp: int) -> None:
    """Consume the BND.ADDR/BND.PORT the reply always carries.

    Unused, but not optional: bytes left in the socket after the handshake
    would prepend themselves to the caller's first request on the tunnel, and
    a server reading that stream would see garbage where an HTTP request line
    belongs.
    """
    if atyp == _SOCKS5_ATYP_IPV4:
        _read_exact(sock, 4 + 2, "the bound IPv4 address")
    elif atyp == _SOCKS5_ATYP_DOMAIN:
        length = _read_exact(sock, 1, "the bound name length")[0]
        _read_exact(sock, length + 2, "the bound name")
    elif atyp == _SOCKS5_ATYP_IPV6:
        _read_exact(sock, 16 + 2, "the bound IPv6 address")
    else:
        raise SOCKSError(f"proxy replied with an unknown address type 0x{atyp:02x}")


# ---------------------------------------------------------------------------
# SOCKS4 / SOCKS4a
# ---------------------------------------------------------------------------


def _socks4_connect(sock, proxy, host, port, timeout) -> None:
    sock.settimeout(timeout)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    userid = (proxy.username or "").encode("ascii", "replace")
    if proxy.password:
        # SOCKS4 has no password field. The user:pass userid is the convention
        # the authenticated socks4 endpoints in public lists actually use; a
        # server that wanted the bare username only will refuse auth and the
        # error will say so.
        userid = f"{proxy.username or ''}:{proxy.password}".encode("ascii", "replace")
    if len(userid) > 255:
        raise SOCKSError("SOCKS4 userid exceeds 255 bytes")

    if ip is not None and ip.version == 4:
        request = bytes([0x04, 0x01]) + struct.pack(">H", port) + ip.packed + userid + b"\x00"
    elif ip is not None:
        raise SOCKSError(
            "SOCKS4 cannot carry an IPv6 target; use a socks5 proxy for that"
        )
    else:
        # SOCKS4a: the proxy resolves the name. DSTIP is 0.0.0.x with x != 0 -
        # 0.0.0.1 is the conventional marker - and the name follows the userid.
        try:
            name = host.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SOCKSError(
                f"target host {host!r} is not an IP or an ASCII name, so it "
                "cannot be carried in a SOCKS4a CONNECT"
            ) from exc
        if len(name) > 255:
            raise SOCKSError("target hostname exceeds the 255-byte SOCKS4a limit")
        request = (
            bytes([0x04, 0x01])
            + struct.pack(">H", port)
            + b"\x00\x00\x00\x01"
            + userid
            + b"\x00"
            + name
            + b"\x00"
        )
    _send_all(sock, request, "the CONNECT request")

    reply = _read_exact(sock, 8, "the SOCKS4 reply")
    code = reply[1]
    if code != _SOCKS4_GRANTED:
        reason = _SOCKS4_REPLIES.get(code, f"reply code 0x{code:02x}")
        raise SOCKSError(f"proxy refused the CONNECT: {reason}")
