"""Loopback reflectors for the amplification profiles.

**Why this exists.** The amplification profiles measure request volume only:
a real reflector answers a *spoofed* query at the victim, so the response is
never visible from the sending host and the engine correctly reports the
measured amplification as ``None`` (see
``RunEngine._calculate_amplification_factor``). But the tool also ships
non-spoofed runs, and against *this* server the replies come back to the
sender: the measured factor becomes computable end to end, on one machine,
with no elevation and no third-party service. That is the loop this module
closes - the lab finally measures what the amplification profiles claim.

**Deliberately fragile, deliberately bounded.** Same philosophy as the HTTP
lab target: the reflector answers maximally, so the amplification being
measured is real. And every reply is capped at :data:`MAX_REPLY_BYTES`
regardless of what the protocol could carry, because a lab service that can be
asked to emit unlimited traffic is not a lab service - it is the attack.

**Dispatch is by port, not by parsing.** The profiles send protocol headers
followed by padding (``_pad`` fills the payload to the requested size), so a
strict parse of, say, an NTP private-mode request would fail on the very
traffic this lab generates. Each socket belongs to one protocol and answers
everything that reaches it. The replies echo just enough of the query to be
correlated in a capture - a DNS transaction ID, an M-SEARCH method line - and
carry the recognizable ``adobo`` filler, so lab traffic stays attributable.

**The numbers are lab numbers.** Real-world DNS amplification uses ~60-byte
queries; the profiles pad to the configured payload size, so at the default
512-byte payload the *measured* factor is modest and falls as the payload
grows. That is not a defect - it is the ratio of the actual run. Run with a
small ``--payload`` to approximate the published figures, which remain
alongside as ``est``.
"""

from __future__ import annotations

import socket
import struct
import threading

__all__ = ["MAX_REPLY_BYTES", "Reflector"]

#: Every reply is capped at this many bytes, whatever the protocol could
#: carry. The ceiling is the lab's restraint: it bounds what this service can
#: be used to emit.
MAX_REPLY_BYTES = 3_000

_FILL = b"adobo-reflector"


def _filler(n: int) -> bytes:
    """Recognisable filler, the same convention as the transports' payloads."""
    if n <= 0:
        return b""
    reps, rest = divmod(n, len(_FILL))
    return _FILL * reps + _FILL[:rest]


def _ber_len(n: int) -> bytes:
    """BER length octets: short form below 128, long form above."""
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def dns_reply(query: bytes, target_size: int) -> bytes:
    """A DNS response with one large NULL answer record.

    Echoes the transaction ID and the question section (padding included - it
    is filler the operator can recognise in a capture), then answers with a
    NULL record (type 10) sized to bring the reply to *target_size*. A NULL
    record is the historically amplified one and is never compressed, so the
    size is exactly what we build.
    """
    qid = query[:2] if len(query) >= 2 else b"\x00\x00"
    question = query[12:] if len(query) > 12 else b"\x00"
    header = qid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    answer_fixed = b"\xc0\x0c" + b"\x00\x0a\x00\x01" + b"\x00\x00\x00\x00"
    budget = target_size - len(header) - len(question) - len(answer_fixed) - 2
    rdata = _filler(max(0, budget))
    rdlength = len(rdata).to_bytes(2, "big")
    return header + question + answer_fixed + rdlength + rdata


def ntp_reply(query: bytes, target_size: int) -> bytes:
    """A private-mode (monlist-shaped) response, packed with peer entries.

    The response header declares implementation 3, request code 42 and the
    response bit - the shape a monlist reply has - followed by fixed-size peer
    entries. The entries are filler, not real peers: this is a lab reflector
    answering a lab query, and the tool counts bytes.
    """
    header = struct.pack(">BBBb", 0x9F, 0x02, 0x06, 42) + b"\x00" * 12
    entry = struct.pack(">HH", 0x0002, 72) + _filler(68)
    count = max(0, (target_size - len(header)) // len(entry))
    return header + entry * count


def cldap_reply(query: bytes, target_size: int) -> bytes:
    """A CLDAP SearchResultEntry with one large attribute value.

    Real BER, so a packet-capture parser reads it as LDAP: a message envelope
    holding a SearchResultEntry with one attribute whose value is sized to
    bring the reply to *target_size*, followed by a SearchResultDone.
    """
    value = _filler(max(0, target_size - 40))
    attr = b"\x30" + _ber_len(2 + 1 + 1 + 1 + len(value)) + (
        b"\x04\x01\x61"                      # type "a"
        + b"\x31" + _ber_len(1 + 1 + len(value))
        + (b"\x04" + _ber_len(len(value)) + value)
    )
    entry = (
        b"\x04\x00"                          # objectName: ""
        + b"\x30" + _ber_len(len(attr)) + attr
    )
    done = b"\x65\x07\x0a\x01\x00\x04\x00\x04\x00"
    body = b"\x02\x01\x01" + b"\x64" + _ber_len(len(entry)) + entry + done
    return b"\x30" + _ber_len(len(body)) + body


def ssdp_reply(query: bytes, target_size: int) -> bytes:
    """An SSDP unicast response: an M-SEARCH answer with a padded USN."""
    if b"M-SEARCH" not in query.upper():
        return b""
    head = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"ST: upnp:rootdevice\r\n"
        b"EXT:\r\n"
        b"SERVER: adobo-reflector/0.1\r\n"
    )
    budget = target_size - len(head) - len(b"USN: \r\n\r\n")
    return head + b"USN: " + _filler(max(0, budget)) + b"\r\n\r\n"


_HANDLERS = {"dns": dns_reply, "ntp": ntp_reply, "cldap": cldap_reply, "ssdp": ssdp_reply}


class Reflector:
    """Four UDP services that answer maximally, for amplification measurement.

    One daemon thread per protocol socket. ``start()`` binds and returns the
    bound ports - pass 0 for a port to let the OS choose, which is how tests
    avoid colliding with anything real. ``stop()`` is responsive: the sockets
    carry a short timeout so the receive loop checks the stop event.
    """

    PROTOCOL_PORTS = {"dns": 53, "ntp": 123, "cldap": 389, "ssdp": 1900}

    def __init__(
        self,
        host: str = "127.0.0.1",
        ports: dict[str, int] | None = None,
    ) -> None:
        self.host = host
        self._ports = dict(self.PROTOCOL_PORTS if ports is None else ports)
        unknown = set(self._ports) - set(_HANDLERS)
        if unknown:
            raise ValueError(f"unknown reflector protocol(s): {sorted(unknown)}")
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self.bound: dict[str, int] = {}
        self.stats: dict[str, dict[str, int]] = {
            name: {"queries": 0, "replies": 0, "bytes_in": 0, "bytes_out": 0}
            for name in self._ports
        }

    def start(self) -> dict[str, int]:
        """Bind every protocol socket and start serving. Returns bound ports."""
        for name, requested in self._ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.1)
            sock.bind((self.host, requested))
            self.bound[name] = sock.getsockname()[1]
            self._sockets.append(sock)
            thread = threading.Thread(
                target=self._serve, args=(name, sock),
                name=f"adobo-reflector-{name}", daemon=True,
            )
            self._threads.append(thread)
            thread.start()
        return dict(self.bound)

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=2)
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass

    def _serve(self, name: str, sock: socket.socket) -> None:
        handler = _HANDLERS[name]
        size = self._ports_size(name)
        stats = self.stats[name]
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue
            stats["queries"] += 1
            stats["bytes_in"] += len(data)
            reply = handler(data, size)
            if reply:
                try:
                    sock.sendto(reply, addr)
                except OSError:
                    continue
                stats["replies"] += 1
                stats["bytes_out"] += len(reply)

    def _ports_size(self, name: str) -> int:
        """Reply ceiling for *name*: the global cap, or the protocol's shape."""
        return MAX_REPLY_BYTES if name != "ssdp" else 1_500


if __name__ == "__main__":  # pragma: no cover - manual entry point
    import argparse

    parser = argparse.ArgumentParser(
        prog="adobo-reflector",
        description="Loopback reflectors for the amplification profiles.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--dns", type=int, default=53, help="port (0 = ephemeral)")
    parser.add_argument("--ntp", type=int, default=123, help="port (0 = ephemeral)")
    parser.add_argument("--cldap", type=int, default=389, help="port (0 = ephemeral)")
    parser.add_argument("--ssdp", type=int, default=1900, help="port (0 = ephemeral)")
    args = parser.parse_args()

    reflector = Reflector(
        host=args.host,
        ports={
            "dns": args.dns, "ntp": args.ntp,
            "cldap": args.cldap, "ssdp": args.ssdp,
        },
    )
    bound = reflector.start()
    print("adobo reflector listening (Ctrl-C to stop):")
    for name, port in sorted(bound.items()):
        print(f"  {name:<6} udp://{args.host}:{port}")
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        reflector.stop()
        print("\nstopped")
