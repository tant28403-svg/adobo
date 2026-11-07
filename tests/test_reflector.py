"""The loopback reflectors, and the measured-amplification loop they close.

The unit tests assert on the replies themselves: size relative to the query,
the ceiling, the echoed correlation bytes. The end-to-end test runs the real
engine against the real reflector and asserts that ``amplification_factor``
is finally a measurement rather than always ``None`` - which, for an
amplification profile, is the entire reason this module exists.

The measured ratios are lab numbers, not protocol maxima: the profiles pad
their queries to the configured payload size, so the factor falls as the
payload grows. Run with a small payload to approach the published figures,
which the report still shows separately as ``est``.
"""

from __future__ import annotations

import socket

import pytest

from adobo.models import AttackProfile, ProfileName, RunConfig, Target, TransportKind
from adobo.target.reflector import MAX_REPLY_BYTES, Reflector


@pytest.fixture()
def reflector():
    reflector = Reflector(ports={"dns": 0, "ntp": 0, "cldap": 0, "ssdp": 0})
    reflector.start()
    yield reflector
    reflector.stop()


def _query(text: bytes = b"q" * 64) -> bytes:
    return text


def _send(reflector: Reflector, name: str, payload: bytes) -> bytes:
    """One query to the reflector, with the reply."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        sock.sendto(payload, ("127.0.0.1", reflector.bound[name]))
        reply, _addr = sock.recvfrom(65_535)
        return reply


class TestReplies:
    def test_dns_reply_amplifies_and_is_bounded(self, reflector) -> None:
        query = b"\xab\xcd" + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + (
            b"\x07example\x03com\x00\x00\x01\x00\x01"
        )
        reply = _send(reflector, "dns", query)
        assert len(reply) > len(query), "the reply is the amplified one"
        assert reply[:2] == b"\xab\xcd", "the transaction ID is echoed"
        assert len(reply) <= MAX_REPLY_BYTES

    def test_ntp_reply_carries_the_monlist_shape(self, reflector) -> None:
        reply = _send(reflector, "ntp", _query())
        assert len(reply) > len(_query())
        assert reply[3] == 42, "the response declares request code 42"
        assert len(reply) <= MAX_REPLY_BYTES

    def test_cldap_reply_is_parseable_ber_and_amplified(self, reflector) -> None:
        query = (
            b"\x30\x84\x00\x00\x00\x2c\x02\x01\x01"
            b"\x63\x84\x00\x00\x00\x27\x04\x00\x0a\x01\x00"
        )
        reply = _send(reflector, "cldap", query)
        assert len(reply) > len(query)
        assert reply[0] == 0x30, "the reply is a BER SEQUENCE"

    def test_ssdp_reply_answers_an_m_search(self, reflector) -> None:
        query = b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n"
        reply = _send(reflector, "ssdp", query)
        assert reply.startswith(b"HTTP/1.1 200 OK")
        assert len(reply) > len(query)

    def test_ssdp_ignores_what_is_not_an_m_search(self, reflector) -> None:
        """An SSDP reflector that answers anything is an open amplifier; the
        lab one answers the method it exists to reflect. (The negative must
        not contain the substring "M-SEARCH" - a past draft's fake query did,
        and the reflector correctly replied to it.)"""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.4)
            sock.sendto(b"NOT-A-SEARCH\r\n\r\n", ("127.0.0.1", reflector.bound["ssdp"]))
            with pytest.raises(socket.timeout):
                sock.recvfrom(65_535)

    def test_stop_is_responsive(self) -> None:
        import time

        reflector = Reflector(ports={"dns": 0})
        reflector.start()
        started = time.monotonic()
        reflector.stop()
        assert time.monotonic() - started < 2.0, "stop() must not hang"

    def test_stats_count_queries_and_bytes(self, reflector) -> None:
        _send(reflector, "dns", _query())
        stats = reflector.stats["dns"]
        assert stats["queries"] == 1
        assert stats["replies"] == 1
        assert stats["bytes_out"] > stats["bytes_in"]


class TestMeasuredAmplification:
    def test_an_end_to_end_run_measures_a_factor(self, reflector) -> None:
        """The loop this module exists to close.

        The engine sends real-source UDP at the reflector's DNS port; the
        replies come back to the sending socket; the transport counts them;
        the run reports an amplification factor derived from observed bytes
        rather than a published constant or None.
        """
        from adobo.engine import RunEngine

        config = RunConfig(
            target=Target(host="127.0.0.1", port=reflector.bound["dns"]),
            attack=AttackProfile(
                profile=ProfileName.UDP_FLOOD,
                pps=300,
                duration_seconds=1.0,
                payload_size=64,
            ),
            transport=TransportKind.SOCKET,
        )
        engine = RunEngine(config, enable_probes=False, observe_target=False)
        outcome = engine.run()

        attack = outcome.result.attack
        assert attack.bytes_sent > 0
        assert attack.amplification_factor is not None, (
            "replies came back and must be counted - the run measures, not "
            "declares, its amplification"
        )
        assert attack.amplification_factor > 1.0
        # The measured figure outranks the declared one in the display.
        assert attack.amplification_display() == f"{attack.amplification_factor:.1f}x"
