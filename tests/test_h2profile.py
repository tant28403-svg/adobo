"""Tests for the HTTP/2 connection preamble.

The organising idea of this module is that the HTTP/2 fingerprint must be
*measured*, not asserted. Everything here decodes frame bytes off a socket and
compares them against what a profile claims, because that is the only assertion
that can tell whether the tool sends what it says it sends.

Three findings from building this are pinned as tests rather than left in
docstrings, since each is a way the feature could silently break:

1. ``h2`` provides no supported way to set the initial SETTINGS frame. Four
   separate approaches were measured; three of them do not work and none of them
   fail loudly in Python. See ``TestH2LibraryQuirksPinned``.
2. ``H2Profile.apply`` replaces an internal attribute to get around (1), so an h2
   upgrade could break the wire output with every h2-API-based test still green.
   ``TestTransportWireOutput`` is the test that would catch it.
3. A profile that reproduces some of a browser's connection layer and not all of
   it must say which, rather than letting "preamble applied" imply completeness.
   ``TestDisclosure`` holds that line.
"""

from __future__ import annotations

import socket

import pytest

from adobo.h2profile import (
    DEFAULT_PSEUDO_HEADER_ORDER,
    H2Profile,
    decode_pseudo_header_order,
    decode_preamble,
    h2_profile,
    h2_profile_for_persona,
    profile_keys,
    setting_name,
)
from adobo.fingerprint import fingerprint as resolve_persona
from adobo.models import AttackProfile, ProfileName, Target

PREAMBLE_MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _attack(**kw) -> AttackProfile:
    defaults = dict(profile=ProfileName.HTTP_FLOOD, pps=10, duration_seconds=1.0)
    defaults.update(kw)
    return AttackProfile(**defaults)


def _client_connection():
    """A bare h2 client connection, configured the way the transport configures it."""
    import h2.config
    import h2.connection

    return h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    )


def _preamble_bytes(profile: H2Profile) -> bytes:
    """The bytes *profile* puts on the wire, built the way the transport builds them.

    Order-sensitive and duplicative of ``H2Transport.open`` on purpose. If the
    transport ever reorders these calls - which is easy to do, since h2 accepts
    them in the wrong order without complaint at the Python level - this helper
    would still produce correct bytes and the transport tests would go on passing
    while the tool sent a malformed preface. ``TestTransportWireOutput`` closes
    that gap by driving the transport itself.
    """
    conn = _client_connection()
    profile.apply(conn)
    conn.initiate_connection()
    increment = profile.window_increment()
    if increment:
        conn.increment_flow_control_window(increment)
    return bytes(conn.data_to_send())


# ---------------------------------------------------------------------------
# The decoder
# ---------------------------------------------------------------------------


class TestPreambleDecoder:
    """``decode_preamble`` is the measuring instrument, so it gets tested hardest.

    A decoder that misreads frames makes every fidelity claim in this codebase
    wrong in the direction that looks like success, which is why these check the
    failure cases first.
    """

    def test_it_rejects_bytes_without_the_client_magic(self) -> None:
        preamble = decode_preamble(b"not an http/2 preamble at all")
        assert preamble.magic_ok is False
        assert preamble.frames == ()

    def test_missing_magic_still_decodes_what_is_there(self) -> None:
        """A capture missing its magic should still report frames, not nothing.

        A malformed preface is exactly the case worth diagnosing, so discarding
        the frames because the magic is wrong would throw away the evidence. The
        frame here is complete - a nine-byte header plus a six-byte setting - so
        it is genuinely decodable rather than truncated.
        """
        frame = b"\x00\x00\x06\x04\x00\x00\x00\x00\x00" + (1).to_bytes(2, "big") + (
            4096
        ).to_bytes(4, "big")
        preamble = decode_preamble(frame)
        assert preamble.magic_ok is False
        assert preamble.settings_frame_count() == 1
        assert preamble.settings()[1] == 4096

    def test_it_decodes_settings_values(self) -> None:
        preamble = decode_preamble(_preamble_bytes(h2_profile("chrome_131")))
        assert preamble.magic_ok is True
        assert preamble.settings()[4] == 6291456  # INITIAL_WINDOW_SIZE
        assert preamble.settings()[3] == 1000  # MAX_CONCURRENT_STREAMS

    def test_it_decodes_the_window_update(self) -> None:
        preamble = decode_preamble(_preamble_bytes(h2_profile("chrome_131")))
        assert preamble.window_update() == 15663105

    def test_it_ignores_a_truncated_trailing_frame(self) -> None:
        """A capture cut mid-frame is normal and must not raise.

        The frames already received are still worth reporting; an exception would
        discard them and, worse, make ``--inspect-h2`` crash on a slow capture
        rather than describing what it got.
        """
        complete = _preamble_bytes(h2_profile("chrome_131"))
        preamble = decode_preamble(complete[:-3])
        assert preamble.magic_ok is True
        assert preamble.settings_frame_count() == 1

    def test_it_counts_repeated_settings_frames(self) -> None:
        """Two SETTINGS frames is a fingerprint, so the count has to be visible."""
        once = _preamble_bytes(h2_profile("chrome_131"))
        preamble = decode_preamble(once + once[24:])
        assert preamble.settings_frame_count() == 2

    def test_merging_repeated_settings_frames_lets_the_later_win(self) -> None:
        """RFC 7540: a later SETTINGS value replaces the earlier one."""
        once = _preamble_bytes(h2_profile("chrome_131"))
        # Strip the magic from the second copy so only the frames repeat.
        preamble = decode_preamble(once + once[24:])
        assert preamble.settings()[4] == 6291456

    def test_it_names_unknown_settings_by_code(self) -> None:
        """An unrecognised identifier must still be readable rather than dropped.

        An unknown setting is not a parse error - a future browser may send one -
        so a decoder that choked on it would make ``--inspect-h2`` useless against
        exactly the captures it exists to compare.
        """
        body = (99).to_bytes(2, "big") + (1234).to_bytes(4, "big")
        # 9-byte frame header: 3 length, 1 type, 1 flags, 4 stream id (0).
        frame = len(body).to_bytes(3, "big") + b"\x04\x00\x00\x00\x00\x00" + body
        assert len(frame) == 15
        preamble = decode_preamble(PREAMBLE_MAGIC + frame)
        assert preamble.settings()[99] == 1234
        assert setting_name(99) == "UNKNOWN_0x63"

    def test_wire_order_is_reported_separately_from_the_sorted_fingerprint(self) -> None:
        """The published fingerprint sorts ascending, which hides ordering.

        Two preambles differing only in SETTINGS order produce the same
        fingerprint string. They are not the same fingerprint, so the ordering has
        to be reachable - this is the accessor that keeps the sorted comparison
        from quietly over-claiming.
        """
        preamble = decode_preamble(_preamble_bytes(h2_profile("chrome_131")))
        wire = preamble.settings_wire_order()
        assert wire != tuple(sorted(wire)), (
            "h2 emits 1,2,4,5,8,3,6 - not ascending. If this assertion now fails, "
            "h2 changed its emission order and --inspect-h2's ordering note needs "
            "rewording."
        )
        assert set(wire) == set(preamble.settings())

    def test_pseudo_header_order_is_extracted_in_order(self) -> None:
        headers = [
            (":method", "GET"),
            (":authority", "x"),
            (":scheme", "https"),
            (":path", "/"),
            ("user-agent", "ua"),
        ]
        assert decode_pseudo_header_order(headers) == (
            ":method",
            ":authority",
            ":scheme",
            ":path",
        )


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------


class TestProfileRegistry:
    def test_every_profile_key_resolves(self) -> None:
        for key in profile_keys():
            assert h2_profile(key).key == key

    def test_an_unknown_key_is_rejected_with_the_valid_ones_listed(self) -> None:
        """A typo must not silently fall back to the default preamble."""
        with pytest.raises(ValueError, match="chrome_131"):
            h2_profile("chrome_132")

    def test_the_default_preamble_is_the_h2_library_ones(self) -> None:
        """A named baseline for "unchanged", which is what the default-path test needs."""
        assert h2_profile("h2_library").settings == (
            (1, 4096),
            (2, 1),
            (4, 65535),
            (5, 16384),
            (8, 0),
            (3, 100),
            (6, 65536),
        )

    def test_every_profile_records_where_its_values_came_from(self) -> None:
        """Transcribed numbers with no provenance are indistinguishable from guesses."""
        for key in profile_keys():
            assert h2_profile(key).source, f"{key} has no source recorded"

    def test_the_fingerprint_sorts_settings_ascending(self) -> None:
        """Both sides must render identically or the comparison is meaningless.

        ``Preamble.fingerprint`` cannot know the wire order it decoded, so it
        sorts. A profile that rendered in declaration order would produce a
        different string from the same settings and never compare equal.
        """
        rendered = h2_profile("chrome_131").fingerprint()
        codes = [int(part.split(":")[0]) for part in rendered[1:].split(";")[0].split("]")[0].split(";")]
        assert codes == sorted(codes)

    def test_an_incomplete_profile_says_so_and_a_complete_one_does_not(self) -> None:
        """Absence means "nothing missing"; only partial profiles carry a note."""
        assert h2_profile("chrome_131").incomplete_because is None
        assert h2_profile("firefox_133").incomplete_because
        assert h2_profile("safari_18").incomplete_because

    def test_the_default_pseudo_header_order_is_what_adobo_always_sent(self) -> None:
        """m,p,a,s - Firefox's order, coincidentally the order the code was written in.

        Making this the module default is what keeps the no-persona path
        byte-identical, so it is worth pinning rather than leaving to a comment.
        """
        assert DEFAULT_PSEUDO_HEADER_ORDER == (
            ":method",
            ":path",
            ":authority",
            ":scheme",
        )


class TestPersonaMapping:
    def test_the_lab_client_maps_to_no_preamble(self) -> None:
        """Nothing is being impersonated, so nothing should be emulated."""
        assert h2_profile_for_persona("lab_default") is None

    @pytest.mark.parametrize(
        "persona", ["chrome_131_win", "chrome_131_mac"]
    )
    def test_chrome_personas_share_one_preamble(self, persona: str) -> None:
        """The preamble is a property of the engine, not of the operating system."""
        assert h2_profile_for_persona(persona).key == "chrome_131"

    @pytest.mark.parametrize(
        "persona", ["firefox_133_win", "firefox_133_linux"]
    )
    def test_firefox_personas_share_one_preamble(self, persona: str) -> None:
        assert h2_profile_for_persona(persona).key == "firefox_133"

    def test_safari_maps_to_its_own_preamble(self) -> None:
        assert h2_profile_for_persona("safari_18_mac").key == "safari_18"

    def test_an_unknown_persona_maps_to_nothing_rather_than_guessing(self) -> None:
        """A near-miss must not resolve to a near-miss profile."""
        assert h2_profile_for_persona("chrome_999_win") is None


# ---------------------------------------------------------------------------
# The load-bearing test: declared values versus bytes on the wire
# ---------------------------------------------------------------------------


class TestProfileWireOutput:
    """Every profile is applied to a real h2 connection and the bytes decoded back.

    This is the assertion the rest of the feature rests on. A test written against
    h2's own API would keep passing if a future h2 stopped honouring
    ``Settings(initial_values=...)``, while the tool quietly sent h2's defaults -
    which is precisely the failure this feature exists to prevent.
    """

    @pytest.mark.parametrize("key", profile_keys())
    def test_the_preamble_is_well_formed(self, key: str) -> None:
        """Magic first, and a server must accept it.

        A preamble the peer rejects is not a weaker fingerprint, it is a broken
        connection - so this is checked before any fidelity claim.
        """
        raw = _preamble_bytes(h2_profile(key))
        assert raw[:24] == PREAMBLE_MAGIC, "the magic must come first"

        import h2.config
        import h2.connection

        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        server.initiate_connection()
        server.data_to_send()  # the server's own preface, which must come first
        events = server.receive_data(raw)  # raises ProtocolError if malformed
        assert any(type(e).__name__ == "RemoteSettingsChanged" for e in events)

    @pytest.mark.parametrize("key", profile_keys())
    def test_exactly_one_settings_frame_is_sent(self, key: str) -> None:
        """Browsers send one. ``update_settings`` after connecting sends two.

        Two SETTINGS frames is not just verbose - it is a signal on its own, and
        it is the second of the two h2 APIs that look like they should work.
        """
        assert decode_preamble(_preamble_bytes(h2_profile(key))).settings_frame_count() == 1

    @pytest.mark.parametrize("key", ["chrome_131", "h2_library"])
    def test_chrome_and_the_library_default_reproduce_exactly(self, key: str) -> None:
        """The two profiles h2's own defaults do not spoil.

        Chrome is the interesting case because it declares all seven settings,
        including the two RFC defaults h2 always emits - so a profile built for it
        is byte-for-byte reproducible, and claiming otherwise would be
        underclaiming.
        """
        profile = h2_profile(key)
        observed = decode_preamble(_preamble_bytes(profile))
        assert observed.settings() == profile.setting_map()
        assert observed.window_update() == profile.window_increment()

    @pytest.mark.parametrize("key", ["firefox_133", "safari_18"])
    def test_partial_profiles_reproduce_their_declared_values(self, key: str) -> None:
        """Every setting a profile declares must appear on the wire.

        The reverse - settings appearing that were not declared - is checked
        separately, because it is expected here and would be a bug elsewhere.
        """
        profile = h2_profile(key)
        observed = decode_preamble(_preamble_bytes(profile))
        declared = profile.setting_map()
        for code, value in declared.items():
            assert observed.settings().get(code) == value, setting_name(code)
        assert observed.window_update() == profile.window_increment()

    @pytest.mark.parametrize(
        "key", ["firefox_133", "safari_18"]
    )
    def test_partial_profiles_expose_exactly_the_surplus_h2_adds(self, key: str) -> None:
        """Pins the measured surplus, so an h2 change here fails a test.

        h2 always emits RFC 7540's default settings and a profile can override
        one but not remove it. That is why these two profiles carry an
        ``incomplete_because``. Naming the exact settings means the note stays
        true: if h2 stopped adding one, this test fails and the note gets fixed.

        Safari's surplus is smaller than Firefox's because Safari's real frame
        already carries ENABLE_PUSH, so declaring it absorbs that one - which is
        the same mechanism that makes Chrome exact.
        """
        profile = h2_profile(key)
        observed = decode_preamble(_preamble_bytes(profile))
        surplus = set(observed.settings()) - set(profile.setting_map())
        expected = {2, 8} if key == "firefox_133" else {8}
        assert surplus == expected, (
            f"{key}: expected h2 to add {sorted(expected)}, but the surplus was "
            f"{sorted(surplus)}"
        )

    def test_chrome_declares_the_settings_h2_always_adds(self) -> None:
        """Why Chrome is exact and the others are not - asserted, not assumed.

        Chrome's real SETTINGS frame includes ENABLE_PUSH and
        ENABLE_CONNECT_PROTOCOL, so declaring them means h2's unavoidable surplus
        coincides with Chrome's truth instead of contradicting it.
        """
        chrome = h2_profile("chrome_131").setting_map()
        assert chrome[2] == 0 and chrome[8] == 0

    def test_the_default_profile_is_byte_identical_to_an_untouched_h2_connection(self) -> None:
        """The strongest form of "the default path is unchanged".

        Not "produces equivalent settings" but "produces the same bytes". Any
        future edit that perturbs the default preamble - a reordering, an added
        frame - breaks this immediately.
        """
        conn = _client_connection()
        conn.initiate_connection()
        untouched = bytes(conn.data_to_send())
        assert _preamble_bytes(h2_profile("h2_library")) == untouched


class TestH2LibraryQuirksPinned:
    """The three ways of setting the initial SETTINGS frame that do not work.

    Each was measured against a real peer before being written down. Left as prose
    they read like caution; as tests they fail if h2 ever starts honouring one, at
    which point ``H2Profile.apply`` can be simplified instead of continuing to
    reach around the library.
    """

    def test_assigning_into_local_settings_silently_does_nothing(self) -> None:
        """The trap. ``Settings.__setitem__`` queues a value for acknowledgement
        rather than committing it, and reads back as the default."""
        import h2.settings

        conn = _client_connection()
        conn.local_settings[h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS] = 1000
        assert conn.local_settings[
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS
        ] == 100, "assigning into local_settings is a no-op"

    def test_update_settings_before_initiating_produces_an_invalid_preamble(self) -> None:
        """Frames queued before the magic land where the magic belongs.

        The peer rejects it, so this is caught by h2 and not by the tool - but it
        is the mistake a reader is most likely to make, and the fix (ordering the
        calls) is invisible unless it is stated.
        """
        import h2.settings

        conn = _client_connection()
        conn.update_settings(
            {h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 1000}
        )
        conn.initiate_connection()
        raw = bytes(conn.data_to_send())

        assert raw[:24] != PREAMBLE_MAGIC, (
            "expected the malformed ordering this test pins; if h2 has changed, "
            "H2Profile.apply may be simplifiable"
        )

        import h2.config
        import h2.connection

        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        with pytest.raises(Exception):
            server.receive_data(raw)

    def test_update_settings_after_initiating_sends_a_second_frame(self) -> None:
        """Legal, and still wrong: browsers send exactly one SETTINGS frame."""
        import h2.settings

        conn = _client_connection()
        conn.initiate_connection()
        conn.data_to_send()  # flush the preface
        conn.update_settings(
            {h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 1000}
        )
        later = bytes(conn.data_to_send())

        assert decode_preamble(PREAMBLE_MAGIC + later).settings_frame_count() == 1
        assert decode_preamble(_bare_preamble() + later).settings_frame_count() == 2

    def test_rebuilding_settings_with_initial_values_is_the_working_route(self) -> None:
        """The approach the module uses, asserted directly so its premise is tested."""
        import h2.settings

        profile = h2_profile("chrome_131")
        conn = _client_connection()
        conn.local_settings = h2.settings.Settings(
            client=True,
            initial_values={
                h2.settings.SettingCodes(code): value
                for code, value in profile.settings
            },
        )
        conn.max_inbound_frame_size = conn.local_settings.max_frame_size
        conn.initiate_connection()
        observed = decode_preamble(bytes(conn.data_to_send()))

        assert observed.settings() == profile.setting_map()

    def test_h2_rejects_the_weight_zero_priorities_firefox_sends(self) -> None:
        """Why no priority tree is emitted.

        Firefox's published priority tree uses weight 0, which the spec allows
        and h2 refuses. Sending weight 1 instead would produce a fingerprint that
        differs from Firefox's in exactly the field being impersonated, so the
        field is left absent instead.
        """
        import h2.exceptions

        conn = _client_connection()
        conn.initiate_connection()
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.prioritize(stream_id=3, weight=0, depends_on=1, exclusive=False)


def _bare_preamble() -> bytes:
    """A bare h2 connection's preamble, for the two-SETTINGS-frame test above."""
    conn = _client_connection()
    conn.initiate_connection()
    return bytes(conn.data_to_send())


# ---------------------------------------------------------------------------
# The transport
# ---------------------------------------------------------------------------


class _RecordingSocket:
    """A socket stand-in that records what was sent and replays a real peer's reply.

    Backed by a server-side h2 connection that consumes the transport's bytes as
    they arrive, rather than by canned frame blobs. That matters: h2 will not send
    a SETTINGS acknowledgement until it has seen the client's preamble, so a stub
    that answered with a fixed frame either deadlocks the ack or forces the test to
    stub out ``_await_settings_ack`` - and a transport whose open() was never
    fully exercised is not the thing whose bytes we care about.
    """

    def __init__(self) -> None:
        import h2.config
        import h2.connection

        self.sent = bytearray()
        self.closed = False
        self._peer = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        self._peer.initiate_connection()
        self._reply = bytes(self._peer.data_to_send())
        self._delivered = False

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)
        # Let the peer consume what just arrived and prepare its response, so the
        # SETTINGS acknowledgement exists by the time the transport asks for it.
        self._peer.receive_data(data)
        pending = bytes(self._peer.data_to_send())
        if pending:
            self._reply += pending

    def recv(self, _size: int) -> bytes:
        if self._delivered:
            return b""
        self._delivered = True
        return self._reply

    def selected_alpn_protocol(self) -> str:
        return "h2"

    def close(self) -> None:
        self.closed = True

    def shutdown(self, _how: int) -> None:
        pass


class _RecordingContext:
    """An SSL context whose ``wrap_socket`` hands the recording socket straight back."""

    def __init__(self, recorder: _RecordingSocket) -> None:
        self._recorder = recorder

    def wrap_socket(self, sock, server_hostname=None):  # noqa: ANN001, ARG002
        return self._recorder


def _drive_transport(monkeypatch, profile: H2Profile | None, *, fingerprint=None):
    """Run the real ``H2Transport.open()`` and return what it put on the wire.

    This is the test that closes the gap ``_preamble_bytes`` leaves open. That
    helper reproduces the transport's call sequence in its own words, so it would
    keep producing correct bytes if the transport's sequence were reordered. This
    drives the transport itself, so a reordered ``apply``/``initiate`` shows up as
    a broken preamble here rather than only in production.

    The bytes the transport sends are captured *before* the peer's reply is
    appended to them, so the returned value is the client's own output and nothing
    else - comparing it against a bare h2 connection would be meaningless if the
    server's SETTINGS frame were mixed in.
    """
    from adobo.transports import http2_transport as module
    from adobo.transports.http2_transport import H2Transport

    recorder = _RecordingSocket()
    monkeypatch.setattr(
        module.socket, "create_connection", lambda *a, **k: _RecordingSocket()
    )
    monkeypatch.setattr(
        H2Transport, "_build_tls_context", lambda self: _RecordingContext(recorder)
    )

    transport = H2Transport(
        Target(host="127.0.0.1", port=443),
        ProfileName.HTTP_FLOOD,
        fingerprint=fingerprint,
        h2_profile=profile,
    )
    transport.open()
    # ``sent`` holds every byte the transport wrote; the peer consumed them all to
    # produce the acknowledgement, so this is exactly the client's preamble.
    try:
        return transport, bytes(recorder.sent)
    finally:
        transport.close()


class TestTransportWireOutput:
    @pytest.mark.parametrize("key", profile_keys())
    def test_the_transport_sends_what_the_profile_declares(
        self, monkeypatch, key: str
    ) -> None:
        """The load-bearing assertion of the whole feature.

        Drives ``H2Transport.open()`` for real, decodes the bytes it actually
        sent, and compares them against the profile's declaration. Written
        against the wire rather than against h2's API on purpose: the code that
        installs these settings reaches around h2's public surface, and a test that
        used the public surface would keep passing if that stopped working.
        """
        profile = h2_profile(key)
        _transport, raw = _drive_transport(monkeypatch, profile)

        assert raw[:24] == PREAMBLE_MAGIC, "the magic must come first"
        observed = decode_preamble(raw)
        assert observed.settings_frame_count() == 1
        assert observed.window_update() == profile.window_increment()
        for code, value in profile.setting_map().items():
            assert observed.settings().get(code) == value, setting_name(code)

    def test_the_transport_preamble_is_accepted_by_a_real_peer(
        self, monkeypatch
    ) -> None:
        """Round-trip the transport's output through a server-side h2 connection.

        Catches the malformed-preamble failure directly, rather than inferring it
        from a byte offset. This is the check that would have caught
        ``apply``/``initiate`` being swapped.
        """
        import h2.config
        import h2.connection
        import h2.settings

        _transport, raw = _drive_transport(monkeypatch, h2_profile("chrome_131"))

        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        server.initiate_connection()
        server.data_to_send()
        events = server.receive_data(raw)  # raises ProtocolError on a bad preface
        settings = next(
            e for e in events if type(e).__name__ == "RemoteSettingsChanged"
        )
        assert settings.changed_settings[
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE
        ].new_value == 6291456

    def test_no_preamble_means_the_bytes_are_unchanged(self, monkeypatch) -> None:
        """The default path must be byte-identical to before this feature existed.

        Asserted against a bare h2 connection rather than against a recorded
        golden, so it states the property rather than a snapshot: whatever h2 emits
        by default, adobo still emits.
        """
        conn = _client_connection()
        conn.initiate_connection()
        untouched = bytes(conn.data_to_send())

        _transport, raw = _drive_transport(monkeypatch, None)

        assert raw == untouched

    def test_no_preamble_means_no_window_update_frame(self, monkeypatch) -> None:
        """The default connection advertises no window increment, as it always has."""
        _transport, raw = _drive_transport(monkeypatch, None)
        assert decode_preamble(raw).window_update() is None


class TestPseudoHeaderOrder:
    """Pseudo-header order is decided per stream, not per connection."""

    @staticmethod
    def _sent_headers(
        monkeypatch, profile: H2Profile | None, *, fingerprint=None
    ) -> list[tuple[str, str]]:
        """Capture the header list the transport hands to h2 on its first stream.

        Read off the ``send_headers`` call rather than off the wire: HPACK would
        compress the order into an opaque index, and the point of these tests is
        the decision the transport makes, not how it is later encoded.
        """
        import h2.connection

        from adobo.transports import http2_transport as module
        from adobo.transports.http2_transport import H2Transport

        recorder = _RecordingSocket()
        captured: list[tuple[str, str]] = []

        monkeypatch.setattr(
            module.socket, "create_connection", lambda *a, **k: _RecordingSocket()
        )
        monkeypatch.setattr(
            H2Transport, "_build_tls_context", lambda self: _RecordingContext(recorder)
        )
        real_send_headers = h2.connection.H2Connection.send_headers

        def spy(self_conn, stream_id, headers, **kw):
            captured.extend(headers)
            return real_send_headers(self_conn, stream_id, headers, **kw)

        monkeypatch.setattr(h2.connection.H2Connection, "send_headers", spy)

        transport = H2Transport(
            Target(host="127.0.0.1", port=443),
            ProfileName.HTTP_FLOOD,
            fingerprint=fingerprint,
            h2_profile=profile,
        )
        transport.open()
        try:
            # The payload is ignored by this transport - it builds its own headers -
            # but the signature requires one, so pass a plausible request.
            transport.send_one(b"GET / HTTP/1.1\r\n\r\n")
        finally:
            transport.close()
        return captured

    def test_chrome_gets_m_authority_scheme_path(self, monkeypatch) -> None:
        """Chrome's published order. m,p,a,s is Firefox's and would be wrong here."""
        headers = self._sent_headers(monkeypatch, h2_profile("chrome_131"))
        order = decode_pseudo_header_order(headers)
        assert order == (":method", ":authority", ":scheme", ":path")

    def test_firefox_gets_m_path_authority_scheme(self, monkeypatch) -> None:
        headers = self._sent_headers(monkeypatch, h2_profile("firefox_133"))
        order = decode_pseudo_header_order(headers)
        assert order == (":method", ":path", ":authority", ":scheme")

    def test_the_default_order_is_unchanged(self, monkeypatch) -> None:
        """No preamble means the order adobo has always sent."""
        captured = self._sent_headers(monkeypatch, None)
        assert decode_pseudo_header_order(captured) == DEFAULT_PSEUDO_HEADER_ORDER

    def test_pseudo_headers_still_precede_ordinary_headers(self, monkeypatch) -> None:
        """RFC 9113, and h2 enforces it.

        Worth an explicit assertion because the profile controls the order *among*
        pseudo-headers: a profile could put :path first and still satisfy its own
        declaration while producing a header block the peer refuses.
        """
        headers = self._sent_headers(
            monkeypatch,
            h2_profile("chrome_131"),
            fingerprint=resolve_persona("chrome_131_win"),
        )
        seen_ordinary = False
        for name, _ in headers:
            if not name.startswith(":"):
                seen_ordinary = True
            elif seen_ordinary:
                pytest.fail(f"pseudo-header {name} followed an ordinary header")

    def test_persona_headers_follow_the_pseudo_headers(self, monkeypatch) -> None:
        """The same invariant with a persona present, so ordinary headers exist.

        Without a persona this transport sends exactly one ordinary header and the
        ordering is barely exercised, so the persona case is the one worth pinning.
        """
        headers = self._sent_headers(
            monkeypatch,
            h2_profile("chrome_131"),
            fingerprint=resolve_persona("chrome_131_win"),
        )
        names = [name for name, _ in headers]
        assert "user-agent" in names
        assert names.index("user-agent") > max(
            i for i, name in enumerate(names) if name.startswith(":")
        )


# ---------------------------------------------------------------------------
# Model integration
# ---------------------------------------------------------------------------


class TestModelIntegration:
    def test_the_default_configures_no_preamble(self) -> None:
        """The constraint that matters most: no persona, no preamble, no change."""
        attack = _attack()
        assert attack.h2_preamble == "auto"
        assert attack.h2_profile() is None

    def test_a_persona_selects_the_matching_preamble(self) -> None:
        assert _attack(fingerprint="firefox_133_win").h2_profile().key == "firefox_133"

    def test_auto_can_be_overridden_with_a_named_preamble(self) -> None:
        """Deliberately incoherent on purpose, which is the point of the override.

        Useful for testing a detector that keys on the connection layer alone.
        """
        attack = _attack(fingerprint="chrome_131_win", h2_preamble="firefox_133")
        assert attack.h2_profile().key == "firefox_133"

    def test_none_forces_the_untouched_preamble_even_when_impersonating(self) -> None:
        attack = _attack(fingerprint="chrome_131_win", h2_preamble="none")
        assert attack.h2_profile() is None
        assert attack.impersonates() is True

    def test_a_preamble_without_a_persona_is_allowed(self) -> None:
        """The connection layer can be emulated on its own.

        Deliberately permitted: the two halves are independently observable, and
        measuring a target's reaction to the preamble alone is a legitimate test.
        """
        attack = _attack(h2_preamble="chrome_131")
        assert attack.h2_profile().key == "chrome_131"
        assert attack.persona() is None

    def test_an_unknown_preamble_is_rejected_at_construction(self) -> None:
        """A typo must not silently leave the default preamble in place."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="chrome_131"):
            _attack(h2_preamble="chrome_132")

    def test_the_incompleteness_note_comes_from_the_resolved_profile(self) -> None:
        attack = _attack(fingerprint="firefox_133_win")
        assert "priority tree" in attack.h2_preamble_incomplete_because()

    def test_a_complete_profile_reports_nothing_incomplete(self) -> None:
        assert _attack(fingerprint="chrome_131_win").h2_preamble_incomplete_because() is None

    def test_no_preamble_reports_nothing_incomplete(self) -> None:
        """Silence is the signal - a complete absence must not read as a gap."""
        assert _attack().h2_preamble_incomplete_because() is None

    def test_rotation_does_not_change_the_connection_preamble(self) -> None:
        """Rotation is per-connection, so all personas must share one preamble.

        If rotation picked a different preamble per connection, a run would send
        Chrome's preamble on one connection and Firefox's on the next - incoherent
        as a browser and wasteful as an attack, since half the connections would
        carry an identity nothing else on them matches.
        """
        keys = "chrome_131_win,firefox_133_win,safari_18_mac"
        attack = _attack(fingerprint=keys, fingerprint_rotation="per_connection")
        resolved = {
            _attack(fingerprint=key).h2_profile().key
            for key in keys.split(",")
        }
        assert len(resolved) == 3, "each persona has its own preamble"
        # And the rotating profile itself resolves stably, to the first persona.
        assert attack.h2_profile().key == "chrome_131"


class TestTransportFactory:
    def test_the_h2_transport_receives_the_resolved_preamble(self) -> None:
        from adobo.models import RunConfig, TransportKind
        from adobo.transports import get_transport

        config = RunConfig(
            target=Target(host="127.0.0.1", port=443),
            attack=_attack(fingerprint="chrome_131_win"),
            transport=TransportKind.H2,
        )
        transport = get_transport(config)
        assert transport._h2_profile.key == "chrome_131"

    def test_a_socket_run_that_asks_for_http2_receives_the_preamble(self) -> None:
        from adobo.models import RunConfig, TransportKind
        from adobo.transports import get_transport

        config = RunConfig(
            target=Target(host="127.0.0.1", port=443),
            attack=_attack(fingerprint="safari_18_mac", use_http2=True),
            transport=TransportKind.SOCKET,
        )
        transport = get_transport(config)
        assert transport._h2_profile.key == "safari_18"

    def test_a_plain_run_gets_no_preamble(self) -> None:
        """An HTTP/1.1 transport has no SETTINGS frame, so it gets no profile."""
        from adobo.models import RunConfig, TransportKind
        from adobo.transports import get_transport

        config = RunConfig(
            target=Target(host="127.0.0.1", port=8000),
            attack=_attack(),
            transport=TransportKind.SOCKET,
        )
        transport = get_transport(config)
        assert not hasattr(transport, "_h2_profile")

    def test_the_socket_transport_does_not_receive_a_preamble(self) -> None:
        """Preambles are an HTTP/2 concept; HTTP/1.1 has no SETTINGS frame.

        Also the reason the impersonating run above passes one: with no ``--http2``
        the factory builds a SocketTransport, and a persona must not cause an
        h2 profile to leak onto it.
        """
        from adobo.models import RunConfig, TransportKind
        from adobo.transports import get_transport

        config = RunConfig(
            target=Target(host="127.0.0.1", port=8000),
            attack=_attack(fingerprint="chrome_131_win"),
            transport=TransportKind.SOCKET,
        )
        transport = get_transport(config)
        assert not hasattr(transport, "_h2_profile")


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------


class TestInspection:
    def test_it_measures_a_profile_against_a_real_socket(self) -> None:
        """The measurement the whole module is for: declared versus observed."""
        from adobo.h2inspect import inspect_profile

        inspection = inspect_profile(h2_profile("chrome_131"))
        assert inspection.ok
        assert inspection.preamble.magic_ok
        assert inspection.settings_match() is True
        assert inspection.window_matches() is True
        assert inspection.extra_settings() == {}

    def test_it_measures_the_pseudo_header_order_it_sent(self) -> None:
        """The fourth fingerprint component is measured, not assumed."""
        from adobo.h2inspect import inspect_profile

        inspection = inspect_profile(h2_profile("chrome_131"))
        assert inspection.pseudo_header_order == (":method", ":authority", ":scheme", ":path")

    def test_a_partial_profile_measures_as_a_mismatch(self) -> None:
        """Firefox cannot be matched, and the tool must say mismatch, not match.

        A measurement that rounded "close enough" up to a pass would be the exact
        overclaim this module refuses to make elsewhere.
        """
        from adobo.h2inspect import inspect_profile

        inspection = inspect_profile(h2_profile("firefox_133"))
        assert inspection.settings_match() is False
        assert inspection.window_matches() is True
        assert set(inspection.extra_settings()) == {2, 8}

    def test_no_preamble_is_reported_rather_than_measured(self) -> None:
        """``None`` is a configuration, not a failure."""
        from adobo.h2inspect import inspect_profile

        inspection = inspect_profile(None)
        assert inspection.preamble is None
        assert inspection.error == "no preamble configured"

    def test_absent_settings_are_reported_separately_from_extra(self) -> None:
        """"Sent something we did not declare" and "dropped something we declared"
        are different faults and need different words."""
        from adobo.h2inspect import Inspection

        class _Fake:
            def settings(self):
                return {1: 4096}

            def window_update(self):
                return None

            magic_ok = True
            frames = ()

            def settings_frame_count(self):
                return 1

            def settings_wire_order(self):
                return (1,)

        inspection = Inspection(
            profile=h2_profile("chrome_131"),
            preamble=_Fake(),
            error="",
        )
        assert inspection.absent_settings() == {
            2: 0,
            3: 1000,
            4: 6291456,
            5: 16384,
            6: 262144,
            8: 0,
        }
        assert inspection.extra_settings() == {}


class TestInspectionRendering:
    def test_a_match_is_reported_as_a_match(self) -> None:
        from adobo.h2inspect import inspect_profile, render_inspection

        lines = "\n".join(render_inspection(inspect_profile(h2_profile("chrome_131"))))
        assert "match the bytes on the wire" in lines
        assert "DO NOT match" not in lines

    def test_a_mismatch_is_reported_as_a_mismatch(self) -> None:
        from adobo.h2inspect import inspect_profile, render_inspection

        lines = "\n".join(render_inspection(inspect_profile(h2_profile("firefox_133"))))
        assert "DO NOT match" in lines

    def test_an_incomplete_profile_prints_why(self) -> None:
        from adobo.h2inspect import inspect_profile, render_inspection

        lines = "\n".join(render_inspection(inspect_profile(h2_profile("firefox_133"))))
        assert "incomplete because" in lines
        assert "priority tree" in lines

    def test_the_declined_components_are_named_on_every_report(self) -> None:
        """What is *not* reproduced, stated unconditionally.

        A reader who only skims should still come away knowing the priority tree
        and JA3 are absent. That is the claim most likely to be assumed rather
        than read, and it is the one this tool cannot honour.
        """
        from adobo.h2inspect import inspect_profile, render_inspection

        for key in profile_keys():
            lines = "\n".join(render_inspection(inspect_profile(h2_profile(key))))
            assert "priority tree" in lines, key
            assert "JA3" in lines, key

    def test_no_preamble_renders_without_a_measurement(self) -> None:
        from adobo.h2inspect import inspect_profile, render_inspection

        lines = render_inspection(inspect_profile(None))
        assert any("no preamble configured" in line for line in lines)

    def test_the_declared_and_observed_strings_both_appear(self) -> None:
        """Showing one without the other would defeat the purpose of the command."""
        from adobo.h2inspect import inspect_profile, render_inspection

        lines = "\n".join(render_inspection(inspect_profile(h2_profile("chrome_131"))))
        assert "declared:" in lines
        assert "observed:" in lines


class TestInspectFlag:
    """``--inspect-h2`` must work without a target and must send nothing."""

    def test_it_runs_without_a_host(self, capsys) -> None:
        from adobo.cli import main

        assert main(["--inspect-h2", "--fingerprint", "chrome_131_win"]) == 0
        out = capsys.readouterr().out
        assert "HTTP/2 connection preamble" in out
        assert "match the bytes on the wire" in out

    def test_it_reports_the_default_as_no_preamble(self, capsys) -> None:
        from adobo.cli import main

        assert main(["--inspect-h2"]) == 0
        out = capsys.readouterr().out
        assert "no preamble configured" in out

    def test_it_honours_an_explicit_preamble(self, capsys) -> None:
        from adobo.cli import main

        main(["--inspect-h2", "--fingerprint", "chrome_131_win", "--h2-preamble", "none"])
        out = capsys.readouterr().out
        assert "no preamble configured" in out

    def test_it_never_reaches_the_run_engine(self, monkeypatch) -> None:
        """The safety-critical property: inspection opens no socket to the target.

        Checked by making the engine explode if constructed. An inspection command
        that could fall through into an attack would be a genuinely dangerous
        thing to have added to a tool like this.
        """
        from adobo.cli import main
        from adobo.engine import RunEngine

        def explode(*_args, **_kwargs):
            raise AssertionError("--inspect-h2 must not construct a RunEngine")

        monkeypatch.setattr(RunEngine, "__init__", explode)
        main(["--inspect-h2", "--fingerprint", "chrome_131_win"])

    def test_it_does_not_reach_the_wizard(self, monkeypatch) -> None:
        """No --host means the wizard would normally take over; inspection must not."""
        from adobo import cli

        def explode(*_args, **_kwargs):
            raise AssertionError("--inspect-h2 must not enter the wizard")

        monkeypatch.setattr(cli, "nuclear_wizard", explode)
        cli.main(["--inspect-h2"])


# ---------------------------------------------------------------------------
# Disclosure
# ---------------------------------------------------------------------------


class TestDisclosure:
    """The report has to say how much of the connection layer was reproduced."""

    @staticmethod
    def _notes(**kw) -> list[str]:
        from adobo.engine import RunEngine
        from adobo.models import RunConfig, TransportKind

        engine = RunEngine(
            RunConfig(
                target=Target(host="127.0.0.1", port=9),
                attack=_attack(**kw),
                transport=TransportKind.VIRTUAL,
            )
        )
        # RunOutcome.notes is never populated; the report's notes are on RunResult.
        # Reading the outer one would assert against an empty list and pass for
        # the wrong reason - which is exactly how the impersonation-note bug hid.
        return engine.run().result.notes

    def test_the_note_actually_reaches_the_report(self) -> None:
        """A computed note that is never appended is not a disclosure.

        Mirrors the impersonation-note bug, which was exactly this: the helper was
        correct and the caller dropped its return value. Asserting on a real run's
        report is the only assertion that catches it.
        """
        notes = self._notes(fingerprint="chrome_131_win")
        assert any("connection preamble" in n.lower() for n in notes), notes

    def test_the_note_carries_the_fingerprint(self) -> None:
        """So a reader can compare it against a capture without rerunning anything."""
        notes = self._notes(fingerprint="chrome_131_win")
        note = next(n for n in notes if "connection preamble" in n.lower())
        assert h2_profile("chrome_131").fingerprint() in note

    def test_an_incomplete_preamble_reports_the_gap_in_the_run(self) -> None:
        """The most important disclosure: which parts did not reproduce."""
        notes = self._notes(fingerprint="firefox_133_win")
        note = next(n for n in notes if "connection preamble" in n.lower())
        assert "Incomplete:" in note
        assert "priority tree" in note

    def test_a_complete_preamble_carries_no_gap(self) -> None:
        notes = self._notes(fingerprint="chrome_131_win")
        note = next(n for n in notes if "connection preamble" in n.lower())
        assert "Incomplete:" not in note

    def test_no_preamble_produces_no_note(self) -> None:
        """Guards the other direction, for the same reason the impersonation note
        does: a line that is always present teaches a reader to ignore it."""
        notes = self._notes()
        assert not any("connection preamble" in n.lower() for n in notes), notes

    def test_the_saved_report_records_the_identity_as_data(self) -> None:
        """A note in ``notes`` is prose; two saved runs cannot be compared on prose.

        The JSON carries the same information as fields, so a diff of two reports
        shows that one impersonated Chrome and the other did not impersonate at
        all - without either reader having to interpret a sentence.
        """
        from adobo.engine import RunEngine
        from adobo.models import RunConfig, TransportKind

        engine = RunEngine(
            RunConfig(
                target=Target(host="127.0.0.1", port=9),
                attack=_attack(fingerprint="firefox_133_win"),
                transport=TransportKind.VIRTUAL,
            )
        )
        payload = engine.run().result.to_json_dict()
        summary = payload["impersonation"]
        assert summary["personas"] == ["firefox_133_win"]
        assert summary["h2_preamble"] == "firefox_133"
        assert summary["h2_fingerprint"] == h2_profile("firefox_133").fingerprint()
        assert "priority tree" in summary["h2_incomplete_because"]

    def test_the_saved_report_records_no_impersonation_as_null(self) -> None:
        """``None`` and a summary of nothing are different claims, and null is the
        honest one for a run that presented itself as the lab client."""
        from adobo.engine import RunEngine
        from adobo.models import RunConfig, TransportKind

        engine = RunEngine(
            RunConfig(
                target=Target(host="127.0.0.1", port=9),
                attack=_attack(),
                transport=TransportKind.VIRTUAL,
            )
        )
        assert engine.run().result.to_json_dict()["impersonation"] is None

    def test_a_preamble_alone_produces_a_note_without_impersonation(self) -> None:
        """The two disclosures are independent and both can be absent.

        Emulating a preamble without a persona produces the connection note and
        not the impersonation one, since no User-Agent is being faked.
        """
        notes = self._notes(h2_preamble="chrome_131")
        assert any("connection preamble" in n.lower() for n in notes)
        assert not any("impersonation" in n.lower() for n in notes)
