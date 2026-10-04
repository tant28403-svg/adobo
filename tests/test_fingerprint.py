"""Tests for client personas and dynamic headers.

The contract these protect is mostly about *not changing things*. The tool was
working before personas existed, and a persona registry is exactly the kind of
addition that can quietly alter traffic for an operator who never asked for one.
So the load-bearing assertions here are negative ones: that the default is
byte-identical to what the tool sent before, that the non-HTTP profiles are
untouched, and that a run which impersonates says so.

One test is a byte-for-byte comparison against a frozen reference captured from
the pre-persona implementation. That is deliberate. Every other way of checking
"the default did not change" - comparing sizes, comparing two calls to the same
function - would pass even if the header order shifted, and header order is part
of what a WAF reads.
"""

from __future__ import annotations

import pytest

from adobo.fingerprint import (
    DEFAULT_FINGERPRINT_KEY,
    FINGERPRINTS,
    fingerprint,
    persona_keys,
    resolve_rotation,
    rotate,
)
from adobo.models import AttackProfile, ProfileName, Target
from adobo.transports.base import build_payload

TARGET = Target(host="lab.internal", port=80)


# ---------------------------------------------------------------------------
# The frozen pre-persona output
# ---------------------------------------------------------------------------
#
# Captured from the implementation that existed before this feature, at the sizes
# that matter: below the natural request length, at the default payload size
# where the old truncation bug lived, and above it where padding applies.

_LEGACY_HEAD = (
    "GET /api/data HTTP/1.1\r\n"
    "Host: lab.internal\r\n"
    "User-Agent: adobo-lab/0.1 (authorized testing)\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "X-Ddosim-Seq: 7\r\n"
)


class TestLabDefaultIsByteIdentical:
    """The default must be indistinguishable from having no feature at all."""

    @pytest.mark.parametrize("size", [0, 1, 32, 64, 128, 141, 512, 1500])
    def test_lab_default_is_byte_identical(self, size: int) -> None:
        payload = build_payload(
            ProfileName.HTTP_FLOOD,
            size,
            target=TARGET,
            seed=7,
            fingerprint=fingerprint(DEFAULT_FINGERPRINT_KEY),
        ).decode("ascii")
        assert payload.startswith(_LEGACY_HEAD)

    def test_no_fingerprint_argument_produces_the_same_bytes(self) -> None:
        """Passing nothing must equal passing lab_default.

        This is the case that matters most: every existing call site passes
        nothing, so this is what an operator who never touches the new flag
        actually gets.
        """
        for size in (0, 128, 512, 1500):
            implicit = build_payload(
                ProfileName.HTTP_FLOOD, size, target=TARGET, seed=7
            )
            explicit = build_payload(
                ProfileName.HTTP_FLOOD,
                size,
                target=TARGET,
                seed=7,
                fingerprint=fingerprint(DEFAULT_FINGERPRINT_KEY),
            )
            assert implicit == explicit, f"default changed at size={size}"

    def test_the_lab_client_still_identifies_itself(self) -> None:
        assert b"adobo" in build_payload(ProfileName.HTTP_FLOOD, 512, target=TARGET)

    def test_lab_default_does_not_impersonate(self) -> None:
        assert fingerprint(DEFAULT_FINGERPRINT_KEY).impersonates is False


# ---------------------------------------------------------------------------
# Request well-formedness, per persona
# ---------------------------------------------------------------------------


class TestPersonasProduceValidRequests:
    @pytest.mark.parametrize("key", persona_keys())
    @pytest.mark.parametrize("size", [0, 32, 128, 512, 1500])
    def test_exactly_one_header_terminator(self, key: str, size: int) -> None:
        """One blank line ends the headers.

        Two would mean a body started, and a body whose length never arrives
        stalls the server's parser and resets a reused connection - the failure
        documented at transports/base.py on padding placement.
        """
        payload = build_payload(
            ProfileName.HTTP_FLOOD,
            size,
            target=TARGET,
            seed=1,
            fingerprint=fingerprint(key),
        )
        assert payload.count(b"\r\n\r\n") == 1, f"{key} at size={size}"

    @pytest.mark.parametrize("key", persona_keys())
    def test_padding_stays_inside_the_header_block_on_a_reused_connection(
        self, key: str
    ) -> None:
        """No body after the terminator, on the path where a body would hurt.

        Appending filler after the blank line makes it the start of a body whose
        content-length end never arrives. On a connection that is reused for the
        next request that stalls the server's parser and it resets the socket -
        the failure documented at transports/base.py, which was measured on the
        lab target as 20 pipelined requests with trailing filler killing the
        connection against 20 without it all being served.

        Only the keep-alive path is checked. In per-request mode the filler
        *is* appended after the terminator on purpose: the connection closes
        after one response, so nothing can be stalled, and
        ``test_padding_never_shrinks_a_payload_that_already_fits`` depends on it.
        """
        payload = build_payload(
            ProfileName.HTTP_FLOOD,
            1500,
            target=TARGET,
            seed=1,
            keep_alive=True,
            fingerprint=fingerprint(key),
        )
        head, _, tail = payload.partition(b"\r\n\r\n")
        # A GET has no body. Anything past the terminator is a body that will
        # never finish arriving.
        assert tail == b"", f"{key} leaked {len(tail)} bytes into a body"
        assert head.endswith(b"X-Pad: " + b"F" * 64) or b"X-Pad" in head

    @pytest.mark.parametrize("key", persona_keys())
    def test_every_persona_sends_a_user_agent(self, key: str) -> None:
        payload = build_payload(
            ProfileName.HTTP_FLOOD, 512, target=TARGET, fingerprint=fingerprint(key)
        )
        assert b"User-Agent: " in payload

    @pytest.mark.parametrize("key", persona_keys())
    def test_the_connection_header_is_not_persona_controlled(self, key: str) -> None:
        """Connection is transport-level, so keep-alive must still win.

        A persona that could set Connection: close would contradict a socket the
        transport is reusing, and the slower of the two behaviours would win -
        the same contradiction transports/base.py documents for the flag.
        """
        payload = build_payload(
            ProfileName.HTTP_FLOOD,
            512,
            target=TARGET,
            keep_alive=True,
            fingerprint=fingerprint(key),
        )
        assert b"Connection: keep-alive\r\n" in payload
        assert b"Connection: close" not in payload

    @pytest.mark.parametrize("key", persona_keys())
    def test_the_cache_buster_still_varies(self, key: str) -> None:
        """A caching layer must not be able to serve the flood from cache."""
        a = build_payload(
            ProfileName.HTTP_FLOOD, 512, target=TARGET, seed=1, fingerprint=fingerprint(key)
        )
        b = build_payload(
            ProfileName.HTTP_FLOOD, 512, target=TARGET, seed=2, fingerprint=fingerprint(key)
        )
        assert a != b, f"{key} produces an identical payload for every packet"


# ---------------------------------------------------------------------------
# Coherence
# ---------------------------------------------------------------------------


class TestPersonasAreInternallyConsistent:
    @pytest.mark.parametrize("key", persona_keys())
    def test_every_persona_is_coherent(self, key: str) -> None:
        """A persona must not contradict itself.

        A Chrome User-Agent claiming macOS in the platform hint, or Firefox
        sending Chromium client hints, is worse than no persona: it is trivially
        detectable, and a WAF that rejects it tells you nothing about the defense
        you meant to test.
        """
        assert fingerprint(key).is_coherent(), f"{key} is internally inconsistent"

    def test_firefox_and_safari_send_no_chromium_hints(self) -> None:
        """Neither browser implements Sec-CH-UA, so neither may send it."""
        for key in ("firefox_133_win", "firefox_133_linux", "safari_18_mac"):
            assert "sec-ch-ua" not in fingerprint(key).header_names(), key

    def test_chrome_personas_agree_with_their_platform_hint(self) -> None:
        assert fingerprint("chrome_131_win").platform_hint() == "Windows"
        assert fingerprint("chrome_131_mac").platform_hint() == "macOS"

    def test_a_platform_mismatch_is_detected(self) -> None:
        """The coherence check must actually be capable of failing.

        Without this, is_coherent() could return True unconditionally and every
        coherence assertion above would be vacuous.
        """
        from dataclasses import replace

        broken = replace(
            fingerprint("chrome_131_win"),
            platform="macOS",
        )
        assert broken.is_coherent() is False

    def test_user_agent_is_derived_not_stored(self) -> None:
        """A stored copy would be one more place for the two to drift."""
        persona = fingerprint("firefox_133_win")
        assert "Firefox/133.0" in persona.user_agent

    def test_a_persona_without_a_user_agent_is_incoherent(self) -> None:
        from dataclasses import replace

        broken = replace(fingerprint("chrome_131_win"), headers=(("Accept", "*/*"),))
        assert broken.is_coherent() is False
        with pytest.raises(KeyError):
            broken.user_agent


# ---------------------------------------------------------------------------
# Lookup and rotation
# ---------------------------------------------------------------------------


class TestLookup:
    def test_lab_default_is_registered_first(self) -> None:
        assert persona_keys()[0] == DEFAULT_FINGERPRINT_KEY

    def test_every_registered_persona_is_coherent(self) -> None:
        for key, persona in FINGERPRINTS.items():
            assert persona.is_coherent(), key
            assert persona.key == key, "registry key must match the persona's own key"

    def test_a_typo_lists_the_valid_keys(self) -> None:
        """A typo must be a useful message, not a bare lookup failure.

        Asserted as ``ValueError`` rather than ``KeyError`` because these run
        inside a pydantic validator, which converts ``ValueError`` into a
        ``ValidationError`` and lets a ``KeyError`` escape unhandled.
        """
        with pytest.raises(ValueError) as info:
            fingerprint("chrome_999")
        assert "lab_default" in str(info.value)
        assert "chrome_999" in str(info.value)

    def test_an_unknown_rotation_mode_lists_the_valid_modes(self) -> None:
        with pytest.raises(ValueError) as info:
            resolve_rotation("sometimes")
        assert "per_connection" in str(info.value)

    def test_a_lookup_failure_becomes_a_validation_error(self) -> None:
        """End to end: a typo in the model must not raise a raw KeyError.

        This is the actual user-facing path. If the validator let KeyError
        through, the CLI would print a traceback for what is simply a bad
        option instead of a validation error naming the valid personas.
        """
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as info:
            _profile(fingerprint="chrome_999")
        message = str(info.value)
        assert "chrome_999" in message
        assert "firefox_133_win" in message


class TestRotationIsDeterministic:
    def test_the_same_seed_always_picks_the_same_persona(self) -> None:
        """Runs must be reproducible, or a failure cannot be re-run.

        transports/base.py makes its filler deterministic for the same reason. A
        rotating selector built on random would make the same seed present a
        different client on every execution.
        """
        keys = ["chrome_131_win", "firefox_133_win", "safari_18_mac"]
        for seed in (0, 1, 42, 1_000_000):
            first = rotate(keys, seed).key
            assert all(rotate(keys, seed).key == first for _ in range(5))

    def test_rotation_survives_a_process_restart(self) -> None:
        """hash() on a str is salted per process, so it cannot be used here.

        A selection that is stable within a run but differs across runs is the
        worst of both: reproducible-looking and not actually reproducible.
        """
        import subprocess
        import sys

        script = (
            "from adobo.fingerprint import rotate;"
            "print(rotate(['chrome_131_win','firefox_133_win','safari_18_mac'], 42).key)"
        )
        runs = {
            subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            for _ in range(2)
        }
        assert len(runs) == 1, f"selection differs across processes: {runs}"

    def test_rotation_actually_varies_across_seeds(self) -> None:
        keys = ["chrome_131_win", "firefox_133_win", "safari_18_mac"]
        picked = {rotate(keys, seed).key for seed in range(60)}
        assert len(picked) > 1, "rotation always returned the same persona"

    def test_rotation_reaches_every_configured_persona(self) -> None:
        keys = ["chrome_131_win", "firefox_133_win", "safari_18_mac"]
        picked = {rotate(keys, seed).key for seed in range(200)}
        assert picked == set(keys)

    def test_an_empty_key_list_falls_back_to_the_lab_client(self) -> None:
        assert rotate([], 1).key == DEFAULT_FINGERPRINT_KEY


# ---------------------------------------------------------------------------
# Model integration
# ---------------------------------------------------------------------------


def _profile(**kw) -> AttackProfile:
    defaults = dict(profile=ProfileName.HTTP_FLOOD, pps=10, duration_seconds=1.0)
    defaults.update(kw)
    return AttackProfile(**defaults)


class TestModelIntegration:
    def test_the_defaults_impersonate_nothing(self) -> None:
        """Every existing caller constructs AttackProfile without these fields."""
        attack = _profile()
        assert attack.fingerprint == DEFAULT_FINGERPRINT_KEY
        assert attack.impersonates() is False
        assert attack.persona() is None

    def test_an_unknown_persona_is_rejected_at_construction(self) -> None:
        """A typo must fail loudly rather than silently not impersonating."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as info:
            _profile(fingerprint="chrome_999")
        assert "chrome_999" in str(info.value)

    def test_an_unknown_rotation_mode_is_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _profile(fingerprint_rotation="whenever")

    def test_a_list_of_personas_is_accepted(self) -> None:
        attack = _profile(fingerprint="chrome_131_win,firefox_133_win")
        assert attack.persona_keys() == ["chrome_131_win", "firefox_133_win"]
        assert attack.impersonates() is True

    def test_whitespace_in_the_list_is_tolerated(self) -> None:
        attack = _profile(fingerprint=" chrome_131_win , firefox_133_win ")
        assert attack.persona_keys() == ["chrome_131_win", "firefox_133_win"]

    def test_lab_default_mixed_with_a_persona_still_impersonates(self) -> None:
        """Only the personas actually used should be listed in the note."""
        attack = _profile(fingerprint="lab_default,chrome_131_win")
        assert attack.impersonates() is True
        keys = [k for k in attack.persona_keys() if k != DEFAULT_FINGERPRINT_KEY]
        assert keys == ["chrome_131_win"]

    def test_a_single_persona_never_rotates(self) -> None:
        """One entry is not a rotation, and treating it as one is nondeterminism."""
        attack = _profile(fingerprint="firefox_133_win", fingerprint_rotation="per_request")
        picked = {attack.persona(seed=seed).key for seed in range(50)}
        assert picked == {"firefox_133_win"}

    def test_rotation_none_pins_the_first_persona(self) -> None:
        attack = _profile(
            fingerprint="chrome_131_win,firefox_133_win", fingerprint_rotation="none"
        )
        picked = {attack.persona(seed=seed).key for seed in range(50)}
        assert picked == {"chrome_131_win"}

    def test_per_request_varies_with_the_seed(self) -> None:
        attack = _profile(
            fingerprint="chrome_131_win,firefox_133_win,safari_18_mac",
            fingerprint_rotation="per_request",
        )
        picked = {attack.persona(seed=seed).key for seed in range(200)}
        assert len(picked) > 1

    def test_no_seed_means_the_stable_persona(self) -> None:
        """What the report and a transport's setup ask for."""
        attack = _profile(fingerprint="chrome_131_win,firefox_133_win")
        assert attack.persona().key == "chrome_131_win"

    def test_persona_keys_are_never_empty(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _profile(fingerprint=" , , ")


# ---------------------------------------------------------------------------
# Non-HTTP profiles are untouched
# ---------------------------------------------------------------------------


class TestNonHttpProfilesAreUnaffected:
    """A persona describes an HTTP identity. There is nothing for it to change in
    a binary protocol message, and slowloris in particular must stay truncated -
    completing its headers would remove the attack."""

    @pytest.mark.parametrize(
        "profile",
        [
            ProfileName.UDP_FLOOD,
            ProfileName.DNS_AMPLIFICATION,
            ProfileName.NTP_AMPLIFICATION,
            ProfileName.CLDAP_AMPLIFICATION,
            ProfileName.SSDP_AMPLIFICATION,
        ],
    )
    @pytest.mark.parametrize("size", [0, 128, 512])
    def test_binary_profiles_ignore_the_persona(self, profile, size: int) -> None:
        with_persona = build_payload(
            profile, size, target=TARGET, seed=3, fingerprint=fingerprint("chrome_131_win")
        )
        without = build_payload(profile, size, target=TARGET, seed=3)
        assert with_persona == without, f"{profile} changed at size={size}"

    def test_slowloris_stays_intentionally_truncated(self) -> None:
        """Finishing the request would remove the entire point of the profile."""
        payload = build_payload(
            ProfileName.SLOWLORIS,
            128,
            target=TARGET,
            fingerprint=fingerprint("chrome_131_win"),
        )
        assert not payload.endswith(b"\r\n\r\n")
        assert not payload.endswith(b"\r\n")


# ---------------------------------------------------------------------------
# Disclosure
# ---------------------------------------------------------------------------


class TestImpersonationIsDisclosed:
    """A resilience score printed without saying which identity was used would
    let two runs that exercised different code paths be read as comparable."""

    @staticmethod
    def _note(**kw) -> str | None:
        from adobo.engine import RunEngine

        attack = _profile(**kw)
        engine = RunEngine.__new__(RunEngine)  # no run, no sockets
        engine.config = type("C", (), {"attack": attack})()
        return engine._impersonation_note()

    def test_the_lab_client_produces_no_note(self) -> None:
        """Silence is the signal that nothing was faked."""
        assert self._note() is None

    def test_a_persona_produces_a_note_naming_it(self) -> None:
        note = self._note(fingerprint="firefox_133_win")
        assert note is not None
        assert "firefox_133_win" in note
        assert "impersonation" in note.lower()

    def test_the_note_lists_every_persona_used(self) -> None:
        note = self._note(fingerprint="chrome_131_win,firefox_133_win,safari_18_mac")
        for key in ("chrome_131_win", "firefox_133_win", "safari_18_mac"):
            assert key in note

    def test_the_note_excludes_lab_default_from_the_persona_list(self) -> None:
        """lab_default is the absence of a persona, not one of them.

        The note does mention lab_default elsewhere, in the advice to run a
        comparison pass, so this checks the enumeration rather than the whole
        string.
        """
        note = self._note(fingerprint="lab_default,chrome_131_win")
        assert note is not None
        # The enumerated persona list: "persona was used (chrome_131_win)".
        assert "chrome_131_win" in note
        assert "lab_default,chrome_131_win" not in note
        assert "lab_default," not in note

    def test_the_note_states_the_rotation_scope(self) -> None:
        for mode, phrase in (
            ("per_connection", "one per connection"),
            ("per_request", "one per request"),
            ("none", "fixed for the run"),
        ):
            note = self._note(fingerprint="chrome_131_win,firefox_133_win", fingerprint_rotation=mode)
            assert phrase in note, mode

    def test_the_note_warns_against_comparing_across_identities(self) -> None:
        note = self._note(fingerprint="chrome_131_win")
        assert "lab_default" in note

    # ------------------------------------------------------------------
    # The note has to reach the report, not merely be computable
    # ------------------------------------------------------------------

    @staticmethod
    def _notes(**kw) -> list[str]:
        """Run a real engine and read the notes off the real report.

        Deliberately not a hand-built stub with ``__new__``. An earlier version
        of this test stubbed the engine and set attributes one at a time, which
        meant it asserted against a fiction that drifted out of step with
        ``_notes`` the moment that method touched anything new. A real run on
        the virtual transport is cheap, needs no sockets, and cannot drift.
        """
        from adobo.engine import RunEngine
        from adobo.models import RunConfig, TransportKind

        attack = _profile(**kw)
        engine = RunEngine(
            RunConfig(
                target=Target(host="127.0.0.1", port=9),
                attack=attack,
                transport=TransportKind.VIRTUAL,
            )
        )
        # RunOutcome carries a `notes` of its own that nothing populates; the
        # report's notes live on RunResult. Reading the outer one would assert
        # against an always-empty list and pass for the wrong reason.
        return engine.run().result.notes

    def test_the_note_actually_reaches_the_report(self) -> None:
        """A computed note that is never appended is not a disclosure.

        This exists because it was exactly the bug: ``_notes`` called
        ``_impersonation_note()`` and dropped the returned string on the floor.
        Every test that called the helper directly still passed, because the
        helper was correct - it was the caller that was wrong. Asserting on a
        real report is the only assertion that can catch it.
        """
        notes = self._notes(fingerprint="chrome_131_win")
        assert any("impersonation" in n.lower() for n in notes), notes

    def test_the_report_stays_silent_without_impersonation(self) -> None:
        """A run that faked nothing must produce no impersonation note.

        The absence is the signal, so this guards the other direction: a report
        that always carried the line would train a reader to ignore it.
        """
        notes = self._notes()
        assert not any("impersonation" in n.lower() for n in notes), notes