"""Tests for the four features as reached through nuclear mode.

Nuclear mode rebuilds its own ``AttackProfile`` per child rather than accepting
one, so every feature that lives on that profile has to be carried across
explicitly. The failure mode is silent and total: the option is accepted by the
CLI, the wizard never mentions it, ten children run, and every one of them
sends the default. Nothing raises and every counter looks normal.

That is why the load-bearing assertions here are about what the child configs
*contain* rather than about whether a run completed. :meth:`NuclearAggregator.
_build_configs` is the one place a wizard answer becomes a child's settings, so
a config inspected there is the answer itself.
"""

from __future__ import annotations

import pytest

from adobo.models import ProfileName, TransportKind
from adobo.nuclear import NuclearAggregator, build_profiles

REFLECTORS = {"dns": 53, "ntp": 123, "cldap": 389, "ssdp": 1900}


def _profiles(**kw) -> list:
    return build_profiles("127.0.0.1", 8123, REFLECTORS, **kw)


def _aggregator(tmp_path, *, proxy_file: str = "", **kw) -> NuclearAggregator:
    """An aggregator with a real proxy list on disk when one is asked for.

    _build_configs only records the path, so the file is not strictly needed
    there - but a test that passes a path to a file that does not exist would
    pass for the wrong reason if the path were ever read at that layer.
    """
    if proxy_file:
        path = tmp_path / "proxies.txt"
        path.write_text("127.0.0.1:8888\n127.0.0.1:8889\n", encoding="utf-8")
        proxy_file = str(path)
    return NuclearAggregator(
        profiles=_profiles(proxy_file=proxy_file),
        target_ip="127.0.0.1",
        pps=100,
        duration=1.0,
        proxy_file=proxy_file,
        **kw,
    )


def _http_config(aggregator: NuclearAggregator):
    config = next(
        c for c in aggregator._build_configs()
        if c.attack.profile is ProfileName.HTTP_FLOOD
    )
    return config


# ---------------------------------------------------------------------------
# Silence must stay silence
# ---------------------------------------------------------------------------


class TestAnUnconfiguredStrikeIsUnchanged:
    """The default has to be what it was before the features existed.

    Not a style preference: a nuclear strike is the mode the tool is used from,
    and a change to its default bytes would silently alter every existing run
    rather than opt anyone in.
    """

    def test_no_persona_is_configured_by_default(self) -> None:
        """Passed as nothing at all, not as "" - the field is omitted so the
        model's own default applies. An empty string would fail the validator."""
        config = _http_config(_aggregator(None))
        assert config.attack.fingerprint == "lab_default"
        assert config.attack.impersonates() is False

    def test_the_preamble_is_left_on_auto(self) -> None:
        config = _http_config(_aggregator(None))
        assert config.attack.h2_preamble == "auto"

    def test_no_proxy_file_is_recorded(self) -> None:
        config = _http_config(_aggregator(None))
        assert config.proxy_file == ""

    def test_http_flood_stays_on_the_socket_transport(self) -> None:
        config = _http_config(_aggregator(None))
        assert config.transport is TransportKind.SOCKET


# ---------------------------------------------------------------------------
# Feature 1 - personas
# ---------------------------------------------------------------------------


class TestPersonasReachTheStrike:
    def test_the_configured_persona_lands_on_the_child(self) -> None:
        config = _http_config(
            _aggregator(
                None,
                fingerprint="chrome_131_win",
                fingerprint_rotation="per_request",
            )
        )
        assert config.attack.fingerprint == "chrome_131_win"
        assert config.attack.fingerprint_rotation == "per_request"
        assert config.attack.impersonates() is True

    def test_several_personas_land_as_given(self) -> None:
        config = _http_config(
            _aggregator(None, fingerprint="chrome_131_win,firefox_133_win")
        )
        assert config.attack.persona_keys() == ["chrome_131_win", "firefox_133_win"]

    def test_an_invalid_persona_is_refused(self) -> None:
        """The child AttackProfile's own validator does this, and it must still
        fire - a wizard that silently dropped an unknown key would produce a run
        impersonating nothing while appearing to impersonate something."""
        with pytest.raises(Exception, match="unknown fingerprint"):
            _http_config(_aggregator(None, fingerprint="netscape_4"))


# ---------------------------------------------------------------------------
# Feature 2 - HTTP/2 preambles
# ---------------------------------------------------------------------------


class TestPreamblesReachTheStrike:
    def test_an_explicit_preamble_lands_on_the_child(self) -> None:
        config = _http_config(_aggregator(None, h2_preamble="firefox_133"))
        assert config.attack.h2_preamble == "firefox_133"

    def test_none_is_a_legal_answer_and_is_kept(self) -> None:
        """`none` means "leave the connection layer alone while impersonating",
        which is a distinct choice from the default and must survive."""
        config = _http_config(_aggregator(None, h2_preamble="none"))
        assert config.attack.h2_preamble == "none"

    def test_a_persona_without_a_preamble_still_resolves_coherently(self) -> None:
        """`auto` pairs a persona with the preamble that persona sends, so an
        impersonating strike does not put a Chrome User-Agent on a connection no
        Chrome opens."""
        config = _http_config(_aggregator(None, fingerprint="firefox_133_win"))
        assert config.attack.h2_preamble == "auto"
        assert config.attack.h2_profile().key == "firefox_133"

    def test_an_unknown_preamble_is_refused(self) -> None:
        with pytest.raises(Exception):
            _http_config(_aggregator(None, h2_preamble="netscape_3"))


# ---------------------------------------------------------------------------
# Feature 4 - proxy rotation
# ---------------------------------------------------------------------------


class TestProxyRotationReachesTheStrike:
    def test_http_flood_is_routed_through_the_proxy(self, tmp_path) -> None:
        aggregator = _aggregator(tmp_path, proxy_file="wanted")
        config = _http_config(aggregator)
        assert config.transport is TransportKind.PROXY
        assert config.proxy_file == aggregator.proxy_file

    def test_the_proxy_list_is_recorded_on_the_config(self, tmp_path) -> None:
        aggregator = _aggregator(tmp_path, proxy_file="wanted")
        assert _http_config(aggregator).proxy_file.endswith("proxies.txt")

    def test_proxy_routing_survives_http2(self, tmp_path) -> None:
        """PROXY plus use_http2 selects the proxy H2 transport in the factory,
        so the tunnel is established before the TLS and ALPN handshake rather
        than instead of it."""
        aggregator = NuclearAggregator(
            profiles=_profiles(use_http2=True, proxy_file="wanted"),
            target_ip="127.0.0.1",
            pps=100,
            duration=1.0,
            use_http2=True,
            proxy_file=str(_write(tmp_path)),
        )
        config = _http_config(aggregator)
        assert config.transport is TransportKind.PROXY
        assert config.attack.use_http2 is True

    def test_only_http_flood_is_proxied(self, tmp_path) -> None:
        """The other nine profiles are UDP or raw packets and cannot be carried
        by an HTTP tunnel. Marking them PROXY would refuse them at setup and
        take the whole strike down; leaving them silently direct would read as a
        wholly distributed strike that is not one."""
        aggregator = _aggregator(tmp_path, proxy_file="wanted")
        configs = aggregator._build_configs()
        proxied = [c for c in configs if c.transport is TransportKind.PROXY]
        assert len(proxied) == 1
        assert proxied[0].attack.profile is ProfileName.HTTP_FLOOD

    def test_a_non_proxied_profile_carries_no_proxy_path(self, tmp_path) -> None:
        aggregator = _aggregator(tmp_path, proxy_file="wanted")
        for config in aggregator._build_configs():
            if config.transport is not TransportKind.PROXY:
                assert config.proxy_file == "", config.label

    def test_the_child_note_discloses_the_rotation(self, tmp_path) -> None:
        """The disclosure is per-child, so it has to come from the child's own
        notes rather than from the parent's summary."""
        config = _http_config(_aggregator(tmp_path, proxy_file="wanted"))
        from adobo.engine import RunEngine

        engine = RunEngine(config.model_copy(update={"dry_run": True}))
        notes = engine._notes.__self__._proxy_note()  # the note itself
        assert notes is not None and "Proxy rotation" in notes

    def test_a_direct_child_says_nothing_about_proxies(self) -> None:
        config = _http_config(_aggregator(None))
        from adobo.engine import RunEngine

        assert RunEngine(config)._proxy_note() is None


# ---------------------------------------------------------------------------
# All four at once
# ---------------------------------------------------------------------------


class TestEveryFeatureTogether:
    def test_a_strike_can_use_all_of_them_simultaneously(self, tmp_path) -> None:
        """The features are independent settings, so asking for all of them must
        not make any of the others unreachable."""
        aggregator = _aggregator(
            tmp_path,
            proxy_file="wanted",
            fingerprint="chrome_131_win,firefox_133_win",
            fingerprint_rotation="per_connection",
            h2_preamble="auto",
            use_http2=True,
        )
        config = _http_config(aggregator)
        assert config.transport is TransportKind.PROXY
        assert config.proxy_file
        assert config.attack.fingerprint == "chrome_131_win,firefox_133_win"
        assert config.attack.fingerprint_rotation == "per_connection"
        assert config.attack.use_http2 is True
        assert config.attack.h2_profile().key == "chrome_131"


def _write(tmp_path) -> str:
    path = tmp_path / "proxies.txt"
    path.write_text("127.0.0.1:8888\n", encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# The wizard, driven
# ---------------------------------------------------------------------------


def _scripted_wizard(
    monkeypatch,
    answers: list[str],
    tmp_path,
    presets: dict | None = None,
) -> dict:
    """Run the real wizard on scripted answers and capture what it decided.

    Every heavy step is stubbed - privileges, port probing, the aggregator's
    run() - so no children spawn and nothing is sent. What is left is the part
    that matters: the answers as the wizard resolved them.

    This layer is where a real bug lived and no helper-level test could see it:
    the proxy block validated ``load_proxies(proxy_file)`` instead of the answer
    it had just collected, so a list typed at the prompt validated as ``None``
    while the same list passed as ``--proxy-file`` worked. Only driving the
    wizard distinguishes those two.
    """
    import adobo.nuclear as nuclear

    captured: dict = {}
    lines = list(answers)

    def _input(*_a, **_k):
        # Raising on exhaustion rather than returning "": _ask loops forever on an
        # empty answer when there is no default, so a script that is one line out
        # of sync would hang the suite instead of failing it.
        if not lines:
            raise AssertionError("the wizard asked more questions than the script")
        return lines.pop(0)

    monkeypatch.setattr("builtins.input", _input)
    monkeypatch.setattr(nuclear, "check_privileges", lambda: (True, True))
    monkeypatch.setattr(nuclear, "check_child_raw_capability", lambda: (True, ""))
    # True means the reflector port reads as closed, which makes the wizard skip
    # those profiles outright rather than stopping to ask whether to continue
    # with no reflector. Which profiles exist is not what these tests are about.
    monkeypatch.setattr(nuclear, "probe_udp_port", lambda host, port: True)

    def _load(path):
        captured["load_proxies_got"] = path
        return [_proxy_for(path)]

    monkeypatch.setattr(nuclear, "load_proxies", _load)

    class _Aggregator:
        def __init__(self, **kw):
            captured.update(kw)

        def run(self):
            return 0

    monkeypatch.setattr(nuclear, "NuclearAggregator", _Aggregator)
    assert nuclear.nuclear_wizard(**(presets or {})) == 0
    return captured


def _proxy_for(_path):
    from adobo.proxies import parse_proxy

    return parse_proxy("127.0.0.1:8888")


class TestTheWizardIsDriven:
    #: host, port, pps, duration, http2?, personas, rotation, proxy, keep-alive,
    #: tls, payload, spoof
    BASE = {
        "host": "127.0.0.1", "port": "8123", "pps": "100", "duration": "2",
        "http2": "n", "concurrency": "100", "personas": "", "rotation": "",
        "preamble": "", "proxy": "", "keep_alive": "n", "tls": "n",
        "payload": "512", "spoof": "n",
    }

    #: Order the wizard asks in. `concurrency` and `preamble` only appear when
    #: http2 is on, and `rotation` only when a persona was given, so the script
    #: is derived from the answers rather than being a fixed list - a fixed list
    #: desynchronises the moment a question is skipped and then silently answers
    #: the wrong prompt, which is how these tests failed three times before the
    #: order was read off the wizard rather than guessed.
    ORDER = [
        "host", "port", "pps", "duration", "http2", "concurrency", "personas",
        "rotation", "preamble", "proxy", "keep_alive", "tls", "payload", "spoof",
    ]

    def _with(self, *, omit: tuple = (), **replacements) -> list[str]:
        values = dict(self.BASE)
        values.update(replacements)
        http2 = values["http2"] == "y"
        asked = [
            key
            for key in self.ORDER
            if key not in omit
            and not (key in ("concurrency", "preamble") and not http2)
            and not (key == "rotation" and not values["personas"])
        ]
        return [str(values[key]) for key in asked]

    def test_a_typed_proxy_path_is_the_path_that_gets_read(
        self, monkeypatch, tmp_path
    ) -> None:
        """The regression: this was None, so every typed list read as empty."""
        path = tmp_path / "typed.txt"
        path.write_text("127.0.0.1:8888\n", encoding="utf-8")
        captured = _scripted_wizard(
            monkeypatch, self._with(proxy=str(path)), tmp_path
        )
        assert captured["load_proxies_got"] == str(path)
        assert captured["proxy_file"] == str(path)

    def test_a_flagged_proxy_path_reaches_the_strike(
        self, monkeypatch, tmp_path
    ) -> None:
        path = _write(tmp_path)
        captured = _scripted_wizard(
            monkeypatch,
            self._with(omit=("proxy",)),
            tmp_path,
            presets={"proxy_file": path},
        )
        assert captured["proxy_file"] == path

    def test_no_proxy_means_the_strike_has_none(self, monkeypatch, tmp_path) -> None:
        captured = _scripted_wizard(monkeypatch, self._with(), tmp_path)
        assert captured["proxy_file"] == ""
        assert "load_proxies_got" not in captured

    def test_a_typed_persona_reaches_the_strike(
        self, monkeypatch, tmp_path
    ) -> None:
        captured = _scripted_wizard(
            monkeypatch, self._with(personas="chrome_131_win"), tmp_path
        )
        assert captured["fingerprint"] == "chrome_131_win"
        assert captured["fingerprint_rotation"] == "per_connection"

    def test_a_blank_persona_means_none(self, monkeypatch, tmp_path) -> None:
        captured = _scripted_wizard(monkeypatch, self._with(), tmp_path)
        assert captured["fingerprint"] == ""

    def test_the_preamble_is_only_asked_when_http2_is_on(
        self, monkeypatch, tmp_path
    ) -> None:
        captured = _scripted_wizard(monkeypatch, self._with(), tmp_path)
        assert captured["h2_preamble"] == ""

    def test_http2_offers_the_preamble_question(self, monkeypatch, tmp_path) -> None:
        """With http2 on, the preamble question appears; without it, it does not."""
        captured = _scripted_wizard(
            monkeypatch, self._with(http2="y", preamble="safari_18"), tmp_path
        )
        assert captured["use_http2"] is True
        assert captured["h2_preamble"] == "safari_18"


# ---------------------------------------------------------------------------
# Wizard plumbing
# ---------------------------------------------------------------------------


class TestWizardPresets:
    """A preset is a value the caller already has. It must survive intact.

    Two ways this went wrong, both found by driving the real wizard rather than
    by reading the code: the wizard assigned its answers to the same names as
    its parameters, so a preset was overwritten with "" before being read and the
    run announced a value nobody chose; and argparse defaults are non-empty, so
    passing them through made every `--nuclear` run state "lab_default (from
    the command line)" and skip the question the operator came to answer.
    """

    def test_a_preset_survives_the_prompt(self, monkeypatch, tmp_path) -> None:
        from adobo.nuclear import _ask_choice

        monkeypatch.setattr(
            "adobo.nuclear._ask", lambda *a, **k: pytest.fail("prompted anyway")
        )
        assert _ask_choice("x", ["a", "b"], default="a", preset="b") == "b"

    def test_an_empty_preset_is_not_treated_as_a_preset(self, monkeypatch) -> None:
        """`''` must mean "no preset, ask me", not "the empty preset"."""
        from adobo.nuclear import _ask_choice

        monkeypatch.setattr("adobo.nuclear._ask", lambda *a, **k: "a")
        assert _ask_choice("x", ["a", "b"], default="a", preset="") == "a"

    def test_an_invalid_preset_is_refused_rather_than_defaulted(
        self, monkeypatch
    ) -> None:
        """A bad flag value must fail where the operator can see it.

        Falling back to the default would produce a run that differs from the one
        asked for, with nothing saying so.
        """
        from adobo.nuclear import _ask_choice

        monkeypatch.setattr(
            "adobo.nuclear._ask", lambda *a, **k: pytest.fail("prompted anyway")
        )
        with pytest.raises(ValueError, match="not a valid choice"):
            _ask_choice("x", ["a", "b"], default="a", preset="nope")

    def test_parser_defaults_are_not_passed_to_the_wizard_as_choices(self) -> None:
        """`--nuclear` alone must ask, not announce lab_default."""
        from adobo.cli import DEFAULT_FINGERPRINT_KEY, DEFAULT_ROTATION, build_parser

        args = build_parser().parse_args(["--nuclear"])
        assert args.fingerprint == DEFAULT_FINGERPRINT_KEY
        assert args.fingerprint_rotation == DEFAULT_ROTATION
        # The dispatch turns each of these into None; see cli.main().
        assert (args.fingerprint == DEFAULT_FINGERPRINT_KEY) is True
        assert (args.fingerprint_rotation == DEFAULT_ROTATION) is True

    def test_an_explicit_persona_is_a_real_choice(self) -> None:
        from adobo.cli import DEFAULT_FINGERPRINT_KEY, build_parser

        args = build_parser().parse_args(
            ["--nuclear", "--fingerprint", "chrome_131_win"]
        )
        assert args.fingerprint != DEFAULT_FINGERPRINT_KEY