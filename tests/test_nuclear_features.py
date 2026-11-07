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
    expect: int = 0,
    wizard_protocol: str = "tls-h2",
    quic_ok: bool = True,
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

    Both port probes are patched to "reachable" so the profile menu is the full
    built list in every test - without the TCP patch, the real probe finds
    nothing listening on 127.0.0.1:8123 and the menu silently shrinks.
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
    # The wizard asks the target what it speaks before the transport questions.
    # Patched, like the port probes: a real detection against 127.0.0.1:8123
    # would refuse, mute the h2/h3/TLS questions and shift every answer down.
    # "tls-h2" is the verdict that keeps the shipped question flow.
    monkeypatch.setattr(
        nuclear, "detect_target_protocol", lambda host, port, timeout=2.0: wizard_protocol
    )
    # The h3 answer now triggers one real QUIC handshake; patched like the
    # probes so a scripted strike never touches the network. Only consulted
    # when the script answers yes to h3.
    monkeypatch.setattr(
        nuclear, "quic_reachable", lambda host, port, timeout=3.0: quic_ok
    )
    # True means the reflector port reads as closed, which makes the wizard skip
    # those profiles outright rather than stopping to ask whether to continue
    # with no reflector. Which profiles exist is not what these tests are about.
    monkeypatch.setattr(nuclear, "probe_udp_port", lambda host, port: True)
    monkeypatch.setattr(nuclear, "probe_tcp_port", lambda host, port: True)

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
    assert nuclear.nuclear_wizard(**(presets or {})) == expect
    return captured


def _proxy_for(_path):
    from adobo.proxies import parse_proxy

    return parse_proxy("127.0.0.1:8888")


class TestTheWizardIsDriven:
    #: host, port, pps, duration, http2?, personas, rotation, proxy, keep-alive,
    #: tls, workers, payload, spoof, profiles
    BASE = {
        "host": "127.0.0.1", "port": "8123", "pps": "100", "duration": "2",
        "http3": "n", "http2": "n", "concurrency": "100", "personas": "",
        "rotation": "", "preamble": "", "proxy": "", "http_host": "",
        "keep_alive": "n", "tls": "n", "verify": "y", "workers": "4",
        "payload": "512", "spoof": "n", "profiles": "",
    }

    #: Order the wizard asks in. `concurrency` and `preamble` only appear when
    #: http2 is on, `rotation` only when a persona was given, http2 is not asked
    #: at all when http3 is, and `verify` appears whenever the strike will speak
    #: TLS at all - so the script is derived from the answers rather than being a
    #: fixed list. A fixed list desynchronises the moment a question is skipped and
    #: then silently answers the wrong prompt, which is how these tests failed
    #: several times before the order was read off the wizard rather than guessed.
    #:
    #: `workers` sits between `verify` and `payload`, and is only *asked* when
    #: lab.yaml leaves max_workers unset - the shipped default, and the
    #: repository ships no lab.yaml. With a ceiling configured the wizard
    #: prints the capped value instead of prompting, capped at the 800 hard
    #: ceiling a configured-but-higher max_workers can never lift. The ask
    #: itself is bounded (like payload), so an over-ceiling answer re-asks
    #: within the question - tested below by splicing in the retry. It was
    #: added to the wizard after these scripts were written, and every test in
    #: this class failed with answers fed to the wrong prompt until the order
    #: was re-read off the wizard.
    #:
    #: `http_host` sits between `proxy` and `keep_alive`; it is asked on every
    #: strike (blank = none), so no conditional is needed for it.
    #:
    #: `profiles` is the last question: it is asked after build_profiles, the
    #: privilege drop and the port filter, because the menu lists what the
    #: strike could actually run. Blank means every available profile.
    ORDER = [
        "host", "port", "pps", "duration", "http3", "http2", "concurrency",
        "personas", "rotation", "preamble", "proxy", "http_host", "keep_alive",
        "tls", "verify", "workers", "payload", "spoof", "profiles",
    ]

    def _with(self, *, omit: tuple = (), protocol: str = "tls-h2", **replacements) -> list[str]:
        """Answers the wizard will read back, one per question it asks.

        *protocol* is the verdict the wizard's target probe is patched to
        return, and it decides which questions exist at all - the same way
        http3/http2 decisions do, below.
        """
        values = dict(self.BASE)
        values.update(replacements)
        # plain has no TLS-capable port in play, so no HTTP-transport question
        # can be honoured: h3 omitted, h2 omitted, and with them the follow-ups.
        http3_asked = protocol != "plain"
        http3_enabled = http3_asked and values["http3"] == "y"
        # Asked and enabled are different questions. HTTP/2 is offered whenever
        # HTTP/3 was declined - but only when the target negotiated h2 (or the
        # probe stayed silent), and only *enabled* when the answer is yes - and
        # only then are the concurrency and preamble follow-ups asked at all.
        http2_asked = protocol in ("tls-h2", "unknown") and not http3_enabled
        http2_on = http2_asked and values["http2"] == "y"
        # The TLS dialogue (and the verify question riding it) exists whenever
        # the strike could speak TLS at all; a plaintext target drops the pair.
        # The "Use TLS" question itself is skipped when h3 is on - QUIC is TLS
        # by definition - but verify is still asked, because it guards the h3
        # handshake too.
        tls_dialogue = protocol != "plain"
        tls_asked = tls_dialogue and not http3_enabled
        verify_asked = tls_dialogue
        asked = [
            key
            for key in self.ORDER
            if key not in omit
            and not (key == "http3" and not http3_asked)
            and not (key == "http2" and not http2_asked)
            and not (key in ("concurrency", "preamble") and not http2_on)
            and not (key == "rotation" and not values["personas"])
            and not (key == "tls" and not tls_asked)
            and not (key == "verify" and not verify_asked)
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

    def test_http2_asks_about_certificate_verification(
        self, monkeypatch, tmp_path
    ) -> None:
        """HTTP/2 here always goes through TLS, so the verify choice applies.

        rapid_reset rides HTTP/2 whether or not HTTP/2 was chosen for http_flood,
        so a strike can speak TLS without having answered yes to anything. The
        verify question is what lets that operator say no to verification.
        """
        captured = _scripted_wizard(
            monkeypatch, self._with(http2="y", verify="n"), tmp_path
        )
        assert captured["tls_verify"] is False

    def test_a_plain_strike_is_still_asked_about_verification(
        self, monkeypatch, tmp_path
    ) -> None:
        """Because every strike now speaks TLS, via rapid_reset.

        Gating this question on use_tls or use_http2 left the tool silently
        choosing "verify" for a profile the operator was never asked about, and a
        strike against a self-signed target failed at the handshake with nothing
        to change. The default stays Yes, so pressing Enter keeps the old
        behaviour.
        """
        captured = _scripted_wizard(monkeypatch, self._with(), tmp_path)
        assert captured["tls_verify"] is True

    def test_a_flagged_data_file_reaches_the_strike(
        self, monkeypatch, tmp_path
    ) -> None:
        """--data-file must reach the strike's children.

        The nuclear branch builds its own profiles and never calls
        config_from_args, so a body file read only there was silently ignored
        and the strike sent GET while the operator watched for POSTs. The
        resolution now happens in the branch itself; this drives cli.main the
        way an operator would.
        """
        import adobo.cli as cli_module
        import adobo.nuclear as nuclear

        body_file = tmp_path / "body.json"
        body_file.write_text('{"a": 1}', encoding="utf-8")

        captured: dict = {}
        lines = list(self._with())

        def _input(*_a, **_k):
            if not lines:
                raise AssertionError("the wizard asked more questions than the script")
            return lines.pop(0)

        monkeypatch.setattr("builtins.input", _input)
        monkeypatch.setattr(nuclear, "check_privileges", lambda: (True, True))
        monkeypatch.setattr(nuclear, "check_child_raw_capability", lambda: (True, ""))
        monkeypatch.setattr(
            nuclear,
            "detect_target_protocol",
            lambda host, port, timeout=2.0: "tls-h2",
        )
        monkeypatch.setattr(nuclear, "probe_udp_port", lambda host, port: True)

        class _Aggregator:
            def __init__(self, **kw):
                captured.update(kw)

            def run(self):
                return 0

        monkeypatch.setattr(nuclear, "NuclearAggregator", _Aggregator)
        exit_code = cli_module.main(
            ["--nuclear", "--method", "post", "--data-file", str(body_file)]
        )
        assert exit_code == 0
        assert captured["http_body"] == '{"a": 1}'
        assert captured["http_method"] == "post"

    def test_the_verify_answer_reaches_the_children(self, monkeypatch, tmp_path) -> None:
        """Declining it has to actually reach each child's AttackProfile."""
        captured = _scripted_wizard(
            monkeypatch, self._with(verify="n"), tmp_path
        )
        assert captured["tls_verify"] is False
        aggregator = NuclearAggregator(
            profiles=captured["profiles"],
            target_ip="127.0.0.1",
            pps=100,
            duration=1.0,
            tls_verify=captured["tls_verify"],
        )
        configs = aggregator._build_configs()
        assert all(c.attack.tls_verify is False for c in configs)

    def test_a_worker_answer_over_the_ceiling_re_asks(
        self, monkeypatch, tmp_path
    ) -> None:
        """The workers ask is bounded, so 900 is refused and 800 is taken.

        The retry lives inside the same prompt (like the payload ask), so the
        script needs two answers in the workers slot - hence the positional
        splice rather than `_with`, which models each question as one answer.
        """
        script = self._with(workers="@@WORKERS@@")
        slot = script.index("@@WORKERS@@")
        script[slot : slot + 1] = ["900", "800"]
        captured = _scripted_wizard(monkeypatch, script, tmp_path)
        assert captured["workers"] == 800

    def test_a_worker_answer_at_the_ceiling_needs_no_retry(
        self, monkeypatch, tmp_path
    ) -> None:
        """800 is accepted on the first answer; the script stays one-per-question."""
        captured = _scripted_wizard(
            monkeypatch, self._with(workers="800"), tmp_path
        )
        assert captured["workers"] == 800

    # -- profile selection --------------------------------------------------

    def test_a_blank_selection_runs_every_available_profile(
        self, monkeypatch, tmp_path
    ) -> None:
        """Blank keeps the historical strike: every profile that survived the
        privilege and port filters runs."""
        blank = _scripted_wizard(monkeypatch, self._with(), tmp_path)
        everything = _scripted_wizard(
            monkeypatch, self._with(), tmp_path, presets={"selected_profiles": "all"}
        )
        assert blank["profiles"] == everything["profiles"]
        assert len(blank["profiles"]) >= 1

    def test_a_preset_selection_reaches_the_strike(self, monkeypatch, tmp_path) -> None:
        captured = _scripted_wizard(
            monkeypatch, self._with(), tmp_path,
            presets={"selected_profiles": "udp_flood"},
        )
        names = [p.name for p in captured["profiles"]]
        assert names == ["udp_flood"]

    def test_numbers_select_by_menu_position(self, monkeypatch, tmp_path) -> None:
        """The menu is numbered; selecting by number must resolve to the same
        profile the operator read off the screen."""
        menu = _scripted_wizard(monkeypatch, self._with(), tmp_path)["profiles"]
        first_name = menu[0].name
        last_name = menu[-1].name

        by_number = _scripted_wizard(
            monkeypatch, self._with(), tmp_path, presets={"selected_profiles": "1"}
        )
        assert [p.name for p in by_number["profiles"]] == [first_name]

        mixed = _scripted_wizard(
            monkeypatch, self._with(), tmp_path,
            presets={"selected_profiles": f"1,{last_name}"},
        )
        assert [p.name for p in mixed["profiles"]] == [first_name, last_name]

    def test_an_unknown_preset_aborts_naming_the_valid_set(
        self, monkeypatch, tmp_path, capsys
    ) -> None:
        """A preset that silently ran everything instead of the requested
        subset is the one failure mode worse than an error here."""
        captured = _scripted_wizard(
            monkeypatch, self._with(), tmp_path,
            presets={"selected_profiles": "nope"}, expect=1,
        )
        assert captured == {}, "no aggregator may be built for a refused preset"
        out = capsys.readouterr().out
        assert "unknown profile" in out
        assert "valid for this strike" in out

    def test_an_interactive_typo_re_asks_and_blank_then_runs_all(
        self, monkeypatch, tmp_path
    ) -> None:
        """Interactive validation is a re-ask, not an abort: the operator
        typos, sees the valid names, and pressing Enter still means all."""
        answers = self._with(profiles="nope") + [""]
        captured = _scripted_wizard(monkeypatch, answers, tmp_path)
        everything = _scripted_wizard(
            monkeypatch, self._with(), tmp_path, presets={"selected_profiles": "all"}
        )
        assert captured["profiles"] == everything["profiles"]

    def test_a_selection_only_warns_about_selected_reflectors(
        self, monkeypatch, tmp_path, capsys
    ) -> None:
        """The reflector warnings run after the selection, so deselecting an
        amplification profile means no 'Continue DNS anyway?' for it.

        The probe here reads as CLOSED for every UDP port: the connectionless
        amplification profiles survive the filter anyway, and the warning loop
        would ask about each one that is still selected - so a strike whose
        selection contains none of them must reach the aggregator with no
        reflector questions at all.
        """
        import adobo.nuclear as nuclear

        captured: dict = {}
        lines = list(self._with())

        def _input(*_a, **_k):
            if not lines:
                raise AssertionError("the wizard asked more questions than the script")
            return lines.pop(0)

        monkeypatch.setattr("builtins.input", _input)
        monkeypatch.setattr(nuclear, "check_privileges", lambda: (True, True))
        monkeypatch.setattr(nuclear, "check_child_raw_capability", lambda: (True, ""))
        monkeypatch.setattr(
            nuclear,
            "detect_target_protocol",
            lambda host, port, timeout=2.0: "tls-h2",
        )
        monkeypatch.setattr(nuclear, "probe_udp_port", lambda host, port: False)
        monkeypatch.setattr(nuclear, "probe_tcp_port", lambda host, port: True)

        def _load(path):
            return [_proxy_for(path)]

        monkeypatch.setattr(nuclear, "load_proxies", _load)

        class _Aggregator:
            def __init__(self, **kw):
                captured.update(kw)

            def run(self):
                return 0

        monkeypatch.setattr(nuclear, "NuclearAggregator", _Aggregator)

        assert nuclear.nuclear_wizard(selected_profiles="udp_flood") == 0
        assert [p.name for p in captured["profiles"]] == ["udp_flood"]
        out = capsys.readouterr().out
        assert "Continue DNS amplification anyway?" not in out
        assert "Continue NTP amplification anyway?" not in out


# ---------------------------------------------------------------------------
# The wizard learns what the target speaks
# ---------------------------------------------------------------------------


class TestTheWizardKnowsWhatTheTargetSpeaks(TestTheWizardIsDriven):
    """The transport questions are gated on the target, not just on itself.

    The regression that produced this: an operator typing a plaintext website's
    IP on port 80 was offered HTTP/3, HTTP/2 and rapid_reset - every one of
    which rides TLS and could only burn its connect timeout on that port - and
    watched a strike hand zero packets to the OS for the entire duration while
    every row read [RUNNING] or [ERROR] and availability read 0% "probed".

    The verdict is the same kind of fact as the privilege and port filters: a
    menu that lists a profile that cannot run is misleading in exactly the way
    those filters exist to prevent.
    """

    def test_a_plain_target_skips_the_transport_questions(
        self, monkeypatch, tmp_path
    ) -> None:
        captured = _scripted_wizard(
            monkeypatch, self._with(protocol="plain"), tmp_path, wizard_protocol="plain"
        )
        assert captured["use_http3"] is False
        assert captured["use_http2"] is False
        assert captured["tls_verify"] is True  # defaulted, not asked
        # http_flood exists and rides the one transport that can speak plain.
        names = {p.name: p for p in captured["profiles"]}
        from adobo.models import TransportKind

        assert "http_flood" in names
        assert names["http_flood"].transport is TransportKind.SOCKET

    def test_a_plain_target_drops_rapid_reset_before_the_menu(
        self, monkeypatch, tmp_path
    ) -> None:
        """Dropped before selection: blank = all must not include it."""
        captured = _scripted_wizard(
            monkeypatch, self._with(protocol="plain"), tmp_path, wizard_protocol="plain"
        )
        names = [p.name for p in captured["profiles"]]
        assert "http_flood" in names
        assert "rapid_reset" not in names

    def test_a_preset_naming_rapid_reset_on_a_plain_target_aborts(
        self, monkeypatch, tmp_path, capsys
    ) -> None:
        """The honest failure mode for a flag: abort naming the valid list.

        Silently running without the named profile would shorten the strike
        without saying so; running everything else and claiming it matched
        would be worse.
        """
        captured = _scripted_wizard(
            monkeypatch,
            self._with(protocol="plain", profiles="rapid_reset"),
            tmp_path,
            presets={"selected_profiles": "rapid_reset"},
            expect=1,
            wizard_protocol="plain",
        )
        out = capsys.readouterr().out
        assert "unknown profile(s): rapid_reset" in out
        assert "http_flood" in out  # the valid list is printed
        assert captured == {}  # nothing ran

    def test_an_open_tls_port_on_443_offers_the_switch(
        self, monkeypatch, tmp_path
    ) -> None:
        """The wizard's suggestion, not an override: declining keeps port N.

        Detection on the typed port says plain; the same detection on 443 says
        tls-h2, so the wizard offers to switch. Accepting re-derives the
        questions on the TLS port - these answers say yes - and every
        TCP-addressing profile is built on 443.
        """
        import adobo.nuclear as nuclear

        captured: dict = {}
        lines = list(self._with(protocol="tls-h2"))
        lines.insert(2, "y")  # the switch offer, right after the port answer

        def _input(*_a, **_k):
            if not lines:
                raise AssertionError("the wizard asked more questions than the script")
            return lines.pop(0)

        monkeypatch.setattr("builtins.input", _input)
        monkeypatch.setattr(nuclear, "check_privileges", lambda: (True, True))
        monkeypatch.setattr(nuclear, "check_child_raw_capability", lambda: (True, ""))

        def _detect(host, port, timeout=2.0):
            return "tls-h2" if port == 443 else "plain"

        monkeypatch.setattr(nuclear, "detect_target_protocol", _detect)
        monkeypatch.setattr(nuclear, "probe_udp_port", lambda host, port: True)
        monkeypatch.setattr(nuclear, "probe_tcp_port", lambda host, port: True)

        class _Aggregator:
            def __init__(self, **kw):
                captured.update(kw)

            def run(self):
                return 0

        monkeypatch.setattr(nuclear, "NuclearAggregator", _Aggregator)
        assert nuclear.nuclear_wizard() == 0
        names = {p.name: p for p in captured["profiles"]}
        assert names["http_flood"].port == 443
        assert "rapid_reset" in names

    def test_declining_the_switch_keeps_the_plain_flow(
        self, monkeypatch, tmp_path
    ) -> None:
        """No is a decision, not a failure: plain questions, plain profiles."""
        import adobo.nuclear as nuclear

        lines = list(self._with(protocol="plain"))
        lines.insert(2, "n")  # decline the switch offer

        captured: dict = {}

        def _input(*_a, **_k):
            if not lines:
                raise AssertionError("the wizard asked more questions than the script")
            return lines.pop(0)

        monkeypatch.setattr("builtins.input", _input)
        monkeypatch.setattr(nuclear, "check_privileges", lambda: (True, True))
        monkeypatch.setattr(nuclear, "check_child_raw_capability", lambda: (True, ""))

        def _detect(host, port, timeout=2.0):
            return "tls-h2" if port == 443 else "plain"

        monkeypatch.setattr(nuclear, "detect_target_protocol", _detect)
        monkeypatch.setattr(nuclear, "probe_udp_port", lambda host, port: True)
        monkeypatch.setattr(nuclear, "probe_tcp_port", lambda host, port: True)

        class _Aggregator:
            def __init__(self, **kw):
                captured.update(kw)

            def run(self):
                return 0

        monkeypatch.setattr(nuclear, "NuclearAggregator", _Aggregator)
        assert nuclear.nuclear_wizard() == 0
        names = {p.name: p for p in captured["profiles"]}
        # The port the operator typed stands.
        assert names["http_flood"].port == 8123
        assert "rapid_reset" not in names

    def test_an_unknown_verdict_asks_everything_as_before(
        self, monkeypatch, tmp_path
    ) -> None:
        """A probe that proves nothing changes no question and drops nothing."""
        captured = _scripted_wizard(
            monkeypatch, self._with(protocol="unknown"), tmp_path, wizard_protocol="unknown"
        )
        names = [p.name for p in captured["profiles"]]
        assert "rapid_reset" in names

    def test_a_quic_that_never_answers_falls_back_to_http1(
        self, monkeypatch, tmp_path
    ) -> None:
        """The h3 'yes' is tested against the target before it can cost a run.

        The QUIC handshake check sits between the h3 question and the next, and
        a target that stays silent gets the fallback question - answering yes
        (the default) converts the strike to HTTP/1.1 rather than running 30
        workers into five-second timeouts apiece.
        """
        # Splice in the answers the fallback branch adds. The harness models
        # the kept-h3 branch, where h2 and the TLS question are never asked;
        # once h3 falls back, both re-open - the h2 question right after the
        # fallback prompt, and the TLS question between keep-alive and verify.
        script = self._with(http3="y")
        i = script.index("y")  # the http3 answer ("verify" is the only other "y")
        script[i + 1 : i + 1] = ["", "n"]  # fallback: Enter (default yes); h2: no
        v = script.index("y", i + 1)  # the verify answer
        script.insert(v, "n")  # the re-opened TLS question: no
        captured = _scripted_wizard(
            monkeypatch, script, tmp_path, quic_ok=False
        )
        assert captured["use_http3"] is False
        assert captured["use_http2"] is False
        assert captured["use_tls"] is False
        # The strike still runs: http_flood on the socket transport.
        from adobo.models import TransportKind

        names = {p.name: p for p in captured["profiles"]}
        assert names["http_flood"].transport is TransportKind.SOCKET

    def test_a_quic_that_answers_keeps_h3_without_a_fallback_question(
        self, monkeypatch, tmp_path
    ) -> None:
        """A target that answers QUIC keeps the h3 choice, no extra prompt."""
        captured = _scripted_wizard(
            monkeypatch, self._with(http3="y"), tmp_path, quic_ok=True
        )
        assert captured["use_http3"] is True

    def test_the_tls_question_is_skipped_when_h3_is_chosen(
        self, monkeypatch, tmp_path
    ) -> None:
        """QUIC is TLS by definition; the 'n' answer could do nothing anyway.

        The script keeps its verify answer (h3 still verifies), but the
        "Use TLS/HTTPS" slot disappears from the question order.
        """
        script = self._with(http3="y")
        captured = _scripted_wizard(monkeypatch, script, tmp_path)
        assert captured["use_http3"] is True
        assert captured["tls_verify"] is True  # verify still asked and answered


class TestTheParentProberCountsAnswers:
    """A 403 is the target answering, not the target being absent.

    The parent prober used to raise on any non-2xx, so a CDN edge that
    redirected every IP-addressed request (308) or a WAF that answered 403
    read as "0% availability, none was refused" - the opposite of what the
    transcript showed. These tests pin the new contract at both layers:
    alive() returns True for any HTTP response, and the aggregator tallies
    the statuses it was answered with.
    """

    @staticmethod
    def _observer_with(exc: Exception | None) -> Any:
        from adobo.observation import TargetObserver

        async def _fetch(timeout: float | None = None) -> dict:
            if exc is not None:
                raise exc
            return {"requests": 1, "errors": 0}

        return TargetObserver("127.0.0.1", 1, fetch=_fetch)

    def test_a_403_answer_counts_as_answered(self) -> None:
        import asyncio

        import httpx

        request = httpx.Request("GET", "https://127.0.0.1:1/stats")
        response = httpx.Response(403, request=request)
        observer = self._observer_with(httpx.HTTPStatusError(
            "Client error '403 Forbidden'", request=request, response=response
        ))
        assert asyncio.run(observer.alive(0.5)) is True
        assert observer.last_probe_error == "HTTP 403"

    def test_a_timeout_is_still_a_failure(self) -> None:
        import asyncio

        observer = self._observer_with(TimeoutError("no answer"))
        assert asyncio.run(observer.alive(0.5)) is False
        assert "TimeoutError" in (observer.last_probe_error or "")

    def test_an_answer_success_clears_the_reason(self) -> None:
        import asyncio

        observer = self._observer_with(None)
        assert asyncio.run(observer.alive(0.5)) is True
        assert observer.last_probe_error is None

    def test_the_aggregator_tallies_answer_statuses(self, monkeypatch) -> None:
        """ok probes answered with 4xx land in the status tally, not failures."""
        import adobo.nuclear as nuclear
        from adobo.models import ProfileName, TransportKind

        profile = nuclear.NuclearProfile(
            name="http_flood",
            profile=ProfileName.HTTP_FLOOD,
            transport=TransportKind.SOCKET,
            port=80,
            spoof=False,
            requires_admin=False,
        )
        aggregator = nuclear.NuclearAggregator(
            profiles=[profile], target_ip="127.0.0.1", pps=1, duration=1.0
        )

        class _StubObserver:
            last_probe_error = "HTTP 403"

            async def alive(self, timeout: float | None = None) -> bool:
                # Async because the prober drives it through asyncio.run;
                # a sync stub answered True into a TypeError that the
                # accommodating except swallowed as a failed sample.
                return True

        aggregator._observer = _StubObserver()
        monkeypatch.setattr(nuclear, "PARENT_PROBE_ENABLED", True)
        aggregator._probe_target()
        assert aggregator._probe_ok == 1
        assert aggregator._probe_status_counts == {"HTTP 403": 1}
        assert aggregator._probe_failures == {}


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

    def test_a_blank_answer_takes_the_yes_no_default(self, monkeypatch) -> None:
        """Enter on a '[y/N]' prompt must mean the advertised default.

        It did not: _ask(None) treats blank as "keep asking", so every yes/no
        question re-asked on Enter - and a scripted blank answer silently
        consumed a second question's slot. The suffix promised a default the
        code never honoured.
        """
        from adobo.nuclear import _ask_yes_no

        monkeypatch.setattr("adobo.nuclear._ask", lambda *a, **k: "")
        assert _ask_yes_no("x", default=True) is True
        assert _ask_yes_no("x", default=False) is False

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