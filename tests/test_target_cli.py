"""Tests for the lab target's entry point.

The target was, until this was wired up, the only part of the tool with no way
to run it. `run_target` and `TargetSettings` existed and were correct, and
nothing in the repository called them - no CLI flag, no `__main__`, no test. That
matters more than it sounds: the target's `/stats` counter is the *only*
independent evidence of delivery in the whole system. A run whose attacker side
is a virtual transport and whose target cannot be started produces no
falsifiable claim at all, because there is no counter to contradict it.

These cover the argument parsing and the delegation, not the HTTP behaviour,
which is exercised by the app's own test suite. What is being pinned down is
that the two ways of starting the target cannot drift apart, and that a typo in
a defense name fails loudly rather than quietly serving a baseline target that
looks like the defenses failed.
"""

from __future__ import annotations

import argparse
from typing import Sequence

import pytest

from adobo.cli import build_parser as build_attack_parser
from adobo.models import DefenseName
from adobo.target.__main__ import (
    ALL_DEFENSES,
    build_parser,
    main,
    parse_defenses,
    settings_from_args,
)


class TestParseDefenses:
    def test_none_is_the_baseline(self) -> None:
        """The default must be the unhardened target, not an empty accident."""
        assert parse_defenses("none") == []
        assert parse_defenses("") == []
        assert parse_defenses("  NONE  ") == []

    def test_all_enables_every_defense(self) -> None:
        assert parse_defenses("all") == list(ALL_DEFENSES)
        assert len(ALL_DEFENSES) == 5

    def test_a_single_defense_is_accepted(self) -> None:
        assert parse_defenses("waf") == [DefenseName.WAF]

    def test_a_list_is_accepted_in_any_order(self) -> None:
        assert parse_defenses("waf,rate_limit") == [
            DefenseName.WAF,
            DefenseName.RATE_LIMIT,
        ]

    def test_whitespace_and_case_are_forgiven(self) -> None:
        assert parse_defenses(" WAF , Rate_Limit ") == [
            DefenseName.WAF,
            DefenseName.RATE_LIMIT,
        ]

    def test_an_unknown_defense_exits_rather_than_being_ignored(self) -> None:
        """Silently dropping a bad name would serve a baseline target.

        The operator would ask for defenses, get none, watch the target fall
        over, and conclude the mitigations do not work. Failing here is the
        only outcome that cannot be misread.
        """
        with pytest.raises(SystemExit) as exc:
            parse_defenses("rate_limit,waff")
        assert "waff" in str(exc.value)
        # The message must name the valid options, or it is not actionable.
        assert "rate_limit" in str(exc.value)

    def test_none_anywhere_in_the_list_wins(self) -> None:
        """'none' is a statement about the whole target, not one item."""
        assert parse_defenses("waf,none") == []
        assert parse_defenses("none,waf") == []

    def test_trailing_commas_are_ignored(self) -> None:
        assert parse_defenses("waf,") == [DefenseName.WAF]


class TestSettingsFromArgs:
    def test_defaults_bind_loopback_on_8000(self) -> None:
        settings = settings_from_args(build_parser().parse_args([]))
        assert settings.host == "127.0.0.1"
        assert settings.port == 8000
        assert settings.active() == []

    def test_work_ms_is_only_forwarded_when_given(self) -> None:
        """Leaving it unset must not overwrite the tuned default with None."""
        default = settings_from_args(build_parser().parse_args([]))
        assert default.work_ms > 0

        explicit = settings_from_args(
            build_parser().parse_args(["--work-ms", "40"])
        )
        assert explicit.work_ms == 40

    def test_defenses_reach_the_settings_object(self) -> None:
        settings = settings_from_args(
            build_parser().parse_args(["--defenses", "all"])
        )
        assert set(settings.active()) == {d.value for d in ALL_DEFENSES}


class TestCliDelegation:
    def test_serve_target_is_a_flag_on_the_main_parser(self) -> None:
        """It has to be reachable from the same binary an operator already uses."""
        args = build_attack_parser().parse_args(["--serve-target"])
        assert args.serve_target is True

    def test_the_attack_port_default_is_unchanged(self) -> None:
        """--port still means 80 for an attack; only --serve-target moves it."""
        args = build_attack_parser().parse_args([])
        assert args.port is None  # None so the target can apply its own default

    def test_config_from_args_still_defaults_the_port_to_80(self) -> None:
        from adobo.cli import config_from_args

        config = config_from_args(
            build_attack_parser().parse_args(
                ["--host", "127.0.0.1", "--profile", "udp_flood", "--duration", "1"]
            )
        )
        assert config.target.port == 80

    def test_an_explicit_attack_port_is_respected(self) -> None:
        from adobo.cli import config_from_args

        config = config_from_args(
            build_attack_parser().parse_args(
                ["--host", "127.0.0.1", "--port", "9999", "--duration", "1"]
            )
        )
        assert config.target.port == 9999

    def test_serve_target_delegates_with_the_target_defaults(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`adobo --serve-target` must not force the attack path's port 80.

        Without this the flag tries to bind a privileged port and fails for a
        reason that has nothing to do with the target.
        """
        seen: dict[str, Sequence[str]] = {}

        def fake(argv: Sequence[str] | None = None) -> int:
            seen["argv"] = argv  # type: ignore[assignment]
            return 0

        monkeypatch.setattr("adobo.target.__main__.main", fake)

        from adobo.cli import main as cli_main

        assert cli_main(["--serve-target"]) == 0
        assert "--port" not in seen["argv"]
        assert "--defenses" in seen["argv"]

    def test_serve_target_forwards_an_explicit_port(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Sequence[str]] = {}

        def fake(argv: Sequence[str] | None = None) -> int:
            seen["argv"] = argv  # type: ignore[assignment]
            return 0

        monkeypatch.setattr("adobo.target.__main__.main", fake)

        from adobo.cli import main as cli_main

        cli_main(["--serve-target", "--port", "9100", "--defenses", "waf"])
        argv = list(seen["argv"])
        assert argv[argv.index("--port") + 1] == "9100"
        assert argv[argv.index("--defenses") + 1] == "waf"

    def test_serve_target_forwards_work_ms_only_when_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Sequence[str]] = {}

        def fake(argv: Sequence[str] | None = None) -> int:
            seen["argv"] = argv  # type: ignore[assignment]
            return 0

        monkeypatch.setattr("adobo.target.__main__.main", fake)

        from adobo.cli import main as cli_main

        cli_main(["--serve-target"])
        assert "--work-ms" not in seen["argv"]

        cli_main(["--serve-target", "--work-ms", "25"])
        argv = list(seen["argv"])
        assert argv[argv.index("--work-ms") + 1] == "25"

    def test_serve_target_never_reaches_the_wizard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--serve-target with no --host must serve, not launch the wizard.

        The wizard is the fallback for "no host given", and serving the target
        is also a no--host invocation. Without an early return the operator gets
        an interactive prompt instead of a target.
        """
        def explode(*a, **k):  # pragma: no cover - must never run
            raise AssertionError("wizard must not start for --serve-target")

        monkeypatch.setattr("adobo.cli.nuclear_wizard", explode)
        monkeypatch.setattr("adobo.target.__main__.main", lambda argv=None: 0)

        from adobo.cli import main as cli_main

        assert cli_main(["--serve-target"]) == 0

    def test_serve_target_reports_an_interrupt_as_130(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ctrl-C on a long-running server is an ordinary stop, not a crash."""
        def interrupt(*a, **k) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr("uvicorn.run", interrupt)

        assert main([]) == 130


class TestHttp2Serving:
    """--http2 on the target must actually reach uvicorn as an ALPN context.

    This is the regression test for a bug that hid in plain sight: the flag
    was parsed into TargetSettings and then never forwarded to run_target, and
    run_target's own ALPN context was passed through a ``ssl_context`` kwarg
    that uvicorn does not accept. Either defect alone made every h2 run
    against the lab target fail with "server offered None".
    """

    def _certs(self, tmp_path):
        from pathlib import Path

        from adobo.target.app import generate_self_signed_cert

        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        generate_self_signed_cert(cert, key, hostname="localhost")
        return cert, key

    def test_run_target_builds_an_alpn_context_when_http2_is_on(
        self, monkeypatch, tmp_path
    ) -> None:
        import ssl

        from adobo.target.app import TargetSettings, run_target

        cert, key = self._certs(tmp_path)
        captured: dict = {}
        monkeypatch.setattr("uvicorn.run", lambda **kwargs: captured.update(kwargs))
        run_target(
            TargetSettings(
                host="127.0.0.1", port=9123,
                ssl_certfile=str(cert), ssl_keyfile=str(key),
            ),
            http2=True,
        )
        assert "ssl_context" not in captured, "uvicorn has no such parameter"
        factory = captured.get("ssl_context_factory")
        assert factory is not None, "http2 must reach uvicorn as an ALPN context"
        context = factory(None, None)
        assert isinstance(context, ssl.SSLContext)
        assert "ssl_certfile" not in captured, "the context carries the chain itself"
        assert captured["http2"] is True, "uvicorn must select an h2-capable protocol"
        assert captured["http"] == "zttp", "uvicorn 0.54 gates h2 on the zttp class"

    def test_plain_tls_keeps_the_certfile_kwargs(self, monkeypatch, tmp_path) -> None:
        from adobo.target.app import TargetSettings, run_target

        cert, key = self._certs(tmp_path)
        captured: dict = {}
        monkeypatch.setattr("uvicorn.run", lambda **kwargs: captured.update(kwargs))
        run_target(
            TargetSettings(
                host="127.0.0.1", port=9123,
                ssl_certfile=str(cert), ssl_keyfile=str(key),
            ),
            http2=False,
        )
        assert captured["ssl_certfile"] == str(cert)
        assert "ssl_context_factory" not in captured

    def test_main_forwards_the_http2_setting(self, monkeypatch, tmp_path) -> None:
        import adobo.target.__main__ as target_main

        cert, key = self._certs(tmp_path)
        captured: dict = {}
        monkeypatch.setattr(
            target_main, "run_target",
            lambda settings, **kwargs: captured.update(kwargs),
        )
        target_main.main(
            ["--port", "9123", "--ssl-certfile", str(cert),
             "--ssl-keyfile", str(key), "--http2"]
        )
        assert captured.get("http2") is True

    def test_main_defaults_to_http2_off(self, monkeypatch) -> None:
        import adobo.target.__main__ as target_main

        captured: dict = {}
        monkeypatch.setattr(
            target_main, "run_target",
            lambda settings, **kwargs: captured.update(kwargs),
        )
        target_main.main(["--port", "9123"])
        assert captured.get("http2") is False
