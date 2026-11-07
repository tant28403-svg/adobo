"""Tests for the single-run summary.

The summary is where a run's numbers become a claim someone acts on, so the
question these cover is not "does it print" but "does what it print survive
being read by someone who did not run it".

The specific hazard: a headline count of packets the sender handed to the
operating system reads as a result of the test, when it is only a record of the
tester's effort. The target's own count is the only figure that says anything
about the target, and its *absence* has to be visible too - otherwise an
unmeasurable run and a devastating one are the same three lines of output.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout

from adobo.cli import summarise
from adobo.engine import RunEngine
from adobo.models import (
    AttackProfile,
    ProfileName,
    RunConfig,
    Target,
    TargetStats,
    TransportKind,
)


def _config(**kw) -> RunConfig:
    return RunConfig(
        target=Target(host="127.0.0.1", port=kw.pop("port", 9999)),
        attack=AttackProfile(
            profile=ProfileName.UDP_FLOOD,
            pps=kw.pop("pps", 1000),
            duration_seconds=kw.pop("duration", 0.2),
            payload_size=64,
            workers=1,
        ),
        transport=kw.pop("transport", TransportKind.VIRTUAL),
        **kw,
    )


def permitted_guard():
    """A guard with permissive ceilings, so these runs are not capped.

    These tests are about how a result is *worded*, so they need runs that
    happen at the values they set. Ceiling behaviour is covered in
    test_safety.py.
    """
    from adobo.config import LabConfig, LimitsConfig
    from adobo.safety import SafetyGuard

    return SafetyGuard(
        lab=LabConfig(
            limits=LimitsConfig(
                max_pps=10_000_000,
                max_duration_seconds=3600,
                max_payload_bytes=65_507,
                max_workers=1000,
            )
        )
    )


def _render(result) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        summarise(type("O", (), {"result": result, "cancelled": False})())
    return buffer.getvalue()


class TestSummaryWording:
    def test_the_headline_does_not_claim_delivery(self) -> None:
        """'sent' alone invites reading it as packets that arrived."""
        outcome = RunEngine(_config(), guard=permitted_guard()).run()
        output = _render(outcome.result)
        assert "sent to OS" in output

    def test_an_observed_target_shows_its_own_count(self) -> None:
        outcome = RunEngine(_config(), guard=permitted_guard()).run()
        result = outcome.result.model_copy(
            update={
                "target_stats": TargetStats(
                    requests_served=250, errors_served=3, stats_observed=True
                )
            }
        )
        output = _render(result)
        assert "target served 250 requests" in output
        assert "3 errors" in output

    def test_the_two_counts_are_reconciled(self) -> None:
        """Two numbers side by side invite the reader to treat them as equals.

        The sender's 1,000 and the target's 250 are not the same measurement, so
        the ratio between them is the actual finding.
        """
        outcome = RunEngine(_config(), guard=permitted_guard()).run()
        result = outcome.result.model_copy(
            update={
                "target_stats": TargetStats(
                    requests_served=250, stats_observed=True
                )
            }
        )
        output = _render(result)
        assert "25.0%" in output
        assert "reached the target" in output

    def test_an_unobserved_target_adds_no_delivery_claim(self) -> None:
        """A dry run or a virtual run has nothing to observe, so it says nothing."""
        outcome = RunEngine(_config(), guard=permitted_guard()).run()
        output = _render(outcome.result)
        assert "target served" not in output
        assert "delivery" not in output

    def test_a_low_ratio_is_explained(self) -> None:
        """Otherwise a mixed UDP/HTTP run always looks like a failing flood."""
        outcome = RunEngine(_config(), guard=permitted_guard()).run()
        result = outcome.result.model_copy(
            update={
                "target_stats": TargetStats(
                    requests_served=5, stats_observed=True
                )
            }
        )
        output = _render(result)
        assert "not counted there" in output

    def test_a_full_ratio_is_not_annotated_with_a_caveat(self) -> None:
        """The caveat is noise on a run that delivered everything it sent."""
        outcome = RunEngine(_config(), guard=permitted_guard()).run()
        sent = outcome.result.attack.packets_sent
        result = outcome.result.model_copy(
            update={
                "target_stats": TargetStats(
                    requests_served=sent,
                    stats_observed=True,
                )
            }
        )
        output = _render(result)
        assert "not counted there" not in output


class TestModeFlags:
    """The mode flags run and exit; two together must refuse, not pick one."""

    def test_two_mode_flags_are_refused_by_name(self, capsys) -> None:
        from adobo import cli

        code = cli.main(["--inspect-h2", "--nuclear"])
        assert code == cli.EXIT_ERROR
        out = capsys.readouterr().out
        assert "--inspect-h2" in out
        assert "cannot be combined" in out

    def test_a_single_mode_flag_still_runs(self, monkeypatch) -> None:
        """The exclusivity guard must not reject the flags it is protecting."""
        from adobo import cli

        captured: dict = {}
        monkeypatch.setattr(cli, "inspect_h2", lambda args: (captured.setdefault("ran", True), 0)[1])
        assert cli.main(["--inspect-h2"]) == 0
        assert captured["ran"] is True


class TestDryRun:
    """--dry-run prints what a run would do, and sends nothing.

    The flag existed below the CLI only: the engine's dry_run machinery ran
    workers-disabled and reported zero packets, which is a preview of nothing.
    A preview worth having names the resolved transport, the request a target
    would receive and the pool the egress would rotate through.
    """

    def test_the_preview_names_the_resolved_run(self, capsys) -> None:
        from adobo import cli

        code = cli.main(
            ["--host", "127.0.0.1", "--port", "8001", "--profile", "http_flood",
             "--method", "post", "--path", "/login", "--data", "a=1", "--dry-run"]
        )
        assert code == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "Dry run" in out
        assert "POST /login" in out
        assert "body: 3 bytes" in out
        assert "proxy" not in out.lower() or "proxies" not in out
        assert "no packet was sent" in out

    def test_the_preview_names_the_proxy_pool(self, capsys, tmp_path) -> None:
        from adobo import cli

        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("socks5://127.0.0.1:1080\n", encoding="utf-8")
        code = cli.main(
            ["--host", "127.0.0.1", "--profile", "http_flood",
             "--proxy-file", str(proxy_file), "--dry-run"]
        )
        assert code == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "proxies    1 from" in out
        assert "default scheme: http" in out

    def test_a_preview_needs_a_target(self, capsys) -> None:
        from adobo import cli

        code = cli.main(["--dry-run"])
        assert code == cli.EXIT_ERROR
        assert "--host" in capsys.readouterr().out


class TestDownloadWriteFailures:
    def test_an_unwritable_output_path_is_reported(self, capsys, tmp_path) -> None:
        from adobo.proxy_sources import download_proxies

        target = tmp_path / "no-such-dir" / "proxies.txt"
        code = download_proxies(
            "socks5", str(target), fetch=lambda url: "5.5.5.5:1080\n"
        )
        assert code == 1
        assert "Could not write" in capsys.readouterr().out
