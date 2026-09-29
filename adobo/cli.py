"""Minimal CLI entry point for UDP stress testing."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Sequence

from pyfiglet import Figlet

from .engine import EngineHooks, RunEngine, RunOutcome
from .models import AttackProfile, ProfileName, RunConfig, Target, TransportKind
from .nuclear import nuclear_wizard
from .safety import PolicyViolation, SafetyGuard
from .wizard import wizard

__all__ = ["main"]

EXIT_OK = 0
EXIT_INTERRUPTED = 130
EXIT_ERROR = 1


def _print_banner() -> None:
    if sys.platform == "linux":
        f = Figlet(font="standard")
        print(f.renderText("ADOBO"), flush=True)


def _say(message: str = "") -> None:
    print(message, flush=True)


def make_progress(quiet: bool = False):
    interactive = sys.stdout.isatty() and not quiet
    state = {"last": 0.0}

    def report(snapshot) -> None:
        now = time.monotonic()
        amp = getattr(snapshot, 'amplification_factor', None)
        amp_text = f"  amp={amp:.1f}x" if amp else ""
        text = (
            f"  t={snapshot.elapsed:6.1f}s  "
            f"pps={snapshot.achieved_pps():>10,.0f}  "
            f"sent={snapshot.counters.sent:>10,}  "
            f"avail={snapshot.availability_pct():6.1f}%"
            f"{amp_text}"
        )
        if interactive:
            print(f"\r{text}", end="", flush=True)
        elif now - state["last"] >= 1.0:
            state["last"] = now
            _say(text)

    def finish() -> None:
        if interactive:
            print(flush=True)

    return report, finish


def summarise(outcome: RunOutcome) -> None:
    result = outcome.result
    _say("\n=== Result ===")
    if result.score.grade == "N/A":
        _say(f"  resilience   n/a (no probes)")
    else:
        _say(f"  resilience   {result.score.total:.1f} / 100  (grade {result.score.grade})")
    _say(f"  sent to OS   {result.attack.packets_sent:,} packets ({result.attack.bytes_sent:,} bytes)")
    _say(f"  throughput   {result.attack.achieved_pps:,.0f} pps")
    amp = getattr(result.attack, 'amplification_factor', None)
    if amp:
        _say(f"  amplification {amp:.1f}x")
    if result.probe.total:
        _say(f"  availability {result.probe.availability_pct:.1f}% over {result.probe.total} probes (p95 {result.probe.latency.p95_ms:.0f}ms)")
    _print_target_evidence(result)
    _print_notes(result.notes)


def _print_target_evidence(result) -> None:
    """Show what the target itself counted, or say that it is unknown.

    "sent" is the sender grading itself. It counts what it handed to the
    operating system and cannot tell "the target served it" from "the target
    refused it" from "the host is down" - all three look identical from here. So
    when the target was readable, its own count is printed next to the sender's,
    and the two are reconciled rather than presented side by side as equals.

    The absence of evidence is stated explicitly. Leaving it out would let a run
    with no measurement read exactly like a run against an unresponsive target.
    """
    stats = result.target_stats
    if not stats.stats_observed:
        # Not an error and not worth a note: dry runs, virtual transports and
        # non-HTTP targets cannot be observed this way, and the run's own notes
        # already explain the ones that matter.
        return
    _say(
        f"  target served {stats.requests_served:,} requests "
        f"({stats.errors_served:,} errors)"
    )
    sent = result.attack.packets_sent
    if sent:
        share = stats.requests_served / sent
        _say(
            f"  delivery     {share:.1%} of packets sent reached the target"
        )
        if share < 0.5:
            _say(
                "               (only the HTTP profile reaches an HTTP"
                " endpoint; UDP and raw"
            )
            _say(
                "                traffic is not counted there, so a mixed run"
                " reads low)"
            )


def _print_notes(notes: Sequence[str]) -> None:
    """Show the caveats that decide whether the numbers above mean anything.

    A run that sent nothing because the transport never opened prints the same
    three headline lines as a successful run - all zeros, no explanation. The
    notes are the only thing that separates "the target ignored us" from "we
    never sent anything", so they are not optional output.
    """
    if not notes:
        return
    _say("\n  Notes:")
    for note in notes:
        _say(f"    - {note}")


# Profiles that require raw sockets (scapy transport) and Admin+Npcap
SCAPY_REQUIRED_PROFILES = {
    "syn_flood", "icmp_flood", "ack_flood",
    "dns_amplification", "ntp_amplification", "cldap_amplification", "ssdp_amplification",
}

# Profiles that use linux_raw transport (non-spoofed variants)
LINUX_RAW_PROFILES = {
    "syn_flood_ns", "icmp_flood_ns", "ack_flood_ns", "udp_flood_ns",
}

# Profiles that use amplification and should auto-enable spoofing
AMPLIFICATION_PROFILES = {
    "dns_amplification", "ntp_amplification", "cldap_amplification", "ssdp_amplification",
}

ALL_PROFILES = sorted({
    "udp_flood", "udp_flood_ns", "syn_flood", "syn_flood_ns",
    "icmp_flood", "icmp_flood_ns", "ack_flood", "ack_flood_ns",
    "dns_amplification", "ntp_amplification", "cldap_amplification", "ssdp_amplification",
    "http_flood", "slowloris",
})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ADOBO",
        description="ADOBO - Network Stress Tester",
    )
    parser.add_argument("--host", help="target IP")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=(
            "target port (default: 80, or 8000 under --serve-target). Left as "
            "None rather than 80 so --serve-target can tell 'not given' from "
            "'given as 80' and apply its own default"
        ),
    )
    parser.add_argument("--profile", choices=ALL_PROFILES, default="udp_flood", help="attack profile (default: udp_flood)")
    parser.add_argument("--pps", type=int, default=5000, help="packets per second (default: 5000)")
    parser.add_argument("--duration", type=float, default=10.0, help="duration in seconds (default: 10)")
    parser.add_argument("--transport", choices=["socket", "scapy", "linux_raw", "virtual", "h2"], default="auto", help="transport type (default: auto)")
    parser.add_argument("--payload", type=int, default=512, help="payload size in bytes (default: 512)")
    parser.add_argument("--workers", type=int, default=4, help="worker threads (default: 4)")
    parser.add_argument("--spoof-sources", action="store_true", help="spoof source IP (requires --transport scapy + Admin)")
    parser.add_argument(
        "--keep-alive",
        action="store_true",
        help="Reuse HTTP connections for http_flood (higher throughput; delivery may overcount if target closes connections)",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Use TLS/HTTPS for http_flood (auto-enabled on port 443)",
    )
    parser.add_argument(
        "--tls-no-verify",
        action="store_true",
        help="Disable TLS certificate verification (lab only; implies --tls)",
    )
    parser.add_argument(
        "--http2",
        action="store_true",
        help="Use HTTP/2 for http_flood (auto-enabled on port 443; requires h2 library)",
    )
    parser.add_argument(
        "--h2-concurrency",
        type=int,
        default=100,
        help="Number of concurrent HTTP/2 streams per connection (default: 100)",
    )
    parser.add_argument(
        "--nuclear",
        action="store_true",
        help="run the interactive nuclear wizard instead of a single profile",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    parser.add_argument(
        "--serve-target",
        action="store_true",
        help=(
            "serve the lab target instead of attacking anything: a deliberately "
            "fragile HTTP service with /healthz, /stats and /api/data, so a run "
            "has something to measure a result against"
        ),
    )
    parser.add_argument(
        "--defenses",
        default="none",
        help=(
            "mitigations for --serve-target, comma-separated or 'all'/'none' "
            "(default: none, i.e. the unhardened baseline)"
        ),
    )
    parser.add_argument(
        "--work-ms",
        type=int,
        default=None,
        help="simulated database work per /api/data request, in ms (--serve-target)",
    )
    return parser


def config_from_args(args: argparse.Namespace) -> RunConfig:
    profile = ProfileName(args.profile)

    # Auto-select transport
    transport = args.transport
    if transport == "auto":
        if args.profile in SCAPY_REQUIRED_PROFILES:
            transport = "scapy"
        elif args.profile in LINUX_RAW_PROFILES:
            transport = "linux_raw"
        else:
            transport = "socket"

    # Auto-enable spoofing for amplification profiles
    spoof_sources = args.spoof_sources
    if not spoof_sources and args.profile in AMPLIFICATION_PROFILES:
        spoof_sources = True

    # Auto-enable TLS on common HTTPS ports
    HTTPS_PORTS = {443, 8443, 8080, 9443, 8000, 8888}
    use_tls = args.tls
    if not use_tls and args.port in HTTPS_PORTS:
        use_tls = True
    if args.tls_no_verify:
        use_tls = True

    # HTTP/2 must be explicitly requested; do not auto-enable based on port
    # because the socket transport doesn't support HTTP/2
    use_http2 = args.http2

    # Clamp before the model sees the values. AttackProfile refuses anything
    # over 65,507 bytes, so a --payload of 1900000 raised a pydantic
    # ValidationError here - before any policy was consulted and with no
    # mention of the 1,400-byte ceiling. Clamping the raw arguments first turns
    # a crash into a value the policy allows plus a note saying it was reduced.
    guard = SafetyGuard()
    fields, policy_notes = guard.clamp_fields(
        pps=args.pps,
        duration_seconds=args.duration,
        payload_size=args.payload,
        workers=args.workers,
        h2_concurrency=args.h2_concurrency,
    )
    if policy_notes:
        print("Ceiling adjustments from lab.yaml:")
        for note in policy_notes:
            print(f"  {note}")

    return RunConfig(
        target=Target(host=args.host, port=args.port if args.port is not None else 80),
        attack=AttackProfile(
            profile=profile,
            pps=fields["pps"],
            duration_seconds=fields["duration_seconds"],
            payload_size=fields["payload_size"],
            workers=fields["workers"],
            spoof_sources=spoof_sources,
            keep_alive=args.keep_alive,
            use_tls=use_tls,
            tls_verify=not args.tls_no_verify,
            use_http2=use_http2,
            h2_concurrency=fields["h2_concurrency"],
        ),
        transport=TransportKind(transport),
        defenses=[],
        label="cli run",
    )


def run_once(config: RunConfig, quiet: bool = False) -> int:
    report, finish = make_progress(quiet=quiet)
    hooks = EngineHooks(on_tick=report)
    engine = RunEngine(config, hooks=hooks)

    try:
        outcome = engine.run()
    except KeyboardInterrupt:
        _say("\nInterrupted.")
        return EXIT_INTERRUPTED
    except PolicyViolation as exc:
        # A refusal is a result, not a crash. Someone refusing to send traffic
        # is the tool working, and it should read as a decision rather than a
        # traceback the operator has to decode.
        _say("\n[!] Refused: not authorised to run this test")
        _say(f"    {exc}")
        return EXIT_ERROR
    finally:
        finish()

    summarise(outcome)
    return outcome.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    _print_banner()
    parser = build_parser()
    args = parser.parse_args(argv)

    # Serving the target is the other half of the tool, and it is a different job
    # from attacking: nothing here is a flood, so the wizard and the run engine
    # must not be reached. Delegating rather than reimplementing keeps
    # `adobo --serve-target` and `python -m adobo.target` on one code path.
    if args.serve_target:
        from .target.__main__ import main as target_main

        return target_main(
            [
                "--host", args.host or "127.0.0.1",
                # Only forwarded when given, so the target's own default of 8000
                # survives instead of being overridden by the attack path's 80.
                *(["--port", str(args.port)] if args.port is not None else []),
                "--defenses", args.defenses,
                *(["--work-ms", str(args.work_ms)] if args.work_ms is not None else []),
            ]
        )

    # Nuclear mode with no --host, or when asked for explicitly. The wizard is
    # interactive, so it reads stdin; a Ctrl-C inside it is a normal way to back
    # out and is handled here rather than left to escape as a traceback.
    if args.nuclear or not args.host:
        try:
            exit_code = nuclear_wizard()
        except KeyboardInterrupt:
            # Same code as an interrupted run, so a caller can treat "the
            # operator stopped this" as one condition however it was stopped.
            _say("\nCancelled.")
            return EXIT_INTERRUPTED
        try:
            if sys.stdin.isatty():
                input("\nPress Enter to exit...")
        except EOFError:
            pass
        return exit_code

    config = config_from_args(args)
    exit_code = run_once(config, quiet=args.quiet)
    try:
        if sys.stdin.isatty():
            input("\nPress Enter to exit...")
    except EOFError:
        pass
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
