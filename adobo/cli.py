"""Minimal CLI entry point for UDP stress testing."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Sequence

try:  # Optional: banner rendering only. Termux/lean installs may not have it.
    from pyfiglet import Figlet
except ImportError:  # pragma: no cover - optional dependency
    Figlet = None

from .engine import EngineHooks, RunEngine, RunOutcome
from .fingerprint import DEFAULT_FINGERPRINT_KEY
from .models import AttackProfile, ProfileName, RunConfig, Target, TransportKind
from pydantic import ValidationError

DEFAULT_ROTATION = "per_connection"
"""Parser default for --fingerprint-rotation, named so nuclear mode can tell an
unset flag from a deliberate ``--fingerprint-rotation per_connection``."""
from .nuclear import nuclear_wizard
from .safety import PolicyViolation, SafetyGuard

__all__ = ["main"]

EXIT_OK = 0
EXIT_INTERRUPTED = 130
EXIT_ERROR = 1


def _print_banner() -> None:
    if sys.platform == "linux" and Figlet is not None:
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

# Profiles that require an HTTP/2 transport. rapid_reset is here because it is
# the same protocol as http_flood - only the frame after HEADERS differs - so it
# needs the h2 transport rather than a socket one.
H2_REQUIRED_PROFILES = {
    "rapid_reset",
}

# Profiles that use amplification and should auto-enable spoofing
AMPLIFICATION_PROFILES = {
    "dns_amplification", "ntp_amplification", "cldap_amplification", "ssdp_amplification",
}

ALL_PROFILES = sorted({
    "udp_flood", "udp_flood_ns", "syn_flood", "syn_flood_ns",
    "icmp_flood", "icmp_flood_ns", "ack_flood", "ack_flood_ns",
    "dns_amplification", "ntp_amplification", "cldap_amplification", "ssdp_amplification",
    "http_flood", "slowloris", "rapid_reset",
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
    parser.add_argument("--transport", choices=["socket", "scapy", "linux_raw", "virtual", "h2", "h3", "proxy"], default="auto", help="transport type (default: auto)")
    parser.add_argument("--payload", type=int, default=512, help="payload size in bytes (default: 512)")
    parser.add_argument("--workers", type=int, default=4, help="worker threads (default: 4)")
    parser.add_argument("--spoof-sources", action="store_true", help="spoof source IP (requires --transport scapy + Admin)")
    parser.add_argument(
        "--proxy-file",
        metavar="PATH",
        default="",
        help=(
            "Proxy list for --transport proxy: one per line as "
            "[scheme://][user:pass@]host:port. Scheme prefixes: http://, "
            "socks4://, socks5://; bare host:port lines follow "
            "--proxy-default-scheme. Rotates per connection, so without "
            "--keep-alive that is one proxy per request. TCP profiles only."
        ),
    )
    parser.add_argument(
        "--proxy-default-scheme",
        choices=["http", "socks4", "socks5"],
        dest="proxy_default_scheme",
        default="http",
        help=(
            "scheme assumed for proxy-list lines without a scheme:// prefix "
            "(default: http). Tags a whole downloaded SOCKS list without "
            "rewriting it; an explicit prefix in the file always wins"
        ),
    )
    parser.add_argument(
        "--download-proxies",
        action="store_true",
        help=(
            "download public proxy lists, merge, dedupe and write them to "
            "--proxy-file (default: proxies.txt), then exit. List management, "
            "not a run: no --host needed"
        ),
    )
    parser.add_argument(
        "--proxy-kind",
        choices=["all", "http", "socks4", "socks5"],
        default="all",
        help="which protocols --download-proxies fetches (default: all)",
    )
    parser.add_argument(
        "--check-proxies",
        action="store_true",
        help=(
            "test every proxy in --proxy-file by tunnelling to a reachability "
            "probe, then exit. Writes the survivors to a new file - the input "
            "is never overwritten"
        ),
    )
    parser.add_argument(
        "--check-output",
        metavar="PATH",
        default="",
        help="where --check-proxies writes the verified list (default: <input>-checked.txt)",
    )
    parser.add_argument(
        "--encrypt-proxies",
        action="store_true",
        help=(
            "Encrypt proxies.txt into proxies.enc using a password. "
            "The encrypted file can be stored safely; the original proxies.txt "
            "is not deleted."
        ),
    )
    parser.add_argument(
        "--proxy-password",
        default="",
        help=(
            "Password for decrypting an encrypted proxy file. "
            "If not provided and the file is encrypted, you will be prompted. "
            "Passing on the command line is visible in process lists."
        ),
    )
    parser.add_argument(
        "--keep-alive",
        action="store_true",
        help="Reuse HTTP connections for http_flood (higher throughput; delivery may overcount if target closes connections)",
    )
    parser.add_argument(
        "--method",
        choices=["get", "post", "head"],
        default="get",
        help=(
            "HTTP verb for http_flood (default: get). Applies to the HTTP/1.1 "
            "transports (socket and proxy); a post body needs --data or --data-file"
        ),
    )
    parser.add_argument(
        "--path",
        dest="http_path",
        default="/api/data",
        help=(
            "request path for http_flood (default: /api/data). Must start with "
            "'/' and be percent-encoded - no raw spaces or control characters"
        ),
    )
    parser.add_argument(
        "--cookie",
        default="",
        help=(
            "Cookie header value for http_flood, e.g. 'id=xxx; session=yyy'. "
            "Omitted from the request when empty"
        ),
    )
    parser.add_argument(
        "--referer",
        default="",
        help="Referer header value for http_flood (omitted from the request when empty)",
    )
    parser.add_argument(
        "--data",
        default="",
        help="request body for --method post, e.g. 'a=1&b=2' (requires --method post)",
    )
    parser.add_argument(
        "--data-file",
        dest="data_file",
        default="",
        help=(
            "read the --method post body from a file, e.g. --data-file data.json "
            "(overrides --data)"
        ),
    )
    parser.add_argument(
        "--content-type",
        dest="content_type",
        default="application/x-www-form-urlencoded",
        help="Content-Type for a --method post body (default: application/x-www-form-urlencoded)",
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
        "--http3",
        action="store_true",
        help=(
            "Use HTTP/3 over QUIC for http_flood (requires the aioquic package and "
            "a target that speaks h3). Selects --transport h3, and reports no "
            "received-bytes figure because UDP is not acknowledged."
        ),
    )
    parser.add_argument(
        "--h2-concurrency",
        type=int,
        default=100,
        help="Number of concurrent HTTP/2 streams per connection (default: 100)",
    )
    parser.add_argument(
        "--fingerprint",
        default=DEFAULT_FINGERPRINT_KEY,
        help=(
            "client identity to present for http_flood/slowloris; comma-separated "
            "to rotate through several. One of: lab_default (self-identifying, "
            "the default), chrome_131_win, chrome_131_mac, firefox_133_win, "
            "firefox_133_linux, safari_18_mac"
        ),
    )
    parser.add_argument(
        "--fingerprint-rotation",
        choices=["none", "per_request", "per_connection"],
        default=DEFAULT_ROTATION,
        help=(
            "when to change persona (default: per_connection). A persona belongs "
            "to a connection, so per_connection is the realistic default; "
            "per_request requires per-request connections to be meaningful"
        ),
    )
    parser.add_argument(
        "--inspect-h2",
        action="store_true",
        help=(
            "measure this run's HTTP/2 connection preamble and exit: sends it to a "
            "loopback listener, decodes the frames back, and prints declared vs "
            "observed side by side. Honours --fingerprint and --h2-preamble, and "
            "sends nothing to the target"
        ),
    )
    parser.add_argument(
        "--nuclear",
        action="store_true",
        help="run the interactive nuclear wizard instead of a single profile",
    )
    parser.add_argument(
        "--profiles",
        default="",
        help=(
            "with --nuclear: comma-separated profiles the strike runs (names "
            "as in the wizard menu, e.g. 'dns_amplification,http_flood'). "
            "Blank or 'all' runs every applicable profile"
        ),
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "resolve the configuration and print exactly what a run would do - "
            "transport, request shape, proxy pool, TLS - then exit. No packet "
            "is sent; needs --host"
        ),
    )
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
        "--reflector",
        action="store_true",
        help=(
            "with --serve-target: also start the UDP reflectors (DNS, NTP, "
            "CLDAP, SSDP on their well-known ports) so amplification profiles "
            "can be measured end to end"
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
        "--h2-preamble",
        default="auto",
        help=(
            "HTTP/2 connection preamble to send: auto (default, follow "
            "--fingerprint), none (leave h2's defaults), or one of: "
            "h2_library, chrome_131, firefox_133, safari_18. Sets the SETTINGS "
            "frame, the connection window update and the pseudo-header order; only "
            "affects --transport h2 and --http2. Changes how much of a browser's "
            "connection layer is reproduced -- 'adobo --inspect-h2' measures it"
        ),
    )
    parser.add_argument(
        "--work-ms",
        type=int,
        default=None,
        help="simulated database work per /api/data request, in ms (--serve-target)",
    )
    return parser


def inspect_h2(args: argparse.Namespace) -> int:
    """Measure the configured HTTP/2 preamble and print declared vs observed.

    Reached from :func:`main` before any run machinery. Resolves the profile
    through the same :meth:`AttackProfile.h2_profile` a real run uses, so what is
    measured here is what a run would send - not a parallel path that could drift
    from the shipping one.
    """
    from .h2inspect import inspect_profile, render_inspection

    attack = AttackProfile(
        profile=ProfileName(args.profile),
        fingerprint=args.fingerprint,
        fingerprint_rotation=args.fingerprint_rotation,
        h2_preamble=args.h2_preamble,
    )
    _say()
    _say(f"persona: {attack.fingerprint}   preamble: {attack.h2_preamble}")
    _say()
    for line in render_inspection(inspect_profile(attack.h2_profile())):
        _say(line)
    _say()
    return EXIT_OK


def _resolve_body(args: argparse.Namespace) -> tuple[str, str]:
    """ ``(body, error)``: the request body from ``--data`` or ``--data-file``.

    An empty error string means success. Reading happens in one helper rather
    than only in the single-profile path because the nuclear branch forwards
    the body too: a ``--data-file`` that only ``config_from_args`` read made a
    nuclear strike silently send GET while the operator watched for POSTs.
    """
    body = getattr(args, "data", "") or ""
    data_file = getattr(args, "data_file", "") or ""
    if data_file:
        from pathlib import Path

        try:
            body = Path(data_file).read_text(encoding="utf-8")
        except OSError as exc:
            # A missing body file is an operator mistake with an obvious fix,
            # not a traceback situation: name the flag, the path and the reason.
            return "", f"could not read --data-file {data_file}: {exc}"
    return body, ""


def config_from_args(args: argparse.Namespace) -> RunConfig:
    profile = ProfileName(args.profile)

    # Read once with a default, because callers that build a Namespace by hand
    # (and several tests do) predate this flag and have no such attribute.
    proxy_file = getattr(args, "proxy_file", "") or ""
    proxy_default_scheme = (
        getattr(args, "proxy_default_scheme", "http") or "http"
    )

    # Auto-select transport
    transport = args.transport
    if transport == "auto":
        # A proxy list is an explicit request to distribute, so it wins over the
        # profile-driven choice below. Otherwise `udp_flood --proxy-file` would
        # silently pick scapy - which cannot be proxied at all - and the operator
        # would get a raw-socket flood from their own address while believing it
        # was routed through their list.
        if proxy_file:
            transport = "proxy"
        elif args.profile in H2_REQUIRED_PROFILES:
            # rapid_reset is HTTP/2-only, so falling through to "socket" would
            # hand it to a transport that cannot speak h2 and fail at the profile
            # check with a message about the wrong thing.
            transport = "h2"
        elif args.profile in SCAPY_REQUIRED_PROFILES:
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
    # HTTP/3 is a different transport rather than a flag on the socket one: it
    # cannot be reached by rewriting a request, and it needs its own package.
    if getattr(args, "http3", False) and transport == "auto":
        transport = "h3"

    # Request-shape flags for http_flood. getattr with defaults because callers
    # that build a Namespace by hand (and several tests do) predate these flags
    # and have no such attribute - the same reason proxy_file is read this way.
    http_method = getattr(args, "method", "get") or "get"
    http_path = getattr(args, "http_path", "/api/data") or "/api/data"
    cookie_header = getattr(args, "cookie", "") or ""
    referer = getattr(args, "referer", "") or ""
    content_type = (
        getattr(args, "content_type", "") or "application/x-www-form-urlencoded"
    )
    body, body_error = _resolve_body(args)
    if body_error:
        print(f"[!] {body_error}")
        raise SystemExit(EXIT_ERROR)

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

    try:
        attack = AttackProfile(
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
            fingerprint=args.fingerprint,
            fingerprint_rotation=args.fingerprint_rotation,
            h2_preamble=args.h2_preamble,
            http_method=http_method,
            http_path=http_path,
            cookie_header=cookie_header,
            referer=referer,
            http_body=body,
            content_type=content_type,
        )
    except ValidationError as exc:
        # A refused configuration is an operator mistake with an obvious fix,
        # not a crash: name each bad field and its reason and stop. Raising the
        # raw pydantic error printed a traceback that buried the one line that
        # mattered - "cookie_header: header values must not contain control
        # characters" - under the construction site's stack.
        print("[!] Invalid run configuration:")
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"]) or "config"
            print(f"    {location}: {error['msg']}")
        raise SystemExit(EXIT_ERROR) from None

    return RunConfig(
        target=Target(host=args.host, port=args.port if args.port is not None else 80),
        attack=attack,
        transport=TransportKind(transport),
        defenses=[],
        label="cli run",
        proxy_file=proxy_file,
        proxy_default_scheme=proxy_default_scheme,
    )


def run_once(config: RunConfig, quiet: bool = False) -> int:
    report, finish = make_progress(quiet=quiet)
    hooks = EngineHooks(on_tick=report)

    # Health check proxies before the run starts
    if config.transport is TransportKind.PROXY:
        from .proxies import shared_pool
        pool = shared_pool(
            config.proxy_file or None,
            default_scheme=config.proxy_default_scheme,
        )
        alive, dead = pool.health_check(
            config.target.host, config.target.port, timeout=5.0
        )
        if dead:
            _say(f"  Proxy health check: {len(alive)}/{len(pool)} alive, "
                 f"{len(dead)} dead (skipped)")
            for proxy, reason in dead:
                _say(f"    - {proxy.label()}: {reason}")
        if not alive:
            _say("\n[!] All proxies are dead. Aborting run.")
            finish()
            return EXIT_ERROR
        # Filter pool to only alive proxies
        pool._proxies = tuple(alive)
        pool._dead = set()

    engine = RunEngine(config, hooks=hooks)

    try:
        outcome = engine.run()
    except KeyboardInterrupt:
        _say("\nInterrupted.")
        return EXIT_INTERRUPTED
    except PolicyViolation as exc:
        # A refusal is a result, not a crash.
        _say("\n[!] Refused by policy")
        _say(f"    {exc}")
        return EXIT_ERROR
    finally:
        finish()

    summarise(outcome)
    return outcome.exit_code


def _print_preview(config: RunConfig) -> None:
    """Print what a run would do, and send nothing.

    --dry-run existed below the CLI only: the flag ran the engine with workers
    disabled, which reported zero packets and previewed nothing. A preview
    worth having answers "what exactly would this command do" - the resolved
    transport, the request a target would receive, the pool the egress would
    rotate through, the certificate decision - before any socket is opened.
    """
    attack = config.attack
    print("=== Dry run: what this command would do ===")
    print(f"  target     {config.target}  ({attack.profile.value})")
    print(f"  transport  {config.transport.value}")
    print(
        f"  rate       {attack.pps:,} pps for {attack.duration_seconds:g}s "
        f"across {attack.workers} worker(s)"
    )
    print(f"  payload    {attack.payload_size:,} bytes per packet")
    if attack.profile is ProfileName.HTTP_FLOOD:
        extras = []
        if attack.cookie_header:
            extras.append("cookie set")
        if attack.referer:
            extras.append("referer set")
        if attack.http_body:
            extras.append(f"body: {len(attack.http_body)} bytes")
        shaped = f"{attack.http_method.upper()} {attack.http_path}"
        if extras:
            shaped += f"  ({', '.join(extras)})"
        print(f"  request    {shaped}")
        print(
            f"  identity   {attack.fingerprint} "
            f"(rotation: {attack.fingerprint_rotation})"
        )
        if attack.use_tls or attack.use_http2:
            verify = "on" if attack.tls_verify else "OFF"
            print(f"  tls        on (certificate verification: {verify})")
    if config.transport is TransportKind.PROXY:
        from .proxies import ProxyListError, load_proxies

        try:
            pool_size = len(
                load_proxies(config.proxy_file or None, config.proxy_default_scheme)
            )
        except ProxyListError as exc:
            print(f"  proxies    UNUSABLE: {exc}")
        else:
            print(
                f"  proxies    {pool_size} from "
                f"{config.proxy_file or 'proxies.txt'} "
                f"(default scheme: {config.proxy_default_scheme})"
            )
    print("  no packet was sent.")


def main(argv: Sequence[str] | None = None) -> int:
    _print_banner()
    parser = build_parser()
    args = parser.parse_args(argv)

    # The mode flags are mutually exclusive. Each one is a run-and-exit branch
    # checked in sequence below, so two set together meant the first in line
    # ran and the second was silently dropped - `--check-proxies --nuclear`
    # checked proxies and never struck, with no word about the discarded flag.
    modes = [
        name
        for name, given in (
            ("--inspect-h2", getattr(args, "inspect_h2", False)),
            ("--encrypt-proxies", getattr(args, "encrypt_proxies", False)),
            ("--download-proxies", getattr(args, "download_proxies", False)),
            ("--check-proxies", getattr(args, "check_proxies", False)),
            ("--serve-target", getattr(args, "serve_target", False)),
            ("--nuclear", getattr(args, "nuclear", False)),
            ("--dry-run", getattr(args, "dry_run", False)),
        )
        if given
    ]
    if len(modes) > 1:
        print("[!] Pick one mode; these cannot be combined: " + ", ".join(modes))
        return EXIT_ERROR

    # Inspecting the HTTP/2 preamble is a measurement, not an attack, so it runs
    # before the target-serving and wizard branches and reaches neither the run
    # engine nor the safety guard: it opens a socket to 127.0.0.1 and to nothing
    # else. Requiring --host here would be wrong - the whole point is to check the
    # preamble without needing, or wanting, a target.
    if args.inspect_h2:
        return inspect_h2(args)

    # Encrypt proxies: read proxies.txt, encrypt with password, write proxies.enc
    if args.encrypt_proxies:
        from .proxies import encrypt_proxies
        import getpass
        from pathlib import Path

        src = Path(args.proxy_file) if args.proxy_file else Path("proxies.txt")
        if not src.exists():
            _say(f"[!] {src} not found. Create it first with your proxy list.")
            return EXIT_ERROR

        plaintext = src.read_text(encoding="utf-8")
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            _say("[!] Passwords do not match.")
            return EXIT_ERROR
        if not password:
            _say("[!] Password cannot be empty.")
            return EXIT_ERROR

        encrypted = encrypt_proxies(plaintext, password)
        dst = src.with_suffix(".enc") if src.suffix == ".txt" else Path("proxies.enc")
        dst.write_bytes(encrypted)
        _say(f"Encrypted {src} -> {dst}")
        _say("Add proxies.enc to .gitignore (already done) and delete proxies.txt if desired.")
        return EXIT_OK

    # Downloading and checking proxy lists are list-management operations, not
    # runs. The checker touches each proxy and one well-known reachability
    # host (1.1.1.1:80) and never the target, so neither step requires --host;
    # both run and exit here, before the wizard and the engine can be reached.
    if getattr(args, "download_proxies", False):
        from .proxy_sources import download_proxies

        return download_proxies(
            getattr(args, "proxy_kind", "all") or "all",
            args.proxy_file or "proxies.txt",
        )

    if getattr(args, "check_proxies", False):
        from .proxy_sources import check_proxies_file

        return check_proxies_file(
            args.proxy_file or "proxies.txt",
            default_scheme=getattr(args, "proxy_default_scheme", "http") or "http",
            output=getattr(args, "check_output", "") or None,
        )

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
                *(["--reflector"] if getattr(args, "reflector", False) else []),
            ]
        )

    # A preview needs a target to describe, and it must come after the mode
    # exclusivity check so --dry-run --nuclear is refused rather than previewed.
    if getattr(args, "dry_run", False):
        if not args.host:
            print("[!] --dry-run previews a run, so it needs --host.")
            return EXIT_ERROR
        config = config_from_args(args)
        print()
        _print_preview(config)
        return EXIT_OK

    # Nuclear mode with no --host, or when asked for explicitly. The wizard is
    # interactive, so it reads stdin; a Ctrl-C inside it is a normal way to back
    # out and is handled here rather than left to escape as a traceback.
    #
    # The identity and egress flags are forwarded rather than dropped. Nuclear
    # mode spawns a child per profile and rebuilds its own AttackProfile, so a
    # flag that is only read in config_from_args would be silently discarded
    # here - the operator would type --fingerprint chrome_131, watch the wizard
    # run ten profiles, and have no reason to suspect the persona never applied.
    if args.nuclear or not args.host:
        # The body is resolved here, not in config_from_args, because the
        # nuclear branch never reaches that function: a --data-file would
        # otherwise be silently ignored and the strike would send GET.
        body_value, body_error = _resolve_body(args)
        if body_error:
            print(f"[!] {body_error}")
            return EXIT_ERROR
        try:
            exit_code = nuclear_wizard(
                # argparse defaults are non-empty, so passing them through
                # unchanged would make every `--nuclear` run announce
                # "lab_default (from the command line)" and skip the question
                # the operator actually came to answer. Only a value that
                # differs from the parser default counts as deliberate.
                fingerprint=(
                    None
                    if args.fingerprint == DEFAULT_FINGERPRINT_KEY
                    else args.fingerprint
                ),
                fingerprint_rotation=(
                    None
                    if args.fingerprint_rotation == DEFAULT_ROTATION
                    else args.fingerprint_rotation
                ),
                h2_preamble=None if args.h2_preamble == "auto" else args.h2_preamble,
                proxy_file=args.proxy_file or None,
                # Request-shape flags. Only a value that differs from the
                # parser default is deliberate, so the wizard announces
                # exactly what the operator typed and nothing else - the same
                # rule the identity flags above follow. getattr because
                # hand-built Namespaces in older tests predate these flags.
                http_method=(
                    None
                    if getattr(args, "method", "get") in (None, "get")
                    else args.method
                ),
                http_path=(
                    None
                    if getattr(args, "http_path", "/api/data") in (None, "/api/data")
                    else args.http_path
                ),
                cookie=getattr(args, "cookie", "") or None,
                referer=getattr(args, "referer", "") or None,
                data=body_value or None,
                content_type=(
                    None
                    if getattr(args, "content_type", "")
                    in (None, "application/x-www-form-urlencoded")
                    else args.content_type
                ),
                proxy_default_scheme=(
                    None
                    if getattr(args, "proxy_default_scheme", "http") in (None, "http")
                    else args.proxy_default_scheme
                ),
                # --profiles is forwarded as a preset: the wizard validates it
                # against the profiles that survive the privilege and port
                # filters, so a name that cannot run in this strike is a hard
                # error naming the valid set, not a silently full strike.
                selected_profiles=getattr(args, "profiles", "") or None,
            )
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
