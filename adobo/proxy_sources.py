"""Provisioning and pruning a proxy list: fetch, merge, and check.

Everything else in the proxy stack assumes the operator already holds a list.
This module is how a list comes to exist at all, and how one that has rotted
gets pruned. It exists because a public list is the only realistic way to
reach "ten thousand addresses" from one machine, and because a list that was
healthy last month can be half-dead today: the rotation survives dead entries,
but a run that spends its opening seconds dialling five thousand refused
connections measures the list's decay as much as the target's behaviour.

**What downloading does and does not do.** It fetches a fixed set of public
aggregate lists, tags every line with the protocol its source serves, merges,
dedupes, and writes one file. It does not test the proxies - that is
:func:`check_proxies_file`, deliberately separate, because fetching proves the
source published a line and nothing more. A list written without checking is
honest about being unverified, and the run's own health check will say how
much of it was real.

**Scheme tagging.** An HTTP entry is written bare (``host:port``), a SOCKS
entry carries its prefix (``socks5://host:port``), so the merged file reads
correctly under the default scheme with no extra flags. Source lists publish
bare lines, so the source's protocol *is* the line's protocol - which is why
the tagging happens at merge time and not at read time.

**The checker never destroys the input.** A transient network failure, or a
laptop waking from sleep mid-check, would otherwise rewrite a ten-thousand-line
list into an empty one. The verified list is written beside the input, and the
input is left alone.

**Sources change without notice.** These are third-party aggregators, not
contracted infrastructure. A source that fails is skipped and its failure
counted, so one dead mirror degrades the merge instead of failing it. The
set below was verified reachable when it was written; when lists rot past
usefulness, replace the URL rather than shipping a wall of dead endpoints.
"""

from __future__ import annotations

import socket
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from .proxies import Proxy, load_proxies

__all__ = [
    "SOURCES",
    "check_proxies_file",
    "download_proxies",
    "encode_entry",
]

#: The public aggregate lists, keyed by the protocol each URL serves.
SOURCES: dict[str, tuple[str, ...]] = {
    "socks4": (
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
        "https://proxyspace.pro/socks4.txt",
    ),
    "socks5": (
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true",
        "https://proxyspace.pro/socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    ),
    "http": (
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&simplified=true",
        "https://proxyspace.pro/http.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    ),
}

#: Exit codes. 0 is cli.EXIT_OK, 1 is cli.EXIT_ERROR; duplicated as literals
#: rather than imported so this module stays below the CLI in the dependency
#: graph and can be scripted from tests without dragging argparse in.
_EXIT_OK = 0
_EXIT_ERROR = 1


def encode_entry(proxy: Proxy) -> str:
    """One line of a proxy file.

    HTTP stays bare because it is the default scheme; SOCKS lines carry their
    prefix so the file reads correctly with no ``--proxy-default-scheme``. The
    inverse of what :func:`adobo.proxies.parse_proxy` accepts.
    """
    if proxy.scheme == "http":
        return proxy.endpoint
    return f"{proxy.scheme}://{proxy.endpoint}"


def _default_fetch(url: str, timeout: float = 15.0) -> str:
    """One HTTP GET. httpx is already a core dependency (the engine probes
    with it), so no new package enters the tree for this."""
    import httpx

    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    return response.text


def _merge_lines(kind: str, text: str) -> list[Proxy]:
    """Every parseable line of one source, tagged with that source's protocol.

    A line that does not parse is skipped, not fatal: public lists carry
    headers, blank lines and the occasional html fragment, and one bad line
    must not cost the rest of the source.
    """
    from .proxies import parse_proxy

    proxies: list[Proxy] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        candidate = line if "://" in line else f"{kind}://{line}"
        try:
            proxies.append(parse_proxy(candidate, default_scheme=kind))
        except Exception:
            continue
    return proxies


def download_proxies(
    kind: str = "all",
    out_path: str = "proxies.txt",
    fetch: Callable[[str], str] | None = None,
) -> int:
    """Fetch every source for *kind*, merge, dedupe, and write *out_path*.

    *fetch* is injectable so tests can stand in for the network. Returns 0
    when at least one proxy was written, 1 when none were - a list of zero
    proxies is a failure the run would only discover later, so it is reported
    at the step that caused it.
    """
    fetch = fetch or _default_fetch
    kinds = list(SOURCES) if kind == "all" else [kind]
    unknown = [k for k in kinds if k not in SOURCES]
    if unknown:
        print(f"[!] Unknown proxy kind {unknown[0]!r}; choose from: all, {', '.join(SOURCES)}")
        return _EXIT_ERROR

    merged: dict[tuple[str, str, int], Proxy] = {}
    for scheme in kinds:
        for url in SOURCES[scheme]:
            try:
                text = fetch(url)
            except Exception as exc:
                print(f"  - skipped (unreachable): {url}")
                print(f"      {exc.__class__.__name__}: {exc}")
                continue
            fetched = _merge_lines(scheme, text)
            before = len(merged)
            for proxy in fetched:
                merged.setdefault((proxy.scheme, proxy.host, proxy.port), proxy)
            print(f"  {len(fetched):>6} from {url}  (+{len(merged) - before} new)")

    if not merged:
        print(f"[!] No proxies fetched. Nothing was written to {out_path}.")
        return _EXIT_ERROR

    entries = sorted(merged.values(), key=lambda p: (p.host, p.port, p.scheme))
    try:
        Path(out_path).write_text(
            "\n".join(encode_entry(p) for p in entries) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        # A bad output path is an operator mistake with an obvious fix, and
        # the fetched list is still on screen in the per-source counts above.
        print(f"[!] Could not write {out_path}: {exc}")
        return _EXIT_ERROR
    by_scheme = Counter(p.scheme for p in entries)
    summary = ", ".join(f"{count} {scheme}" for scheme, count in sorted(by_scheme.items()))
    print(f"\n> Wrote {len(entries)} unique proxies to {out_path} ({summary})")
    print("> They are unverified. Run --check-proxies to prune the dead ones.")
    return _EXIT_OK


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------


def _check_one(proxy: Proxy, probe_host: str, probe_port: int, timeout: float) -> tuple[bool, str]:
    """Dial *proxy* and tunnel to the probe host. Returns (alive, reason).

    Uses the same :func:`~adobo.transports.proxy_transport.connect_tunnel` a
    run uses, so a proxy that passes this check is verified through exactly
    the code path the flood will take - including the SOCKS handshake for
    socks:// entries.
    """
    from .transports.proxy_transport import connect_tunnel

    sock = None
    try:
        sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
        connect_tunnel(sock, proxy, probe_host, probe_port, timeout)
        return True, ""
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def check_proxies_file(
    path: str,
    *,
    default_scheme: str = "http",
    timeout: float = 5.0,
    output: str | None = None,
    probe_host: str = "1.1.1.1",
    probe_port: int = 80,
    max_workers: int = 200,
) -> int:
    """Test every proxy in *path* and write the survivors to a new file.

    The probe is a well-known reachability host rather than the target: this
    is list hygiene, not an attack, and it runs with no ``--host`` configured.
    Returns 0 when at least one proxy survived, 1 otherwise.

    A list that cannot be read at all - an encrypted file, a malformed line -
    is reported and exited rather than raised: this is a mode flag an operator
    runs directly, and a traceback naming a line number buries the fix.
    """
    from .proxies import ProxyListError

    try:
        proxies = load_proxies(path, default_scheme)
    except ProxyListError as exc:
        print(f"[!] {exc}")
        return _EXIT_ERROR
    if not proxies:
        print(f"[!] No proxies found in {path}. Nothing to check.")
        return _EXIT_ERROR

    print(f"> Checking {len(proxies)} proxies against {probe_host}:{probe_port} ...")
    workers = max(1, min(max_workers, len(proxies)))
    results: list[tuple[Proxy, bool, str]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_check_one, proxy, probe_host, probe_port, timeout)
            for proxy in proxies
        ]
        for proxy, future in zip(proxies, futures):
            alive, reason = future.result()
            results.append((proxy, alive, reason))

    alive = [proxy for proxy, ok, _ in results if ok]
    dead = [(proxy, reason) for proxy, ok, reason in results if not ok]
    for proxy, reason in dead[:10]:
        print(f"  dead  {proxy.label()}: {reason}")
    if len(dead) > 10:
        print(f"  ... and {len(dead) - 10} more dead proxies")

    out_path = output or str(Path(path).with_name(Path(path).stem + "-checked.txt"))
    if alive:
        Path(out_path).write_text(
            "\n".join(encode_entry(proxy) for proxy in alive) + "\n", encoding="utf-8"
        )
    print(f"\n> Checked all proxies. Total worked: {len(alive)} of {len(proxies)}")
    if alive:
        print(f"> Verified list written to {out_path}. The original {path} is untouched.")
        return _EXIT_OK
    print("> None survived. The input list is rotten; re-download with --download-proxies.")
    return _EXIT_ERROR
