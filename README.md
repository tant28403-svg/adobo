# ADOBO

> [!IMPORTANT]
> **Please read this whole README before running the tool.** It explains the
> required setup, the profiles, nuclear mode and the proxy options, and it
> points out a few things that commonly cause confusion or problems (for
> example the port to use and when "errors" in the output are expected). Taking
> a couple of minutes to read it will save you a lot of guesswork.

> **Open Source Notice:** This project is open source. The source code, documentation
> and README fully describe how every profile, transport and attack mechanism
> works. Anyone who clones this repository can read and understand the complete
> implementation. Please use it responsibly, and only against systems you own or
> have explicit written permission to test.
>
> **Capability Notice:** This is a moderate to low intensity DDoS testing tool.
> It is designed for authorised resilience testing and educational purposes.
> It does not represent advanced or sophisticated attack capabilities. The tool
> measures how services behave under controlled load and is intended for lab
> and authorised testing environments only.

## ⚠️ FOR EDUCATIONAL USE AND AUTHORISED RESILIENCE TESTING ONLY

**Please use this tool only against systems you own or have explicit written permission to test. Unauthorised testing is illegal in most jurisdictions.**

## ⚠️ The author cannot be held responsible for any misuse.

---

A DDoS resilience lab for authorised testing: it measures how your services behave under load.

## What is ADOBO?

ADOBO is a command-line tool and a deliberately fragile lab target used together to
measure how a service holds up under controlled load. It sends traffic from a chosen
profile (UDP, TCP, HTTP, HTTP/2, HTTP/3, amplification, slowloris, rapid reset) at a
configurable rate, probes the target for availability and latency throughout the run,
and prints a resilience score plus what the target itself counted. The lab target
(`adobo.target`) reports its own served-request count, so the result does not rely
solely on the sender's claims.

Use cases:

- Resilience benchmarking: quantify availability and latency under load
- Mitigation testing: run against the hardened target to validate rate limits, WAF rules, circuit breakers
- Education: study how different flood and amplification techniques behave
- Protocol inspection: measure HTTP/2 connection preambles and fingerprints
- Proxy/egress testing: distribute HTTP floods across a proxy list

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Commands](#commands)
- [Flags Reference](#flags-reference)
- [Profiles](#profiles)
- [Output](#output)
- [Understanding the Result](#understanding-the-result)
- [Nuclear Mode](#nuclear-mode)
- [Hardened Target](#hardened-target)
- [Proxies](#proxies)
- [Configuration Files](#configuration-files)
- [Project Structure](#project-structure)
- [Termux / Android](#termux--android)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Links](#links)

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/tant28403-svg/adobo.git
cd adobo

# 2. Install core dependencies
pip install pydantic pyyaml psutil httpx h2 cryptography

# 3. Start the lab target (port 8001 recommended)
python -m adobo.target --port 8001

# 4. In another terminal, send traffic
python -m adobo --host 127.0.0.1 --port 8001 \
                --profile http_flood --pps 2000 --duration 10 --workers 8
```

Expected output shape:

```
  sent to OS   1,220 packets (624,640 bytes)
  availability 100.0% over 36 probes (p95 35ms)
  target served 1,218 requests (0 errors)
  delivery     99.8% of packets sent reached the target
```

> Please use port **8001** rather than 8000. TLS is enabled automatically on
> `443, 8443, 8080, 9443, 8000, 8888`, and a TLS client talking to a plaintext
> target will fail.

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/tant28403-svg/adobo.git
cd adobo
```

If any dependencies are missing:

```bash
pip install pydantic pyyaml psutil httpx h2 cryptography
```

Optional dependencies:

```bash
pip install scapy aioquic          # raw profiles and HTTP/3
pip install pyfiglet               # banner rendering only
```

Or install everything for a feature set at once:

```bash
pip install -e .[raw,http3,ui,lab]
```

### Requirements

- Python 3.11 or later
- Linux or Termux/Android (Windows has known issues)
- Git
- `scapy` + Administrator/root for raw (spoofed) profiles
- `aioquic` for HTTP/3 (`--transport h3`)
- `fastapi` + `uvicorn` for the lab target (`--serve-target` / `adobo.target`)

### Termux / Android (download & install)

```bash
pkg update && pkg upgrade -y
pkg install -y python git

git clone https://github.com/tant28403-svg/adobo.git
cd adobo

pip install pydantic pyyaml httpx h2

# Optional extras (fall back to pkg if a pip build fails):
pip install psutil cryptography pyfiglet
# pkg install python-psutil   # if pip's psutil build fails
pip install scapy aioquic      # raw profiles and HTTP/3 (won't send on unrooted devices)
```

> **If `pydantic` fails to install on Termux:** it usually has no prebuilt
> Android wheel, so pip compiles `pydantic-core` in Rust. Install the
> toolchain first, then retry:
> ```bash
> termux-wake-lock
> pkg install rust clang
> pip install pydantic
> ```
> Or use Termux's package if available: `pkg install python-pydantic`.
> Keep the device awake and plugged in; the build can take 10-20 minutes.

## Commands

| Command | Description |
|---|---|
| `python -m adobo` | Run a single profile against a target (default entry point) |
| `python -m adobo --nuclear` | Interactive nuclear wizard: runs every applicable profile in parallel |
| `python -m adobo --serve-target` | Serve the lab target instead of attacking |
| `python -m adobo.target` | Start the lab target server directly |
| `python -m adobo --encrypt-proxies` | Encrypt a proxy list into `proxies.enc` |
| `python -m adobo --inspect-h2` | Measure the configured HTTP/2 preamble and exit |
| `ADOBO` | Installed console script (see `[project.scripts]`) |

## Flags Reference

### Common Flags (single-profile runs)

| Flag | Default | Description |
|---|---|---|
| `--host` | (required) | Target IP/hostname |
| `--port` | 80 (8000 with `--serve-target`) | Target port |
| `--profile` | `udp_flood` | Attack profile (see [Profiles](#profiles)) |
| `--pps` | 5000 | Packets per second |
| `--duration` | 10 | Seconds |
| `--workers` | 4 | Worker threads |
| `--payload` | 512 | Payload size in bytes |
| `--transport` | `auto` | `socket`, `scapy`, `linux_raw`, `virtual`, `h2`, `h3`, `proxy` |
| `--tls` | auto on HTTPS ports | Use TLS/HTTPS for `http_flood` |
| `--tls-no-verify` | off | Disable TLS certificate verification (lab only; implies `--tls`) |
| `--http2` | off | Use HTTP/2 for `http_flood` |
| `--http3` | off | Use HTTP/3 over QUIC (requires `aioquic`) |
| `--h2-concurrency` | 100 | Concurrent HTTP/2 streams per connection |
| `--keep-alive` | off | Reuse HTTP connections (higher throughput) |
| `--spoof-sources` | off | Spoof source IP (requires scapy + Admin) |
| `--proxy-file` | (none) | Path to proxy list for `--transport proxy` (HTTP profiles only) |
| `--proxy-password` | (none) | Password for an encrypted proxy file |
| `--proxy-health-check` | on | Test proxies before the run |
| `--fingerprint` | `lab_default` | Client identity for `http_flood`/`slowloris` |
| `--fingerprint-rotation` | `per_connection` | `none`, `per_request`, `per_connection` |
| `--h2-preamble` | `auto` | HTTP/2 connection preamble to send |
| `--inspect-h2` | off | Measure preamble and exit (sends nothing to target) |
| `--quiet` | off | Suppress progress output |
| `--nuclear` | off | Run the interactive nuclear wizard |

### Target Flags (`--serve-target`)

| Flag | Default | Description |
|---|---|---|
| `--defenses` | `none` | Mitigations: comma-separated or `all`/`none` |
| `--work-ms` | (none) | Simulated database work per `/api/data` request, in ms |

Ceilings (`max_pps`, `max_duration_seconds`, `max_payload_bytes`, `max_workers`) are
read from `config/lab.yaml` and only ever lower requested values; reductions are
printed. Throughput is not capped by default.

## Profiles

`udp_flood` · `udp_flood_ns` · `syn_flood` · `syn_flood_ns` · `icmp_flood` ·
`icmp_flood_ns` · `ack_flood` · `ack_flood_ns` · `dns_amplification` ·
`ntp_amplification` · `cldap_amplification` · `ssdp_amplification` · `http_flood` ·
`slowloris` · `rapid_reset`

> **Spoofing and the `_ns` suffix:** Some profiles can send a packet with a forged
> source address (spoofing), which needs root or Administrator privileges. Profiles
> ending in `_ns` are the non-spoofed variants: they send from your real IP and need
> no special privileges. The plain names (`udp_flood`, `syn_flood`, ...) are the
> spoofing versions.

> **Note on errors:** When running `http_flood` or `rapid_reset` you may notice
> "errors" reported in the output. This is **normal and expected** — it means the
> tool is working and the target is responding (for example with HTTP errors or
> connection resets). If the tool were **not** working, no error messages would
> appear at all and the run would simply show zero activity.

```bash
python -m adobo --host 127.0.0.1 --port 8001 --profile <name> --pps 2000 --duration 10
```

## Output

A run prints a result block like:

```
=== Result ===
  resilience   87.3 / 100  (grade B)
  sent to OS   1,220 packets (624,640 bytes)
  throughput   122 pps
  availability 100.0% over 36 probes (p95 35ms)
  target served 1,218 requests (0 errors)
  delivery     99.8% of packets sent reached the target
```

- `sent to OS` counts what was handed to the operating system (sender's view).
- `target served` is what the lab target itself counted (authoritative).
- `delivery` reconciles the two.
- `resilience` is a 0-100 score with a grade, derived from availability and latency.

## Understanding the Result

- **Resilience score** (`total / 100`, grade): higher is better; based on probe availability and p95 latency.
- **Sent to OS**: packets/bytes handed to the OS. Cannot distinguish "served", "refused", or "host down".
- **Target served**: requests the lab target actually handled (only for HTTP profiles against the lab target).
- **Delivery**: `target served / sent`. Low values are expected for non-HTTP or mixed runs.
- **Availability / p95**: probe success rate and 95th-percentile latency over the run.
- **Notes**: caveats that decide whether the numbers mean anything (e.g. transport never opened). Read them.

## Nuclear Mode

> ## ⚠️ WARNING: HIGH CPU USAGE ⚠️
>
> **Nuclear mode runs every applicable profile in parallel and can consume
> significant CPU and system resources.** Make sure you have a capable machine
> (multi-core CPU, sufficient RAM) before running it. On low-end or shared
> systems, nuclear mode may cause high CPU usage, slow response times, or
> system instability. **Consider running individual profiles first to gauge
> your system's capacity.**
>
> **Minimum recommended specs for full potential:**
> - **CPU:** 8 cores or above
> - **RAM:** 16 GB or more
>
> **⚠️ Network saturation warning:** Nuclear mode runs every applicable profile
> in parallel and can saturate your own network bandwidth. Make sure your network
> connection and infrastructure can handle the combined load of all profiles
> running simultaneously. On limited or shared networks, this may cause
> congestion, packet loss, or connectivity issues for other devices and services
> on the same network. **Avoid setting PPS too high** — in nuclear mode, PPS is
> applied per profile, not divided across them, so 10 profiles at 500 PPS
> means 5,000+ PPS combined. Start low and increase gradually.

Runs every applicable profile in parallel:

```bash
python -m adobo --nuclear
```

It asks up to 17 questions, some depending on earlier answers:

```
=== Nuclear Strike ===
Target IP: 127.0.0.1
Port (for TCP/UDP profiles) [80]: 8001
PPS per profile (max 20,000 - max_pps) [500]:
Duration (s) [60]:
Use HTTP/2 for http_flood? (requires TLS, enables multiplexing) [y/N]:
Enable HTTP/1.1 keep-alive for http_flood? (higher throughput, delivery may overcount) [y/N]:
Use TLS/HTTPS for http_flood? (auto-enabled on port 443) [y/N]:
Payload size (bytes) (max 1,400 - max_payload_bytes) [512]:
Enable IP spoofing for raw profiles? (requires root/CAP_NET_RAW) [y/N]:
```

One question uses a default that isn't prompted:

- **Reflector ports** use the well-known service ports (53 / 123 / 389 / 1900).
- **Worker threads** are capped by `max_workers` (default ceiling: 200).

| Question | What it does |
|---|---|
| PPS / Duration | Applied to **each** profile, not divided across them |
| Workers | Per profile. Default 4, maximum `max_workers` (200) |
| Payload | Bytes per packet. Ceiling 1,400 |
| IP spoofing | Adds the spoofed variants. Needs root |

Any profile that cannot run is reported together with the reason. On Windows, the raw
socket profiles (scapy and linux_raw) will fail unless Npcap and Administrator
privileges are available:

```
icmp_flood: never attempted a packet
  - TransportError('Linux raw sockets unavailable: ...')
```

The results table reports **"Handed to OS"** rather than "sent", counting packets
passed to the operating system (not confirmation of delivery).

## Hardened Target

The target can be started with its defenses enabled:

```bash
python -m adobo.target --port 8001 --defenses all
```

Defenses: `rate_limit` · `connection_cap` · `waf` · `circuit_breaker` · `challenge_page`

Or via the main entry point:

```bash
python -m adobo --serve-target --port 8001 --defenses all
```

## Proxies

Create a `proxies.txt` (one proxy per line) and point the tool at it:

```
# proxies.txt
# Format: [user:pass@]host:port
# Lines starting with # are comments.
1.2.3.4:8080
user:pass@5.6.7.8:3128
```

```bash
python -m adobo --host 127.0.0.1 --port 8001 --profile http_flood \
                --transport proxy --proxy-file proxies.txt
```

`ADOBO_PROXY_FILE` and `ADOBO_PROXIES` environment variables also work.

To keep the list encrypted:

```bash
python -m adobo --encrypt-proxies --proxy-file proxies.txt
```

This produces `proxies.enc`, prompting for a password (requested twice, cannot be
empty). The original `proxies.txt` is not deleted.

### How the tool uses your proxies

This is not proxy chaining. Each proxy sends one request (rotated round-robin), so
the target sees that proxy's address as the source. Only HTTP traffic (`http_flood`)
can be proxied; UDP, amplification and raw packets are still sent from your own
machine.

## Configuration Files

Located under `config/` (resolved via `adobo.paths`, source-tree or PyInstaller bundle):

| File | Purpose |
|---|---|
| `config/lab.yaml` | Policy: allowlist CIDRs, ceilings, measurement cadence, paths. Optional; defaults are conservative. |
| `config/waf_rules.yaml` | Mitigation rule set (parsed by `adobo.defenses`) |
| `config/authorization.yaml` | Legacy authorisation record; no longer consulted by the engine |

`lab.yaml` is optional; when absent the tool falls back to conservative defaults
(max payload 1400 bytes, allowlist 127.0.0.0/8, probe path /healthz, etc.).

## Project Structure

```
adobo/
├── pyproject.toml
├── README.md
├── adobo/
│   ├── __main__.py
│   ├── __init__.py
│   ├── cli.py              # argparse entry point
│   ├── engine.py           # run orchestration
│   ├── models.py           # RunConfig, AttackProfile, Target, ...
│   ├── config.py           # lab.yaml / authorization / waf loading
│   ├── safety.py           # policy ceilings (clamp only)
│   ├── nuclear.py          # nuclear wizard
│   ├── wizard.py
│   ├── fingerprint.py      # client identity / HTTP/2 preamble
│   ├── h2profile.py / h2inspect.py
│   ├── observation.py / monitor.py / scoring.py / report.py
│   ├── defenses.py / cancellation.py / paths.py
│   ├── proxies.py
│   ├── transports/         # socket, scapy, linux_raw, virtual, h2, h3, proxy, ...
│   └── target/             # lab target server (FastAPI/uvicorn)
├── config/
│   ├── authorization.yaml
│   └── waf_rules.yaml
├── tests/
└── scripts/
```

## Termux / Android

ADOBO runs on [Termux](https://termux.dev) directly from a phone. The core is
pure Python and works without root; raw-packet profiles needing `CAP_NET_RAW`
report themselves as unavailable instead of crashing.

### Run

```bash
git clone https://github.com/tant28403-svg/adobo.git
cd adobo

termux-wake-lock

# Local target + load (same device):
python -m adobo.target --port 8001
python -m adobo --host 127.0.0.1 --port 8001 --profile http_flood --pps 500 --duration 10
```

To let another device reach the target, bind to all interfaces (only on a trusted
network — the lab target is intentionally fragile):

```bash
python -m adobo.target --host 0.0.0.0 --port 8001
python -m adobo --host <device-ip> --port 8001 --profile http_flood --pps 500 --duration 10
```

### Notes for mobile

- **No root needed** for `http_flood`, `slowloris`, `rapid_reset`, the `_ns`
  variants, and the socket/h2/h3/proxy/virtual transports. Spoofed raw profiles
  report `CAP_NET_RAW` unavailable on unrooted devices — use the `_ns` variants.
- **Battery/thermal:** keep PPS and workers low; nuclear mode is heavy.
- **Backgrounding:** Android may kill Termux. Use `termux-wake-lock`, `tmux`,
  or `nohup`.
- **Python:** 3.11 or later (Termux `pkg install python` currently provides 3.11+).

## Tests

```bash
python -m pytest tests/ -q
```

Optional extras for the full suite:

```bash
pip install -e .[dev]
```

## Troubleshooting

**"Command not found" / import errors**
Install core dependencies: `pip install pydantic pyyaml psutil httpx h2 cryptography`.
Missing optional features (raw/HTTP3) degrade gracefully or report unavailable.

**TLS client talking to plaintext target**
Use port 8001 (not 8000) or disable auto-TLS. TLS auto-enables on
`443, 8443, 8080, 9443, 8000, 8888`.

**Raw profiles fail on Windows**
Install Npcap and run as Administrator, or use the `_ns` variants.

**Run seems to do nothing**
Read the `Notes:` block — a transport that never opened produces zero activity
with no error otherwise.

**Ceiling adjustments printed**
`lab.yaml` clamped a value down. Edit `config/lab.yaml` to raise limits.

## License

MIT — see `LICENSE`.

## Links

- Repository: https://github.com/tant28403-svg/adobo
- Issues: https://github.com/tant28403-svg/adobo/issues

---

**Please only send traffic to hosts you own or have written permission to test.**