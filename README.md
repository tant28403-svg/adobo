# ADOBO

> **Open Source Notice:** This project is open source. The source code, documentation,
> tests, and README fully document how every profile, transport, and attack mechanism
> works. Anyone who clones this repository can read and understand the complete
> implementation. Use responsibly and only against systems you own or have explicit
> written permission to test.
>
> **Capability Notice:** This is a moderate to low intensity DDoS testing tool.
> It is designed for authorised resilience testing and educational purposes.
> It does not represent advanced or sophisticated attack capabilities. The tool
> measures how services behave under controlled load and is intended for lab
> and authorised testing environments only.

## ⚠️  FOR EDUCATIONAL AND AUTHORISED RESILIENCE TESTING ONLY  ⚠️

**Only use against systems you own or have explicit written permission to test. Unauthorised testing is illegal in most jurisdictions.**

The author accepts **no responsibility** for misuse.

---

An authorised DDoS resilience lab: measures how your services behave under load.

## Download

Python 3.11+ required. **Linux only.**

```bash
git clone https://github.com/tant28403-svg/adobo.git
cd adobo
```

If dependencies are missing:

```bash
pip install pydantic pyyaml psutil pyfiglet httpx h2 cryptography
```

Optional (for raw profiles and HTTP/3):
```bash
pip install scapy aioquic
```

## Use

Nothing to configure. Clone it and run it.

**1. Start the lab target.** It counts what it served, so you can check the result against a number that isn't the sender's own claim:

```bash
python -m adobo.target --port 8001
```

**2. Attack it:**

```bash
python -m adobo --host 127.0.0.1 --port 8001 \
                --profile http_flood --pps 2000 --duration 10 --workers 8
```

```
  sent to OS   1,220 packets (624,640 bytes)
  availability 100.0% over 36 probes (p95 35ms)
  target served 1,218 requests (0 errors)
  delivery     99.8% of packets sent reached the target
```

The sender counted 1,220. The target counted 1,218. They are allowed to differ — the second number is the one you can trust. (Exact counts vary run to run; the shape is what matters.)

> Use port **8001**, not 8000. TLS turns on automatically on `443, 8443, 8080, 9443, 8000, 8888`, and a TLS client against a plaintext target fails.

### Profiles

`udp_flood` · `udp_flood_ns` · `syn_flood` · `syn_flood_ns` · `icmp_flood` · `icmp_flood_ns` · `ack_flood` · `ack_flood_ns` · `dns_amplification` · `ntp_amplification` · `cldap_amplification` · `ssdp_amplification` · `http_flood` · `slowloris` · `rapid_reset`

> **Note on errors:** When running `http_flood` or `rapid_reset`, you may see
> "errors" reported in the output. This is **normal and expected** — it means
> the tool is working and the target is responding (e.g. with HTTP errors or
> connection resets). If the tool is **not** working, you won't see any error
> messages at all; the run will simply show zero activity. Errors in these
> profiles indicate the target is actively handling (and rejecting) your
> requests, which is the intended behavior.

```bash
python -m adobo --host 127.0.0.1 --port 8001 --profile <name> --pps 2000 --duration 10
```

### Nuclear mode

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

Every applicable profile in parallel.

```bash
python -m adobo --nuclear
```

It asks up to 17 questions (some are conditional on previous answers):

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

One question uses a default that isn't prompted (no decision needed):

**Reflector ports** use the well-known service ports (53 / 123 / 389 / 1900).

**Worker threads** are capped by `max_workers` (default ceiling: 200). The nuclear wizard asks how many workers to use per profile.

| Question | What it does |
|---|---|
| PPS / Duration | Applied to **each** profile, not divided across them |
| Workers | Per profile. Default from lab.yaml or 4 if no ceiling. Max is `max_workers` (200) |
| Payload | Bytes per packet. Ceiling is 1,400 |
| IP spoofing | Adds the spoofed variants. Needs root |

Profiles that can't run are reported with the reason, never dropped silently. On Windows, raw socket profiles (scapy and linux_raw) fail unless Npcap and Administrator privileges are available:

```
icmp_flood: never attempted a packet
  - TransportError('Linux raw sockets unavailable: ...')
```

The results table reports **"Handed to OS"**, not "sent". That column counts packets given to the operating system, which is not confirmation of delivery.

### Hardened target

```bash
python -m adobo.target --port 8001 --defenses all
```

`rate_limit` · `connection_cap` · `waf` · `circuit_breaker` · `challenge_page`

### Common options

| Option | Default | Notes |
|---|---|---|
| `--pps` | 5000 | packets per second |
| `--duration` | 10 | seconds |
| `--workers` | 4 | worker threads |
| `--payload` | 512 | bytes per packet |
| `--transport` | auto | `socket` · `scapy` · `linux_raw` · `virtual` · `h2` · `h3` · `proxy` |
| `--tls` | auto on HTTPS ports | `--tls-no-verify` for self-signed certs |
| `--http2` | off | also `--h2-concurrency N` |
| `--proxy-file` | (none) | path to proxy list for `--transport proxy` (HTTP profiles only) |
| `--proxy-health-check` | on | test proxies before run (only when proxies are used) |

Run `python -m adobo --help` for everything else.

## Limits

Throughput is not capped. Ask for the rate you want and the run sends it — what the machine can actually achieve shows up in the achieved figure rather than being trimmed in advance. Add `max_pps` to `config/lab.yaml` if you want a limit.

The other three are capped, and every reduction is reported rather than applied silently:

```
Ceiling adjustments from lab.yaml:
  payload_size clamped from 1,900,000 to 1,400 bytes (max_payload_bytes in lab.yaml)
  workers clamped from 99,999 to 200 (max_workers in lab.yaml)
```

| Ceiling | Value |
|---|---|
| Throughput | none (configurable via max_pps) |
| Duration | none (configurable via max_duration_seconds) |
| Payload | 1,400 bytes |
| Workers | none (configurable via max_workers) |

## Tests

```bash
python -m pytest tests/ -q
```

## License

MIT — see `LICENSE`.

---

**Only send traffic to hosts you control or have written permission to test.**
