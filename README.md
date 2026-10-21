# ADOBO

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

## Download

Python 3.11 or later is required. **Linux only.**

> **Windows support:** The tool currently has some known issues on Windows, and work to resolve them is planned for a future update.

```bash
git clone https://github.com/tant28403-svg/adobo.git
cd adobo
```

If any dependencies are missing:

```bash
pip install pydantic pyyaml psutil pyfiglet httpx h2 cryptography
```

Optional dependencies (for the raw profiles and HTTP/3):
```bash
pip install scapy aioquic
```

## Proxies

If you have your own proxies, you can create a `proxies.txt` file (one proxy per line) and point the tool at it:

```
# proxies.txt
# Format: [user:pass@]host:port
# Lines starting with # are comments.
1.2.3.4:8080
user:pass@5.6.7.8:3128
```

You can then run the tool with `--transport proxy --proxy-file proxies.txt` (for HTTP profiles). The `ADOBO_PROXY_FILE` and `ADOBO_PROXIES` environment variables work as well.

A plain `proxies.txt` does not require a password. If you would prefer to keep the list encrypted, run `python -m adobo --encrypt-proxies` and choose a password when prompted (it is requested twice and cannot be empty). This produces `proxies.enc`, which is the file you then point the tool at, and the same password is requested when the list is decrypted.

In nuclear mode, when the wizard asks for the proxy list path, you can type the path to the file you created, or leave it blank if you do not want to use proxies. If the file is encrypted, the wizard asks for the password next.

### How the tool uses your proxies

Please note that this is not proxy chaining. In online proxy chaining, a request passes through every proxy in the chain before it reaches the target. This tool works differently: it uses each of the proxies you provide to send the request, one proxy per request, so the target sees that proxy's address as the source, just as it would see a regular client. The list is rotated round-robin, meaning consecutive requests are sent from different addresses. Only HTTP traffic (`http_flood`) can be proxied; UDP, amplification and raw packets are still sent from your own machine.

## Use

There is nothing to configure - clone the repository and you are ready to run.

**1. Start the lab target.** It keeps a count of what it served, so you can compare the result against a figure that does not come from the sender's own claim:

```bash
python -m adobo.target --port 8001
```

**2. Send the traffic to it:**

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

The sender counted 1,220, while the target counted 1,218. A small difference between the two is expected, and the second figure is the one you can rely on. (Exact counts vary from run to run; the overall shape is what matters.)

> Please use port **8001** rather than 8000. TLS is enabled automatically on `443, 8443, 8080, 9443, 8000, 8888`, and a TLS client talking to a plaintext target will fail.

### Profiles

`udp_flood` · `udp_flood_ns` · `syn_flood` · `syn_flood_ns` · `icmp_flood` · `icmp_flood_ns` · `ack_flood` · `ack_flood_ns` · `dns_amplification` · `ntp_amplification` · `cldap_amplification` · `ssdp_amplification` · `http_flood` · `slowloris` · `rapid_reset`

> **Note on errors:** When running `http_flood` or `rapid_reset` you may notice
> "errors" reported in the output. This is **normal and expected** — it means the
> tool is working and the target is responding (for example with HTTP errors or
> connection resets). If the tool were **not** working, no error messages would
> appear at all and the run would simply show zero activity. Errors in these
> profiles mean the target is actively handling (and rejecting) the requests,
> which is the intended behaviour.

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

This runs every applicable profile in parallel.

```bash
python -m adobo --nuclear
```

It asks up to 17 questions, some of which depend on earlier answers:

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

Any profile that cannot run is reported together with the reason, rather than being skipped silently. On Windows, the raw socket profiles (scapy and linux_raw) will fail unless Npcap and Administrator privileges are available:

```
icmp_flood: never attempted a packet
  - TransportError('Linux raw sockets unavailable: ...')
```

The results table reports **"Handed to OS"** rather than "sent". This column counts the packets passed to the operating system, which should not be read as confirmation of delivery.

### Hardened target

The target can also be started with its defenses enabled:

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

Run `python -m adobo --help` to see all remaining options.

## Limits

Throughput is not capped. You can request the rate you need and the run will send at that rate — what the machine can actually achieve appears in the achieved figure rather than being trimmed in advance. If you would prefer a limit, add `max_pps` to `config/lab.yaml`.

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

The test suite is maintained privately and is not included in this public repository. If you have a copy that includes it, the suite runs with:

```bash
python -m pytest tests/ -q
```

## Reporting issues

If you run into a bug, or something in the tool does not behave the way this README describes, please feel free to report it. Issues are welcome at:

https://github.com/tant28403-svg/adobo/issues

A short description of what you ran, what you expected and what happened instead is usually enough to get started. Bug reports, feature requests and general feedback are all appreciated.

## License

MIT — see `LICENSE`.

---

**Please only send traffic to hosts you own or have written permission to test.**
