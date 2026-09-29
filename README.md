# ADOBO

# ⚠️  FOR EDUCATIONAL AND AUTHORISED RESILIENCE TESTING ONLY  ⚠️

**Any use against systems you do not own or have explicit written permission to test is illegal in most jurisdictions.**

An authorised DDoS resilience lab: a tool for measuring how your services behave under load, against hosts you own and have explicitly authorised.

ADOBO reports a number only when something independent confirms it. The attack side counts what it handed to the OS; the lab target counts what it actually served; the two are printed side by side. When they disagree, or when no independent number exists, the tool says so rather than estimating.

## Install

```bash
git clone https://github.com/tant28403-svg/adobo.git
cd adobo
python -m adobo --help
```

No install step needed. If dependencies are missing:

```bash
pip install pydantic pyyaml psutil pyfiglet httpx h2 cryptography
```

Windows users can also download `ADOBO.exe` from the releases page.

## Quick start

**1. Enable the run.** The shipped `authorization.yaml` is expired on purpose, so an unconfigured checkout is inert. Set a future date, and allow your lab network:

```yaml
# config/authorization.yaml
expires_on: 2027-01-01

# config/lab.yaml
allowed_cidrs: ["127.0.0.0/8"]
```

**2. Start the lab target** — the other half of the tool. It keeps its own count, so a run can be checked against an independent number instead of the sender's claim.

```bash
python -m adobo.target --port 8001
```

| Endpoint | Purpose |
|---|---|
| `/healthz` | liveness check, exempt from all mitigations |
| `/api/data` | expensive simulated work (`--work-ms`) |
| `/stats` | the target's own counts |

**3. Run a profile:**

```bash
python -m adobo --host 127.0.0.1 --port 8001 \
                --profile http_flood --pps 2000 --duration 10 --workers 8
```

```
  sent to OS   1,210 packets (619,520 bytes)
  availability 100.0% over 35 probes (p95 38ms)
  target served 1,208 requests (0 errors)
  delivery     99.8% of packets sent reached the target
```

The sender counted 1,210, the target counted 1,208. They are allowed to differ — that is the point.

> Use port **8001**, not 8000. ADOBO auto-enables TLS on `443, 8443, 8080, 9443, 8000, 8888`, and a TLS client against a plaintext target fails with `WRONG_VERSION_NUMBER`. The target's own default is 8000, so this bites immediately.

## Nuclear mode

Runs every applicable profile in parallel.

```bash
python -m adobo --nuclear                        # 17 prompts
python -m adobo --nuclear --skip-reflector-prompts # 13 prompts, default reflector ports
```

Prompts, in order:

```
Target IP: 127.0.0.1
Port (for TCP/UDP profiles) [80]: 8001

--- Amplification Reflector Ports (auto-filled) ---   ← skipped with --skip-reflector-prompts
  DNS reflector port: 53
  NTP reflector port: 123
  CLDAP reflector port: 389
  SSDP reflector port: 1900
DNS reflector port [53]:
NTP reflector port [123]:
CLDAP reflector port [389]:
SSDP reflector port [1900]:

PPS per profile [500]:
Duration (s) [60]:
Use HTTP/2 for http_flood? (requires TLS, enables multiplexing) [y/N]:
Enable HTTP/1.1 keep-alive for http_flood? (higher throughput, delivery may overcount) [y/N]:
Use TLS/HTTPS for http_flood? (auto-enabled on port 443) [y/N]:
Worker threads per profile [200]:
Payload size (bytes) [512]:
Enable IP spoofing for raw profiles? (requires root/CAP_NET_RAW) [y/N]:
```

Answering **y** to the TLS prompt adds `Verify TLS certificates? [Y/n]:`.

Every value reaches the child processes. PPS and duration apply to **each** profile, not divided across them.

Profiles that cannot run are reported with the reason, never silently dropped. On Windows the four raw profiles always fail:

```
icmp_flood: never attempted a packet
  - TransportError('Linux raw sockets unavailable: Linux raw sockets are only
    available on Linux. Use scapy transport on Windows/macOS, ...')
```

The results table says **"Handed to OS"**, not "sent" — it counts packets given to the operating system, which is not confirmation of delivery. When the target's count cannot support a ratio, nuclear says so instead of dividing the numbers anyway.

Amplification profiles need a reflector you control. Nuclear probes the reflector port first and asks before continuing if it looks closed.

## Profiles & Transports

| Profile | Transports |
|---|---|
| `udp_flood` / `_ns` | socket, scapy, linux_raw, virtual |
| `syn_flood` / `_ns` | scapy, linux_raw |
| `icmp_flood` / `_ns` | scapy, linux_raw |
| `ack_flood` / `_ns` | scapy, linux_raw |
| `dns_` / `ntp_` / `cldap_` / `ssdp_amplification` | socket, scapy, virtual |
| `http_flood` | socket, scapy, virtual, h2 |
| `slowloris` | socket |

`_ns` variants are non-spoofed (real source IP) and need no privileges.

| Transport | Notes |
|---|---|
| `socket` (default) | no privileges needed |
| `scapy` | needs Npcap + Admin (Windows) or root (Linux) |
| `linux_raw` | root or CAP_NET_RAW, Linux only |
| `virtual` | **no network I/O at all** |
| `h2` | HTTP/2 over TLS with multiplexed streams |

### The virtual transport is a control

```bash
python -m adobo --host 127.0.0.1 --port 8001 \
                --profile http_flood --pps 1000 --duration 5 --transport virtual
```

Generates 5,000 packets, delivers none. The target's count does not move and **no delivery claim is printed** — because there is none to make. This is the falsification control: the harness can be shown not to fabricate numbers.

## Defenses

```bash
python -m adobo.target --port 8001 --defenses all
python -m adobo.target --port 8001 --defenses rate_limit,waf
```

`rate_limit`, `connection_cap`, `waf`, `circuit_breaker`, `challenge_page`.

> **The WAF runs with no rules by default.** `config/waf_rules.yaml` is not shipped and an absent file means an empty rule set. A `--defenses waf` run measures nothing until you write that file. `/stats` reports `rules_loaded` so you can tell which case you are in.

## TLS and HTTP/2

TLS auto-enables on `443, 8443, 8080, 9443, 8000, 8888`. HTTP/2 is **never** automatic — the socket transport cannot speak it, so `--http2` is required.

```bash
python -m adobo --host 127.0.0.1 --port 8443 --profile http_flood \
                --pps 2000 --duration 10 --http2 --h2-concurrency 100 \
                --tls --tls-no-verify
```

`--tls-no-verify` is for self-signed lab certs only.

> **Two limitations.** The prober builds a plaintext `http://` URL, so against an HTTPS target availability reads 0% and `/stats` cannot be read — take all availability and delivery evidence over plaintext. And end-to-end HTTP/2 against the local `adobo.target` does not complete; test HTTP/2 against a real server.

## What is actually verified

| Profile | Independent evidence |
|---|---|
| `http_flood` | **Yes** — counted by the target's `/stats` |
| `slowloris` | Partial — opens a connection, request never completes |
| all raw and amplification profiles | **No** — the target counts HTTP only |

**1 of 10 profiles has a fully witnessed delivery figure.** For the rest the tool reports packets handed to the OS and says plainly that this is not delivery. To evidence a non-HTTP profile, capture the traffic on the target host and count it there.

Availability is reported as two separate questions, because two different situations look identical from the sender's side: was there an HTTP surface at all, and did the target collapse. A run where every probe was refused means *"the target served no HTTP endpoint at any point"* — which is **not** evidence it failed under load. Silence is never read as death.

## Output

| File | Purpose |
|---|---|
| `results/<run_id>.json` | machine-readable result |
| `reports/<run_id>.html` | report with charts |
| `logs/audit.jsonl` | append-only audit trail |

## Configuration

| File | Purpose |
|---|---|
| `lab.yaml` | policy ceilings, allowlist, default target |
| `authorization.yaml` | dated authorisation record, must not be expired |
| `waf_rules.yaml` | WAF rules — **optional, absent by default** |

`lab.yaml` is the only place ceilings live, and runs are clamped down to them. No flag can raise them.

| Ceiling | Value |
|---|---|
| `max_pps` | 20,000 |
| `max_duration_seconds` | 60 |
| `max_payload_bytes` | 1,400 |
| `max_workers` | 200 |

## CI

The `virtual` transport needs no target, no network, and no listener:

```bash
python -m adobo --host 127.0.0.1 --port 8001 \
  --profile http_flood --pps 5000 --duration 30 --transport virtual --quiet
```

## Tests

```bash
python -m pytest tests/ -q
```

568 tests, covering the display and wiring bugs this tool has had: falsely asserted outages, a prober measuring the wrong thing, worker and payload values that were reported but never used, a UDP probe that hid a live web service, and a virtual transport that must never claim delivery.

## License

MIT — see `LICENSE`.

---

**Only send traffic to hosts you control or have written permission to test.**
