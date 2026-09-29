# ADOBO

## ⚠️  FOR EDUCATIONAL AND AUTHORISED RESILIENCE TESTING ONLY  ⚠️

**Only use against systems you own or have explicit written permission to test. Unauthorised testing is illegal in most jurisdictions.**

The author accepts **no responsibility** for misuse.

---

An authorised DDoS resilience lab: measures how your services behave under load.

## Download

Python 3.11+ required.

```bash
git clone https://github.com/tant28403-svg/adobo.git
cd adobo
```

If dependencies are missing:

```bash
pip install pydantic pyyaml psutil pyfiglet httpx h2 cryptography
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

`udp_flood` · `syn_flood` · `icmp_flood` · `ack_flood` · `http_flood` · `slowloris` · `dns_amplification` · `ntp_amplification` · `cldap_amplification` · `ssdp_amplification`

```bash
python -m adobo --host 127.0.0.1 --port 8001 --profile <name> --pps 2000 --duration 10
```

### Nuclear mode

Every applicable profile in parallel.

```bash
python -m adobo --nuclear
```

It asks 12 questions:

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

Two questions aren't asked, because there was no decision to make:

**Reflector ports** use the well-known service ports (53 / 123 / 389 / 1900).

**Worker threads** use the `max_workers` ceiling, so every profile runs with
200 by default.

| Question | What it does |
|---|---|
| PPS / Duration | Applied to **each** profile, not divided across them |
| Workers | Per profile. Ceiling is `max_workers` (200) |
| Payload | Bytes per packet. Ceiling is 1,400 |
| IP spoofing | Adds the spoofed variants. Needs root |

Profiles that can't run are reported with the reason, never dropped silently. On Windows the four raw profiles always fail:

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
| `--transport` | auto | `socket` · `scapy` · `linux_raw` · `virtual` · `h2` |
| `--tls` | auto on HTTPS ports | `--tls-no-verify` for self-signed certs |
| `--http2` | off | also `--h2-concurrency N` |

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
| Throughput | none |
| Duration | 60 seconds |
| Payload | 1,400 bytes |
| Workers | 200 |

## Tests

```bash
python -m pytest tests/ -q
```

## License

MIT — see `LICENSE`.

---

**Only send traffic to hosts you control or have written permission to test.**
