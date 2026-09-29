# ADOBO

---

# ⚠️  FOR EDUCATIONAL AND AUTHORISED RESILIENCE TESTING ONLY  ⚠️

**Any use against systems you do not own or have explicit written permission to test is illegal in most jurisdictions.**  
The author accepts **no responsibility** for misuse.

---

An authorised DDoS resilience lab: a tool for measuring how your services behave
under load, against hosts you own and have explicitly authorised.

ADOBO is built around one rule — **a number is only reported if something
independent confirms it.** The attack side counts what it handed to the OS; the
lab target counts what it actually served; the two are reconciled and printed
side by side. When they disagree, or when no independent number exists, the tool
says so instead of estimating.

## Installation

### Pre-built executable (Windows)
Download `ADOBO.exe` from the releases page. No dependencies, no install.

### From source (Python 3.11+)

```bash
git clone https://github.com/tant28403-svg/adobo.git
cd adobo
python -m adobo --help
```

No install step is required to run from the clone. If dependencies are missing
(Kali blocks system pip):

```bash
pip install pydantic pyyaml psutil pyfiglet httpx h2 cryptography
# or create a venv:
python -m venv .venv && source .venv/bin/activate && pip install -e .
```

Optional extras:

```bash
pip install -e .[raw]     # scapy transport (needs Npcap + Admin on Windows)
```

> **Linux raw sockets (no root):** the `linux_raw` transport uses native
> `AF_INET SOCK_RAW` and only needs `CAP_NET_RAW`:
> ```bash
> sudo setcap cap_net_raw+ep $(which python3)
> python -m adobo --host 10.0.0.7 --profile syn_flood --transport linux_raw --pps 5000 --duration 10
> ```

---

## Quick start

### 1. One-time setup

Two config files must be edited before anything can be sent. The shipped
`authorization.yaml` is **deliberately expired** so an unconfigured checkout is
inert.

```yaml
# config/authorization.yaml
expires_on: 2027-01-01        # must be a future date

# config/lab.yaml
allowed_cidrs:
  - "127.0.0.0/8"             # add your lab network deliberately
```

`lab.yaml` is the single source of truth for what runs are *permitted* to do.
Every value under `limits` is a hard ceiling — the engine clamps runs down to
them and no flag can raise them:

| Ceiling | Default |
|---|---|
| `max_pps` | 20,000 |
| `max_duration_seconds` | 60 |
| `max_payload_bytes` | 1,400 |
| `max_workers` | 200 |

### 2. Start the lab target

An attack on its own only proves packets were sent. The **lab target** is the
other half: a deliberately fragile HTTP service that keeps its own count, so a
run can be checked against an independent number instead of the sender's claim.

```bash
python -m adobo.target --port 8001
```

Verify it is up:

```bash
python -c "import httpx; print(httpx.get('http://127.0.0.1:8001/stats').json())"
# {'requests': 0, 'errors': 0, 'settings': {'defenses': [], 'work_ms': 6}}
```

> **Use 8001, not 8000, for a plain-HTTP target.** ADOBO auto-enables TLS on
> `443, 8443, 8080, 9443, 8000, 8888`. On one of those ports the attack side
> opens a TLS connection to a plaintext target and fails with
> `SSL: WRONG_VERSION_NUMBER`. The target's own default is 8000, so this trips
> people immediately — serving on 8000 requires a certificate
> (see [TLS and HTTP/2](#tls-and-http-2)).

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | cheap liveness check; exempt from every mitigation so the prober measures the target rather than the WAF |
| `GET /api/data` | the expensive one — simulated database work, tunable with `--work-ms` |
| `GET /stats` | the target's own counts, for corroborating the attack side |

### 3. Run one profile and read the result

```bash
python -m adobo --host 127.0.0.1 --port 8001 \
                --profile http_flood --pps 2000 --duration 10 --workers 8
```

Real output from that command:

```
=== Result ===
  resilience   90.0 / 100  (grade B)
  sent to OS   1,210 packets (619,520 bytes)
  throughput   120 pps
  availability 100.0% over 35 probes (p95 38ms)
  target served 1,208 requests (0 errors)
  delivery     99.8% of packets sent reached the target
```

`target served` and `delivery` come from the target's own `/stats`. That is the
line that makes the run a measurement rather than a claim. Note that the sender
counted 1,210 and the target counted 1,208 — the two are reported side by side
precisely because they are allowed to differ.

---

## Nuclear mode

Nuclear mode runs every applicable profile in parallel, as separate processes.

```bash
python -m adobo --nuclear
```

### The prompts, in order

With reflector prompts shown (17 total):

```
=== Nuclear Strike ===
Target IP: 127.0.0.1
Port (for TCP/UDP profiles) [80]: 8000

--- Amplification Reflector Ports (auto-filled) ---
  DNS reflector port: 53
  NTP reflector port: 123
  CLDAP reflector port: 389
  SSDP reflector port: 1900
  (Press Enter to use defaults, or enter custom values)
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

Answering **y** to the TLS prompt adds one more prompt:

```
Verify TLS certificates? (disable for self-signed certs) [Y/n]:
```

### Skipping the reflector prompts

```bash
python -m adobo --nuclear --skip-reflector-prompts
```

This takes **13 prompts** instead of 17 and uses the default reflector ports
(53 / 123 / 389 / 1900). Use it when you are not testing amplification against
reflectors you control.

### What the prompts actually do

Every value you enter reaches the child processes. This was not always true —
`workers` and `payload size` were collected and then discarded in favour of
hardcoded literals, so a run configured for 200 workers ran with 4 and said
nothing. It is now covered by tests in
`tests/test_nuclear.py::TestOperatorValuesReachTheChildren`.

| Prompt | Effect |
|---|---|
| PPS per profile | Applied to **each** profile, not divided across them |
| Duration | Applied to each profile |
| HTTP/2 | Selects the `h2` transport for `http_flood` |
| Keep-alive | Reuses connections; delivery may overcount if the target closes them |
| TLS / verify | Applied to `http_flood`; verification is on by default |
| Workers | Worker threads per profile (ceiling: `max_workers`, default 200) |
| Payload size | Bytes per packet (ceiling: `max_payload_bytes`, default 1,400) |
| Spoofing | Adds the spoofed raw variants; needs root/CAP_NET_RAW |

### What nuclear prints afterwards

Profiles that cannot run are reported with the reason, never silently dropped:

```
[!] Not running as Administrator or raw sending unavailable
   Skipping 4 raw profiles, running 6 socket profiles
```

The results table labels its column **"Handed to OS"**, not "sent". That
distinction is deliberate — it counts packets given to the operating system and
is not confirmation of delivery:

```
  'Handed to OS' counts packets given to the operating system. It is not
  confirmation of delivery: the target may have dropped them, been firewalled,
  or never received them at all.
```

When the target's count cannot support a delivery ratio, nuclear says so instead
of dividing the two numbers:

```
Target-side evidence (/stats, read by the target itself):
  requests served by target : 554
  No profile addressed this endpoint, so no delivery ratio can
  be formed. The served count above covers traffic from outside
  this run.
```

On Windows, the four raw profiles (icmp, syn, ack, and the spoofed variants)
cannot run at all and each reports why. That is a platform limit, not a silent
skip:

```
icmp_flood: never attempted a packet
  - TransportError('Linux raw sockets unavailable: Linux raw sockets are only
    available on Linux. Use scapy transport on Windows/macOS, ...')
```

### Amplification and reflectors

The four amplification profiles (`dns`, `ntp`, `cldap`, `ssdp`) need a reflector
you control. Nuclear probes the reflector port first and asks before continuing
if it looks closed. Without a valid reflector they send at low rate with no
amplification.

---

## Profiles & Transports

| Profile | Transports | Description |
|---------|------------|-------------|
| `udp_flood` / `udp_flood_ns` | socket, scapy, linux_raw, virtual | Raw UDP datagrams |
| `syn_flood` / `syn_flood_ns` | scapy, linux_raw | TCP SYN packets |
| `icmp_flood` / `icmp_flood_ns` | scapy, linux_raw | ICMP echo requests |
| `ack_flood` / `ack_flood_ns` | scapy, linux_raw | TCP ACK packets |
| `dns_amplification` | socket, scapy, virtual | DNS queries to open resolvers |
| `ntp_amplification` | socket, scapy, virtual | NTP time queries |
| `cldap_amplification` | socket, scapy, virtual | CLDAP search requests |
| `ssdp_amplification` | socket, scapy, virtual | SSDP M-SEARCH discovery |
| `http_flood` | socket, scapy, virtual, h2 | HTTP/1.1 GET requests |
| `slowloris` | socket | Partial HTTP requests (connection exhaustion) |

The `_ns` variants are non-spoofed (real source IP) and work without elevated
privileges. Spoofed variants require raw socket privileges.

**Transports:**

| Transport | What it is |
|---|---|
| `socket` (default) | standard UDP/TCP sockets, no privileges needed |
| `scapy` | raw L3/L4 crafting; needs Npcap + Admin (Windows) or root/CAP_NET_RAW (Linux) |
| `linux_raw` | native `AF_INET SOCK_RAW`; root or CAP_NET_RAW, Linux only |
| `virtual` | **no network I/O at all** — counters only |
| `h2` | HTTP/2 over TLS with multiplexed streams (requires `h2`) |

### The virtual transport is a control, not a feature

`--transport virtual` generates the packets it is asked to generate and delivers
**none** of them:

```bash
python -m adobo --host 127.0.0.1 --port 8001 \
                --profile http_flood --pps 1000 --duration 5 --transport virtual
```

The target's `/stats` count does not move, and the tool prints **no delivery
claim** — because it has none to make. That is the falsification control: the
harness generates 5,000 packets and correctly reports that none were delivered.

---

## TLS and HTTP/2

TLS is enabled automatically on common HTTPS ports
(`443, 8443, 8080, 9443, 8000, 8888`). HTTP/2 is **never** auto-enabled — the
socket transport cannot speak it, so it must be requested explicitly.

```bash
# HTTPS, HTTP/1.1
python -m adobo --host 127.0.0.1 --port 8443 --profile http_flood \
                --pps 2000 --duration 10 --tls --tls-no-verify

# HTTPS, HTTP/2 with 100 multiplexed streams per connection
python -m adobo --host 127.0.0.1 --port 8443 --profile http_flood \
                --pps 2000 --duration 10 --http2 --h2-concurrency 100 \
                --tls --tls-no-verify
```

Serve a matching target:

```bash
python -m adobo.target --port 8443 --generate-cert \
                --ssl-certfile cert.pem --ssl-keyfile key.pem --http2
```

Serve a matching target:

```bash
python -m adobo.target --port 8443 --generate-cert \
                --ssl-certfile cert.pem --ssl-keyfile key.pem --http2
```

`--tls-no-verify` is for self-signed lab certificates only. Never point it at a
third-party host.

> **The prober does not speak TLS.** The attack side negotiates TLS correctly
> and does deliver packets to an HTTPS target, but `TargetObserver` builds a
> plaintext `http://` URL (`adobo/observation.py:117`). Against an HTTPS target
> that means availability reports **0%** and the target's `/stats` cannot be
> read, so there is **no independent evidence for HTTPS runs**. The 0% is a
> measurement failure, not an outage.
>
> Until the prober learns TLS, **take availability and delivery evidence over
> plaintext HTTP**. Use the TLS and HTTP/2 paths for attack-surface coverage,
> not for measurement.

> **Known limitation:** the HTTP/2 client works against real internet servers,
> but end-to-end HTTP/2 against the local `adobo.target` does not currently
> complete — the target's SETTINGS exchange fails. Test HTTP/2 against a real
> server, and treat local HTTP/2 as unimplemented.

---

## Defenses

Enable mitigations on the target and measure their effect:

```bash
python -m adobo.target --port 8000 --defenses all
python -m adobo.target --port 8000 --defenses rate_limit,waf
```

| Defense | What it simulates |
|---------|-------------------|
| `rate_limit` | Token-bucket rate limiting |
| `connection_cap` | Max concurrent connections |
| `waf` | Request inspection/blocking |
| `circuit_breaker` | Trips on error rate |
| `challenge_page` | Interstitial challenge |

> **The WAF runs with no rules by default.** `config/waf_rules.yaml` is not
> shipped, and `load_waf_rules` treats an absent file as an empty rule set — a
> legitimate, if useless, configuration. A `--defenses waf` run measures
> nothing unless you write that file first. The target reports
> `rules_loaded` in `/stats` so you can confirm which case you are in.

---

## Reading results

Every run produces:

| File | Format | Purpose |
|------|--------|---------|
| `results/<run_id>.json` | JSON | machine-readable complete result |
| `reports/<run_id>.html` | HTML | human-readable report with charts |
| `logs/audit.jsonl` | JSONL | append-only audit trail |

Run `python -m adobo --help` to see your resolved config and output directories.

### Availability is reported as two separate questions

The tool does not collapse "the target stopped answering" into a single
availability percentage, because two very different situations look identical
from the sender's side:

- **Was there an HTTP surface at all?** If every probe was refused, the honest
  reading is *"the target served no HTTP endpoint at any point in the run"* —
  which is **not** evidence that it failed under load.
- **Did the target collapse?** Answered separately, from refusal-versus-timeout
  counts.

Silence is also never read as death. A run with no probes answered and none
refused says exactly that, and no more.

### What is and is not independently verified

| Profile | Independent evidence |
|---|---|
| `http_flood` | **Yes** — counted by the target's `/stats` |
| `slowloris` | Partial — opens a real connection, but the request never completes |
| `udp_flood`, `syn_flood`, `icmp_flood`, `ack_flood` | **No** — the target counts HTTP only |
| `dns_`, `ntp_`, `cldap_`, `ssdp_amplification` | **No** — same reason |

So 1 of 10 profiles has a fully witnessed delivery figure. For the others the
tool reports *packets handed to the OS* and says plainly that this is not
confirmation of delivery. If you need delivery evidence for a non-HTTP profile,
capture the traffic on the target host and count it there.

---

## Configuration

| File | Purpose |
|---|---|
| `lab.yaml` | policy ceilings, allowlist, default target, lab ID |
| `authorization.yaml` | dated authorisation record (must not be expired) |
| `waf_rules.yaml` | WAF rules — **optional, absent by default** |

`lab.yaml` is the only place ceilings live. The Python model defaults
(`max_workers: 8`, `max_pps: 20_000`) are a fallback used only when no
`lab.yaml` is present — the shipped file is what applies in practice.

---

## CI Example

The `virtual` transport makes a hermetic run that needs no target, no network
and no listener:

```yaml
# .github/workflows/resilience.yml
- name: Resilience test
  run: |
    python -m adobo --host 127.0.0.1 --port 8001 \
      --profile http_flood --pps 5000 --duration 30 \
      --transport virtual --quiet
```

To assert on the result, read the JSON rather than scraping stdout:

```bash
python -c "
import json, pathlib, sys
run = sorted(pathlib.Path('results').glob('*.json'))[-1]
r = json.loads(run.read_text())
sys.exit(0 if r['score']['total'] >= 80 else 1)
"
```

Note `--defenses` is a **target-side** flag: it configures the service being
attacked, so it only applies together with `--serve-target` or
`python -m adobo.target`. It is not an attack-side option.

## Tests

```bash
python -m pytest tests/ -q
```

564 tests, including the regression cases for the display and wiring bugs this
tool has had: falsely asserted outages, a prober that measured the wrong thing,
worker and payload values that were reported but never used, and a virtual
transport that must never claim delivery.

## License

MIT — see `LICENSE` for details.

---

**Remember:** only send traffic to hosts you control or have written permission
to test. Unauthorised testing is illegal in most jurisdictions.
