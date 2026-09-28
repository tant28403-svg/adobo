# ADOBO

---

# ⚠️  FOR EDUCATIONAL AND AUTHORISED RESILIENCE TESTING ONLY  ⚠️

**Any use against systems you do not own or have explicit written permission to test is illegal in most jurisdictions.**  
The author accepts **no responsibility** for misuse.

---

Authorised DDoS resilience lab. A tool for measuring how your services behave under load — only against hosts you own and have explicitly authorised.

## Installation

### Pre-built executable (Windows)
Download `ADOBO.exe` from the releases page. No dependencies, no install.

### From source (Python 3.11+)
```bash
# From PyPI
pip install adobo
# or with raw-socket support (needs Npcap + Admin on Windows):
pip install adobo[raw]

# From a local clone (Linux / macOS / Windows)
git clone https://github.com/<your-org>/adobo.git
cd adobo
pip install -e .              # editable install
# or with raw transport (scapy):
pip install -e .[raw]
```

> **Linux raw sockets (no root):** The `linux_raw` transport uses native `AF_INET SOCK_RAW` and only needs `CAP_NET_RAW`:
> ```bash
> sudo setcap cap_net_raw+ep $(which python3)
> ADOBO --host 10.0.0.7 --profile syn_flood --transport linux_raw --pps 5000 --duration 10
> ```

## Quick start

### 1. One-time setup
Edit `config/authorization.yaml` — set `expires_on` to a future date  
Edit `config/lab.yaml` — add your lab CIDR to `allowed_cidrs`

### 2. Run the wizard
```bash
ADOBO
```

It prompts exactly this:
```
Target IP: 10.0.0.7
Port (for TCP/UDP profiles) [80]: 80

--- Amplification Reflector Ports (auto-filled) ---
  DNS reflector port [53]: 
  NTP reflector port [123]: 
  CLDAP reflector port [389]: 
  SSDP reflector port [1900]: 
  (Press Enter to use defaults, or enter custom values)

PPS per profile [500]: 5000
Duration (s) [60]: 30
Enable IP spoofing for raw profiles? (requires root/CAP_NET_RAW) [y/N]: n
```

### 3. Read results
```
Results: %ADOBO_HOME%\results\<run_id>.json    (Windows)
         ~/.local/share/adobo/results/...       (Linux/macOS)

Report:  %ADOBO_HOME%\reports\<run_id>.html    (Windows)
         ~/.local/share/adobo/reports/...       (Linux/macOS)

Run `ADOBO --help` to see your resolved config/output directories.
```

## Profiles & Transports

| Profile | Transports | Description |
|---------|------------|-------------|
| `udp_flood` / `udp_flood_ns` | socket, scapy, linux_raw, virtual | Raw UDP datagrams |
| `syn_flood` / `syn_flood_ns` | scapy, linux_raw | TCP SYN packets |
| `icmp_flood` / `icmp_flood_ns` | scapy, linux_raw | ICMP echo requests |
| `ack_flood` / `ack_flood_ns` | scapy, linux_raw | TCP ACK packets |
| `dns_amplification` | socket, scapy, virtual | DNS queries to open resolvers |
| `ntp_amplification` | socket, scapy, virtual | NTP monlist/time queries |
| `cldap_amplification` | socket, scapy, virtual | CLDAP search requests |
| `ssdp_amplification` | socket, scapy, virtual | SSDP M-SEARCH discovery |
| `http_flood` | socket, scapy, virtual | HTTP/1.1 GET requests |
| `slowloris` | socket | Partial HTTP requests (connection exhaustion) |

**Transports:**
- `socket` (default) — standard UDP/TCP sockets, no privileges needed
- `scapy` — raw L3/L4 crafting, needs Npcap + Admin (Windows) or root/CAP_NET_RAW (Linux)
- `linux_raw` — native `AF_INET SOCK_RAW`, needs root or CAP_NET_RAW (Linux only)
- `virtual` — no network I/O, counters only (for CI/tests)

## Defenses

Enable mitigations on the target to measure their effect:
```bash
ADOBO --host 10.0.0.7 --defenses waf,rate-limit,circuit-breaker ...
```

| Defense | What it simulates |
|---------|-------------------|
| `rate-limit` | Token-bucket rate limiting |
| `connection-cap` | Max concurrent connections |
| `waf` | Request inspection/blocking |
| `circuit-breaker` | Trip on error rate |
| `challenge-page` | Interstitial challenge |

## Configuration

Config files live in `%ADOBO_HOME%\config\` (or `~/.config/adobo/` on Linux/macOS):

- `lab.yaml` — policy ceilings, default target, lab ID, allowlist
- `authorization.yaml` — dated authorisation records (must not be expired)
- `waf_rules.yaml` — WAF rule definitions

Run `ADOBO --help` to see the resolved config directory.

## Output

Every run produces:
| File | Format | Purpose |
|------|--------|---------|
| `results/<run_id>.json` | JSON | Machine-readable complete result |
| `reports/<run_id>.html` | HTML | Human-readable report with charts |
| `logs/audit.jsonl` | JSONL | Append-only audit trail |

JSON result includes: `attack` (packets sent, throughput, amplification), `probe` (availability %, latency p50/p95/p99), `score` (0–100 resilience grade), `target_stats` (CPU, memory, threads), `notes` (policy adjustments, warnings).

## CI Example

```yaml
# .github/workflows/resilience.yml
- name: Resilience test
  run: |
    ADOBO --host 127.0.0.1 --profile udp_flood --pps 5000 --duration 30 \
      --transport virtual --defenses rate-limit --yes
    python -c "
import json, sys
with open('results/latest.json') as f:
    r = json.load(f)
sys.exit(0 if r['score']['total'] >= 80 else 1)
"
```

## License

MIT — see `LICENSE` for details.

---

**Remember:** Only send traffic to hosts you control or have written permission to test. Unauthorised testing is illegal in most jurisdictions.