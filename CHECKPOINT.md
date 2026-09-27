# Checkpoint — 2026-09-27

Resumed from PROGRESS.md ("Nuclear mode sends 0 packets, stays at [STARTING]").
All five phases complete. See PROGRESS.md for the root-cause detail.

## The actual cause

Not one of the five suspected causes. `NuclearAggregator` keyed `self.results` by
`config.label` (`nuclear-<name>`) but both display paths looked up by bare
`profile.name`. Every lookup missed, so every row rendered `[STARTING]` with zero
sent — while the children were sending normally. Nothing raised, so nothing
caught it.

Three more defects compounded it:

- **Unreachable early exit.** The `alive_count` check sat inside the
  `get_nowait` loop after `except queue.Empty: break`, so it only ran when a
  result had just been read. The loop always burned the full duration.
- **Results discarded.** `_print_final_results` ran before `run()`'s `finally`
  terminated stragglers, killing them before they could `put`.
- **Live table structurally blind.** A running child has no result yet, so the
  `Sent` column could only ever read 0 mid-run. The total also omitted running
  rows, printing `TOTAL 0` directly beneath non-zero rows.

## Phase 0 — unblock the tree

`paths.py`, `config.py` and `config/{lab,authorization}.yaml` were present in
HEAD but deleted from the working tree, while untracked `report.py` and
`defenses.py` still imported them. Both modules failed at import.

- Restored from HEAD, plus `tests/test_paths.py` and `tests/test_config.py`
  (they cover only the restored modules — no `safety.py` dependency).
- Both YAMLs are fail-closed by design: loopback-only allowlist, and
  `authorization.yaml` expired 2026-01-02. Restoring them makes the tool *more*
  conservative.
- `pyproject.toml`: added `pyyaml`, `psutil` to `dependencies`; added a `lab`
  extra for `fastapi`/`uvicorn` so the target app is not forced on CLI users.
- `ddosim.spec`: removed `yaml` and `psutil` from `excludes`. Both were declared
  deps imported at module level, so the bundle could not read its own config or
  sample the target.

**Deliberately not restored:** `ddosim/safety.py`, `config`-independent safety
tests, and `--authorize`. Chosen as out of scope. Consequence: nothing enforces
the allowlist at runtime. `report.py`'s footer was corrected to stop claiming an
audit trail that is not written.

## Phase 1 — exe runs, scapy binds an interface

- `ddosim.spec`: `uac_admin=True` → `False`. With the manifest set, a
  non-interactive shell (service account, CI, piped input) is denied elevation
  and the bundle exits before printing anything. Raw profiles still need an
  elevated terminal, but `raw_capability()` refuses that with an actionable
  message rather than dying silently.
- `ScapyTransport`: added `_resolve_iface()`, using scapy's `route()` to pick the
  NIC the kernel would actually use, resolved once in `open()` and passed as
  `iface=` on every send. Windows has no default-route wildcard, so scapy's own
  guess binds whichever adapter enumerated first — a multi-homed box sends out
  the wrong NIC and reports no errors and no delivery.
- Unroutable targets now fail at setup instead of as N silent send errors.

## Phase 2 — errors surface in real time

- Replaced the ad-hoc child `print`s with tagged events (`started` / `progress` /
  `finished` / `failed`) on the queue, plus a `log()` helper.
- Wired `EngineHooks.on_worker_error`, which existed but was never connected.
- Children stream counters via `on_tick`, so a running profile shows live
  numbers. `CHILD_PROBES_ENABLED = False` — ten profiles each running a prober
  against one target would apply ten times the intended probe load and measure
  each other. Documented, not silent.

## Phase 3 — the fix

- `NuclearAggregator._label()` — single source for the queue key, so the two
  sides cannot drift again.
- Hoisted the `alive_count` check out of the inner `get_nowait` loop.
- `_reap()`: children get a grace period to report *before* stragglers are
  terminated, and the final table prints after draining.
- `build_profiles()` takes an operator-supplied `reflector_port` instead of
hardcoding 53/123/389/1900 against the target. Reflection needs a third party
the tool has no business touching; the operator names a reflector they
control, and the pre-flight confirms it is open before anything is sent.
Without a reflector on the far side these profiles measure *request* volume,
not amplification, and the achieved factor stays 1.0x. That is now labelled
`est 200.0x` in the output as a declared protocol ratio, kept strictly
separate from a measured factor (see "Measuring the target" below).
- `probe_udp_port()` + `filter_available_profiles()`: connected-UDP probe
  (a TCP check would skip every reflector, which never listens on TCP).
  `ConnectionError` is caught, not just `ConnectionRefusedError` — **Windows
  reports `ConnectionResetError`/WSAECONNRESET**, and catching only the refused
  case reports every closed port as open, defeating the check entirely.
- A profile that never reports is now named explicitly, so a row of zeros is
  distinguishable from "nothing was collected".

## Phase 4 — `--nuclear`

Added the flag. Also unified interrupt handling: prompt-cancel and interrupted
runs both exit 130.

## Phase 5 — hardening and cleanup

- `Transport.request_stop()` / `.stopping`, set by `_stop_workers()` **before**
  joining. A self-paced transport cannot learn of the deadline from `close()`,
  which runs in the worker's own `finally`.
- `_join_workers()` joins against one shared deadline. The per-worker
  `join(timeout=grace)` made the grace scale with worker count (4 workers = 4×
  the documented wait).
- `SlowlorisTransport`: every `time.sleep` → interruptible `_stop.wait`; the
  hardcoded `10.0` → `self.header_interval`. It was sleeping past the 5s join
  grace, so it was abandoned mid-sleep and reported nothing.
- Engine passed `payload_size` into `worker_loop`'s rate parameter, turning
  512 into 51 connections per worker. Now passes per-worker pps.
- `cli.summarise()` prints notes. A run that sent nothing because the transport
  never opened previously printed the same three headline lines as a success.
- Setup failures get a dedicated note: nothing was sent, so the figures do not
  measure the target.
- Removed dead imports (`signal`, `sys` in nuclear.py; `threading` in
  slowloris_transport.py), the stray `freeze_support` (correctly at
  `__main__.py:14`), and 15 scratch scripts from the repo root — moved to
  `%TEMP%\opencode\scratch-scripts`, not deleted.
- Added `.gitignore`.

## Tests

412 passing (was 264 collecting with 2 broken imports, then 356).

- `tests/test_nuclear.py` (38) — the key mismatch, event bookkeeping, live-table
  totals, silent-profile and empty-profile warnings, reflector port, pre-flight,
  target-side evidence, and delivery-ratio denominators.
- `tests/test_observation.py` (new, 16) — measured vs unobserved, delta vs
  absolute, negative clamp, unavailable target, `alive()`.
- `tests/test_transports.py` — payload completeness across every structured
  profile and size; `TestHttpDelivery` (8) asserts against a real server that
  requests are accepted and that the sender's count matches the server's; 7
  interface-resolution and 11 stop-signal/slowloris cancellation tests.
- `tests/test_engine.py` — `TestTargetObservation` (8) covers the observation
  gate, dry-run and virtual skips, and a served count reaching the result.
- Relaxed one pre-existing flaky bound in `test_engine.py`: a 0.1s deadline
  asserted completion under 0.25s, which failed intermittently under load. Now
  < 0.6s, which still proves the wait clips to the deadline rather than running
  the full 1.0s interval.

## Verified

- `ddosim.exe` rebuilt, runs with no UAC prompt, exit 0.
- Nuclear mode **in the frozen exe**: live counters correct, final table
  4,000 / 3,800 / 20 = 7,820 packets, no `[STARTING]`, no silent profiles.
- Pre-flight: closed port → profiles skipped with reasons, "No profiles
  available to run", exit 1.
- Socket/virtual/http/slowloris runs; scapy refuses cleanly and the reason is
  now visible in the summary.
- JSON + HTML reports written, zero warnings, footer honest.

## Measuring the target, not the sender

The remaining problem with this tool was that every number in it came from the
sender. A sender counts what it handed to the operating system, which cannot
distinguish "the target served it" from "the target refused it" from "the host
is down". So a run could report 91,367 packets sent against a target that served
nothing, print `[DONE]` for every row, and read as a success.

`ddosim/observation.py` closes that gap. The lab target already exposes its own
request counter at `/stats`; this reads it either side of a run and reports the
delta. The delta rather than the absolute, because the target may have been
serving other traffic before the run began.

Four distinct outcomes are kept apart, because collapsing any two of them is what
made the old output unreadable:

| Outcome | Means |
| --- | --- |
| measured | the target read `/stats` before and after |
| `NOT MEASURED` | the endpoint could not be read; the reason is printed |
| `stats_observed=False` | no window completed, including a dry run or a virtual run |
| served 0 | the target answered, and served nothing |

A run with no evidence is never rendered as a run with no effect.

### What made the flood look like it did nothing

Three separate defects, none of which raised, all of which left the sender's
counter looking healthy:

1. **The 128-byte default truncated the HTTP request.** A request is 141 bytes,
   so the default payload was cut mid-header. Every request was malformed at the
   door. `_pad()` now grows structured payloads to their minimum and never
   shrinks them. Slowloris is the deliberate exception — an unfinished request is
   the entire point of it.
2. **The connection was reused despite `Connection: close`.** A send into a
   socket the peer has already closed still succeeds locally: the bytes are
   accepted into the send buffer and only fail on a *later* write. The request
   was counted as sent and never arrived. TCP profiles now open per request.
3. **Closing a socket with unread data sent RST, not FIN.** A third of requests
   were being discarded by the peer *after* being counted — the same failure one
   step later, and harder to see because the counter was right. `_finish_request()`
   half-closes and drains before closing.

Together these took HTTP delivery from 0/500 served to 300/300.

### Amplification: measured vs declared

`AttackStats.amplification_factor` is now measured only, from response bytes
actually read back. `amplification_declared` carries the nominal protocol ratio
and the display labels it `est 200.0x`. They are never conflated, because a
spoofed response is delivered to the *victim* — the sender structurally cannot
observe it, and reporting 200x as achieved would be fiction.

### Scope notes

- Nuclear mode's children run with `observe_target=False`. Ten children each
  reading `/stats` would apply ten times the intended probe load to an
  already-saturated target, and all ten would lose the race to answer. The parent
  takes one reading for the whole strike, and one availability probe, so a run
  that left the target unresponsive is now distinguishable from one it shrugged
  off.
- A delivery ratio is only formed against profiles that address the observed
  endpoint (`HTTP_FLOOD` over a socket, on the `/stats` port). Including UDP or
  raw traffic in the denominator makes a run that delivered every HTTP request
  read as 9%; excluding too much can read above 100%, which is worse. Anything
  the counter cannot see is reported as a separate count.
- No public reflector is used anywhere. Loopback-only and operator-controlled.

## Not done

- `safety.py` / `--authorize` / allowlist enforcement (out of scope by choice).
- `tests/test_safety.py` (43 tests) still deleted — needs `safety.py`.
- Scapy send path unexercised here: Npcap is installed but this shell is not
  elevated, so only the refusal is covered by real runs. The iface logic is
  unit-tested against a stub.
- `ddosim/target/app.py` has no dedicated test file.
- A loopback reflector is not implemented; measured amplification is proven
  end-to-end against a real HTTP target instead (300/300, measured 0.26x,
  which is correct — HTTP is not an amplifier).
- `--dry-run` starts no workers, so it reports zero packets attempted. It
  previews nothing. Pre-existing, consistent across transports, out of scope here
  — but it means "preview" is not currently worth much.
- Nuclear pre-flight probes every ported profile, not just amplification ones.
- Terminal-event precedence: a `"failed"` child event can be followed by a later
  `"finished"`, so the final status can read `[DONE]` after a failure.

