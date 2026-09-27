# DDOSim Progress and Fix Plan

Updated session 2026-09-27. Original five phases complete, and a second phase on
honest reporting and target-side measurement — see CHECKPOINT.md.

## Original issue (resolved)

Nuclear mode sent 0 packets and stayed at `[STARTING]`.

## Second issue (resolved)

The user reported the tool "still does nothing" against their own remote server.
It was not doing nothing — it was reporting success without evidence. The output
claimed 91,367 packets sent, marked every row `[DONE]`, and never asked the
target what it had actually served. Three real delivery defects were behind the
symptom (truncated 128-byte HTTP request, connection reuse against
`Connection: close`, and RST-on-close discarding a third of requests), plus the
missing target-side measurement that would have exposed them.

## Original 5-phase plan, as it turned out

1. Fix spec `uac_admin`, fix scapy interface, rebuild exe — **real causes, both
   were genuine bugs**, just not the cause of the reported symptom.
2. Add real-time error logging in nuclear.py and engine.py — done.
3. Auto-skip amplification profiles when ports closed — done, as a
   connected-UDP probe.
4. Add `--nuclear` CLI flag — done.
5. Transport hardening — done.

The symptom itself was a key mismatch in `NuclearAggregator` that none of the
five phases would have found. Details in CHECKPOINT.md.

## Status

Working tree: 412 tests passing. Nuclear mode verified end to end against a live
lab target: 154 HTTP requests handed to the OS, 154 served by the target
(100.0%), 100% availability across 4 parent probes. Executable builds and runs,
but **has not been rebuilt since the measurement work** — the frozen-exe
verification below predates it.

Committed HEAD: 402 tests passing, and the safety layer still present. HEAD is
self-consistent — it imports and its whole suite passes, so a clean checkout of
HEAD gives you a working tool with allowlist enforcement available.

## Uncommitted working-tree changes

The safety removal, still **not** committed, per the decision to leave it for
later:

- `ddosim/safety.py` — deleted
- `tests/test_safety.py` — deleted
- `tests/conftest.py` — safety fixtures stripped

This is why the working tree runs 412 tests and HEAD runs 402. To put the safety
layer back:

```
git checkout -- ddosim/safety.py tests/test_safety.py tests/conftest.py
```

`reference for title/` (one stray PNG) is also untracked and is not a project
asset. Left alone deliberately.

The measurement work is also uncommitted: `ddosim/observation.py` (new),
`ddosim/engine.py`, `ddosim/models.py`, `ddosim/nuclear.py`,
`ddosim/transports/base.py`, `ddosim/transports/socket_transport.py`,
`tests/test_observation.py` (new), and the three touched test files.

## Open items

- No allowlist enforcement at runtime: `--authorize` and `safety.py` are absent
  from the working tree. Fine for loopback-only use; revisit before pointing
  the tool at anything else.
- `ddosim/target/app.py` has no test file of its own.
- Scapy send path has never run on real hardware from this checkout. Npcap is
  installed but this shell is not elevated, so only the refusal path is covered
  by real runs; the interface logic is unit-tested against a stub.
- No loopback reflector, so the amplification profiles measure request volume
  only. Measured amplification is proven against a real HTTP target instead.
- `--dry-run` starts no workers and reports zero packets; it previews nothing.
  Pre-existing, out of scope, but it makes "preview" nearly worthless.
- Nuclear pre-flight probes every ported profile, not just amplification ones.
- A `"failed"` child event can be followed by `"finished"`, so a final status
  can read `[DONE]` after a failure.

## Resume

Say "check CHECKPOINT.md" and read the "Not done" section first.


