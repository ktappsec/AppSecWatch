# Ticket: Stream httpx output so a mid-scan block is observable and partial results survive

**Type:** robustness / observability
**Area:** engine — recon (`recon.httpx`), subprocess plumbing
**Priority:** high (highest-value robustness fix outstanding)
**Effort:** medium
**Status:** IMPLEMENTED 2026-07-21 (`stream_tool` + `-probe` + `ProbeProgress`/
`ProbeCoverage`; tests in `tests/test_probe_streaming.py`). Remaining follow-ups
are listed under "Not done" at the end.

## Problem

When a hardened target's edge blocks our source IP **during the httpx phase**, the
scan gives no live signal and loses all work:

1. **No observability during the block.** httpx runs as ONE batch subprocess over
   every live FQDN, and `run_tool` reads it with `communicate()`, which buffers to
   EOF. Nothing is parsed until the process fully exits, so the stage sits on a
   single `await` with no per-host progress. The UI shows "running"; the log shows
   the `running httpx` line and then silence until the process ends.
2. **A silent-drop block is invisible until too late.** The real-world block is a
   blackhole (`curl` → `code=000`, no HTTP response), not a 403. httpx does not
   error — each remaining host just hangs to its `-timeout` (10s), one after
   another at low thread count, against a dead network, until either the list
   finishes or the outer `budget` deadline fires.
3. **A timeout kill discards everything.** On the `budget` deadline `run_tool`
   raises `TimeoutError` and SIGKILLs the process group; because parsing happens
   only after exit, **every host successfully probed before the block is thrown
   away too.** The stage records a bare `recon.httpx / TimeoutError` and
   `live_servers` stays empty.
4. **"0 live servers" is ambiguous.** `LivenessGateStage` then sets
   `degraded=true`, but a blocked probe is indistinguishable from a target that
   genuinely has no web servers. There is no attribution — the operator has to
   open a separate browser tab to discover they were blocked.

This is the same buffering defect behind the throttle investigation
(commit `607a1ed`) and the `degraded`/scaled-`budget` workarounds. Note the tlsx
edge-concurrency fix (also `607a1ed`) reduces *how often* we get blocked; it does
nothing for observability once a block happens. The `rate_limit_signal` warning in
`web_probe.py` only fires **after** a completed pass and only for hosts that
returned an HTTP 403/429/503 — a blackhole never reaches it.

## Current code (read these first)

- `appsecwatch/recon/web_probe.py:76-112` — `run_httpx`: builds the batch cmd,
  `res = await run_tool(cmd, stdin=payload, ...)`, then `parse_httpx_records(
  res.stdout...splitlines())` **after** exit. httpx already emits `-json` (JSONL),
  so the output is line-delimited and ready to stream; only the plumbing buffers.
- `appsecwatch/util/subproc.py:~33` — `run_tool` uses
  `await asyncio.wait_for(proc.communicate(input=stdin), timeout=timeout)`; on
  `TimeoutError`/`CancelledError` it `_kill_process_group(proc)` and re-raises.
  This is the buffering point. A streaming variant is needed here (or a sibling).
- `appsecwatch/stages/recon.py:91-115` — `HttpxStage`: computes the scaled
  `budget = max(600, len(fqdns)/threads * timeout * 1.5)`, calls `run_httpx`, sets
  `state.live_servers` / `state.page_signals` wholesale.
- `appsecwatch/stages/suppress_stage.py` (`LivenessGateStage`) — the degraded-run
  detector; keys on `state.live_servers` being empty despite live assets.
- `appsecwatch/recon/web_probe.py:parse_httpx_records` — the pure parser; already
  takes an iterable of lines, so it can be fed incrementally.

## Proposed approach

Add a **streaming** subprocess path and consume httpx's stdout line-by-line as it
arrives, instead of `communicate()`-to-EOF.

1. **Streaming primitive in `util/subproc.py`.** Add `run_tool_streaming(...)` (or
   a `stream=True` mode) that yields decoded stdout lines as the process emits
   them (`async for line in proc.stdout`), preserves the existing invariants:
   process-group kill on timeout/`CancelledError` (`start_new_session=True`), the
   same timing/label logging, and the SIGKILL-on-cancel contract. Keep the
   buffered `run_tool` for every other caller — only httpx (and later nuclei/dnsx)
   need streaming.

2. **Incremental parse + persistence in `run_httpx`.** Parse each JSONL line as it
   arrives; append to `01_recon/httpx.jsonl` incrementally (flush per line or small
   batch) so partial results are on disk even if the process is later killed.
   Accumulate `live` / `signals` in memory as today. On timeout/kill, RETURN what
   was collected so far instead of discarding it — a partial pass is strictly
   better than zero.

3. **Live-progress + block detection.** Track "time since last live host / last
   line". Emit a progress event (reuse `RunLogger`, and surface via `ScanState` so
   the Web API poller shows it) as hosts resolve. When the stream goes quiet for
   an abnormal stretch while hosts remain unprobed — the blackhole signature —
   log a distinct `event="probe_stalled"` / mark a `state` flag so the block is
   attributable in real time, not inferred from a final zero.

4. **Sharpen the degraded signal.** With partial results + a stall signal,
   `LivenessGateStage` (and `degraded_reason`) can distinguish "edge blocked us
   mid-pass after N hosts" from "target has no web servers". Update the reason
   string / add a field accordingly. Consider retiring or relaxing the scaled
   `budget` hack in `recon.py` once a stalled stream is detectable and partial
   results survive.

## Acceptance criteria

- [ ] httpx output is parsed and persisted **incrementally**; killing the process
      mid-pass keeps the hosts already probed (assert: partial `httpx.jsonl` +
      non-empty `live_servers` after a simulated mid-stream timeout).
- [ ] A stalled/blocked probe produces a distinct, timestamped signal
      (`event="probe_stalled"` or equivalent) **while the stage is still running**,
      not only in the post-hoc summary.
- [ ] `degraded_reason` distinguishes a mid-pass block from a genuinely
      server-less target.
- [ ] The process-group-kill-on-cancel / on-timeout contract is preserved
      (`CancelledError` still SIGKILLs the tree and unwinds); a Web-API `/cancel`
      mid-httpx still renders a partial report.
- [ ] The buffered `run_tool` path is unchanged for all other tools.
- [ ] `./.venv/bin/python -m pytest -q` green; add tests that feed a fake
      line-by-line stdout (including a stream that stalls then is killed) and
      assert partial results + the stall signal.

## Out of scope / notes

- Do NOT convert nuclei/dnsx/tlsx to streaming in this ticket — httpx first
  (it's the source of the "host is live" stream and the worst offender). A later
  ticket can pipeline nuclei off the same stream (feed URLs into one long-lived
  nuclei stdin as httpx discovers live hosts) — see the earlier per-host
  streaming discussion.
- The tlsx edge-concurrency fix (commit `607a1ed`) already reduces block
  frequency; this ticket is about what happens **when a block still occurs**.
- Keep `parse_httpx_records` pure; only the driver changes.
- Reproduce/validate with the control-probe technique documented in `AGENTS.md`
  (independent 15s curl to a known-good URL from the scanner's egress IP,
  correlated against `stage_start`) — a silent drop can't be seen from inside the
  scanner otherwise.

---

## Outcome (2026-07-21)

Implemented as specced, with three corrections the investigation forced:

1. **`-probe` is load-bearing, not incidental.** The ticket proposed detecting a
   block from the stream "going quiet". It cannot: with plain `-json` a host that
   never answers emits *nothing*, and ~41% of this estate never answers, so quiet
   is the normal state. `-probe` emits a record per input (`failed:true`), which
   turns the stream into real progress. Consequence: `parse_httpx_records` must
   drop `failed:true` records or every scan gains a phantom live server per
   blackholed host.
2. **The stall rule needs a "was it ever working" precondition.** A failure run
   starting at record 1 is an unreachable estate, not a block. `ProbeProgress`
   only fires when ≥15 consecutive failures follow at least one success.
3. **`StreamReader.readline()` is unusable here.** Its 64 KiB line ceiling is
   blown by a single `-include-response` record (the body is inline; 200 KB+ is
   routine) — it raises `ValueError` and kills the stage. `stream_tool` buffers
   and splits on `\n` itself. This surfaced only against the real binary; the
   fake-stream unit tests could not have caught it.

Verified against the live target: a 150s budget that previously yielded 0 servers
now keeps 5, with 11 records persisted; and an induced block produced
`probe_stalled` mid-pass naming the last-good host.

## Not done (follow-ups)

- **The real cost lever: don't probe hosts that will never answer.** ~41% of this
  estate is internal-only, burning ~55% of the httpx budget every scan. A cheap
  bounded TCP-connect pre-filter (80+443) would cut the pass several-fold. NB you
  cannot reuse tlsx's responder set for this — it is 443-only and IP-keyed, so it
  would drop http-only hosts.
- `ProbeCoverage` is engine-side only; it is not surfaced on `ScanResult` /
  `JobStatus` / the UI (only the sharpened `degraded_reason` string is). Wiring it
  through would let the UI show "probed 62/440" instead of a bare "Blocked" badge.
- nuclei/dnsx/tlsx still use the buffered `run_tool` path, per the original scope.
  tlsx is the next best candidate: its budget is a FLAT 600s that does not scale
  with `-c`, so the `607a1ed` concurrency cut (20→2) pushed it from ~77s to ~475s
  against an unchanged ceiling — it now runs at ~80% of budget and tips over on
  variance.
