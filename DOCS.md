# WatchTower — Overview

WatchTower is an automated, **point-in-time, single-run** external AppSec audit
orchestrator. It runs a modular pipeline of recon and audit tools, augments the
results with a pluggable local LLM, and renders everything into a single
self-contained HTML report. There is no database, no delta tracking, and no
state across runs — every scan produces a complete, standalone artifact set.

> This file is a top-level overview. **`DESIGN.md` is the canonical specification**
> (locked decisions, data model, module layout); **`API.md`** is the CLI and
> Python-API reference. Where this overview and `DESIGN.md` disagree, `DESIGN.md`
> wins. Target deployment: Docker on Debian Linux.

---

## Pipeline

```
recon spine ─▶ triage ─▶ audit fan-out ─▶ AI analysis ─▶ aggregate ─▶ report.html
```

### 1. Recon, scope & triage

The discovery spine runs sequentially; it is always a prerequisite for every
other capability.

- **subfinder** — passive subdomain discovery over the configured root domains.
- **dnsx** — resolves every discovered name (A + CNAME; IPv4 only).
- **Triage router** — records each asset's **liveness** (the configured roots are the only scope; WatchTower is an L7 tool, so where an IP is hosted is irrelevant):
  - **live:** resolves to ≥1 A record → fully scanned.
  - **dead:** NXDOMAIN / no A record (e.g. a dangling CNAME) → takeover-watch only.
  ASN / org is attached as display-only enrichment when an optional MMDB is configured.
- **tlsx re-feed loop** — pulls SANs from live certs, filters to the configured roots, and feeds new names back through dnsx + triage (bounded to 3 iterations; `*.` wildcards are recorded but never iterated). The same handshake also captures a passive **cert inventory** (expiry, issuer, self-signed/wildcard, fingerprint) — surfaced in the report + UI, inventory only.
- **httpx** — isolates live web servers from the resolving (live) set. Run with `-include-response`, it also yields per-host **PageSignals** (title, meta/OpenGraph, a pre-JS body snippet, form/password-field signals, detected tech) used by the AI profiler.

### 2. Audit nodes (run in parallel)

- **Takeovers** — two halves: live hosts whose CNAME chain leaves the roots are checked with `nuclei -t http/takeovers/` (severity floor `high`); the dead/dangling set is matched **offline** against a bundled provider-fingerprint DB. (Replaces the original `subjack`, whose fingerprints went stale.)
- **TLS** — `sslscan` against live HTTPS servers, projected to a per-host **pass/fail scorecard** (insecure protocols disabled, no weak ciphers, cert validity + ≥30d, key strength, signature algorithm, secure renegotiation). Passive — no attack-signature probes, so it doesn't trip WAFs. Raw XML kept per host. HSTS lives under `headers`.
- **Web CVEs** — `nuclei` (auto-scan) against live web servers.
- **Security headers** (`headers`) — a deterministic, passive analysis of the response headers httpx already captured: the OWASP best-practice catalog (HSTS, clickjacking, `nosniff`, Referrer-/Permissions-Policy, cookie flags, info-disclosure, deprecated `X-XSS-Protection`, cross-origin isolation) plus a structured **CSP** weakness pass. Emits first-class findings (sources `headers`/`csp`), each with a stable `check_id`. No new requests; full-scan only.
- **Supply chain** — a Playwright/Chromium crawler visits each live host (root path by default), captures all `script`-typed responses and the document's response headers, one JSON artifact per host.

### 3. AI-assisted analysis (local LLM, OpenAI-compatible)

The AI layer's distinguishing value is **per-application context awareness**.

- **Profiling pass** (`ai.profile`, on by default) — runs early, right after httpx and before the audit fan-out. From the PageSignals it infers an **`AppProfile`**: what the app is, its audience, sensitive capabilities (auth/PII/payments/upload/API), and the security controls it *ought* to have. It never gates the deterministic scanners — an LLM guess must never suppress a security scan.
- **Header analysis** — reasons over the host's response headers **alongside the deterministic `headers` findings**: it adds only the nuance the rules miss (subtle issues, dangerous combinations, CSP allowlist-bypass risk) and may **soft-suppress** a rule finding it judges a false-positive. Suppression is gated (high confidence + a usable, non-low-confidence profile) and an AI degrade suppresses nothing — a suppressed finding is hidden + uncounted but never deleted (kept in `findings.json`, shown in a collapsible section).
- **Supply-chain analysis** — risk reasoning over the crawler's scripts, each pre-labeled 1st/3rd-party **in Python** via `tldextract` (the LLM never decides party-ness), weighted by the profile.
- All AI output is **Pydantic-validated JSON** with one retry, then graceful degradation: a host that hard-fails profiling falls back to the default context-light prompts; a degraded analysis call is recorded as an error, not a crash.

### 4. Aggregation & reporting

A single self-contained **`report.html`** (CSS/JS inlined, survives email). It includes:

- **Executive summary** — a **severity histogram** with source provenance (e.g. `high: 8 nuclei, 4 sslscan`). No aggregate score, no letter grade.
- **Run health** — duration, error counts by stage, AI-degraded and TLS-errored counts, notable rate-limit/timeout events.
- **Recon** — two liveness groups: Live (scanned) and Dead / dangling (takeover-watch).
- **Findings** — separate "lens" tables per tool (nuclei, takeovers) — no cross-tool dedup.
- **TLS scorecard** — per-host pass/fail badges + a fleet rollup.
- **AI** — profile cards plus header and supply-chain findings.
- **Run Errors** — every recorded failure (stage crashes *and* per-host failures), and a collapsible **provenance** footer (tool/model versions, config hash).

---

## Operability

- **Selective scans** — `--only` / `--skip` take capability tokens (`recon`, `takeovers`, `tls`, `nuclei`, `headers`, `supply-chain`, `ai`); the recon spine always runs. A **coverage manifest** records what ran vs. was skipped (and why); skipped report sections show a "Not run in this scan" placeholder rather than a misleading empty table.
- **Throttle profiles** — a single `throttle: gentle | normal | aggressive` sets conservative rates across all network-touching tools at once; any explicit per-tool value overrides it.
- **Logging & observability** — an always-on structured `run.log.jsonl`, plus a pluggable terminal view: `--progress plain` (default), `rich` (live stage tree + warnings panel + summary; falls back to plain on a non-TTY), or `quiet`. Every subprocess flows through `run_tool`, which emits `tool_timeout` / `tool_nonzero` / `rate_limit_signal` events. Each run ends with a **`RunSummary`** (logged, written to `summary.json`, shown in the report).
- **Failure signaling** — a completed scan exits `0` by default (it always emits a full artifact set). `--strict` exits non-zero (code `3`) if any failure was recorded — for CI / programmatic callers.
- **Provenance** — tool versions, nuclei template SHA, MMDB build epoch, model + base URL, and timestamps are captured per run.

## Deployment

Docker-only. The image pins the Go binaries (subfinder, dnsx, tlsx, httpx,
nuclei), sslscan, Playwright + Chromium, and the Python deps. A MaxMind
GeoLite2-ASN MMDB can be **bind-mounted** to enable ASN / org enrichment, but it
is **optional** — scans run without it. `watchtower verify-deps` checks the
toolchain, Python modules, and (optionally) the MMDB + LLM endpoint before a run.

See **`API.md`** for the full CLI (`scan`, `init-config`, `verify-deps`),
the YAML config schema, the run-directory layout, and the Python API.

## Web API & UI

WatchTower can also run as an authenticated HTTP service, exposing the same scan
engine to other systems and to a web UI.

- **`watchtower serve -c server.yaml`** — a FastAPI app (the `serve` subcommand,
  shipped in the same image; `pip install '.[web]'`). It reuses the async runner
  in-process, keeps `runs/` as the durable record, and rebuilds its job index
  from disk on startup. Endpoints: `POST /scans`, `GET /scans[/{id}]`,
  `/scans/{id}/{result,report,log}`, `POST /scans/{id}/cancel`, `/healthz`,
  `/capabilities`, `GET`/`PUT /config`, plus OpenAPI at `/docs`. Config is
  **UI-managed** (store-primary; `serve -c` optional) and the per-scan `roots` is
  the only scope — there is **no scan-target allowlist**; an unconfigured server
  refuses scans with `409 not_configured` until llm/mmdb are set. Auth is a static
  API key (`Authorization: Bearer`) — with it unset the API is OPEN and has no
  scope ceiling. Optional HMAC-signed, SSRF-guarded webhooks fire on terminal
  state. See **`WEB_API_PLAN.md`** for the full contract and `example.server.yaml`.
  Module: `watchtower/api/`.
- **`web/`** — a Next.js 16 / React 19 / Tailwind v4 UI (the AppSecMan design
  system) over that API: dashboard, scans list, a new-scan form, and a live scan
  detail view (findings, recon, TLS scorecard, AI profiles, log, embedded
  report). See **`web/README.md`**.
- **Single image** — the `Dockerfile` is multi-stage: a Node stage statically
  exports the UI, and `watchtower serve` serves it at `/` with the API under `/api`
  (same origin) when `WATCHTOWER_UI_DIR` is set. So one `docker run … watchtower serve`
  ships both. The UI can also run standalone against a remote API.
