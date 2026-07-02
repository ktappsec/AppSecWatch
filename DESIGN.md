# WatchTower — Design Specification

> **Status:** Locked v1.1 — base from the `DOCS.md` grilling session; extended
> with **context-aware AI profiling** (§2.3) and **selective stage invocation**
> (§2.8) from a follow-up grilling session.
> **Deployment target:** Docker on Debian Linux.

WatchTower is a **point-in-time, single-run** external AppSec audit orchestrator. It executes a modular pipeline of recon and audit tools, augments the result set with a pluggable local LLM, and renders everything into a single self-contained HTML report. The **engine** has no database — each scan writes a complete, standalone artifact set under `runs/<id>/` (the source of truth). The **Web API** adds a server-side **SQLite relational layer** (`<output_root>/watchtower.db`) for cross-run state — the asset inventory (and, per the roadmap, scheduling/suppression/findings index) — but the engine and CLI stay DB-free, so `runs/` remains self-describing. See `WEB_API_PLAN.md`.

---

## 1. Pipeline overview

```
                        ┌───────────────────────────────────────────────────┐
 roots.yaml             │                Phase 1: Recon                     │
        │               │                                                   │
        ▼               │  subfinder ──► dnsx ──► triage ──► tlsx ──► httpx │
   config.yaml          │                  │                                │
                        │                  ├─► Live  (resolved, scanned)    │
                        │                  └─► Dead  (no A record, watched) │
                        │                                                   │
                        └─────────┬─────────────────────────────────────────┘
                                  │
                ┌─────────────────┼─────────────────┐
                ▼                 ▼                 ▼
        ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
        │ Phase 2A     │  │ Phase 2B/C/D │  │ Phase 3      │
        │ Takeovers    │  │ TLS / CVEs / │  │ AI analysis  │
        │ nuclei(Live)+│  │ Supply chain │  │ (per host)   │
        │ offline(Dead)│  │ on Live      │  │              │
        └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
               │                 │                 │
               └────────┬────────┴─────────────────┘
                        ▼
                ┌────────────────┐
                │ Aggregator +   │
                │ Jinja2 render  │
                └───────┬────────┘
                        ▼
                  report.html
                  (single file)
```

Each stage **always** emits its artifact, possibly empty. `errors.json` at the run root is the single source of truth for failures.

---

## 2. Locked decisions

### 2.1 Recon and triage

| Decision | Value |
|---|---|
| IP → ASN lookup | Local MaxMind **GeoLite2-ASN MMDB** via `maxminddb` Python lib (no `asnmap` binary). **Display-only enrichment** — optional, and never gates a scan: a missing/None mmdb just yields `asn`/`as_org` = `None`. |
| Triage scope | **IPv4 only** — AAAA records ignored. |
| CNAME handling | **CNAME-aware**. The full `cname_chain` is preserved for takeover evaluation — a hop pointing to an eTLD+1 not under any configured root flags a live host for the nuclei takeover pass. |
| Liveness axis | A host that resolves to ≥1 A record is `live`; NXDOMAIN / no A record (e.g. a dangling CNAME) is `dead`. |
| `tlsx` re-feed loop | **Seen-set FQDN dedup + max 3 iterations + SAN filter to configured root domains**. Wildcards (`*.foo.com`) recorded but never iterated. The same single handshake/IP also captures a passive **cert dossier** → `CertInfo` (expiry, issuer, serial, sha256, self-signed/wildcard) into `state.tls_certs` — inventory only, no findings. Command: `tlsx -silent -json -c <concurrency>` (tlsx 1.1.7 has **no `-rl`**; `-json` returns the full dossier). |

#### 2.1.1 Triage classification rules (executed in order)

WatchTower is a **Layer-7 AppSec tool**: assets are *not* classified by where their
IP is hosted. The configured `roots` are the **only** scope — `under_any_root` is the
sole scope boundary, and every name resolving under a root is scanned regardless of
hosting. Within that scope, triage assigns a single **liveness** status. For each
subdomain after `dnsx` resolution:

1. **NXDOMAIN / no A record** (e.g. a dangling CNAME) → status `dead`. **Not actively
   scanned** — only watched for takeover (offline against the bundled provider DB).
2. **Otherwise** (resolves to ≥1 A record) → status `live`. **Fully scanned**, and its
   cert SANs feed the DNS→TLS re-discovery loop.

Each triaged asset records the reason its status was chosen, surfaced in the report.

### 2.2 Audit nodes

| Node | Tool | Target | Notes |
|---|---|---|---|
| A — Takeovers | **`nuclei -t http/takeovers/`** (live hosts with a third-party CNAME) **+ deterministic CNAME check** (`audit/takeover_fingerprints.py` over the `dead` set) | per-class targeting | Two halves: nuclei's HTTP body-fingerprint templates need a *resolving* host, so they run on `live` hosts whose `cname_chain` has a hop **not** under any configured root; the dangling/NXDOMAIN class (the `dead` set, no A records) is matched offline against a bundled provider DB (`data/takeover_fingerprints.json`, from can-i-take-over-xyz) — the class nuclei structurally can't reach. Replaces `subjack`. Severity floor `high` (claimable) / `medium` (edge case). |
| B — TLS | `sslscan --no-failed --xml=<path>` | Live web servers (httpx output) | Per-host pass/fail checklist (§2.5), parsed from sslscan XML via stdlib `xml.etree.ElementTree`. |
| C — Web CVEs | `nuclei -as` | Live web servers | `severity: low,medium,high,critical`, `-rl 100`, templates **always latest** (not pinned — fresh CVEs > reproducibility). |
| D — Supply chain | Playwright (Chromium) | Live web servers | Root path only, `networkidle` 30s cap, 5 parallel browsers. Captures the rendered page **structure only, never values** — scripts, all response resources, cookie/storage **names**, rendered visible text, and an optional screenshot. See §2.2.2. |
| E — Security headers | `audit/header_checks.py` (pure Python) | httpx `PageSignals.headers` | **Deterministic + passive** (no new requests). OWASP best-practice catalog + structured CSP. See §2.2.1. |

Every tool config block in `config.yaml` supports an `extra_flags: []` passthrough escape hatch for unsurfaced flags (timing, user-agent, retries, etc.).

#### 2.2.1 Security-header analysis (deterministic + AI hybrid)

The `headers` capability (sub-tokens `headers.csp`, `headers.best-practice`; `headers.cors` reserved for a future **active** probe) evaluates the response headers httpx already captured — zero new requests — and is the deterministic half of a hybrid with the `ai.triage` stage (formerly `ai.headers`; the old token is still accepted as an alias).

| Decision | Value |
|---|---|
| Determinism | Rules calibrate **only on response facts** they can read unambiguously (URL scheme, `content-type`, `set-cookie`, `has_password_input`): HSTS is N/A over http, clickjacking is informational on a JSON endpoint, situational cross-origin/cache checks fire only on apparently-session-bearing pages. They never infer business context — that is the AI's job. |
| Catalog | OWASP Secure Headers (HSTS, `nosniff`, clickjacking via XFO **or** CSP `frame-ancestors`, Referrer-/Permissions-Policy, per-cookie Secure/HttpOnly/SameSite, info-disclosure, deprecated `X-XSS-Protection`) + situational COOP/COEP/CORP, `X-Permitted-Cross-Domain-Policies`, cache-control, Clear-Site-Data. CSP = structured directive parse with high-confidence rules (unsafe-inline/eval, wildcard, insecure scheme, missing `object-src 'none'`/`base-uri`, report-only-only). **Cookie-flag checks skip infrastructure cookies** (`audit/cookies.py::is_infra_cookie` — F5 BIG-IP/LB/WAF/RUM cookies that carry no session state); their flag gaps are dropped, not reported. |
| Output | First-class `Finding`s (sources `headers`/`csp`), each with a stable, host-unique **`check_id`**. They **always stand on their own** — running even with `--skip ai`. |
| AI relationship | `ai.triage` is a per-host pass over **all** of the host's deterministic findings (nuclei/TLS/js_lib/headers/takeover), not just headers. It adds **only** nuance the rules miss (header combinations, CSP allowlist bypassability — these keep source `ai_headers`) and **soft-suppresses** false-positives across every source. |
| Soft-suppression | Each finding offered to the AI carries an ephemeral integer `ref`; the AI returns the `ref`s it judges false-positive. A suppressed finding is **hidden from the report + dropped from severity counts but never deleted** (kept in `findings.json`, shown in a collapsible "Suppressed" section, verdict `source='ai_triage'`) — fully auditable. **Gated** via `ai.suppression`: `enabled`, `min_confidence` (default **medium**), a `max_severity` ceiling (default **medium** — findings above it are never even offered, so always stay visible + counted), and `require_profile` (default **false**: the `AppProfile` is calibration context, not a precondition). An AI degrade suppresses nothing — preserving the **"AI never gates deterministic scanners"** invariant: an LLM failure can never erase a deterministic finding. |
| Scope | Operates on the `PageSignals` captured by the httpx recon step, i.e. every live host discovered by the recon spine. |

#### 2.2.2 Crawler capture (structure only, never values)

The Playwright crawler (`audit/crawler.py`, the `supply-chain` capability) records the
**shape** of each live host's rendered page into a `CrawlerArtifact` (§5) under
`02_audit/playwright/<host>.json` — and **never a value**:

* `scripts` — script URLs (unchanged).
* `resources` — every response resource `{url, type, status, method}`, deduped and capped
  at ~500.
* `cookies` — cookie **names + flags** (`name`, `domain`, `path`, `secure`, `http_only`,
  `same_site`, `expires`) — **never** the cookie value.
* `local_storage_keys` / `session_storage_keys` — storage **key names** only.
* `rendered_text` — the rendered visible text (`document.body.innerText`),
  whitespace-normalized and capped at 2 KB.
* `screenshot` — an optional per-host PNG (`tools.playwright.screenshot`, default `true`).

**Hard rule:** never any value, cookie content, or response body. `runs/<id>/` and
`report.html` are **shareable / emailable**, so capturing secrets would turn a scan into a
credential-leak vector. Captures are best-effort (a failed capture leaves the field empty).

`audit/surface.py::curated_surface(artifact)` projects an artifact into a names-only dict
`{third_party_domains, script_domains, endpoints, cookie_keys, storage_keys}` (endpoints =
`"METHOD host/path"`, query strings dropped) — the **single source** reused by both the
profiler's input summary (§2.3.1) and the per-asset EASM surface exposed by the Web API
(§5 / `WEB_API_PLAN.md`).

### 2.3 AI layer

The AI layer's distinguishing value is **per-application context awareness**: before
analysing headers or scripts, it infers *what each application actually is* and tailors
the analysis to that. A missing `HSTS` header is a high-severity gap on a public login
portal and a non-issue on an internal static-asset host — the AI should treat them
differently, and it can only do that if it first establishes context.

| Decision | Value |
|---|---|
| Runtime | **Fully pluggable** — config-driven `base_url`, `api_key`, `model`. OpenAI-compatible `/v1/chat/completions` endpoint. |
| Call granularity | **Per-host**, parallelized via `asyncio.Semaphore` (cap **4** by default — LLMs are heavier than HTTP scans). |
| Party-ness (1st/3rd) | **Computed in Python via `tldextract`**. Compare script URL's eTLD+1 to host's eTLD+1. The LLM never decides this. |
| Output contract | **Pydantic-validated JSON**. Retry once on validation failure. On second failure: record `{error: "..."}` and continue. |
| Histogram contribution | AI findings **count in the histogram**, with no visual badge. Prompt quality must earn that trust. |

#### 2.3.1 The profiling pass

A dedicated **profiling stage** (`ai.profile`) runs **once per host**, at the **head of the
AI-analysis phase** — *after* the audit fan-out (so it can consume the crawler's rendered
capture), *before* the `ai.triage` / `ai.supply-chain` prompts — and produces a structured
`AppProfile` that those downstream prompts consume as context.

| Decision | Value |
|---|---|
| Toggle | `ai.profiling: true` by default (the headline capability ships enabled). When `false`, header/supply prompts revert to their **default, context-light prompts verbatim**, no profile artifact is written, and the pipeline makes 2 LLM calls/host instead of 3. |
| Placement | **Head of the AI-analysis phase** — *after* the audit fan-out, *before* `ai.triage`/`ai.supply-chain`. Nothing in the takeovers/audit phases consumes the `AppProfile`; only the two downstream AI prompts do, and the profile is produced before them. **In v1 it influences only the AI prompts.** Deterministic scanners (nuclei/sslscan/crawler) always run at full coverage regardless of profile — an LLM guess must never *gate* a security scan. |
| Inputs (signals) | Governed by **`ai.profile.render`** (`auto` \| `always` \| `never`, default `auto`). The always-present base is the httpx `PageSignals` (`httpx -include-response` → response headers, `<title>`, `<meta name=description>`, OpenGraph tags, a stripped `≤2 KB` *pre-JS* visible-text snippet, `form_count`, `has_password_input`) + the detected `tech`. On top of that: **`auto`** — when the crawler (`supply-chain`) ran for the host, add its **rendered** visible text + a curated resource/endpoint/cookie/storage manifest (§2.2.2); else fall back to the httpx pre-JS signals (a browser is **never** spun up solely to profile). **`always`** — force-include the crawler so the rendered capture is always available (see §2.8.3). **`never`** — httpx pre-JS signals only. `auto`/`always` add `rendered_body_text` + `observed_resources` to `build_profile_prompt` (assembly in code; the JSON shape hint is unchanged). |
| SPA caveat | On the **httpx-only** path (`render: never`, or `auto` with no crawler for the host) the body is **pre-JavaScript**: `<title>`/meta/OG live in the static `<head>` so they survive, but visible body text is thin for SPAs, and the profiler is explicitly told the HTML is pre-render so it does not over-read emptiness. `render: auto`/`always` close this gap by feeding the crawler's **post-render** text when available. |
| Output contract | Same machinery as the other calls: Pydantic-validated JSON, **retry once**, then graceful degrade. |
| Failure degrade | A **hard failure** (LLM error or unparseable after retry) on a host ⇒ that host falls back to the **default prompts** (no profile). |
| Confidence tiers | A profile that parses but self-reports `confidence: low` ⇒ still passed to the prompts, but they are instructed **not to aggressively escalate** on expectation gaps. Severity escalation requires `med`/`high` confidence. |

**`AppProfile` schema** (persisted to `03_ai/profile/<host>.json`, shown in the report):

* **Core** — `app_type` (free text, e.g. *"customer login portal"*), `audience`
  (`public` / `internal` / `partner` / `unknown`), `reasoning`, `confidence`
  (`low` / `medium` / `high`).
* **Capability flags** — `handles_auth`, `handles_pii`, `handles_payments`,
  `has_file_upload`, `is_api` (booleans the model infers from the signals).
* **Expected controls** — `expected_controls`: the security controls/headers this
  *specific* app **ought** to have given the inferred type (e.g. a public login app:
  HSTS, strict CSP, `Secure`+`HttpOnly` cookies, `X-Frame-Options`). This is the dial
  the header prompt grades reality against.

#### 2.3.2 The two analysis prompts (profile-aware)

Both run in the AI phase (after the crawler) and now receive the `AppProfile` as context
when profiling is on. **Header analysis is sourced from `httpx` response headers** (from
the always-on spine), so it does *not* depend on the crawler; only the supply-chain half
needs the crawler's scripts.

* **Prompt 1 — Headers (expectation-gap analysis).** Input: host URL + response headers
  + the `AppProfile`. The analysis is a **diff against `expected_controls`**:
  * Missing/weak control the profile flagged as **expected** for this app ⇒ **escalated**
    (medium/high).
  * Missing a control **not** expected for this app type ⇒ info/low, or omitted.
  * The expectation gap — not a rote header checklist — is the primary severity driver.
  * (When profiling is off, this reverts to the prior context-light header prompt.)
* **Prompt 2 — Supply chain.** Input: host URL + Python-labeled `{url, party, etld+1,
  status, initiator}` script entries + the `AppProfile`. Findings are **weighted by the
  profile** (a 3rd-party tracker on a `handles_payments` login portal is graver than the
  same script on a marketing page). The LLM never re-classifies party-ness; it reasons
  about risk only.

### 2.4 Orchestration

| Decision | Value |
|---|---|
| Runtime | Single-process `asyncio`. Stages execute **sequentially**; intra-stage fan-out via `asyncio.gather`. |
| Concurrency cap | `asyncio.Semaphore` per stage, default **10** for HTTP-ish workloads, **4** for LLM, **5** for Playwright (one browser context each), **5** for sslscan (`concurrency.tls`). All scaled down by the `gentle` throttle profile (§2.9). |
| Failure semantics | Per-asset errors caught at the coroutine boundary are kept in the artifact **and** returned by the stage as `StageResult.asset_errors`; `execute_stages` (and `ParallelStage`, per child) folds them into the single error sink (`ScanState.errors` → `errors.json` + the report's Run Errors panel + the summary). That fold is the **one place** a `(target, message)` pair becomes an attributed `StageError`, so no stage touches the sink directly. Stage crashes are caught in `execute_stages` and recorded with their exception type (+ a truncated traceback under `--verbose`). **Stage always completes.** |
| Empty inputs | Every stage **always emits its artifact**, possibly empty. Downstream stages run-but-produce-empty. Report always renders every section. |
| Subprocess invocation | `asyncio.create_subprocess_exec`. Each tool writes raw output to its stage directory; the wrapper reads + parses post-completion. |

### 2.5 Reporting

Every run writes **two self-contained HTML documents** from one shared, themeable
Jinja base (`report/templates/_base.html.j2` + `_theme.css.j2`): the full technical
**`report.html`** and a ≤2-page leadership **`executive.html`**, plus an optional
**`executive.pdf`**. Both carry a **light/dark toggle** (head theme-init reads
`localStorage` then `prefers-color-scheme`; `@media print` forces the light palette).

The **executive one-pager** has a deterministic core that ALWAYS renders — a posture
rating (**highest severity present** + a volume note), severity counts, scale
(DNS-live vs HTTP-responding `live_servers`), and the **top-5 risks** (grouped by
`source|title`, ranked severity→host-count). An **optional AI overlay** (`ai.summary`,
one LLM call at the **tail** of the AI phase, after triage suppression) adds the
narrative paragraph, per-risk "why it matters", and next-steps; it degrades to
templated prose. The overlay merges onto risks by a **stable key** (not the prompt
`ref`), so it survives the later manual `SuppressionStage` re-selecting the visible
set. `executive.pdf` renders from `executive.html` via the bundled Chromium
(best-effort; gated on `report.executive_pdf`; never raises). Branding is the optional
`report` config block (`org_name`→root fallback, `classification`, embedded
`logo_path`).

| Decision | Value |
|---|---|
| Form factor | **Two self-contained HTML docs** (CSS, JS, SVG inlined) from a shared base. Must survive being emailed. Per-host **screenshots are dashboard-only** — served by the Web API at `GET /assets/{fqdn}/screenshot` (404 when absent) and **never** inlined into `report.html`, preserving emailability. |
| Executive Summary (in report.html) | **Severity histogram only**. No aggregate score, no letter grade. Counts include source provenance (`high: 8 nuclei, 4 sslscan`). (The standalone `executive.html` adds the deterministic posture rating + top-5 risks described above.) |
| TLS scorecard | **Per-host pass/fail badges** on a fixed checklist: insecure protocols disabled (SSLv2/SSLv3/TLS 1.0/TLS 1.1), no weak ciphers (RC4/3DES/DES/EXPORT/NULL/MD5/anonymous, or bits < 112), cert valid + not expiring <30d, key strength (RSA ≥ 2048 / EC ≥ 256), signature algorithm not SHA-1/MD5, secure renegotiation supported. Fleet rollup at top. No letter grade. (Chain-trust and HSTS are *not* graded here — the recon cert dossier already carries issuer/expiry/self-signed, and HSTS is covered by the `headers` capability.) |
| Recon / triage view | Two groups — **Live (scanned)** and **Dead / dangling (watch)**. Each row shows FQDN + IP + AS (ASN/org from the optional MMDB, when present). |
| Cross-tool dedup | **None**. Each tool gets its own section ("lenses"). Overlap reads as corroboration. |
| Interactivity | **Inlined vanilla JS** (~3-5 KB): severity filter, free-text search, column sort, section collapse. No external libs. |
| Provenance footer | Collapsible block with `versions.json` contents (tool versions, model name, run timestamps, config hash). |

### 2.6 IO surface

| Item | Value |
|---|---|
| CLI | `watchtower scan --config <path> [--output-dir runs/] [--progress plain\|rich\|quiet] [--verbose] [--only \| --skip <tokens>] [--strict]` |
| Stage selection | `--only`/`--skip` take a comma-separated list of **capability tokens** (§2.8). Mutually exclusive. |
| Config format | **YAML**. Sections: `roots`, `mmdb_path` (optional), `llm`, `ai`, `headers`, `concurrency`, `paths_per_host`, plus per-tool config blocks. |
| Run dir | `runs/<UTC-ISO-timestamp>-<slug>/` |
| Run dir layout | See §3. |
| Logging | `--progress plain` (default, timestamped stderr) / `rich` (live stage tree + warning panel + summary, auto-falls back to plain on a non-TTY) / `quiet` (warnings/errors + final summary only). `run.log.jsonl` **always written**, and tallied into an end-of-run `RunSummary` (logged + `summary.json`). |
| Failure signaling | Completed scans exit `0` by default (locked "always emit a complete artifact set", §2.4). `--strict` exits `3` if any stage crash or per-host failure was recorded — for CI / the Web API. |

### 2.7 Deployment

| Decision | Value |
|---|---|
| Form factor | **Docker-only.** Image pins all Go binaries (subfinder, dnsx, tlsx, httpx, nuclei), `sslscan` (Debian package), Playwright + Chromium, Python deps. |
| MMDB delivery | **Bind-mount, optional.** If `GeoLite2-ASN.mmdb` is present at `/data/mmdb/GeoLite2-ASN.mmdb` it supplies ASN/org display enrichment; if absent the scan runs normally with `asn`/`as_org` left `None`. User owns refresh. |
| Authorization preflight | **None.** Tool runs on whatever YAML it's pointed at. Operator trust. |

### 2.8 Selective stage invocation

Operators can run a subset of the pipeline — *"only TLS"*, *"everything but nuclei"*,
*"just map my attack surface"* — through one selection model shared by the CLI and the
Python API.

#### 2.8.1 Capability tokens

Selection is expressed in **stable, user-facing capability tokens** decoupled from internal
stage names:

| Token | Maps to | Notes |
|---|---|---|
| `recon` | the discovery spine (subfinder → dnsx → triage → tlsx → httpx) | Always runs as a **prerequisite** for every other capability. As a standalone `--only recon` it means *discovery-only*: emit the asset inventory + triage graph (live/dead), then stop. |
| `takeovers` | `nuclei` takeover templates (live hosts with a third-party CNAME) + deterministic dangling-CNAME check (`dead` set) | Two halves — see §2.2. |
| `tls` | `sslscan` per-host TLS scorecard | |
| `nuclei` | main `nuclei` web-CVE scan | |
| `headers` | deterministic header + CSP analysis (§2.2.1) | Passive over httpx headers; sub-tokens `headers.csp`, `headers.best-practice`. Full-scan only. |
| `supply-chain` | the Playwright crawler | |
| `zap` | OWASP ZAP **active scan** (sidecar daemon over REST) | **OPT-IN** — the one capability that breaks WatchTower's otherwise-passive posture. It is NEVER part of a default/preset/`--skip` selection (`OPT_IN_TOKENS` is subtracted from those caps seeds); it runs only via explicit `--only zap`, against operator-specified, scope-locked targets (`cfg.zap.targets` / `ScanRequest.zap_targets`, each `under_any_root`). The daemon is a sidecar (not bundled, not `run_tool` — driven over REST by `audit/zap_runner.py`); time-bounded by `zap.max_minutes_*`, exempt from `throttle`. Findings are `source='zap'` (risk→severity, no `critical`; `check_id=zap.<pluginId>`); they flow through `ai.triage` for FP suppression but there is **no cross-source dedup** (overlap with `headers`/`nuclei` is tolerated). Gated three ways: `/capabilities` omits it when the daemon is off, `submit` 409s (`zap_rejected`) on disabled/empty/out-of-scope, and the stage factory no-ops when unconfigured. Unauthenticated in v1. |
| `ai` | `ai.profile` + cross-source triage + supply-chain analysis + executive summary | Supply-chain *analysis* requires the crawler (see resolution). `ai.triage` (formerly `ai.headers`) soft-suppresses false-positives across **all** deterministic findings + adds header-gap findings. `ai.summary` makes one whole-run LLM call at the **tail** of the AI phase for the `executive.html` narrative (§2.5); degrades to deterministic prose. |

#### 2.8.2 Selection flags

* `--only <tokens>` — allowlist. Run **only** these capabilities (plus the implied spine).
* `--skip <tokens>` — denylist. Run everything **except** these.
* The two are **mutually exclusive**. Unknown tokens are a hard error listing the valid set.

#### 2.8.3 Dependency resolution — **auto-include + log**

Every capability except `ai`'s supply half depends only on the always-on spine. The one
real intra-capability edge is **`ai`'s supply-chain analysis needs the crawler's scripts**.
Resolution never errors:

* Selecting `ai` **auto-enables** the crawler, with an explicit log line
  (`auto-enabled supply-chain: required by ai`).
* `--skip supply-chain` while `ai` is active **gracefully drops only the affected half**:
  the profile + header analysis still run; supply-chain analysis is silently disabled (it
  has no data). Header analysis is unaffected because it is sourced from `httpx` headers,
  not the crawler.
* `recon` is implied whenever any audit/AI token is selected; it cannot be skipped while
  other capabilities run.
* **`ai.profile.render: always`** force-includes the crawler in `build_pipeline` even when
  supply-chain *analysis* is off, so the profiler can read the rendered capture. Only
  `CrawlerStage` runs (no supply-chain LLM call); coverage marks supply-chain
  `{"ran": true, "reason": "forced for profile.render=always"}`.

#### 2.8.4 Reporting honesty (three-state coverage)

Selective scans create a three-state problem per section: **ran-with-findings**,
**ran-and-clean**, **never-run**. Conflating the last two would imply false coverage
(an empty nuclei table reads as *"scanned, no web vulns"* when nuclei never ran). So:

* A **coverage manifest** is computed (which capabilities ran, which were skipped, and the
  reason: `user-selected` / `auto-included` / `discovery-only`), written to `manifest.json`
  and carried in `run_meta`.
* The report header renders a **coverage strip** (`recon✓ tls✓ nuclei✗ …`).
* Skipped sections render a muted **"Not run in this scan"** placeholder **instead of** an
  empty table.

#### 2.8.5 Programmatic surface

A shared `CAPABILITIES` registry maps tokens → stage factories, and
`build_pipeline(cfg, *, only, skip, …)` applies the resolution logic in **one place** that
both the CLI and the API call. `run_scan` takes `only=` / `skip=` parameters mirroring the
CLI, plus a `stages=[...]` escape hatch for callers that want to hand-assemble an explicit
stage list (bypassing token logic entirely). See API.md §5.

### 2.9 Rate limiting & observability

External audits hit live, often production, targets — and aggressive probing (a burst of
httpx/nuclei requests in particular) can trip a target's WAF / rate-limiter. (`sslscan` is
passive — no ROBOT/CCS/attack-signature probes — so it doesn't trip WAFs the way the old
active TLS prober did.) Two mechanisms address this.

#### 2.9.1 Throttle profiles

A single top-level **`throttle: gentle | normal | aggressive`** sets conservative rates
across *all* network-touching tools at once:

| | `gentle` | `normal` (default) | `aggressive` |
|---|---|---|---|
| httpx / nuclei `-rl` | 10 | 100 | 500 |
| takeovers `-rl` | 10 | 50 | 150 |
| dnsx `-rl` | 100 | 1000 | 5000 |
| tlsx `-c` (concurrency) | 20 | 100 | 300 |
| sslscan per-host timeout | 600s | 300s | 180s |
| concurrency default / tls / playwright | 3 / 2 / 2 | 10 / 5 / 5 | 20 / 10 / 8 |

Resolution rule: the profile fills only fields the operator did **not** explicitly set
(decided via Pydantic's `model_fields_set` in a `model_validator`), so **any per-tool or
per-concurrency value in the YAML overrides the profile**. `normal` equals every field's own
default, so an unset `throttle` reproduces prior behavior exactly. The closed gaps:
sslscan gained a per-host `timeout` + its own `concurrency.tls` (previously it shared
`concurrency.default` and had no per-host throttle). dnsx gained `rate_limit`; tlsx uses
`concurrency` (`-c`) — it has no rate-limit flag.

#### 2.9.2 Rate-limit observability

So an operator can answer *"where did we hit the limit?"*, every subprocess flows through
`run_tool`, which emits structured JSONL events (`run.log.jsonl`):

* **`tool_timeout`** — the primary signal. A killed-on-timeout invocation with `tool`,
  `elapsed_s`, `timeout_s`; edge throttling usually manifests as stalled handshakes/timeouts.
* **`tool_nonzero`** / **`tool_done`** — non-zero exit (with stderr tail) / normal completion
  with elapsed time.
* **`rate_limit_signal`** — emitted by httpx when a burst of `403/429/503` responses appears
  on the probe pass (a direct WAF/rate-limit tell), listing the affected hosts.
* **`sslscan_host_done`** / **`sslscan_summary`** — per-host pass/total + elapsed, and a run
  rollup of `ok` vs `errored/timed-out` hosts.
* **`throttle`** — logged once at run start: the resolved profile and the effective per-tool
  rates, so later timeout/limit events can be read against the limits that were in force.
* **`run_summary`** — emitted once at run end: the `RunSummary` (findings by severity, asset
  counts, error totals by stage, per-stage timings, AI degraded count, TLS errored count, and
  the run's `tool_timeout`/`tool_nonzero`/`rate_limit_signal`/warning/error tallies). Also
  written to `summary.json` and rendered in the report's Run Health panel. The logger tallies
  every event it emits, so these counts come for free rather than re-deriving them from state.

---

## 3. Run directory layout

```
runs/2026-05-26T10-24-00Z-prod-fleet/
├── config.snapshot.yaml         # exact config used for this run (llm.api_key redacted)
├── versions.json                # tool versions, model, MMDB date, watchtower sha
├── manifest.json                # capability coverage: ran / skipped + reason
├── run.log.jsonl                # structured event log (incl. the run_summary event)
├── errors.json                  # consolidated failures: stage crashes + every per-host error
├── summary.json                 # end-of-run RunSummary (findings/assets/errors/timings)
├── 01_recon/
│   ├── subfinder.txt
│   ├── dnsx.jsonl
│   ├── triage.json              # {live: [...], dead: [...]}
│   ├── tlsx.jsonl
│   └── httpx.jsonl              # final live web servers
├── 02_audit/
│   ├── takeovers/
│   │   └── nuclei-takeovers.jsonl
│   ├── sslscan/
│   │   └── <host>.xml           # raw sslscan XML, one per host
│   ├── nuclei/
│   │   └── findings.jsonl
│   ├── headers/
│   │   └── <host>.json          # deterministic header/CSP findings (sources headers/csp)
│   ├── playwright/
│   │   ├── <host>.json          # CrawlerArtifact (§5): url/status/headers + scripts,
│   │   │                        #   resources, cookies (names+flags), *_storage_keys,
│   │   │                        #   rendered_text — structure only, never values
│   │   └── <host>.png           # optional per-host screenshot (tools.playwright.screenshot)
│   └── zap/                     # opt-in OWASP ZAP active scan (only when --only zap ran)
│       ├── zap-report.json      # raw ZAP JSON report
│       └── alerts-<host>.json   # per-target grouped alert instances
├── 03_ai/
│   ├── profile/
│   │   └── <host>.json          # AppProfile (omitted when ai.profiling: false)
│   ├── headers/
│   │   └── <host>.json
│   └── supply_chain/
│       └── <host>.json
└── report.html
```

---

## 4. Config schema (YAML)

> The example below is illustrative. The canonical, always-current example is
> produced by `watchtower init-config` (see API.md §1).
>
> `WatchTowerConfig` sets `model_config = ConfigDict(extra="ignore")`, so older stored
> configs that still carry the removed `sanctioned_cidrs` / `sanctioned_asns` keys load
> without error (the keys are simply dropped).

```yaml
# config.yaml
roots:
  - example.com
  - example-corp.io

mmdb_path: /data/mmdb/GeoLite2-ASN.mmdb   # optional: ASN/org display enrichment only

concurrency:
  default: 10
  llm: 4
  playwright: 5

paths_per_host:
  - "/"
  # Optional additional paths to crawl per live host

llm:
  base_url: http://host.docker.internal:11434/v1
  api_key: ollama         # required by OpenAI-compat shim; can be a placeholder
  model: llama3.1:8b-instruct
  timeout_seconds: 120
  max_retries: 1

ai:
  profiling: true         # context-aware per-app profiling (the headline AI capability).
                          # false => header/supply prompts use the default context-light
                          # prompts and no 03_ai/profile/ artifact is written.
  profile:
    render: auto          # auto | always | never (default auto): the profiler's INPUT.
                          # auto  = crawler rendered text + curated surface when supply-chain
                          #         ran for the host, else httpx pre-JS signals (a browser is
                          #         never spun up solely to profile).
                          # always= force the crawler (CrawlerStage only, no extra LLM calls).
                          # never = httpx pre-JS signals only.

tools:
  subfinder:
    extra_flags: []
  dnsx:
    extra_flags: []
  tlsx:
    extra_flags: []
  httpx:
    rate_limit: 100
    timeout: 10
    extra_flags: []
  nuclei:
    severities: [low, medium, high, critical]
    auto_scan: true
    rate_limit: 100
    timeout: 5
    user_agent: "WatchTower/0.1"
    extra_flags: []
  takeovers:
    severities: [high, critical]
    rate_limit: 50
    extra_flags: []
  sslscan:
    timeout: 300
    extra_flags: []
  playwright:
    wait_until: networkidle
    timeout_ms: 30000
    screenshot: true      # capture an optional per-host PNG (dashboard-only; never in report.html)
    user_agent: null      # null = use Chromium default
```

---

## 5. Data model (Pydantic)

### Asset

```python
class TriagedAsset(BaseModel):
    fqdn: str
    a_records: list[str]
    cname_chain: list[str]
    asn: int | None                 # display-only enrichment (optional MMDB; None if absent)
    as_org: str | None              # display-only enrichment (optional MMDB; None if absent)
    status: Literal["live", "dead"]
    reason: str  # human-readable explanation
```

### Finding (cross-tool)

```python
class Finding(BaseModel):
    source: Literal["nuclei", "takeover", "sslscan",
                    "headers", "csp",                 # deterministic header checks
                    "ai_headers", "ai_supply_chain"]
    host: str | None
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str
    evidence: dict[str, Any]   # source-specific; rendered via .evidence_rows()
                               # so the report never reads source keys directly
    check_id: str | None       # stable id; rule findings + AI findings (derived
                               # from `type`, e.g. ai_headers.cookie-missing-httponly-flag)
    ai_verdict: AIFindingVerdict | None   # soft-suppression (§2.2.1); never deletes
    # .suppressed → ai_verdict.suppressed; excluded from histogram + finding_count
    # .group_key → check_id-or-natural-key-or-title: the ONE dedup/grouping +
    #   suppression-fingerprint key (select_top_risks, report groupby, suppress)
```

### AI response (validated)

```python
class AIFinding(BaseModel):
    type: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)

class AISuppression(BaseModel):           # header analysis only (FP verdicts)
    check_id: str
    suppressed: bool = True
    confidence: Literal["low", "medium", "high"] = "low"
    reason: str = ""

class AIResponse(BaseModel):
    findings: list[AIFinding] = []
    suppressions: list[AISuppression] = []   # gated + applied as AIFindingVerdict
    error: str | None = None            # set when the call hard-failed after retry
    # .usable property: True when error is None (mirrors AppProfile.usable)

class AIFindingVerdict(BaseModel):        # attached to a deterministic Finding
    suppressed: bool = False              # True → hidden + uncounted, never deleted
    confidence: Literal["low", "medium", "high"] = "low"
    reason: str = ""
```

### Page signals (parsed from `httpx -include-response`)

```python
class PageSignals(BaseModel):
    host: str
    headers: dict[str, str] = {}        # response headers (lower-cased keys)
    set_cookies: list[str] = []         # raw Set-Cookie values, one per cookie
                                        # (the dict above collapses duplicates)
    title: str | None = None
    meta_description: str | None = None
    og_tags: dict[str, str] = {}
    body_snippet: str = ""              # stripped visible text, <= 2 KB, pre-JS
    form_count: int = 0
    has_password_input: bool = False
    tech: list[str] = []                # carried from httpx tech-detect
```

### Crawler artifact (Playwright capture — structure only, never values; §2.2.2)

```python
class CrawlerCookie(BaseModel):         # NAME + flags only — never the value
    name: str
    domain: str | None = None
    path: str | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    expires: float | None = None

class CrawlerResource(BaseModel):
    url: str
    type: str | None = None             # resource type (script / xhr / fetch / image / …)
    status: int | None = None
    method: str | None = None

class CrawlerArtifact(BaseModel):       # → 02_audit/playwright/<host>.json
    url: str
    status: int | None = None
    headers: dict[str, str] = {}
    scripts: list[str] = []             # script URLs (unchanged)
    resources: list[CrawlerResource] = []      # all responses, deduped, ~500 cap
    cookies: list[CrawlerCookie] = []   # names + flags, never values
    local_storage_keys: list[str] = []  # key names only
    session_storage_keys: list[str] = []
    rendered_text: str = ""             # document.body.innerText, normalized, <= 2 KB
    screenshot: str | None = None       # PNG filename, when captured
```

The Web API projects this artifact via `curated_surface` (§2.2.2) into a names-only
`surface` dict stored on the server-side `Asset` (latest scan only; `assets.surface TEXT`
column + guarded migration) and exposes the per-host PNG at `GET /assets/{fqdn}/screenshot`
— engine-side it stays a `runs/<id>/` artifact only. See `WEB_API_PLAN.md`.

### Cert info (recon tlsx dossier, one handshake/IP)

```python
class CertInfo(BaseModel):              # → state.tls_certs (inventory only)
    ip: str
    subject_cn: str | None
    sans: list[str] = []
    issuer: str | None                  # issuer_cn (+ org)
    serial: str | None
    sha256: str | None                  # fingerprint_hash.sha256
    not_before: str | None
    not_after: str | None
    days_remaining: int | None          # derived from not_after
    expired: bool = False               # derived: days_remaining < 0
    self_signed: bool = False           # derived: subject_dn == issuer_dn
    wildcard: bool = False
```

### App profile (AI-inferred, validated)

```python
class AppProfile(BaseModel):
    host: str
    app_type: str                       # free text, e.g. "customer login portal"
    audience: Literal["public", "internal", "partner", "unknown"]
    confidence: Literal["low", "medium", "high"]
    reasoning: str
    # capability flags
    handles_auth: bool = False
    handles_pii: bool = False
    handles_payments: bool = False
    has_file_upload: bool = False
    is_api: bool = False
    # controls this specific app *ought* to have, given its type
    expected_controls: list[str] = []
    error: str | None = None            # set when profiling hard-failed for the host
```

### Run bookkeeping (errors + summary)

```python
class StageError(BaseModel):
    stage: str
    target: str | None = None           # the host/asset the error relates to, when known
    message: str
    error_type: str | None = None       # exception class for crashes; "asset" for per-host failures
    ts: str | None = None               # UTC ISO timestamp recorded

class StageOutcome(BaseModel):          # one per stage, for the summary
    name: str
    duration_s: float = 0.0
    errors: int = 0

class RunSummary(BaseModel):            # end-of-run rollup → summary.json + report + run_summary log event
    duration_s: float = 0.0
    findings_total: int = 0
    findings_by_severity: dict[str, int] = {}
    assets: dict[str, int] = {}         # live / dead / live_servers / wildcards
    errors_total: int = 0
    errors_by_stage: dict[str, int] = {}
    stages: list[StageOutcome] = []
    ai: dict[str, int] = {}             # profiled / degraded
    tls: dict[str, int] = {}            # hosts / ok / errored
    events: dict[str, int] = {}         # tool_timeout / tool_nonzero / rate_limit_signal / warn / error
```

Per-asset failures (sslscan timeouts, crawler nav errors, AI degradations) are
returned by their stage as `StageResult.asset_errors` and folded by
`execute_stages` into the single `StageError` sink (`ScanState.errors`), so
`errors.json`, the report's Run Errors panel, and the `RunSummary` all agree.

---

## 6. Module layout

```
watchtower/
├── __init__.py
├── __main__.py            # python -m watchtower
├── cli.py                 # argparse subcommands; --only/--skip token parsing
├── config.py              # YAML load + Pydantic models (incl. AIConfig)
├── models.py              # TriagedAsset, Finding, PageSignals, CrawlerArtifact, AppProfile, StageError, RunSummary, …
├── runner.py              # bootstrap + run_scan(only=, skip=, stages=)
├── logging.py             # JSONL audit log + counters + plain/quiet renderers + RunSummary hook
├── progress.py            # rich live-progress renderer (lazy-imported by logging when --progress rich)
├── example_config.py      # canonical EXAMPLE_CONFIG_YAML (init-config)
├── preflight.py           # verify-deps probes
├── util/
│   ├── subproc.py         # async subprocess helper (run_tool: structured tool events)
│   ├── domains.py         # tldextract wrappers, eTLD+1 + host_to_filename helpers
│   └── ipinfo.py          # optional GeoLite2-ASN MMDB lookup (asn/as_org; tolerates a missing/None mmdb)
├── recon/                 # raw recon tool wrappers (subfinder, dnsx+triage, tlsx loop, httpx)
├── audit/                 # sslscan / nuclei / takeovers / crawler / header_checks / surface (curated names-only projection) + nuclei_parse (shared JSONL→Finding)
├── ai/
│   ├── client.py          # OpenAI-compat httpx client
│   ├── schemas.py         # AIFinding + AISuppression + AIResponse (AppProfile lives in models.py)
│   ├── prompts.py         # build_profile_prompt + profile-aware header/supply prompts
│   └── analyzer.py        # per-host fan-out; profile-aware, confidence-tiered
├── stages/                # the Stage plugin layer (orchestration unit)
│   ├── state.py           # ScanState (app_profiles, page_signals, header_findings, coverage, …)
│   ├── base.py            # Stage ABC + StageResult, ParallelStage, execute_stages()
│   ├── recon.py           # Subfinder/Dnsx+Triage/TlsxLoop/Httpx (parses PageSignals)
│   ├── profile.py         # AIProfileStage (head of the AI phase, after the audit fan-out)
│   ├── audit.py           # Takeovers/Sslscan/Nuclei/Crawler/Headers stages
│   ├── ai.py              # AIStage (cross-source triage + supply analysis + soft-suppression)
│   ├── report_stage.py    # ReportStage, CompressStage
│   ├── capabilities.py    # CAPABILITIES registry + token→stage resolution
│   └── pipeline.py        # build_pipeline(cfg, only=, skip=) — CLI + API share this
└── report/
    ├── renderer.py        # Jinja2 render (coverage strip, profile cards)
    └── templates/
        └── report.html.j2
```

---

## 7. Operational notes

* **Tool versions** captured in `versions.json` at run start: each tool's `-version`, nuclei templates SHA, MMDB build epoch, Python and key library versions, WatchTower git SHA, LLM `model` and `base_url`.
* **Timeouts** — every tool invocation has a default outer timeout (subfinder/dnsx: 5 min; nuclei: 60 min; sslscan: 5 min/host; playwright: 30 s/host; LLM: 120 s/host).
* **Resource limits** — each `asyncio.Semaphore` is configurable. sslscan and nuclei each have their own internal concurrency; WatchTower only bounds *parallel invocations*, not the parallelism inside each tool.
* **Rate-limit at the target** — `httpx` and `nuclei` both honor `-rl` from their config blocks. Playwright is gated by the parallel-context cap.
* **Empty pipeline behavior** — even with zero subdomains found, the pipeline runs to completion and emits a report with "No assets discovered" across every section.

---

## 8. Out of scope for v1

* Delta comparison between runs (explicit spec exclusion).
* Cross-tool finding deduplication (locked: segregated lenses).
* Authorization preflight (locked: none).
* Authenticated scans / login flows in Playwright.
* Active exploitation — every tool is in detection-only mode.
* IPv6 triage.
* Template repo pinning.
* Aggregate "score" (locked: histogram only).
* Native (non-Docker) install paths.
* **Profile-driven scanner tuning** — letting the `AppProfile` steer which deterministic
  scans run (skip nuclei on a "static" asset, pick nuclei tags by app type). Deferred:
  v1 keeps every deterministic scanner at full coverage; the profile is available as a
  documented future hook but never gates a scan.

---

## 9. Known risks (acknowledged)

| Risk | Mitigation |
|---|---|
| AI findings counted in histogram with no badge | Strict Pydantic schema + retry + graceful degrade. Prompt engineering carries the trust. |
| Nuclei templates always-latest = runs not comparable across days | Each run records template SHA in `versions.json` for after-the-fact attribution. |
| No authz preflight | Operator-trust model; recommended only for internal use. |
| Docker-only excludes Docker-averse Debian users | Documented; not addressed in v1. |
| AI mis-profiles an app and skews finding severity | Influence is confined to **AI findings only** — deterministic scanners run full coverage regardless. `confidence: low` profiles suppress escalation; hard failures fall back to default prompts. The profile + its reasoning are shown in the report for operator override. |
| httpx pre-JS body is thin for SPAs | `<title>`/meta/OG come from the static `<head>` and survive; the profiler is told the HTML is pre-render so it does not over-read an empty body. **`ai.profile.render: auto`/`always`** further closes this by feeding the crawler's **post-render** text + curated surface when the crawler ran for the host (§2.3.1). |
| Selective scans imply false coverage | Three-state coverage manifest + "Not run in this scan" placeholders ensure a skipped capability never reads as scanned-and-clean (§2.8.4). |
