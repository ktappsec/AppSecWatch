# AGENTS.md — working in the AppSecWatch repo

Orientation for AI agents. Read this first, then the canonical docs below.

## What this is

AppSecWatch is a **point-in-time, single-run external AppSec audit orchestrator**.
A modular async pipeline (recon → triage → audit fan-out → AI analysis →
aggregate → `report.html`) driven by a CLI, a Python API, and a Web API. **No
database, no state across runs** — every scan writes a complete, standalone
artifact set under `runs/<id>/`. Target deployment: Docker on Debian.

## Canonical docs (where to look before changing things)

| Topic | File | Authority |
|---|---|---|
| Locked design / data model / decisions | **`DESIGN.md`** | **Wins on any conflict.** |
| CLI + config + run layout + Python API | `API.md` | Reference |
| Web API contract & design | `WEB_API_PLAN.md` | Reference (implemented in `appsecwatch/api/`) |
| UI stack & design system | `UI-SPEC.md` | Reference (implemented in `web/`) |
| Top-level overview | `DOCS.md` | Summary |

If you change behavior, update the matching doc in the same change.

## Repo layout

```
appsecwatch/              Python package (the engine)
├── cli.py             argparse CLI: scan, serve, init-config, verify-deps
├── runner.py          run_scan (+ make_run_dir)
├── config.py          AppSecWatchConfig (Pydantic) + throttle profiles
├── models.py          Finding, TLSHostReport, AppProfile, TriagedAsset, RunSummary, …
├── stages/            Stage protocol, pipeline assembly, capability registry, ScanState
├── recon/ audit/ ai/  tool wrappers (subfinder/dnsx/tlsx/httpx, sslscan/nuclei/crawler, LLM).
│                      audit/ also: header_checks, js_libs (retire.js-style),
│                      secrets (client-side secret exposure over JS bodies),
│                      suppress (manual fingerprints), tech (httpx+AI merge),
│                      zap_runner (OWASP ZAP active scan over REST — opt-in)
├── report/            aggregator + Jinja renderer; two self-contained docs from a
│                      shared themeable base (report.html technical + executive.html
│                      one-pager) + optional executive.pdf
├── util/subproc.py    run_tool — every subprocess flows through here
└── api/               Web API (FastAPI): config, auth, security, models, jobs, result,
                       server, db (SQLite); assets, history (scans index), scheduler,
                       suppressions, nuclei_catalog, nuclei_custom (+ generator)
tests/                 pytest suite (asyncio_mode=auto). External tools are mocked.
web/                   Next.js 16 UI (AppSecMan design system) over the Web API
Dockerfile             multi-stage, layer-cached: deps installed in layers keyed
                       only on pyproject.toml / package-lock.json, source copied
                       LAST + BuildKit cache mounts — a code edit rebuilds in ~10s
                       (no dep reinstall / Chromium re-download). Don't move the
                       `COPY appsecwatch`/`COPY web/` above the dep installs.
example.config.yaml    scan config sample;  example.server.yaml  server config sample
```

## Dev commands

```sh
# Python (a local venv lives at .venv; Python 3.11+):
./.venv/bin/python -m pytest -q                 # full suite (currently 263 passing)
./.venv/bin/python -m pytest tests/test_api.py  # just the Web API tests
./.venv/bin/python -m appsecwatch --help

# Run the Web API locally (OPEN if APPSECWATCH_API_KEYS is unset):
./.venv/bin/python -m appsecwatch serve -c example.server.yaml --host 127.0.0.1 --port 8099

# UI:
cd web && npm install
npm run dev                                      # dev server :3000 → talks to NEXT_PUBLIC_API_BASE
npm run build                                    # Node build
NEXT_OUTPUT=export npm run build                 # static export → web/out (served by FastAPI)

# Full image (UI + API + tools in one container):
docker build -t appsecwatch .
docker run --rm -p 8080:8080 -e APPSECWATCH_API_KEYS=key \
  -v "$PWD/example.server.yaml:/etc/appsecwatch/server.yaml:ro" \
  appsecwatch serve -c /etc/appsecwatch/server.yaml --host 0.0.0.0 --port 8080
# → UI at /,  API at /api/...
```

## Conventions & invariants (don't break these)

**Engine**
- `runs/` is the source of truth; runs are self-describing. No DB, no cross-run state.
- **Liveness, not ownership.** AppSecWatch is a Layer-7 AppSec tool, so assets are
  NOT classified by where their IP is hosted. There is **no** `in_scope`/
  `shadow_it`/`dead` bucket model and **no** `sanctioned_cidrs`/`sanctioned_asns`
  (both removed). `TriagedAsset.status` is a single liveness axis: `live` (≥1 A
  record → fully scanned; cert SANs feed the DNS→TLS re-feed loop) vs `dead`
  (NXDOMAIN/no A → takeover-watch only). The configured **`roots` are the only
  scope** (`under_any_root`); every name resolving under a root is scanned
  regardless of hosting. ASN/org is **display-only** enrichment via an **optional**
  `mmdb_path` (`IPInfoLookup(mmdb_path=None)` degrades to no ASN, never errors) —
  it does **not** gate scans. `ScanState` exposes `live()`/`dead()`. Old stored
  configs with the removed keys still load (`AppSecWatchConfig` uses
  `ConfigDict(extra="ignore")`).
- **TLS = sslscan** (`audit/sslscan_runner.py`, stage `audit.sslscan`, leaf token
  `tls`). `build_sslscan_cmd` → `sslscan --no-failed --xml=<path> … host:port`,
  parsed with stdlib `xml.etree.ElementTree` into `TLSCheck`/`TLSHostReport`/
  `Finding` (`source='sslscan'`); raw XML kept under `runs/<id>/02_audit/sslscan/`.
  Scorecard: insecure protocols disabled, no weak ciphers (RC4/3DES/DES/EXPORT/
  NULL/MD5/anon or `<112`-bit), cert valid + `>30d`, key strength (RSA≥2048/
  EC≥256), sig-algo not SHA1/MD5, secure renegotiation. HSTS lives under `headers`,
  not here. sslscan is **passive** (no ROBOT/CCS probes) → doesn't trip the
  WAFs that blocked sslyze. **Aggressiveness is tuned down in `build_sslscan_cmd`**:
  it drops the probe categories the scorecard never reads —
  `--no-heartbleed` (an ACTIVE malformed-heartbeat exploit probe, the loudest
  "attack scanner" tell), `--no-compression`, `--no-fallback`, `--no-groups` —
  for fewer handshakes + a quieter signature (protocol/cipher/cert/renegotiation
  stay on). Within a host, `SslscanConfig.sleep_ms` (throttle-controlled → the
  `--sleep=<ms>` flag) paces between the many per-cipher handshakes so a full
  enumeration doesn't burst a hardened edge; it's **0 on normal/aggressive/insane**
  and **150/400 on gentle/paranoid** (`_PROFILES["tls_sleep_ms"]`, surfaced in
  `throttle_details`). Cross-host pacing is still `concurrency.tls`. Config
  `tools.sslscan` (`timeout`+`sleep_ms`+`extra_flags`). There is **no sslyze** anymore.
- Every subprocess goes through `util/subproc.run_tool` (timing/timeout/cancel events,
  process-group kill via `start_new_session=True`). Don't spawn tools directly.
  NB tool flags must match the **pinned** binary versions (Dockerfile) — e.g. tlsx
  1.1.7 has **no `-rl`**; its pacing knob is `-c` (`TlsxConfig.concurrency`). Verify
  flags against the binary in the image, not from memory.
- `recon.tlsx` does double duty in one handshake/IP: SAN harvest (the re-feed loop)
  AND a passive **cert dossier** → `CertInfo` (expiry, issuer, serial, sha256,
  self-signed/wildcard, derived in Python) into `state.tls_certs`. Inventory only
  (no findings); surfaced in report.html + `ScanResult.tls_certs` + the UI Certs tab.
  **The dossier is IP-keyed** — it connects to an IP and reads whatever cert is
  served; that cert names hosts via `subject_cn`/SANs which may point their DNS at a
  DIFFERENT IP (shared hosting, a stale/decommissioned endpoint). So a cert here is
  "observed on IP X", NOT "hostname N's posture" (the authoritative per-host check is
  `sslscan`, which connects by hostname+SNI). `tls_san.annotate_certs_dns` stamps each
  cert (post-loop, zero new lookups from the `final_live` set) with `resolving_names`
  (scanned FQDNs whose DNS resolves to this cert's IP) and `subject_cn_ips` (where the
  cert's own CN resolves; empty = wildcard/unscanned = "unknown"). The Certs table +
  report show a "Serving" column and a **"CN resolves elsewhere →"** pill when
  `subject_cn ∉ resolving_names` and it resolves elsewhere (the real owa.saglampay
  case: an expired cert on a stale IP reached via a sibling name, not the live host).
  Per-asset, `GET /assets/{fqdn}/certs` matches by **IP intersection**
  (`cert.ip ∈ asset.a_records`), never by SAN, so a host shows the cert on the IP it
  actually resolves to (surfaced in the Assets drawer's Certificates section).
- The recon spine always runs as a prerequisite. Capability tokens
  (`recon, takeovers, tls, nuclei, headers, supply-chain, zap, ai`) are the stable
  user-facing names; the token→stage mapping + dependency resolution live **only**
  in `stages/capabilities.py` / `stages/pipeline.py`. Four of them split into
  dotted **sub-tokens** (`recon.subfinder|dns|tlsx|httpx`, `ai.profile|triage|
  supply-chain|summary`, `headers.csp|best-practice`, `nuclei.<severity>`); a parent
  expands to all its sub-tokens (back-compat), and `resolve_selection` returns a
  `SelectionPlan` that `build_pipeline` uses to assemble the exact sub-steps.
  Coverage marks a parent `partial` when only some sub-steps ran. If you
  add/rename a sub-token, update `SUBTOKENS` + the UI `CAPABILITY_TOKENS` together.
  NB `ai.headers` was renamed `ai.triage`; `_TOKEN_ALIASES` in `capabilities.py`
  maps the old token forward so saved templates/schedules keep working.
- The AI layer never gates deterministic scanners; all LLM output is
  Pydantic-validated with one retry then graceful degradation. Party-ness
  (1st/3rd) is decided in Python (`tldextract`), never by the LLM.
- **LLM request attribution** (`LLMConfig.app_title`/`app_url`/`tag_requests`,
  applied in `ai/client.py`): the client sets `X-Title` (default `AppSecWatch`) +
  optional `HTTP-Referer` default headers so OpenRouter can name/group the spend.
  `LLMClient.chat(..., label=...)` reuses the existing per-call label
  (`profile[host]`/`triage[host]`/`supply[host]`, plus `nuclei-gen` from
  `nuclei_custom`): when `tag_requests`, it overrides `X-Title` with the call
  **purpose** (`AppSecWatch: profile`) so spend breaks down by call type, and on an
  OpenRouter `base_url` it sets the OpenAI `user` field to the full label for
  per-host granularity. Headers/`user` are ignored by other backends, so it's safe
  off OpenRouter. If you add a new `chat()` caller, pass a `label`.
- **Per-call model overrides** (`LLMConfig.models`, applied in `chat()`): a dict
  keyed by the same call **purpose** (`profile`/`triage`/`supply`/`nuclei-gen`);
  `chat()` resolves the per-call model from it via the label, falling back to
  `model`. Empty = one model everywhere (default). Lets a cheap model run profiling
  while triage (it can suppress findings) keeps a capable one. The purpose key is
  the label prefix, NOT the capability token — note `supply`, not `supply-chain`.
- **Two reports, one shared base.** `report/renderer.py` renders BOTH `report.html`
  (the full technical doc — content unchanged) and `executive.html` (a ≤2-page
  leadership one-pager) from the SAME `build_report_context` dict, via a shared
  Jinja base (`templates/_base.html.j2` + `_theme.css.j2`). Both stay single-file
  /self-contained (inline CSS+JS, no external assets) and gain a **light/dark
  toggle** (head theme-init sets `data-theme` from `localStorage` else
  `prefers-color-scheme`; `@media print` forces the light palette). When you touch
  report markup, keep it shared in `_base.html.j2`; never interpolate a Jinja var
  into the theme-init `<script>` (use `|tojson`).
- **The executive report has a deterministic core + optional AI overlay.**
  `aggregator.build_executive_context` computes the posture rating (highest
  severity present + volume note), severity counts, scale (DNS-live vs
  HTTP-responding `live_servers`), and **top-5 risks** (`select_top_risks`, grouped
  by `source|title`, ranked severity→host-count→key) — ALWAYS, even with AI off.
  `ai.summary` (new sub-token; ONE LLM call at the **TAIL** of `ai-analyze`, after
  triage suppression; label/purpose `summary`) adds the narrative paragraph +
  per-risk "why it matters" + next-steps onto `state.exec_summary`; a degrade falls
  back to templated prose. **Merge is by stable key, not `ref`**: the stage binds
  each AI note's `ref`→the risk `key`, and the renderer re-selects top-N over the
  FINAL visible set (manual `SuppressionStage` runs after the summary stage) and
  drops notes whose key isn't shown. So the AI overlay is strictly best-effort.
- **Executive artifacts + branding.** `ReportStage` always writes `executive.html`
  next to `report.html`. A separate `ExecPdfStage` (`report.pdf`, gated on
  `cfg.report.executive_pdf`, threaded as `build_pipeline(include_exec_pdf=…)`)
  best-effort renders `executive.pdf` via the bundled Chromium — it **catches
  everything internally and never raises** (raising would pollute `errors.json` +
  trip `--strict`). Branding is `cfg.report` (`org_name`→root fallback,
  `classification`→"Confidential", `logo_path` base64-embedded, `executive_pdf`).
  Web API exposes `GET /scans/{id}/executive` + `/executive.pdf` and result
  `executive_url`/`executive_pdf_url` (PDF url null when absent).
- **The profiler (`ai.profile`) runs at the HEAD of the `ai-analyze` phase**
  (after the audit fan-out), NOT pre-audit — so it can read the crawler's rendered
  capture. Nothing in takeovers/audit consumes `app_profiles`; only `ai.triage`/
  `ai.supply-chain` do, and the profile is produced first. Its INPUT source is
  `cfg.ai.profile.render` (`auto|always|never`, default `auto`, per-scan override
  `ScanRequest.profile_render`): **auto** uses the crawler's `rendered_text` +
  `curated_surface()` manifest when supply-chain ran (else httpx pre-JS signals);
  **always** force-includes the crawler (the `supply-chain` capability) in
  `build_pipeline` even when supply-chain analysis is off — running `CrawlerStage`
  only, never extra LLM calls (coverage marks it `forced for profile.render=always`);
  **never** = httpx only. `build_profile_prompt` adds `rendered_body_text` +
  `observed_resources` to the user payload (assembly in code; shape hint unchanged).
- **The crawler captures a STRUCTURE-ONLY manifest** (`audit/crawler.py`): every
  response (`resources`: url/type/status/method, dedup+capped), `scripts` (kept for
  `js_libs`/supply-chain back-compat), cookie **names+flags** (`cookies`, NO value),
  localStorage/sessionStorage **key names** (NO values), `rendered_text`
  (`body.innerText`, whitespace-normalized + ≤2KB), and an optional per-host
  **screenshot** (`tools.playwright.screenshot`, default true). **Never values or
  bodies** — `runs/<id>/` + `report.html` are shareable/emailable; capturing
  secrets would make a scan a credential-leak vector. `_capture_state` is
  best-effort (each step wrapped). **Requests that FAIL at the network layer**
  (WAF reset/abort, DNS, timeout) fire Playwright's `requestfailed`, NOT
  `response` — so they're captured separately into `failed_requests`
  ({url,type,method,failure}, names/reason only). Without this a bot-blocked crawl
  (only the document loads, 0 subresources) is byte-identical to a script-free
  page; `_summarize_failed_requests` appends a "crawl degraded / likely
  bot-blocked" note to `artifact.errors` (→ surfaced in `errors.json` by
  `CrawlerStage`) when failures are **material** (document itself failed, ≥3
  failures, or only the document(s) returned) so a few blocked trackers stay
  quiet. `audit/surface.py::curated_surface()` projects an
  artifact into the names-only `{third_party_domains, script_domains, endpoints,
  cookie_keys, storage_keys}` dict (query strings dropped) — the ONE source reused
  by both the profiler summary and the EASM per-asset surface. Playwright is
  lazy-imported inside the browser-driving functions, so `crawler.py` (and its pure
  helpers) import without the heavy dep.
- `headers` is a deterministic, passive capability: `audit/header_checks.py`
  evaluates the captured `PageSignals.headers` (OWASP best-practice + structured
  CSP) into first-class `Finding`s (sources `headers`/`csp`, each with a stable
  `check_id`). **Cookie-flag checks skip infrastructure cookies.**
  `audit/cookies.py::is_infra_cookie()` is the single source of truth for
  load-balancer / WAF / RUM cookies (F5 BIG-IP `TS*`/`BIGipServer*`/`f5avr*`/
  `f5_cspm`/`MRHSession`, AWS ALB, Citrix `NSC_`, Cloudflare `__cf*`, Imperva,
  Akamai, AppDynamics `ADRUM`, Dynatrace `dt*`). These carry no session/auth state,
  so their missing HttpOnly/Secure/SameSite flags are **dropped entirely** (not a
  finding) and they no longer trip `_apparently_sensitive`. Reused by the AI guard.
- **Finding identity / dedup.** Every finding has a stable `group_key` property
  (`models.py`): `check_id` when present, else a source-specific natural key, else
  the title. It is the ONE grouping key reused by `suppress.finding_key` (manual
  fingerprints), `aggregator.select_top_risks` (`source|group_key`), and the
  `report.html.j2` `groupby('group_key')` — so the same issue collapses across
  hosts into one row instead of one-per-host.
- **`ai.triage`** (formerly `ai.headers`) is a per-host pass that triages **all**
  deterministic findings for the host — nuclei/TLS/js_lib/headers/takeover, not
  just headers. It (a) **soft-suppresses** false-positives across every source by
  the ephemeral integer `ref` each finding is given in the prompt payload, and
  (b) adds new header findings the rules miss (these keep source `ai_headers`).
  **The keep/suppress decision is anchored on a multi-vector harm test, not on
  list length** (`_TRIAGE_HARM_TEST` in `prompts.py`): a finding is KEPT when it
  contributes real risk under any of host/data compromise, user harm, brand /
  reputational damage, phishing / impersonation enablement, or supply-chain
  exposure — even at **low** severity — and suppressed only when it contributes to
  none (false-positive, N/A here, or accepted by-design). The supply-chain prompts
  use the same harm framing (brand-damage from a compromised third-party script is
  explicit). The old "prefer FEW / when unsure omit" volume heuristics were removed.
  **AI findings now get a stable `check_id`** derived from the finding's **title**
  (slugified + length-capped; `ai/analyzer.py::_ai_check_id`, e.g.
  `ai_headers.session-cookie-missing-httponly`) so they dedup/group/suppress by
  class via `group_key`. **It keys on the title, NOT the model's `type` tag**: the
  independent per-host LLM calls keep the human title consistent for the same issue
  but routinely emit a *different* `type` slug, so a type-derived id split two
  visibly-identical cross-host findings into separate report rows (the regression
  this replaced). The non-finding drop guard still keys on `type` (a class name),
  not the grouping id. A code-level guard in
  `_ai_findings_to_findings` **drops** AI non-findings (`type` in
  `positive-observation`/`no-scripts-loaded`/`best-practice-reminder`/
  `missing-control-check`/`server-config-concern`) and infra-cookie findings
  (`is_infra_cookie` on the evidence cookie), backstopping the tightened prompts.
  Suppression attaches an `AIFindingVerdict` (`source='ai_triage'`) that hides a
  finding from the report + severity counts but **never deletes** it (kept in
  `findings.json`). Gating lives in `cfg.ai.suppression`: `enabled`,
  `min_confidence` (default **medium**), `max_severity` ceiling (default
  **medium** — findings above it are never offered to the AI, so always stay
  visible), and `require_profile` (default **false** — the profile is calibration,
  not a precondition). An AI degrade suppresses nothing, so the no-gating
  invariant holds. System prompts are overridable via `cfg.ai.prompts`
  (`appsecwatch/ai/prompts.py` `PROMPT_SLOTS` registry; UI: the AI Tuning page);
  shape-hints + user assembly stay in code so an override can't break JSON.
- **`takeovers` has two halves** (`stages/audit.py` `TakeoversStage`): nuclei
  `http/takeovers/` templates all `GET {{BaseURL}}` + match a live unclaimed-page
  body fingerprint, so they need a **resolving** host → fed the **live** hosts
  whose `cname_chain` has a hop NOT `under_any_root(cfg.roots)` (a third-party
  CNAME, NOT `dead` which has no A records). The dangling/NXDOMAIN class (the
  `dead` set) is matched **deterministically/offline** against a bundled provider
  DB (`audit/takeover_fingerprints.py` + `data/takeover_fingerprints.json`, from
  can-i-take-over-xyz) over the stored `cname_chain` — the class nuclei
  structurally can't reach. Both emit `source='takeover'`; deterministic findings
  carry `check_id=takeover.<service>`.
- **`zap` is the OPT-IN active-DAST capability** (OWASP ZAP). It is the ONE thing
  that breaks the otherwise-passive posture, so it is gated hard. ZAP is NOT
  bundled and NOT a `run_tool` subprocess: it runs as a **sidecar daemon**
  (`ghcr.io/zaproxy/zaproxy`, `docker-compose.yml` `zap` service) and
  `audit/zap_runner.py` drives it over the **REST API** with `httpx` (already a
  dep — no new package). `ZapStage` (`audit.zap`, in `stages/audit.py`) lazy-imports
  `run_zap`; the flow per target is spider → (optional ajax) → active scan, polled
  against a Python deadline (`ZapConfig.max_minutes_per_host/_total/spider_max_minutes`;
  ZAP self-paces, so it is **exempt from the throttle profiles** — top-level
  `cfg.zap`, NOT a `tools.*` `ToolBlock`). On a deadline or `/cancel`
  (`CancelledError`) it stops the scans + removes the context in `finally` and
  re-raises; an unreachable daemon **degrades** (no findings, run continues).
  **Opt-in is enforced in three layers**: `OPT_IN_TOKENS={"zap"}` is subtracted
  from the default + `--skip` caps seeds in `capabilities.py` (so `zap` runs ONLY
  via explicit `--only zap`, never on a preset); `/capabilities` omits `zap` unless
  `zap.enabled && base_url`; and `submit` 409s (`ZapRejected`/`zap_rejected`) when
  zap is selected but the daemon is off, targets are empty, or any target is not
  `under_any_root(cfg.roots)`. **Targets are operator-specified + scope-locked**:
  `ScanRequest.zap_targets` rides on `cfg.zap.targets` (injected in
  `jobs._build_config`, persisted on `JobRecord`), and `ZapStage` re-filters scope
  as defense-in-depth. Alerts → `Finding(source='zap')`, grouped by
  `(pluginId, host)`, risk→severity (High→high … Informational→info, **no
  critical**), `check_id=zap.<pluginId>`; raw report under `02_audit/zap/`. ZAP
  findings flow through `ai.triage` for normal FP suppression but there is
  **deliberately no cross-source dedup** — ZAP passive overlap with
  headers/nuclei/js_lib is tolerated as separate source-labeled rows (zap is rare).
  `zap.api_key` is a secret (masked like `llm.api_key`; `_mask_secrets` in
  `api/config.py`, redacted in `runner._snapshot_config`). v1 is **unauthenticated**
  (the `auth_headers` config field is a future header-injection seam). UI: `zap`
  config is a **promoted friendly card** in `web/.../settings/scan-config.tsx`
  (enable/url/key/ajax/policy/time-caps; spreads the loaded block so un-exposed
  knobs survive); `ScanRequest.zap_ajax_spider` (`bool | null`) is a **per-scan
  override** of `zap.ajax_spider` plumbed exactly like `profile_render` (a New Scan
  form checkbox → injected into the merged `cfg.zap` in `jobs._build_config`).
- A completed scan exits `0` even with recorded errors; `--strict` → exit `3`.
- **subfinder is OPTIONAL** (`RECON_REQUIRED=(dns,httpx)`, `RECON_OPTIONAL=(subfinder,tlsx)`).
  `DnsxAndTriageStage` always seeds `cfg.roots` as candidates, so `--skip recon.subfinder`
  = a quick scan of exactly the given roots/assets (no enumeration). httpx needs triaged
  targets → dns stays in the floor.
- **5 nmap-like throttle tiers**: paranoid/gentle/normal/aggressive/insane (`_PROFILES`),
  default normal. `/capabilities` returns `throttle_details` (per-profile knob summary)
  so the UI shows what each tier does. paranoid=edge_conc 1; insane=200.
- **Edge concurrency is ONE shared budget, not a per-tool preference.** Each tier
  declares `edge_conc` = how many TCP+TLS connections it will hold open against the
  TARGET at once; every target-facing knob derives from it and **none may exceed
  it** — httpx `-threads`, tlsx `-c`, `conc_tls` (parallel sslscan hosts),
  `conc_playwright`. `config._assert_profiles_coherent()` enforces this at import
  (+ tests); `dnsx_rl` is deliberately OFF this axis (it queries resolvers, not the
  web edge, and is measured not to contribute). **A tier is only as quiet as its
  loudest tool.** Two independent triggers are proven:
  - **httpx `-threads`** — a 50-thread burst at a bank's few IPs trips temporary
    source-blocking (live A/B: threads 3 → 84 live, threads 50 → 0).
  - **tlsx `-c`** — 2026-07-17 (kuveytturk.com.tr): `-c 20` blackholed our source
    IP **~30s into the cert-grab, BEFORE httpx sent a packet**. The table had let
    tlsx run ~10x the tier's edge concurrency at EVERY tier, so `gentle` paced
    httpx to 2 threads then opened 20 simultaneous handshakes. tlsx has no `-rl` —
    `-c` is its only control, so `tlsx_conc == edge_conc`.
  **Diagnostic tell — read it the right way round**: "httpx returns 0 live while
  tlsx (TLS-only) still works" is NOT evidence that httpx is too loud. It is the
  signature of a **prior** stage having already blocked the source IP: tlsx is
  unaffected by the L7 block it caused and reports full success, while httpx then
  probes a dead network, hangs every host to its timeout, hits the `recon.py`
  `budget` deadline, and loses **all** results (`run_tool` buffers to EOF). That
  misreading is what produced runs showing "0 live servers / 0 findings" with an
  empty `errors.json`.
- **The block is a silent packet drop, not an HTTP 403** (`curl` → `code=000
  rc=28`). Nothing in a response can reveal it, and the tool that causes it
  reports success — so it only ever surfaces in a LATER stage. To attribute a
  block to a stage, run an **independent control probe** (one request every 15s to
  a known-good URL from the same egress IP) alongside the scan and correlate its
  first failure against `stage_start`. **Use `gentle` for hardened targets.**
- **Assessability** (`audit/liveness.py`): a probed host is only audited as a real
  application when its response IS one. `classify_assessability(PageSignals)` →
  `(assessed, reason)` is the single source of truth: NOT assessed for no-response,
  `status>=500`, or a WAF/block signature (a block-marker phrase in title/body at any
  status — e.g. F5 "Request Rejected", the Turkish "Aradığınız sayfaya ulaşılamıyor" —
  or a 401/403/429 with an empty/tiny body). A form/password input or real 2xx content
  is always assessed. `PageSignals.status_code` (new, carried from httpx) feeds it;
  `web_probe` stamps `LiveWebServer.assessed`/`not_assessed_reason`. The pre-report
  `LivenessGateStage` (`stages/suppress_stage.py`, always on, runs before manual
  suppression + report) then (a) **coverage-suppresses** every finding on a
  not-assessed host across ALL sources via an `AIFindingVerdict(source="coverage")`
  (hidden + uncounted + off the posture, kept in findings.json; never overwrites an
  existing verdict) so an error/WAF page can't emit fake findings — the report lists
  those hosts in a distinct "Not assessed / blocked" section (NOT "clean"); and (b)
  flags a **degraded run** when httpx returned 0 live servers despite ≥1 live asset
  (edge blocked the probe — nothing audited): `state.degraded`/`degraded_reason` +
  `summary.not_assessed`, a `StageError` (so `--strict` exits 3), a report/executive
  banner, and `ScanResult.degraded`/`JobStatus.degraded` (UI "Blocked" badge) so a
  blocked scan is never shown as a clean, finding-free success. `AIFindingVerdict.source`
  gained `"coverage"`; both are DB-free (engine-computed, surfaced by the server).
- **AI-invented severity is clamped** (`ai/analyzer._AI_SEV_CEILING`): `ai_headers`
  and `ai_supply_chain` findings are capped at **high** at emit time in
  `_ai_findings_to_findings` (deterministic sources keep the full range), so the AI
  can never mint its own `critical` and unilaterally drive a CRITICAL posture — the
  mirror of the suppression `max_severity` ceiling (which caps what it may HIDE). The
  shape-hint enums (`prompts.py`) no longer offer `critical` as a backstop.
  `_extract_json` uses `json.JSONDecoder().raw_decode` to take the first top-level
  object (recovers the "Extra data: trailing object" degradations); `_ai_evidence_cookie`
  also reads `set-cookie`/`set_cookie`/`value` keys so F5 infra cookies the model
  labels itself are dropped by the infra-cookie guard.
- **Stealth identity** (`config.IdentityConfig`, `AppSecWatchConfig.identity`): a
  `preset` (off | chrome-win | chrome-mac | firefox) bundles a coherent browser
  UA + headers + locale; `user_agent`/`headers`/`locale` override/extend it. The
  default is now **`chrome-win`** (every scan presents a Chrome-on-Windows identity
  unless set to `off`). Chrome presets ship **only the low-entropy client hints**
  (`Sec-CH-UA`/`-Mobile`/`-Platform`) a real browser sends on a cold first request —
  the high-entropy `Sec-CH-UA-*` and the Google-proprietary `x-client-data`/
  `x-browser-*` are deliberately omitted (sending them unsolicited is itself a bot
  tell). A browser preset also rotates a **`Referer`** from `REFERER_POOL` (10
  external search/social origins) and sets **`Sec-Fetch-Site: cross-site`** to match;
  rotation is per `effective_headers()` call (once per tool run → httpx/nuclei/crawler
  each get an independent referrer), and an operator-pinned `headers['Referer']`
  overrides it. `effective_user_agent/headers/locale` are injected into **httpx**
  (`-H`), **nuclei** (`build_nuclei_cmd` UA override + `-H`), and the **crawler**
  (browser context UA/extra_http_headers/locale). Takeovers are skipped (they hit
  dangling third-party services, not the target). NB this defeats UA/header WAF
  rules only — NOT TLS/JA3 fingerprinting or IP-reputation (the crawler's real
  Chromium fingerprint is the genuinely stealthy surface). No proxy support yet.

**Web API (`appsecwatch/api/`)**
- Thin async layer over the **unchanged** engine; reuses `run_scan`
  with an injected `run_dir` + shared `ScanState` for live progress.
- **Config is UI-managed and primary** (`GET`/`PUT /config`); `serve -c` is
  **optional**. `server.yaml` only *seeds* first boot; a writable JSON store
  (`ConfigManager`, path via `APPSECWATCH_CONFIG_STORE`, default
  `<output_root>/.config/server-config.json`, `0600`) is the source of truth and
  may be edited at runtime — `PUT` mutates the live `ServerConfig` in place (the
  same instance `JobManager` reads) + persists, so the next scan uses it with no
  restart. The whole scan config is editable. `llm.api_key` is UI-managed and
  **persists in the store** (write-only: masked `********` on GET; a blank/masked
  value on PUT keeps the stored key). Only the API's own auth
  (`APPSECWATCH_API_KEYS`) + webhook secret stay env-only.
- **No scan-target allowlist** (ZAP-like): the per-request `roots` is the only
  scope. The server boots even fully unconfigured; a scan is gated at submit on a
  *valid* base config (**llm endpoint only**; `mmdb` is optional — display-only
  ASN/org enrichment, not a gate) → `409 not_configured` until set via the UI,
  not on boot. NB this **removes** the earlier invariants ("secrets only from
  env", "`allowed_roots` 403 guardrail"). With auth OPEN there is now NO
  server-side scope ceiling — keep `APPSECWATCH_API_KEYS` set before exposing it.
- **SQLite** (`api/db.py`, `<output_root>/appsecwatch.db`, stdlib `sqlite3` off-loop
  via `asyncio.to_thread`) is the cross-run **relational layer** — phase 1 ships the
  `assets` inventory (`api/assets.py`). **Server-only**: the engine + CLI `scan`
  stay DB-free; the server does all DB writes (UI CRUD + recon→assets sync after a
  scan, from the shared `ScanState`). `runs/<id>/` stays authoritative. Assets are
  FQDN-keyed (imported via CSV `domain,group` upsert; discovered subdomains synced
  at recon end, inheriting their root's group, imported group/notes never
  clobbered). Scan targeting is a selector: `roots | group | assets | all_assets`
  → resolved to roots before the run. Assets also store `cname_chain` + a
  liveness `status` (`live`/`dead`), both synced from recon.
- **Asset bulk**: `POST /assets/bulk {action: delete|set_group, fqdns[] |
  filter{...}}` (empty selection matches nothing — never wipes the table). The
  filter keys on `status` (was `bucket`). NB there is **no re-evaluation** step:
  `status` is a pure DNS-liveness fact recorded at recon time, not an
  ownership classification recomputed against config — so the old
  `POST /assets/reevaluate` route, `AssetManager.reevaluate`, and the
  `PUT /config` auto-reevaluate are **gone**. UI: bulk bar on the Assets page;
  assets "Scan" buttons **deep-link** to `/scans/new?group=…`/`?assets=…` (one
  scan form), and finding rows **deep-link** to `/assets?q=<fqdn>`.
- **Asset enrichment**: `_sync_assets` also writes per-host `profile` (AppProfile JSON
  when ai.profile ran) + `finding_counts` (per-severity, visible-only, seeded at 0 so
  re-scans clear stale counts) + **`surface`** (the curated names-only EASM blob from
  `curated_surface()`, last crawl only; `assets.surface TEXT` col + migration).
  `GET /assets/{fqdn}/findings` returns the asset's visible findings from its last scan
  (reads `last_scan_id`'s result.json, host=fqdn). **`GET /assets/{fqdn}/screenshot`**
  serves the last scan's per-host PNG (`02_audit/playwright/<host>.png`), 404 when
  absent — dashboard only, never in report.html; the UI fetches it as an
  authenticated blob → object URL (an `<img src>` can't send the Bearer header).
  **Compression is the default**, so by the time the endpoint runs the loose
  `02_audit/playwright/` dir has been tar+gzipped and deleted by `CompressStage` —
  the endpoint reads the PNG back out of `02_audit.tar.gz` via
  `server._read_artifact_bytes(run_dir, rel)` (loose file first, then the matching
  `<subdir>.tar.gz` member), off-loop in a thread. (Older scans that predate the
  screenshot feature have no PNG at all → 404; re-scan to populate.)
  UI: Findings column (severity dots) + a Details dialog (profile · tech · findings ·
  **surface/connections + screenshot thumbnail**, all lazy-loaded on expand).
- **Scan templates** (`api/scan_templates.py`, `scan_templates` table): reusable
  OPTION presets (only/skip/throttle/compress, NO target). `GET/POST/DELETE
  /scan-templates`; New-Scan form has Load-template + Save-as-template + a one-click
  "Quick scan (roots only)" (selection=skip + recon.subfinder). The separate recon
  toggles were removed — subfinder/tlsx are controlled via the only/skip picker.
- **Persistence**: config store + `appsecwatch.db` live under `output_root` (`/data/runs`),
  so a Docker REBUILD wipes them unless mounted. `docker-compose.yml` mounts a named
  volume `appsecwatch-data:/data/runs`; `/capabilities.paths` surfaces the live paths
  (shown on the Settings page). DB column adds use guarded `_MIGRATIONS` in `db.py`.
- **DB tables (all server-only):** `assets`, `scans` (history index, written at
  terminal state by `history.ScanHistory`), `schedules`, `suppressions` (legacy —
  retained for rollback; superseded by `finding_state`), `finding_state`,
  `notifications`, `nuclei_templates` (catalog), `custom_templates`, plus the
  guarded FTS5 virtual tables `assets_fts` / `findings_fts` (created only when the
  SQLite build has fts5; `Database.fts_enabled` gates search, LIKE fallback else).
  `assets_fts` is kept in sync on **every asset CRUD** (not just at scan end):
  `AssetManager` holds an optional `.search` (set to the `FTSIndex` in the app
  factories) and its write methods reindex/remove/rebuild best-effort —
  `upsert_imported`/`update` → `reindex_asset`, `delete` → `remove_asset`,
  `bulk_*` → `rebuild_assets` — so a freshly-imported (never-scanned) asset is
  findable in global search immediately. `FTSIndex._asset_fts_fields`/`_names`
  accept BOTH raw JSON-string rows and parsed `AssetManager` rows (`_coerce`), so
  tech/contacted-domains/profile index correctly from the scan-end reindex too.
- **Controlled finding taxonomy** (`audit/taxonomy.py`): a closed ~53-class
  vocabulary (`FINDING_CLASSES`) grouped into ~11 `CATEGORY_LABELS`. `classify()`
  maps every `FindingSource` to one class (total — falls back to
  `misc.uncategorized`); a classification pass stamps real `finding_class`/
  `category` fields on `Finding` in `build_report_context` + `build_scan_result`.
  AI findings emit a `class` from this vocabulary (aliased `finding_class` on
  `AIFinding`); their cross-scan identity + `check_id` now key on `(source, class)`
  via `analyzer._ai_check_id`, NOT the drifting title. This taxonomy is the ONE
  cross-source category dimension reused by the report/UI category collapse + the
  analytics breakdowns.
- **Unified cross-scan finding state** (`api/finding_state.FindingStateManager`,
  `finding_state` table keyed on the suppression fingerprint `source|host|group_key`):
  lifecycle (`first/last_seen_scan`, `status` open|resolved|suppressed|accepted,
  `consecutive_absent`) + freeform `tags`. **`SuppressionManager` is now a thin
  adapter over it** (suppression = `status='suppressed'`; delete = un-suppress);
  the legacy `suppressions` table is backfilled once at `db._init_schema`. RESOLVE
  RULE: a finding flips to `resolved` after being ABSENT for **2 consecutive scans
  that actually ran its producing source** (`audit/lifecycle.source_ran` +
  `state.coverage`); manual suppressed/accepted are sticky. `sync()` runs at scan
  end from `jobs._sync_finding_state` and returns the per-scan diff
  (new/recurring/resolved/reopened), persisted onto `JobRecord.diff` + `result.json`.
  The report note + exec risk-trend chart are fed by **injecting** `prior_open` +
  `report_history` into `run_scan` (engine stays DB-free; CLI passes None → degrade).
  **Group filtering of `analytics()` + `list()` resolves the group from the LIVE
  asset inventory** (`LEFT JOIN assets a ON a.fqdn = fs.host`,
  `COALESCE(a."group", fs."group")`), NOT the `finding_state."group"` stamped at
  scan time. That stamped column is only set for **group-targeted** scans —
  roots/all-assets scans leave it NULL — so filtering it alone made
  `GET /analytics?group=` (and the Analytics page's group dropdown, populated from
  asset groups) return an empty dataset for every group. The join also means
  re-grouping an asset (Assets bulk bar) re-buckets its findings immediately. NB
  **`/trends` is unavoidably per-scan** (`scans."group"`): a scan's risk_score/
  severity snapshot can't be decomposed per-group after the fact, so per-group
  trends exist ONLY for group-targeted scans (the Analytics trend card shows a
  group-scoped empty state otherwise).
- **Boot-time analytics reconcile** (`api/backfill.py::reconcile_finding_state`,
  called from both server lifespans via `server._reconcile_analytics`): `runs/` is
  authoritative and `finding_state`/the `scans` severity index are DERIVED, so on
  startup the server replays any **completed** run under `output_root` NOT yet
  reflected in `finding_state` (reconstructing `Finding`s from
  `runs/<id>/result.json`, re-`classify_findings`-ing them since pre-taxonomy rows
  carry no class/category, and calling `finding_state.sync` + repairing the scans
  `sev_*`/`risk_score` from `histogram_totals`). Fixes two cases that otherwise
  make Analytics show only the last audit: scans that completed BEFORE
  finding_state sync existed, and a rebuilt DB over a surviving runs/ volume. The
  gate is cheap (a first/last-seen membership query + a dir scan; result.json is
  read only for unreflected runs) and replay is idempotent (sync upsert), so it is
  safe on every boot. Best-effort — one malformed run never blocks startup.
- **Pluggable notifier** (`api/notify.py`): `Channel` protocol + `Notifier.dispatch`
  (best-effort). Ships `InAppChannel` (writes `notifications`) + `WebhookChannel`
  (Slack/Teams/generic, from `ServerConfig.notifier`); `EmailChannel` is a stub
  seam. Fired on `asset.new` when `assets.sync_discovered` returns FQDNs with no
  prior row (new `assets.first_seen_scan`).
- **JS-lib content scan** (`audit/js_libs.py` + `audit/crawler._scan_script_bodies`):
  in addition to URL-version matching, the crawler reads each script BODY in memory,
  runs retire.js-style `filecontent` signatures, and records only
  `{library,version,url}` onto `CrawlerArtifact.detected_libs` — **never the body**
  (shareable-artifact invariant). `library_inventory()` feeds detected libs into
  asset tech at `_sync_assets`.
- **Client-side secret scan** (`audit/secrets.py` + the SAME
  `crawler._scan_script_bodies` loop, `source='secret'`): a deterministic,
  fully-passive scan for exposed credentials in **external JS bundles** — it reads
  the bodies the js-lib scan already has in hand (**zero new requests**), runs a
  curated **precision-first** ruleset (`audit/data/secrets.json`), and records only
  `{rule,url,line,preview}` onto `CrawlerArtifact.detected_secrets`. `preview` is a
  **MASKED** boundary-only string (cred-URLs mask just the password; `mask:false`
  marker rules like `-----BEGIN … PRIVATE KEY-----` show the non-secret literal);
  the raw value is used only to mask + allow-list check, then discarded — **never
  persisted** (shareable-artifact invariant holds). An **allow-list matched FIRST**
  hard-drops known-public tokens (Firebase/Maps `AIza…`, Stripe *publishable*
  `pk_…`, Sentry DSN, reCAPTCHA, GA/GTM, Algolia search) so a bank report isn't
  flooded with public-by-design keys; no generic high-entropy catch-all in v1.
  Per-rule severity: `critical` (private keys, cloud secret keys, DB conn strings)
  / `high` (vendor secret tokens) / `medium`. It's a **deterministic** source so
  `_AI_SEV_CEILING` does NOT clamp it (a real leak can be `critical`); it flows
  through `ai.triage` normally, but `high`+ sits above the suppression
  `max_severity` ceiling → **structurally immune to AI hiding**. `check_id =
  secret.<rule>.<masked-fingerprint>` gives cross-scan/-host identity from the
  preview (no hash) → same key collapses to one report row + drives finding_state
  (rotate → old resolves, new opens). Rides `CrawlerStage` like js-libs (**no new
  capability token**; gated by `supply-chain`), kill-switch `cfg.secrets.enabled`
  (default on). Taxonomy `secrets.exposed-key` (category `crypto`). **v1 limit:
  external `<script>` bodies only** — inline `<script>` blocks + XHR/JSON response
  bodies + generic-entropy matching + user-editable rules are out of scope.
- **Report language** (`ReportConfig.language` en|tr): when `tr`, the AI profile
  summary + executive-summary narrative are written in Turkish and executive.html
  chrome is Turkish (`_EXEC_STRINGS`); vuln/finding NAMES + technical report stay
  English. Executive charts are server-rendered inline SVG (`report/svg.py`:
  donut/trend/delta), self-contained + print-friendly.
- **New API routes:** `GET /finding-state` (+ `PATCH` tags/status), `GET /analytics`,
  `GET /search` (FTS), `GET /notifications` (+ `POST /notifications/read`); `diff`
  on `ScanResult`; `GET /assets` gained `q` over tech/surface/profile + `new_since_scan`
  + `sort=priority` + **`summary=1`** (slim projection: only
  `fqdn,group,source,status,priority,finding_counts` — drops the heavy
  `tech`/`profile`/`surface` JSON; the rest of `Asset` fills from defaults). The
  **dashboard uses `summary=1`** (`listAssets({summary:true})`) since it only reads
  those fields — avoids pulling the full ~420 KB inventory. Mirrored in
  `web/src/lib/{types,api}.ts`. **Still TODO (UI):** dashboard notifications widget.
- **Inventory filtering** (`web/src/app/assets/page.tsx`): an inline filter bar —
  search + Status/Findings/Priority/Source selects (self-describing options) + Sort
  + a New toggle, with removable active-filter chips + Clear all. Facets are
  **client-side** (the full list is loaded; instant) and applied before grouping;
  the view stays **grouped by iştirak** and Sort applies **within each group** (no
  flatten). `q`/`status` stay server-side via `listAssets`, **debounced 250 ms**
  (`useDebouncedValue`) so typing fires one refetch, not one per keystroke. Rows are
  a memoized `AssetRow` (stable `useCallback` handlers) + the grouped list is
  `useDeferredValue`d — so a keystroke over ~468 rows no longer re-renders the whole
  table (was ~1.2 s INP → ~215 ms).
- **Inventory is window-virtualized** (`@tanstack/react-virtual`): the
  grouped/filtered/sorted assets are FLATTENED into one `flatItems` list of virtual
  rows (`group` divider · `colhead` · `asset`, collapsed groups contribute only
  their header) and `useVirtualizer` renders **only the ~30 rows in view** — the DOM
  holds **~960 nodes instead of ~19,500**. This was THE fix for the profiled jank:
  scroll went **13→60 fps** (max frame 833→18 ms at 4× CPU) and the route-in DOM
  cost collapsed, because scroll smoothness + the per-navigation forced reflow
  (Next's `ScrollAndFocusHandler` reads `getBoundingClientRect` after every mount)
  both scale with DOM size. Key invariants: **the real scroll container is the
  nested `<main className="overflow-y-auto">`, NOT the window** — `useScrollParent`
  (in `hooks.ts`) walks up to find it and feeds it to `getScrollElement`. It MUST
  use a **callback ref**, not a plain ref + mount effect: the virtualized list
  mounts LATE (after the async asset load), so a mount-time effect runs while the
  list element is still absent and wrongly falls back to `document.scrollingElement`
  (the `<html>`, which never scrolls) → react-virtual binds its scroll listener to
  the wrong element and **the list never advances past the first screen** (the bug
  this shipped with once). The callback ref resolves the scroll parent exactly when
  the node attaches. The list starts below the header/summary/filter cards so the
  virtualizer needs a
  **`scrollMargin`** = that offset (recomputed in a `useIsomorphicLayoutEffect` on
  load/bulk-bar/chip/resize changes, item transform is `translateY(start -
  scrollMargin)`). Rows are **flex divs, not `<table>`** (absolute positioning +
  `<table>` don't mix): a shared `COL` class map keeps the column header and every
  asset row aligned, optional columns hide at the same breakpoints on all rows.
  Per-kind heights are FIXED and exact (`ROW_SIZE`, rows render `h-full` in a
  fixed-size wrapper) so estimates never drift → no `measureElement`, no scroll
  jump. `content-visibility:auto` was REMOVED (it caused the 833 ms reveal spikes
  and is redundant once virtualized). The view still **groups by iştirak** and Sort
  still applies **within each group**; select-all-per-group / collapse / Scan group
  live on the `GroupHeaderRow`.
- **Scheduling** (`api/scheduler.py`): in-process asyncio loop over `schedules`;
  friendly cadence (hourly/daily/weekly + at_time/weekday, UTC), fires a normal
  scan via JobManager (skip-if-running; run-overdue-once-on-boot). **The New-Scan
  builder is the single scan-config surface** — a `Run now ▾` split button also
  offers **Schedule…** (a cadence dialog `POST`s the full config as a schedule).
  The Schedules page is a **management list**: light fields (name/cadence/time/
  weekday/enabled) edit inline; **Edit config ⇢** deep-links to
  `/scans/new?schedule=<id>` where the builder loads it (banner + **Update
  schedule** `PUT` / **Save as new**); each row has **Run now**. There is no
  separate schedule-create form. Every schedule `PUT` sends a COMPLETE
  `ScheduleUpsert` (via `toUpsert`) so a toggle/edit never drops only/skip/throttle.
  Cadence controls are the shared `web/src/components/schedule/cadence-fields.tsx`.
- **Manual suppression** (`api/suppressions.py` + `audit/suppress.py`): fingerprint
  `source|host|key` (host `*` = global); the server injects the set into `run_scan`,
  and `SuppressionStage` (just before report) marks matches via the verdict path
  (`source='manual'`) — cross-run, hidden+uncounted+kept. CLI passes no set.
- **JS-lib vulns** (`audit/js_libs.py`, `source='js_lib'`): retire.js-style URL
  match over crawler scripts, run inside `CrawlerStage`; bundled DB in
  `audit/data/js_libs.json`.
- **AI tech** (`audit/tech.py`): `ai.profile` emits `detected_tech`; merged with
  httpx (`[{name,source}]`) onto assets at recon→assets sync.
- **Nuclei catalog/custom** (`api/nuclei_catalog.py`, `api/nuclei_custom.py`):
  `POST /nuclei/reindex` walks the templates dir (`NUCLEI_TEMPLATES_DIR`) into
  `nuclei_templates`; custom templates (DB) are validated (structural + best-effort
  `nuclei -validate -duc -no-interactsh`, stdin=DEVNULL), mirrored into the catalog
  (`source=custom`), and materialized to a dir + added via `-t` at scan start.
  Granular selection lives in `NucleiConfig` (tags/exclude_tags/template_ids/
  templates/exclude_templates → `build_nuclei_cmd`; explicit selection suppresses `-as`).
- Errors use the `{"error":{code,message}}` envelope.
- Add API tests to `tests/test_api.py` with the runner mocked (no external tools);
  manager unit tests live in `tests/test_{assets,scheduler,suppress,js_libs,tech,nuclei}.py`.
- In the single image the API is mounted under `/api`; standalone it's at root.
- **Compression + static caching** (`server.py`): `GZipMiddleware` is added to the
  standalone `create_app` app AND to the `create_combined_app` **`parent`** (which
  wraps both the `/` static-UI mount and the `/api` sub-app — do NOT also add it to
  `api_app` or `_install`, that double-encodes `/api`). `_SPAStaticFiles` stamps
  `Cache-Control: …immutable` on `_next/static/*` (content-hashed → safe forever);
  `index.html`/other paths keep default revalidation.

**UI (`web/`)**
- Tailwind v4 oklch tokens in `src/app/globals.css`; always compose classes with
  `cn()` (`src/lib/utils.ts`). **Light-first** theme provider (dark via toggle);
  Geist Sans/Mono via the `geist` package (wired in `layout.tsx` + `@theme inline`);
  a SINGLE desaturated-indigo accent (`--primary`; `--accent` is only the quiet
  shadcn hover tint) plus semantic status/severity tokens (`--success`, `--warning`,
  `--sev-critical…--sev-info`) — never hardcode status/severity hex in components.
  shadcn/ui over Radix in `src/components/ui/`. Typed API client in `src/lib/api.ts`;
  TS types in `src/lib/types.ts` mirror `appsecwatch/api/models.py` — **keep them in sync**.
  NB `UI-SPEC.md` documents the parent AppSecMan system; AppSecWatch deliberately
  diverges where the spec header notes it (fonts, light-first, severity tokens).
- Must stay **static-export-safe** (no dynamic route segments — the scan detail page
  uses `/scans/detail?id=…`), so FastAPI can serve the built `out/` from one image.
- **Polling/fetch** (`src/lib/hooks.ts`, `src/lib/api.ts`): `usePoll` is the one
  polling primitive and now **gates its interval on tab visibility** — it pauses
  while `document.hidden` and fires one immediate refresh on becoming visible again
  (so background tabs don't re-download/re-render). Anything that needs periodic
  refresh should use `usePoll`, not a raw `setInterval` (`api-status.tsx` was
  converted). `request()` in `api.ts` **dedupes concurrent identical GETs** via an
  in-flight map. There is intentionally **no** SWR/react-query — keep it hand-rolled.
- **Charts are lazy** (`src/components/charts.tsx`): Recharts lives in
  `charts-impl.tsx` and is loaded via `next/dynamic({ssr:false})` behind
  `charts.tsx`, so non-chart routes don't ship it. `EmptyChart` is a light static
  export in `charts-empty.tsx` (no Recharts). Sidebar `<Link>`s use `prefetch={false}`
  so mounting the app doesn't eagerly prefetch every route (hover still prefetches).
- **`.transition-smooth`** (`globals.css`) transitions color/bg/border/opacity/
  transform but **deliberately NOT `box-shadow`** — shadow is the priciest property
  to transition (re-rasterizes the blur each frame) and this utility is on many
  hover targets, so shadows snap instead of fading. Keep box-shadow out of any
  broadly-applied transition.

## After you change things
- Run `./.venv/bin/python -m pytest -q` (engine + API) and `cd web && npm run build`.
- If you touched the API contract, update both `appsecwatch/api/models.py` and
  `web/src/lib/types.ts`, plus `WEB_API_PLAN.md` / `API.md`.
- Commit only when asked; this repo is currently not a git repository.
