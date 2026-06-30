# AGENTS.md — working in the WatchTower repo

Orientation for AI agents. Read this first, then the canonical docs below.

## What this is

WatchTower is a **point-in-time, single-run external AppSec audit orchestrator**.
A modular async pipeline (recon → triage → audit fan-out → AI analysis →
aggregate → `report.html`) driven by a CLI, a Python API, and a Web API. **No
database, no state across runs** — every scan writes a complete, standalone
artifact set under `runs/<id>/`. Target deployment: Docker on Debian.

## Canonical docs (where to look before changing things)

| Topic | File | Authority |
|---|---|---|
| Locked design / data model / decisions | **`DESIGN.md`** | **Wins on any conflict.** |
| CLI + config + run layout + Python API | `API.md` | Reference |
| Web API contract & design | `WEB_API_PLAN.md` | Reference (implemented in `watchtower/api/`) |
| UI stack & design system | `UI-SPEC.md` | Reference (implemented in `web/`) |
| Top-level overview | `DOCS.md` | Summary |

If you change behavior, update the matching doc in the same change.

## Repo layout

```
watchtower/              Python package (the engine)
├── cli.py             argparse CLI: scan, serve, init-config, verify-deps
├── runner.py          run_scan (+ make_run_dir)
├── config.py          WatchTowerConfig (Pydantic) + throttle profiles
├── models.py          Finding, TLSHostReport, AppProfile, TriagedAsset, RunSummary, …
├── stages/            Stage protocol, pipeline assembly, capability registry, ScanState
├── recon/ audit/ ai/  tool wrappers (subfinder/dnsx/tlsx/httpx, sslscan/nuclei/crawler, LLM).
│                      audit/ also: header_checks, js_libs (retire.js-style),
│                      suppress (manual fingerprints), tech (httpx+AI merge)
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
                       `COPY watchtower`/`COPY web/` above the dep installs.
example.config.yaml    scan config sample;  example.server.yaml  server config sample
```

## Dev commands

```sh
# Python (a local venv lives at .venv; Python 3.11+):
./.venv/bin/python -m pytest -q                 # full suite (currently 263 passing)
./.venv/bin/python -m pytest tests/test_api.py  # just the Web API tests
./.venv/bin/python -m watchtower --help

# Run the Web API locally (OPEN if WATCHTOWER_API_KEYS is unset):
./.venv/bin/python -m watchtower serve -c example.server.yaml --host 127.0.0.1 --port 8099

# UI:
cd web && npm install
npm run dev                                      # dev server :3000 → talks to NEXT_PUBLIC_API_BASE
npm run build                                    # Node build
NEXT_OUTPUT=export npm run build                 # static export → web/out (served by FastAPI)

# Full image (UI + API + tools in one container):
docker build -t watchtower .
docker run --rm -p 8080:8080 -e WATCHTOWER_API_KEYS=key \
  -v "$PWD/example.server.yaml:/etc/watchtower/server.yaml:ro" \
  watchtower serve -c /etc/watchtower/server.yaml --host 0.0.0.0 --port 8080
# → UI at /,  API at /api/...
```

## Conventions & invariants (don't break these)

**Engine**
- `runs/` is the source of truth; runs are self-describing. No DB, no cross-run state.
- **Liveness, not ownership.** WatchTower is a Layer-7 AppSec tool, so assets are
  NOT classified by where their IP is hosted. There is **no** `in_scope`/
  `shadow_it`/`dead` bucket model and **no** `sanctioned_cidrs`/`sanctioned_asns`
  (both removed). `TriagedAsset.status` is a single liveness axis: `live` (≥1 A
  record → fully scanned; cert SANs feed the DNS→TLS re-feed loop) vs `dead`
  (NXDOMAIN/no A → takeover-watch only). The configured **`roots` are the only
  scope** (`under_any_root`); every name resolving under a root is scanned
  regardless of hosting. ASN/org is **display-only** enrichment via an **optional**
  `mmdb_path` (`IPInfoLookup(mmdb_path=None)` degrades to no ASN, never errors) —
  it does **not** gate scans. `ScanState` exposes `live()`/`dead()`. Old stored
  configs with the removed keys still load (`WatchTowerConfig` uses
  `ConfigDict(extra="ignore")`).
- **TLS = sslscan** (`audit/sslscan_runner.py`, stage `audit.sslscan`, leaf token
  `tls`). `build_sslscan_cmd` → `sslscan --no-failed --xml=<path> … host:port`,
  parsed with stdlib `xml.etree.ElementTree` into `TLSCheck`/`TLSHostReport`/
  `Finding` (`source='sslscan'`); raw XML kept under `runs/<id>/02_audit/sslscan/`.
  Scorecard: insecure protocols disabled, no weak ciphers (RC4/3DES/DES/EXPORT/
  NULL/MD5/anon or `<112`-bit), cert valid + `>30d`, key strength (RSA≥2048/
  EC≥256), sig-algo not SHA1/MD5, secure renegotiation. HSTS lives under `headers`,
  not here. sslscan is **passive** (no ROBOT/CCS/attack probes) → doesn't trip the
  WAFs that blocked sslyze. Config `tools.sslscan` (`timeout`+`extra_flags`),
  concurrency `concurrency.tls`. There is **no sslyze** anymore.
- Every subprocess goes through `util/subproc.run_tool` (timing/timeout/cancel events,
  process-group kill via `start_new_session=True`). Don't spawn tools directly.
  NB tool flags must match the **pinned** binary versions (Dockerfile) — e.g. tlsx
  1.1.7 has **no `-rl`**; its pacing knob is `-c` (`TlsxConfig.concurrency`). Verify
  flags against the binary in the image, not from memory.
- `recon.tlsx` does double duty in one handshake/IP: SAN harvest (the re-feed loop)
  AND a passive **cert dossier** → `CertInfo` (expiry, issuer, serial, sha256,
  self-signed/wildcard, derived in Python) into `state.tls_certs`. Inventory only
  (no findings); surfaced in report.html + `ScanResult.tls_certs` + the UI Certs tab.
- The recon spine always runs as a prerequisite. Capability tokens
  (`recon, takeovers, tls, nuclei, headers, supply-chain, ai`) are the stable
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
  applied in `ai/client.py`): the client sets `X-Title` (default `WatchTower`) +
  optional `HTTP-Referer` default headers so OpenRouter can name/group the spend.
  `LLMClient.chat(..., label=...)` reuses the existing per-call label
  (`profile[host]`/`triage[host]`/`supply[host]`, plus `nuclei-gen` from
  `nuclei_custom`): when `tag_requests`, it overrides `X-Title` with the call
  **purpose** (`WatchTower: profile`) so spend breaks down by call type, and on an
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
  best-effort (each step wrapped). `audit/surface.py::curated_surface()` projects an
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
  **AI findings now get a stable `check_id`** derived from the model's `type` tag
  (`ai/analyzer.py::_ai_check_id`, e.g. `ai_headers.cookie-missing-httponly-flag`)
  so they dedup/group/suppress by class via `group_key`. A code-level guard in
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
  (`watchtower/ai/prompts.py` `PROMPT_SLOTS` registry; UI: the AI Tuning page);
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
- A completed scan exits `0` even with recorded errors; `--strict` → exit `3`.
- **subfinder is OPTIONAL** (`RECON_REQUIRED=(dns,httpx)`, `RECON_OPTIONAL=(subfinder,tlsx)`).
  `DnsxAndTriageStage` always seeds `cfg.roots` as candidates, so `--skip recon.subfinder`
  = a quick scan of exactly the given roots/assets (no enumeration). httpx needs triaged
  targets → dns stays in the floor.
- **5 nmap-like throttle tiers**: paranoid/gentle/normal/aggressive/insane (`_PROFILES`),
  default normal. `/capabilities` returns `throttle_details` (per-profile knob summary)
  so the UI shows what each tier does. paranoid=httpx threads 1; insane=200.
- **httpx concurrency = the main block trigger** vs WAF'd targets. `HttpxConfig.threads`
  → httpx `-threads`, throttle-controlled (paranoid=1, gentle=2, normal=10, aggressive=50, insane=200);
  previously unset (httpx default 50) and only `-rl` was throttled. A 50-thread burst
  at a bank's few IPs trips temporary source-blocking → httpx returns 0 live while
  tlsx (TLS-only) still works. **Use `gentle` for hardened targets** (live A/B:
  threads 3 → 84 live, threads 50 → 0). This — not the stealth headers — was the fix.
- **Stealth identity** (`config.IdentityConfig`, `WatchTowerConfig.identity`): a
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

**Web API (`watchtower/api/`)**
- Thin async layer over the **unchanged** engine; reuses `run_scan`
  with an injected `run_dir` + shared `ScanState` for live progress.
- **Config is UI-managed and primary** (`GET`/`PUT /config`); `serve -c` is
  **optional**. `server.yaml` only *seeds* first boot; a writable JSON store
  (`ConfigManager`, path via `WATCHTOWER_CONFIG_STORE`, default
  `<output_root>/.config/server-config.json`, `0600`) is the source of truth and
  may be edited at runtime — `PUT` mutates the live `ServerConfig` in place (the
  same instance `JobManager` reads) + persists, so the next scan uses it with no
  restart. The whole scan config is editable. `llm.api_key` is UI-managed and
  **persists in the store** (write-only: masked `********` on GET; a blank/masked
  value on PUT keeps the stored key). Only the API's own auth
  (`WATCHTOWER_API_KEYS`) + webhook secret stay env-only.
- **No scan-target allowlist** (ZAP-like): the per-request `roots` is the only
  scope. The server boots even fully unconfigured; a scan is gated at submit on a
  *valid* base config (**llm endpoint only**; `mmdb` is optional — display-only
  ASN/org enrichment, not a gate) → `409 not_configured` until set via the UI,
  not on boot. NB this **removes** the earlier invariants ("secrets only from
  env", "`allowed_roots` 403 guardrail"). With auth OPEN there is now NO
  server-side scope ceiling — keep `WATCHTOWER_API_KEYS` set before exposing it.
- **SQLite** (`api/db.py`, `<output_root>/watchtower.db`, stdlib `sqlite3` off-loop
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
  UI: Findings column (severity dots) + a Details dialog (profile · tech · findings ·
  **surface/connections + screenshot thumbnail**, all lazy-loaded on expand).
- **Scan templates** (`api/scan_templates.py`, `scan_templates` table): reusable
  OPTION presets (only/skip/throttle/compress, NO target). `GET/POST/DELETE
  /scan-templates`; New-Scan form has Load-template + Save-as-template + a one-click
  "Quick scan (roots only)" (selection=skip + recon.subfinder). The separate recon
  toggles were removed — subfinder/tlsx are controlled via the only/skip picker.
- **Persistence**: config store + `watchtower.db` live under `output_root` (`/data/runs`),
  so a Docker REBUILD wipes them unless mounted. `docker-compose.yml` mounts a named
  volume `watchtower-data:/data/runs`; `/capabilities.paths` surfaces the live paths
  (shown on the Settings page). DB column adds use guarded `_MIGRATIONS` in `db.py`.
- **DB tables (all server-only):** `assets`, `scans` (history index, written at
  terminal state by `history.ScanHistory`), `schedules`, `suppressions`,
  `nuclei_templates` (catalog), `custom_templates`.
- **Scheduling** (`api/scheduler.py`): in-process asyncio loop over `schedules`;
  friendly cadence (hourly/daily/weekly + at_time/weekday, UTC), fires a normal
  scan via JobManager (skip-if-running; run-overdue-once-on-boot).
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

**UI (`web/`)**
- Tailwind v4 oklch tokens in `src/app/globals.css`; always compose classes with
  `cn()` (`src/lib/utils.ts`). Dark-first theme provider; shadcn/ui over Radix in
  `src/components/ui/`. Typed API client in `src/lib/api.ts`; TS types in
  `src/lib/types.ts` mirror `watchtower/api/models.py` — **keep them in sync**.
- Must stay **static-export-safe** (no dynamic route segments — the scan detail page
  uses `/scans/detail?id=…`), so FastAPI can serve the built `out/` from one image.

## After you change things
- Run `./.venv/bin/python -m pytest -q` (engine + API) and `cd web && npm run build`.
- If you touched the API contract, update both `watchtower/api/models.py` and
  `web/src/lib/types.ts`, plus `WEB_API_PLAN.md` / `API.md`.
- Commit only when asked; this repo is currently not a git repository.
