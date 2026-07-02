# WatchTower Web API — Implementation Plan

> **Status:** Implemented in `watchtower/api/` (+ `watchtower serve`, tests in
> `tests/test_api.py`). A Next.js UI over this API lives in `web/`. This document
> remains the design reference; where it and the code disagree, the code wins.
> **Goal:** Expose WatchTower as an authenticated HTTP service so other systems can
> submit scans, track progress, and retrieve results/reports remotely.
> **Scope:** v1. Reuses the existing async runner (`run_scan`)
> and Pydantic config/models. Ships in the **same Docker image** via a new
> `watchtower serve` subcommand.

The tool is currently CLI + Python-API only: an asyncio runner over subprocess
tools, single-run, writing to a `runs/` directory and rendering a single-file
HTML report. This plan adds a thin async HTTP layer on top — it does **not**
change the scan engine.

---

## 1. Locked decisions

| # | Area | Decision | Rationale |
|---|------|----------|-----------|
| 1 | Framework | **FastAPI + uvicorn** | Async-native (awaits `run_scan` directly), Pydantic v2-native (existing models become schemas), free OpenAPI/Swagger at `/docs`. |
| 2 | Execution model | **In-process asyncio tasks**, semaphore-bounded; `runs/` is the durable record; in-memory job index rebuilt from disk on startup. | No new infra; reuses the async runner. Limitation: in-flight scans die on process restart (documented; a worker queue is the upgrade path). |
| 3 | Job state | **`job.json` per run dir** + in-memory index. On startup, glob `runs/*/job.json`; a record left `running` with no live task → `interrupted`. | Keeps the "no DB, `runs/` is truth" ethos; each run is self-describing. |
| 4 | Config delivery | **Server-side base config + minimal per-request params** (mode, target/roots, only/skip, throttle, compress). | Secrets (LLM api_key) and the optional MMDB path stay server-side; callers send tiny payloads. |
| 5 | Auth | **Static API key(s)** via `Authorization: Bearer <key>` (also accept `X-API-Key`); constant-time compare; multiple keys for per-caller revocation; 401 on missing/invalid. | Simple, sufficient for service-to-service; no identity provider. |
| 6 | Scan scope | **No scan-target allowlist (REVISED).** The per-request `roots` is the only scope (the UI specifies the domain per scan). A scan is gated only on a *valid* base config (the llm endpoint set; mmdb is optional and not part of the gate) → `409 not_configured`, not on a target allowlist. | Operator chose ZAP-like UX (UI-only, scope = the domain you enter). Trade-off: with auth OPEN there is no server-side scope ceiling — keep `WATCHTOWER_API_KEYS` set. |
| 7 | Endpoints | Standard REST + **machine-readable JSON result**. | Callers consume findings as JSON, not by scraping HTML. |
| 8 | Progress | **Polling** — rich status (state, current stage, completed_stages, elapsed, finding count); `GET /scans/{id}/log?tail=N`. | Most robust/proxy-friendly; no long-lived connections. SSE is a documented follow-on. |
| 9 | Callbacks | **Optional HMAC-signed webhook** on terminal state + SSRF guards (callback-host allowlist, short timeout, no redirect-following, failures logged not retried forever); callers without `callback_url` just poll. | Fire-and-forget for long scans without an SSRF foot-gun. |
| 10 | Backpressure | **Bounded concurrency (`max_concurrent_scans`, default 2) + bounded queue (`max_queue_depth`)**; 429 + `Retry-After` only when **both** are full. | Each scan is itself highly parallel; smooth backpressure without callers babysitting retries. |
| 11 | Cancel | `POST /scans/{id}/cancel`: queued → dropped; running → **cancel task + kill child process group** (so nuclei/sslscan actually stop), then render a **partial** report + manifest. | Kill-switch for a scan that starts tripping a target's WAF; keeps what ran. |
| 12 | Packaging | **`watchtower serve` subcommand, same image** (+ `fastapi`, `uvicorn[standard]` deps). | Server runs scans in-process, so it needs the full toolchain the image already bundles. |
| 13 | Server config | **UI-managed, store-primary** (REVISED — see §4). `serve -c` is optional; `server.yaml` only *seeds* first boot; a writable JSON store (`WATCHTOWER_CONFIG_STORE`) is the source of truth, editable at runtime via `GET`/`PUT /config`. The full scan config is UI-editable; `llm.api_key` is UI-managed and persists in the store (masked on read). Only `WATCHTOWER_API_KEYS` + `WATCHTOWER_WEBHOOK_SECRET` stay env-only. | Operator chose the UI as the primary manager; the YAML is a bootstrap seed that may later be dropped. Trade-off: the LLM secret sits at rest in the store. |
| 14 | Idempotency | **`Idempotency-Key` header** → repeat returns the same job (200, not a new 202); plus **in-flight dedupe** by (target + params) for identical queued/running scans. | Retry-safe; prevents a retry storm becoming N concurrent scans of the same target. |

---

## 2. Architecture

### 2.1 Request lifecycle (submit)

```
POST /scans  (Authorization: Bearer <key>, optional Idempotency-Key, optional callback_url)
  │
  ├─ 401 if key missing/invalid
  ├─ Idempotency-Key seen?  → 200 existing job
  ├─ identical (roots+params) in-flight?  → 200 existing job
  ├─ base config invalid (llm endpoint unset)?  → 409 not_configured
  ├─ running == max_concurrent AND queue full?  → 429 Retry-After
  │
  └─ create job:
       • make run dir, write job.json {state: queued}
       • merge per-request params over server base config → WatchTowerConfig
       • enqueue; asyncio task started when a semaphore slot frees
       • 202 Accepted { id, state, links{self, result, report, log, cancel} }
```

### 2.2 Job execution

A `JobManager` owns:
- an `asyncio.Semaphore(max_concurrent_scans)`,
- an `asyncio.Queue` (bounded by `max_queue_depth`),
- `tasks: dict[job_id, asyncio.Task]`,
- `index: dict[job_id, JobRecord]` (in-memory cache of `job.json`),
- `idempotency: dict[key, job_id]`.

A worker loop pulls from the queue, acquires the semaphore, flips state
`queued → running`, then `await run_scan(...)`. On
completion it writes terminal state to `job.json`, fires the webhook (if any),
and releases the slot.

### 2.3 Cancellation & child processes

Cancel must stop live subprocesses, not just drop the task:
- Scans are launched so every tool subprocess is in a **new process group**
  (`asyncio.create_subprocess_exec(..., start_new_session=True)` in
  `util/subproc.run_tool`).
- `run_tool` already kills its process on timeout; additionally, on
  `asyncio.CancelledError` during `wait_for`, it kills the **process group**
  (`os.killpg`) so children spawned by the tool die too.
- `JobManager.cancel(id)`: queued → remove + mark `cancelled`; running →
  `task.cancel()`, await teardown, then render a partial report from whatever
  `ScanState`/artifacts exist, mark `cancelled`.

### 2.4 Startup reindex

On boot, `JobManager` globs `runs/*/job.json`:
- terminal states (`completed`/`failed`/`cancelled`) loaded as-is,
- `running`/`queued` with no live task → rewritten to `interrupted`.

---

## 3. Job state machine

```
queued ──▶ running ──▶ completed
   │          │   └────▶ failed        (bootstrap/render error)
   │          └────────▶ cancelled     (POST /cancel on a running job)
   ├─────────────────────▶ cancelled   (POST /cancel on a queued job)
   └─(on restart, never started)──────▶ interrupted
running ─(process restart mid-scan)───▶ interrupted   (set at next startup reindex)
```

`job.json` fields:
```json
{
  "id": "2026-06-04T09-30-00Z-example_com",
  "state": "running",
  "roots": ["example.com"],
  "only": ["tls"], "skip": null,
  "throttle": "gentle",
  "submitted_at": "...", "started_at": "...", "finished_at": null,
  "current_stage": "audit.sslscan",
  "completed_stages": ["recon.httpx"],
  "coverage": { ... manifest ... },
  "finding_count": 0,
  "error": null,
  "callback_url": "https://svc/ingest",   // nullable
  "idempotency_key": "abc"                 // nullable
}
```

---

## 4. Server configuration

`ServerConfig` (new Pydantic model, `watchtower/api/config.py`):

`serve -c` is **optional**. With no file the server boots UI-managed (config from
the store / UI). When given, the YAML only *seeds* first boot:

```yaml
# server.yaml — OPTIONAL bootstrap seed (the store is authoritative afterward)
base_config: /etc/watchtower/scan.yaml   # path to a WatchTowerConfig (mmdb/llm/tools) — optional
# — or — inline base config under `base_config:` as a mapping
bind:
  host: 0.0.0.0
  port: 8080
limits:
  max_concurrent_scans: 2
  max_queue_depth: 10
webhook:
  callback_host_allowlist:              # hosts the server may POST callbacks to
    - svc.internal
  timeout_seconds: 10
docs_enabled: true                      # expose /docs + /openapi.json (behind auth)
```

Secrets / paths via env:
| Env var | Purpose |
|---|---|
| `WATCHTOWER_API_KEYS` | comma-separated API keys (the API's own auth — **env-only**) |
| `WATCHTOWER_WEBHOOK_SECRET` | HMAC-SHA256 signing secret for webhooks (**env-only**) |
| `WATCHTOWER_LLM_API_KEY` | *seeds* `base_config.llm.api_key` on first boot; thereafter UI-managed (persists in the store) |
| `WATCHTOWER_CONFIG_STORE` | path to the writable runtime store (default `<output_root>/.config/server-config.json`) |

No scan-target allowlist. The server boots even fully unconfigured (no file,
empty base config); a scan is gated at submit on a valid `WatchTowerConfig` (the
llm endpoint set — mmdb is optional and not part of the gate) → `409
not_configured` until the operator sets it via `PUT /config`.

**Runtime store (UI-managed, primary — REVISED).** `server.yaml` is a bootstrap
seed; the writable JSON store overlays it on boot and is the source of truth
afterward. `ConfigManager` (in `config.py`) loads the store onto the live
`ServerConfig` at app build, and `PUT /config` validates → mutates that instance
in place (the same one `JobManager` reads) → persists (`0600`). So edits to the
full scan config take effect on the next scan with no restart. `llm.api_key`
persists in the store, masked (`********`) on `GET`; a blank/masked value on `PUT`
keeps the stored secret. This is a **deliberate
relaxation** of decision 13's original "secrets only in env / fixed guardrail"
stance — the YAML may eventually be dropped entirely in favor of the store.

Two base-config keys back the rendering features above and, like the rest of
`base_config`, are editable at runtime via `PUT /config`:
- **`ai.profile.render`** (`auto` | `always` | `never`, default `auto`) — the
  server-wide default for the profiler's input/render mode, overridable per scan
  via `ScanRequest.profile_render`.
- **`tools.playwright.screenshot`** (bool, default `true`) — gates per-host
  screenshot capture (the source for `GET /assets/{fqdn}/screenshot`).

---

## 5. Endpoint reference

All endpoints require auth except `GET /healthz`. Errors use a consistent
`{ "error": { "code": "...", "message": "..." } }` body.

**OWASP ZAP active scan (opt-in).** `ScanRequest.zap_targets: list[str]` carries the
scope-locked hosts/URLs for the `zap` capability. It is offered only when the
daemon is configured: `GET /capabilities` **omits** `zap` unless `base_config.zap`
has `enabled: true` + a `base_url`. Submitting `only:["zap"]` is gated server-side
(→ `409 zap_rejected`) when the daemon is off, `zap_targets` is empty, or any target
is not under a scan root; supplying `zap_targets` without `"zap"` in `only` is a
`422`. `ScanRequest.zap_ajax_spider` (`bool | null`) is a per-scan override of
`zap.ajax_spider` (null = server-config default) — handy to flip the AJAX spider on
for a one-off SPA target; it is plumbed like `profile_render` (injected into the
merged `cfg.zap` at build time). `base_config.zap.api_key` is a write-only secret
(masked on `GET /config`, preserved on a blank/masked `PUT`, exactly like
`llm.api_key`). ZAP config (enable / base_url / api_key / ajax / scan policy / time
caps) is editable as a friendly card on the Settings page. The heavy ZAP daemon
runs as a separate sidecar (`docker-compose.yml`), driven over REST — it is never
bundled into the server image.

| Method | Path | Body / params | Success | Errors |
|---|---|---|---|---|
| `POST` | `/scans` | `ScanRequest` (+ `Idempotency-Key`, optional `callback_url`) | `202 {id, state, links}` (or `200` if deduped) | 401, 409 (not_configured / **zap_rejected**), 422 (validation), 429 (full) |
| `GET` | `/scans` | `?state=&limit=&offset=` | `200 {jobs:[JobStatus], total}` | 401 |
| `GET` | `/scans/{id}` | — | `200 JobStatus` | 401, 404 |
| `GET` | `/scans/{id}/result` | — | `200 ScanResult` (JSON) | 401, 404, 409 (not finished) |
| `GET` | `/scans/{id}/report` | — | `200 text/html` (report.html) | 401, 404, 409 |
| `GET` | `/scans/{id}/executive` | — | `200 text/html` (executive.html) | 401, 404, 409 |
| `GET` | `/scans/{id}/executive.pdf` | — | `200 application/pdf` (executive.pdf) | 401, 404 (best-effort artifact) |
| `GET` | `/scans/{id}/log` | `?tail=N` | `200 application/x-ndjson` | 401, 404 |
| `POST` | `/scans/{id}/cancel` | — | `200 JobStatus` (state→cancelled) | 401, 404, 409 (already terminal) |
| `GET` | `/healthz` | — | `200 {status, version}` | — |
| `GET` | `/capabilities` | — | `200 {version, capabilities:[...], throttle_profiles}` | 401 |
| `GET` | `/config` | — | `200 {base_config}` (llm.api_key masked) | 401 |
| `PUT` | `/config` | `{base_config}` (full replace) | `200` effective config | 401, 422 (invalid config) |
| `GET` | `/prompts` | — (editable AI system-prompt registry) | `200 {slots:[{id,label,description,default_text,override,modified,effective}]}` | 401 |
| `PUT` | `/prompts/{slot_id}` | `{text}` (null/blank reverts to built-in default) | `200 {slots:[…]}` | 401, 404 |
| `POST` | `/prompts/{slot_id}/preview` | `{text}` (candidate system text) | `200 {system,user}` (assembled from a fixture; no LLM call) | 401, 404 |
| `GET` | `/assets` | `?group=&status=&source=&q=` | `200 [Asset]` | 401 |
| `GET` | `/assets/groups` | — | `200 [{group,count,last_scan_id}]` | 401 |
| `POST` | `/assets` | `{fqdn, group?, notes?}` | `201 Asset` | 401, 422 (invalid domain) |
| `PUT` | `/assets/{fqdn}` | `{group?, notes?}` | `200 Asset` | 401, 404 |
| `DELETE` | `/assets/{fqdn}` | — | `200 {deleted}` | 401, 404 |
| `POST` | `/assets/import` | `{csv}` (`domain,group`) | `200 {added,updated,skipped}` | 401 |
| `POST` | `/assets/bulk` | `{action: delete\|set_group, fqdns[] \| filter{group,status,source}, group?}` | `200 {affected}` | 401 |
| `GET` | `/assets/{fqdn}/findings` | — (visible findings from the asset's last scan) | `200 [Finding]` | 401 |
| `GET` | `/assets/{fqdn}/screenshot` | — (last-scan per-host PNG screenshot) | `200 image/png` | 401, 404 (not_found) |
| `GET` | `/scan-templates` | — | `200 [ScanTemplate]` | 401 |
| `POST` | `/scan-templates` | `{name, only?, skip?, throttle?, compress?}` (option preset, no target) | `201 ScanTemplate` | 401 |
| `DELETE` | `/scan-templates/{id}` | — | `200 {deleted}` | 401, 404 |
| `GET` | `/schedules` | — | `200 [Schedule]` | 401 |
| `POST` | `/schedules` | `{name?,target,cadence,at_time?,weekday?,only?,skip?,throttle?,enabled?}` | `201 Schedule` | 401, 422 |
| `PUT` | `/schedules/{id}` | (same body) | `200 Schedule` | 401, 404, 422 |
| `DELETE` | `/schedules/{id}` | — | `200 {deleted}` | 401, 404 |
| `GET` | `/suppressions` | — | `200 [Suppression]` | 401 |
| `POST` | `/suppressions` | `{source,host?,key,scope?,reason?}` | `201 Suppression` | 401 |
| `DELETE` | `/suppressions/{fingerprint}` | — | `200 {deleted}` | 401, 404 |
| `GET` | `/nuclei/templates` | `?q=&category=&tag=&severity=&source=&limit=` | `200 [NucleiTemplate]` | 401 |
| `GET` | `/nuclei/categories` | — | `200 [{category,count}]` | 401 |
| `POST` | `/nuclei/reindex` | — | `200 {indexed,root}` | 401, 409 (no templates dir) |
| `GET` | `/nuclei/custom` | — | `200 [CustomTemplate]` | 401 |
| `POST` | `/nuclei/custom` | `{name?,yaml,enabled?}` | `201 CustomTemplate` (with valid/error) | 401 |
| `PUT` | `/nuclei/custom/{id}` | (same) | `200 CustomTemplate` | 401, 404 |
| `DELETE` | `/nuclei/custom/{id}` | — | `200 {deleted}` | 401, 404 |
| `POST` | `/nuclei/custom/generate` | `{description}` | `200 {yaml,valid,error}` | 401, 409 (LLM not configured) |

Schedules fire normal scans via the JobManager (source=`schedule`). Suppressions
are injected into `run_scan` and mark matching findings cross-run (hidden +
uncounted, never deleted). Custom templates are validated, mirrored into the
catalog (`source=custom`), and materialized + `-t`-loaded at scan start.

The `Asset` model (returned by `GET /assets`, `GET /assets/{fqdn}`) carries an
optional **`surface`** object — a curated, NAMES-ONLY snapshot from the last
scan's crawl that answers "what does this host call?" (a lightweight EASM view):
```json
"surface": {
  "third_party_domains": ["cdn.vendor.com"],
  "script_domains": ["js.analytics.com"],
  "endpoints": ["GET app.example.com/api/v1/users"],  // "METHOD host/path"; no query string
  "cookie_keys": ["session"],
  "storage_keys": ["theme"]
}
```
Endpoints are `"METHOD host/path"`; query strings and all values/bodies are
excluded. `_sync_assets` persists it on the assets row — latest snapshot only (no
over-time history). `GET /assets/{fqdn}/screenshot` serves the asset's last-scan
per-host PNG (`image/png`), or `404 not_found` when there is no screenshot
(screenshots disabled / host not crawled / older scan). Because compression is the
default, the PNG normally lives inside `02_audit.tar.gz` (the loose `playwright/`
dir is deleted post-run) — the endpoint reads it back out of the tarball (loose
file first, then the archive member). It is **dashboard-only** —
the screenshot is NEVER embedded in `report.html`; the UI fetches it as an
authenticated blob (an `<img src>` can't send the `Authorization` header).

### 5.1 `ScanRequest`

Exactly one **target** must be given — it resolves to root domains from the
inventory before the run:
```json
{
  // target: exactly ONE of —
  "roots": ["example.com"],            //   ad-hoc root domains
  "group": "Bank",                     //   an asset group (iştirak) → its imported roots
  "assets": ["app.example.com"],       //   specific asset FQDNs
  "all_assets": true,                  //   all imported assets
  "only": ["tls"],                     // optional capability tokens
  "skip": null,                        // mutually exclusive with only
  "throttle": "gentle",                // optional override of base config
  "compress": true,                    // optional
  "profile_render": "auto",            // optional: auto|always|never (null = use ai.profile.render)
  "callback_url": "https://svc/ingest" // optional, must be in callback_host_allowlist
}
```
`profile_render` is a per-scan override of the AI profiler's input/render mode
(nullable; `null` → use the server config's `ai.profile.render`): `always` forces
a headless-browser render per host (the crawler runs even if supply-chain analysis
isn't selected), `auto` (default) only uses rendered capture when supply-chain ran,
and `never` uses the fast httpx fetch only.

A `group`/`assets`/`all_assets` that resolves to **no** roots → `422 empty_target`.
After the scan, discovered (triaged) FQDNs are synced back into `assets`
(discovered inherit their root's group; imported group/notes are never clobbered).

### 5.2 `JobStatus` (poll)

```json
{
  "id": "...", "state": "running",
  "roots": ["example.com"],
  "only": ["tls"], "skip": null, "throttle": "gentle",
  "submitted_at": "...", "started_at": "...", "finished_at": null,
  "current_stage": "audit.sslscan",
  "completed_stages": ["recon.httpx"],
  "elapsed_s": 42, "finding_count": 0,
  "coverage": { ...manifest... },
  "error": null,
  "links": { "self": "...", "result": "...", "report": "...", "log": "...", "cancel": "..." }
}
```

### 5.3 `ScanResult` (`/result`, machine-readable)

Assembled from the run dir (`result.py`):
```json
{
  "id": "...", "state": "completed",
  "coverage": { ...manifest... },
  "histogram": { "critical": {...}, "high": {...}, ... },
  "findings": [ { "source": "sslscan", "host": "...", "severity": "high", "title": "...", "evidence": {...} } ],
  "tls": [ { "host": "...", "checks": [ {"name":"...","passed":true} ], "error": null } ],
  "tls_certs": [ { "ip": "...", "subject_cn": "...", "issuer": "...", "not_after": "...", "days_remaining": 60, "expired": false, "self_signed": false, "wildcard": true, "sha256": "...", "sans": ["..."] } ],
  "app_profiles": { "host": { ...AppProfile... } },
  "report_url": "/scans/{id}/report",
  "executive_url": "/scans/{id}/executive",
  "executive_pdf_url": "/scans/{id}/executive.pdf"
}
```
`executive_url` is always present (the one-pager is written every run);
`executive_pdf_url` is `null` when the PDF wasn't rendered (`report.executive_pdf`
off, or the best-effort render skipped).

---

## 6. Webhook spec

On terminal state, if `callback_url` was supplied and its host is in
`callback_host_allowlist`:

```
POST <callback_url>
  Content-Type: application/json
  X-WatchTower-Event: scan.completed | scan.failed | scan.cancelled
  X-WatchTower-Signature: sha256=<hex HMAC-SHA256(body, WATCHTOWER_WEBHOOK_SECRET)>
  body: { id, state, finished_at, finding_count, result_url, report_url, executive_url }
```

SSRF guards: host must be allowlisted; resolve + connect with a short timeout;
**do not follow redirects**; a single attempt (failures logged as
`event=webhook_failed`, not retried indefinitely).

---

## 7. Module layout

```
watchtower/api/
├── __init__.py
├── config.py     # ServerConfig (+ env secret overlay, base_config load/validate)
├── auth.py       # API-key dependency (constant-time compare → 401)
├── security.py   # HMAC signer + SSRF-guarded webhook sender (no scan-target allowlist)
├── models.py     # ScanRequest, JobStatus, ScanResult, error envelope
├── jobs.py       # JobManager: semaphore+queue, task lifecycle, job.json r/w,
│                 #   startup reindex, cancel (process-group kill), idempotency
├── result.py     # build ScanResult JSON from a run dir
└── server.py     # FastAPI app factory + routes + lifespan (reindex on startup)
```

### Touched files
- `cli.py` — add `serve` subcommand (lazy-import `watchtower.api.server`) → `uvicorn.run(app, host, port)`.
- `util/subproc.py` — `start_new_session=True`; kill **process group** on timeout *and* `CancelledError`.
- `runner.py` — expose `current_stage`/`completed_stages` progress hook the JobManager can read (the stage driver already tracks `completed_stages` in `ScanState`; surface it live).
- `pyproject.toml` — add `fastapi>=0.110`, `uvicorn[standard]>=0.29`.
- `Dockerfile` — `EXPOSE 8080` (no other change; deps via `pip install .`).

---

## 8. Testing plan (`tests/test_api_*.py`, FastAPI `TestClient`)

Scan execution is **mocked** (monkeypatch `run_scan`) so tests
need no external tools:
- **auth** — no/invalid key → 401; valid key → 202.
- **scope** — any root is accepted (no allowlist); an unconfigured server → `409 not_configured` until base config set.
- **idempotency** — same `Idempotency-Key` → same id (200); identical in-flight → reuse.
- **backpressure** — fill running+queue → 429 with `Retry-After`.
- **lifecycle** — submit → status `queued`→`running`→`completed`; `/result` 409 before finish, JSON after.
- **cancel** — queued → cancelled; running → cancelled + partial (mock asserts task cancellation + killpg called).
- **webhook** — on completion, callback POSTed with correct `X-WatchTower-Signature`; non-allowlisted host skipped.
- **reindex** — pre-seed `runs/*/job.json` with `running`; startup → `interrupted`.
- **validation** — `only`+`skip` together → 422; missing `roots` → 422.

---

## 9. Deployment

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/mmdb:/data/mmdb:ro" \
  -v "$PWD/runs:/data/runs" \
  -v "$PWD/server.yaml:/etc/watchtower/server.yaml:ro" \
  -v "$PWD/scan.yaml:/etc/watchtower/scan.yaml:ro" \
  -e WATCHTOWER_API_KEYS="$(cat ./api.key)" \
  -e WATCHTOWER_WEBHOOK_SECRET="$(cat ./wh.secret)" \
  --add-host=host.docker.internal:host-gateway \
  watchtower serve -c /etc/watchtower/server.yaml --host 0.0.0.0 --port 8080
```

Example call:
```sh
curl -sS -X POST http://localhost:8080/scans \
  -H "Authorization: Bearer $KEY" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"roots":["kuveytturk.com.tr"],"only":["tls"],"throttle":"gentle"}'
# → 202 {"id":"...","state":"queued","links":{...}}
```

---

## 10. Out of scope for v1 (documented upgrade paths)

- Worker queue / horizontal scaling (Celery/arq + Redis) — survives restarts, scales out.
- SSE / WebSocket live progress streaming (polling only for v1).
- mTLS and OAuth2/JWT auth; per-API-key target scoping (multi-tenant).
- `DELETE /scans/{id}` and raw-artifact browsing endpoints.
- Run-dir retention/cleanup policy (disk growth) — operator-managed for v1.
- Webhook retry/backoff with a delivery log.

---

## 11. Open implementation notes

- **Process-group kill** is the linchpin of cancel + timeout correctness; verify
  `start_new_session=True` + `os.killpg(os.getpgid(pid), SIGTERM→SIGKILL)` across
  all tools (especially nuclei/playwright which spawn their own children).
- **Live progress**: `ScanState.completed_stages` already exists; add a callback
  or shared reference so `JobManager` reads `current_stage` without polling disk.
- **Partial report on cancel** reuses `ReportStage` against the partial `ScanState`.
- **OpenAPI** at `/docs` gated by `docs_enabled` + auth.
