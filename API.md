# WatchTower API Reference

This document is the canonical reference for WatchTower's surface area:

1. [CLI Reference](#1-cli-reference)
2. [Configuration Reference (YAML)](#2-configuration-reference-yaml)
3. [Run Directory Layout](#3-run-directory-layout)
4. [Artifact JSON Schemas](#4-artifact-json-schemas)
5. [Python API](#5-python-api)
6. [Data Models](#6-data-models)
7. [Extension Points](#7-extension-points)
8. [Exit Codes](#8-exit-codes)
9. [Environment Variables](#9-environment-variables)
10. [Runtime Behavior Reference](#10-runtime-behavior-reference)

For high-level design rationale see [`DESIGN.md`](DESIGN.md).
For the original product brief see [`DOCS.md`](DOCS.md).

---

## 1. CLI Reference

### Synopsis

```
watchtower <command> [options]
```

### Global flags

| Flag | Description |
|---|---|
| `-V`, `--version` | Print version and exit. |
| `-h`, `--help` | Print help and exit. (also accepted on every subcommand) |

### Commands

#### `watchtower scan`

Run a full audit pipeline against the scope defined in a YAML config file.

```
watchtower scan -c <config.yaml> [-o RUNS_DIR] [--progress MODE] [-v]
              [--compress | --no-compress]
              [--only TOKENS | --skip TOKENS] [--strict]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | *(required)* | Path to YAML config (see §2). |
| `-o, --output-dir` | path | `/data/runs` | Where run directories are created. |
| `--progress` | enum | `plain` | One of `plain`, `rich`, `quiet`. `plain` = timestamped stderr lines; `rich` = a live stage tree + warning/error panel + summary (falls back to plain on a non-TTY); `quiet` = warnings/errors + final summary only. `run.log.jsonl` is always written regardless. |
| `-v, --verbose` | flag | off | Enable debug-level events in stderr, and attach truncated tracebacks to recorded stage errors (still always in JSONL). |
| `--compress` | flag | **on** | Tar+gzip per-stage artifact directories at end of run (`01_recon/` → `01_recon.tar.gz`, etc.). |
| `--no-compress` | flag | — | Keep raw per-stage directories uncompressed. Use for direct inspection or downstream tools that read individual files. |
| `--only` | tokens | — | Comma-separated capability tokens to run **exclusively** (plus the implied recon spine). Mutually exclusive with `--skip`. See [Stage selection](#stage-selection). |
| `--skip` | tokens | — | Comma-separated capability tokens to **exclude**. Mutually exclusive with `--only`. |
| `--strict` | flag | off | Exit non-zero (code `3`) if **any** stage crash or per-host failure was recorded this run. Default is exit `0` (failures are still in `errors.json`, `summary.json`, and the report). For CI / programmatic callers. |

**Stdout:** the path to `report.html` on success.
**Stderr:** progress events per `--progress` mode.

**Example:**

```sh
docker run --rm \
  -v "$PWD/mmdb:/data/mmdb:ro" \
  -v "$PWD/runs:/data/runs" \
  -v "$PWD/config.yaml:/etc/watchtower/config.yaml:ro" \
  --add-host=host.docker.internal:host-gateway \
  watchtower scan -c /etc/watchtower/config.yaml --progress plain
```

<a id="stage-selection"></a>
##### Stage selection (`--only` / `--skip`)

`scan` accepts capability tokens — stable, user-facing names decoupled from internal stage names:

| Token | Runs | Notes |
|---|---|---|
| `recon` | discovery spine (subfinder → dnsx → triage → tlsx → httpx) | Always runs as a prerequisite. `--only recon` = **discovery-only**: asset inventory + live/dead liveness graph, then stop. |
| `takeovers` | nuclei takeover templates (resolving CNAME candidates) + deterministic dangling-CNAME check (dead hosts) | Two complementary halves — see `tools.takeovers`. |
| `tls` | sslscan per-host TLS scorecard | |
| `nuclei` | main nuclei web-CVE scan | |
| `headers` | deterministic OWASP header + CSP analysis | Passive — evaluates the headers httpx already captured (no new requests). |
| `supply-chain` | Playwright crawler | |
| `ai` | `ai.profile` + cross-source triage + supply-chain analysis | Supply-chain analysis auto-enables the crawler. `ai.triage` reviews **all** deterministic findings and may soft-suppress false-positives. |

Rules:

- `--only` and `--skip` are **mutually exclusive**; supplying both is an error.
- Unknown tokens are a hard error that lists the valid set.
- **Dependency resolution is auto-include + log**: `--only ai` auto-enables `supply-chain` (logged). `--skip supply-chain` while `ai` runs keeps the profile + header analysis and silently drops only supply-chain analysis. The spine cannot be skipped while any audit/AI capability runs.
- The report's coverage strip + `manifest.json` record exactly what ran vs. was skipped (and why); skipped sections render a "Not run in this scan" placeholder rather than an empty table.

##### Sub-tokens (finer granularity)

Four of the capabilities split into dotted **sub-tokens** for `--only`/`--skip`
(and the API `only`/`skip`). A parent token still means "all of its sub-steps"
(so existing selections are unchanged); a sub-token runs just that slice plus its
dependencies.

| Parent | Sub-tokens | Effect |
|---|---|---|
| `recon` | `recon.subfinder`, `recon.dns`, `recon.tlsx`, `recon.httpx` | Narrow discovery (`--only recon.subfinder` = enumerate & stop) or drop the optional re-feed (`--skip recon.tlsx`). `subfinder`/`dns`/`httpx` are the mandatory chain whenever audit runs; only `recon.tlsx` is skippable. |
| `ai` | `ai.profile`, `ai.triage`, `ai.supply-chain` | Run one analysis. `ai.triage`/`ai.profile` need only httpx; `ai.supply-chain` auto-includes the crawler. They don't pull each other in. `ai.headers` is a deprecated alias of `ai.triage`. |
| `headers` | `headers.csp`, `headers.best-practice` | Run one deterministic header analysis. `headers.csp` = structured CSP weakness rules; `headers.best-practice` = the OWASP header catalog (HSTS, clickjacking, cookies, info-disclosure, …). Both passive over httpx headers. (`headers.cors` is reserved for a future active probe.) |
| `nuclei` | `nuclei.critical`, `nuclei.high`, `nuclei.medium`, `nuclei.low` (opt-in `nuclei.info`) | Map to `nuclei -severity …`. Parent `nuclei` uses the config's `tools.nuclei.severities`. |

When only some of a parent's sub-steps run, the coverage strip / `manifest.json`
mark the parent **partial** and record per-sub-token `ran`/`reason`.

```sh
watchtower scan -c config.yaml --only tls                  # only the TLS scorecard
watchtower scan -c config.yaml --skip nuclei,supply-chain  # everything but those two
watchtower scan -c config.yaml --only recon                # attack-surface map only
watchtower scan -c config.yaml --only recon.subfinder      # subdomain names only
watchtower scan -c config.yaml --only nuclei.high,nuclei.critical   # high+crit CVEs only
watchtower scan -c config.yaml --only ai.triage            # just the AI cross-source triage
watchtower scan -c config.yaml --only headers              # deterministic header + CSP audit
watchtower scan -c config.yaml --only headers.csp          # just the CSP weakness rules
watchtower scan -c config.yaml --skip recon.tlsx           # full run, no cert-SAN re-feed
```

#### `watchtower verify-deps`

Probe required binaries, Python modules, and optionally the MMDB + LLM endpoint. Exits non-zero if any check fails.

```
watchtower verify-deps [-c CONFIG]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | — | If supplied, also probes the MMDB at `mmdb_path` and the LLM endpoint declared in the config. |

**Stdout:** a checklist of `✓` / `✗` per dependency.
**Exit:** `0` if all checks pass, `1` if anything failed.

**Example:**

```sh
watchtower verify-deps                          # binaries + Python deps only
watchtower verify-deps -c /etc/watchtower/config.yaml   # adds MMDB + LLM probes
```

This is safe to run *before* installing the heavy deps — the CLI lazy-imports the scan path, so missing modules show as `✗` entries rather than crashing the command.

#### `watchtower init-config`

Print or write a fully-commented example YAML config.

```
watchtower init-config [-o FILE] [-f]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-o, --output` | path | *(stdout)* | Write to this path instead of stdout. Creates parent directories as needed. |
| `-f, --force` | flag | off | Overwrite the target if it already exists. Without `--force` the command refuses to clobber. |

**Stdout (no `-o`):** the YAML content.
**Stderr (with `-o`):** confirmation message.

**Examples:**

```sh
# Print to stdout (e.g., pipe into a file):
watchtower init-config > config.yaml

# Write directly:
watchtower init-config -o /etc/watchtower/config.yaml

# Refresh from latest defaults, overwriting existing file:
watchtower init-config -o config.yaml --force
```

#### `watchtower serve`

Run the authenticated **Web API** (FastAPI + uvicorn) over the scan engine. The
server reuses the async runner in-process, keeps `runs/` as the durable record,
and rebuilds its job index from disk on startup. Requires the web extras
(`pip install '.[web]'`; bundled in the Docker image).

```
watchtower serve [-c <server.yaml>] [--host HOST] [--port PORT] [--ui-dir DIR]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | *(optional)* | Bootstrap seed only. With no file the server boots **UI-managed** (config from the runtime store / UI). When given, `server.yaml` seeds first boot. See `example.server.yaml` and `WEB_API_PLAN.md` §4. |
| `-o, --output-dir` | path | from config (`/data/runs`) | Where run dirs + the config store live. Needed for UI-only local runs (the default `/data/runs` isn't writable outside the container). |
| `--host` | str | from config | Bind host (overrides `server.yaml`). |
| `--port` | int | from config | Bind port (overrides `server.yaml`). |
| `--ui-dir` | path | `$WATCHTOWER_UI_DIR` | Serve a built UI (Next.js static export) at `/` with the API mounted under `/api`. When unset the API serves at root. |

The API's own auth secrets are read from the environment (see §9):
`WATCHTOWER_API_KEYS` (a comma-separated allowlist — **if unset the API runs OPEN**)
and optional `WATCHTOWER_WEBHOOK_SECRET`. There is **no scan-target allowlist** — the
per-scan `roots` is the only scope, so with auth OPEN anyone who can reach the API
can scan any host; keep `WATCHTOWER_API_KEYS` set before exposing it.

**Runtime config is UI-managed (store-primary).** `serve -c` is optional;
`server.yaml` only seeds first boot. A writable JSON store (`WATCHTOWER_CONFIG_STORE`,
default `<output_root>/.config/server-config.json`, `0600`) is the source of truth
and is edited at runtime via `GET`/`PUT /config`. The full scan config is editable;
`llm.api_key` is UI-managed and persists in the store (`WATCHTOWER_LLM_API_KEY` only
*seeds* it; masked `********` on read, blank/masked on write keeps it). The server
boots even unconfigured — a scan is refused with `409 not_configured` until a valid
LLM config is set (the MMDB is optional). Edits apply to the next scan with no restart.

**Endpoints** (full contract + payloads in `WEB_API_PLAN.md` §5): `POST /scans`,
`GET /scans[/{id}]`, `GET /scans/{id}/{result,report,log}`,
`POST /scans/{id}/cancel`, `GET /healthz`, `GET /capabilities`,
`GET`/`PUT /config`, and OpenAPI at `/docs`. In `--ui-dir` mode these live under
`/api/…` and the UI is served at `/`.

**Example:**

```sh
# API + bundled UI from the Docker image (one container, one port):
docker run --rm -p 8080:8080 \
  -v "$PWD/mmdb:/data/mmdb:ro" -v "$PWD/runs:/data/runs" \
  -v "$PWD/server.yaml:/etc/watchtower/server.yaml:ro" \
  -e WATCHTOWER_API_KEYS="$(cat api.key)" \
  -e WATCHTOWER_WEBHOOK_SECRET="$(cat wh.secret)" \
  --add-host=host.docker.internal:host-gateway \
  watchtower serve -c /etc/watchtower/server.yaml --host 0.0.0.0 --port 8080
# → UI:  http://localhost:8080/        API: http://localhost:8080/api/...

# Submit a scan:
curl -sS -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer $KEY" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"roots":["example.com"],"only":["tls"]}'
```

---

## 2. Configuration Reference (YAML)

The config file is parsed with PyYAML and validated against `watchtower.config.WatchTowerConfig`. Any validation failure aborts with a non-zero exit.

### Top-level keys

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `roots` | `list[str]` | ✓ | — | At least one root domain. Trailing dots stripped, lower-cased. The configured `roots` are the **only** scope — every name resolving under a root is scanned regardless of where it's hosted. |
| `mmdb_path` | `str` | ✗ | `null` | Optional path to `GeoLite2-ASN.mmdb`. **Display-only** ASN/org enrichment; it does **not** gate scans. With no MMDB, scans run identically minus the ASN/org column. |
| `throttle` | enum | ✗ | `normal` | Global politeness tier (`gentle`/`normal`/`aggressive`) applied across all tools; per-tool fields override it. See [`throttle`](#throttle). |
| `concurrency` | object | ✗ | see below | Per-stage parallelism caps. |
| `paths_per_host` | `list[str]` | ✗ | `["/"]` | URL paths visited by the Playwright crawler per host. |
| `llm` | object | ✓ | — | OpenAI-compatible LLM endpoint. |
| `ai` | object | ✗ | see below | AI behavior, incl. context-aware profiling. |
| `tools` | object | ✗ | defaults | Per-tool config blocks. |

> **Removed keys (back-compat).** The old ownership model is gone: `sanctioned_cidrs` and `sanctioned_asns` no longer exist, and there is no `in_scope`/`shadow_it`/`dead` bucketing — assets now carry a single `status` of `live` (resolves to ≥1 A record) or `dead` (NXDOMAIN / no A records). Config files (or JSON) that still contain `sanctioned_*` keys load cleanly; unknown keys are ignored.

<a id="throttle"></a>
### `throttle`

One global knob to avoid hammering (and tripping the WAF of) a live target. Sets conservative rates across **all** network-touching tools at once:

```yaml
throttle: normal        # gentle | normal | aggressive
```

| Field affected | `gentle` | `normal` (default) | `aggressive` |
|---|---|---|---|
| `tools.httpx.rate_limit` / `tools.nuclei.rate_limit` | 10 | 100 | 500 |
| `tools.takeovers.rate_limit` | 10 | 50 | 150 |
| `tools.dnsx.rate_limit` | 100 | 1000 | 5000 |
| `tools.tlsx.concurrency` (`-c`; tlsx has no rate-limit flag) | 20 | 100 | 300 |
| `tools.sslscan.timeout` | 600 | 300 | 180 |
| `concurrency.default` / `.tls` / `.playwright` | 3 / 2 / 2 | 10 / 5 / 5 | 20 / 10 / 8 |

**Precedence:** the profile only fills fields you did **not** set explicitly. Any per-tool / per-concurrency value in the YAML overrides it — e.g. `throttle: gentle` with `tools: {nuclei: {rate_limit: 200}}` runs everything gently except nuclei at 200. `normal` equals every field's own default, so omitting `throttle` reproduces prior behavior exactly.

### `concurrency`

```yaml
concurrency:
  default: 10        # int — generic fan-out cap
  llm: 4             # int — LLM call cap
  playwright: 5      # int — parallel browser contexts
  tls: 5             # int — parallel sslscan host scans
```

### `llm`

```yaml
llm:
  base_url: <str>           # required; e.g., http://host.docker.internal:11434/v1
  api_key: <str>            # required; many local backends accept any non-empty value
  model: <str>              # required; e.g., llama3.1:8b-instruct
  timeout_seconds: 120      # optional; default 120
  max_retries: 1            # optional; default 1
```

The client posts to `{base_url}/chat/completions` with OpenAI-shape payloads. `response_format: {"type": "json_object"}` is sent; backends that reject it get a retry without that field automatically.

### `ai`

```yaml
ai:
  profiling: true       # bool; default true
  suppression:          # cross-source AI false-positive suppression (ai.triage)
    enabled: true
    min_confidence: medium     # low | medium | high
    max_severity: medium       # info | low | medium | high | critical
    require_profile: false
  prompts:              # optional system-prompt overrides (null = built-in default)
    profile_system: null
    triage_system_default: null
    triage_system_profiled: null
    supply_system_default: null
    supply_system_profiled: null
    low_confidence_nudge: null
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `profiling` | bool | `true` | Enable the **context-aware profiling pass** (`ai.profile` stage). When `true`, an `AppProfile` is inferred per host from httpx signals and fed into the triage + supply-chain prompts (triage becomes an expectation-gap diff against the app's `expected_controls`; severity is calibrated to the inferred app type). When `false`, the analysis prompts use their **default context-light form**, no `03_ai/profile/` artifact is written, and the pipeline makes 2 LLM calls/host instead of 3. |
| `suppression.enabled` | bool | `true` | Let the `ai.triage` stage **soft-suppress** deterministic findings (any source) it judges false-positive. Hidden + uncounted but kept in `findings.json` (auditable, never deleted). |
| `suppression.min_confidence` | enum | `medium` | Minimum AI verdict confidence to actually hide a finding. |
| `suppression.max_severity` | enum | `medium` | Highest severity the AI may auto-hide. Findings **above** this are never offered to the AI and always stay visible + counted. |
| `suppression.require_profile` | bool | `false` | When `true`, only hosts with a usable, non-low-confidence `AppProfile` get suppression (legacy gate). Default `false`: the profile is calibration, not a precondition. An AI degrade hides nothing either way. |
| `prompts.*` | str \| null | `null` | Override a built-in AI **system** prompt (slot ids mirror `watchtower/ai/prompts.py` `PROMPT_SLOTS`). `null`/blank = built-in default. Shape-hints + user-message assembly stay in code, so an override can change judgment but never break JSON validation. Usually edited via the UI's **AI Tuning** page. |

Profiling adds one LLM call per host. Hard failures degrade to the default prompts for that host; a profile that self-reports `confidence: low` is still used but does not drive aggressive severity escalation. The profiling stage runs **early** (after httpx, before the audit fan-out) and never gates the deterministic scanners — nuclei/sslscan/crawler always run at full coverage regardless of the profile.

### `headers`

```yaml
headers:
  severity_overrides: {}            # {check_id: severity}
  disabled_checks: []               # [check_id | dotted-prefix]
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `severity_overrides` | map | `{}` | Override a check's severity by its `check_id` (e.g. `{hsts.missing: high}`). |
| `disabled_checks` | list | `[]` | Skip checks by `check_id` or dotted prefix (e.g. `[permissions-policy, cookie]`). |

The `headers` capability is **deterministic and passive**: `audit/header_checks.py` evaluates the response headers httpx already captured and emits first-class `Finding`s (sources `headers`/`csp`, each with a stable `check_id`). The AI never gates these — `ai.triage` only adds nuance findings and, gated, soft-suppresses false-positives across all sources (see `ai.suppression`).

### `tools.subfinder`

Accepts only `extra_flags: list[str]` — a pass-through list appended verbatim to the command line.

### `tools.dnsx` / `tools.tlsx`

```yaml
tools:
  dnsx:
    rate_limit: 1000   # int — passes as `-rl <n>` (DNS queries/sec)
    extra_flags: []
  tlsx:
    concurrency: 100   # int — passes as `-c <n>` (parallel threads). tlsx has NO
                       # rate-limit flag. Recon cert-grab vs target:443 — harvests
                       # SANs AND a passive cert dossier (one handshake/IP).
    extra_flags: []
```

### `tools.sslscan`

```yaml
tools:
  sslscan:
    timeout: 300             # int seconds — per-host outer timeout
    extra_flags: []          # appended after the host:port target
```

sslscan opens connections per host probing every cipher/protocol; it runs sequentially per host, so the cross-host pacing knob is `concurrency.tls` (not `concurrency.default`), which the throttle profile lowers for sensitive targets (`throttle: gentle`). The per-host scorecard grades: insecure protocols disabled (SSLv2/SSLv3/TLS1.0/TLS1.1), no weak ciphers (RC4/3DES/DES/EXPORT/NULL/MD5/anon or <112-bit), certificate valid >30 days, key strength (RSA ≥ 2048 / EC ≥ 256), signature algorithm not SHA-1/MD5, and secure renegotiation. (HSTS is **not** graded here — it's covered by the `headers` capability.)

### `tools.httpx`

```yaml
tools:
  httpx:
    rate_limit: 100    # int — passes as `-rl <n>`
    timeout: 10        # int seconds — passes as `-timeout <n>`
    extra_flags: []
```

### `tools.nuclei`

```yaml
tools:
  nuclei:
    severities: [low, medium, high, critical]   # subset of {info, low, medium, high, critical}
    auto_scan: true                              # adds `-as` (wappalyzer-driven template selection)
    rate_limit: 100                              # `-rl`
    timeout: 5                                   # `-timeout`
    user_agent: "WatchTower/0.1"                   # injected via `-H`
    extra_flags: []
```

### `tools.takeovers`

Used by the nuclei half — `-t http/takeovers/` against **live** hosts with a third-party CNAME (the HTTP body-fingerprint templates need a host that resolves). The dangling/NXDOMAIN class (the `dead` hosts) is covered by a deterministic, offline CNAME→provider match (`audit/takeover_fingerprints.py`, bundled `data/takeover_fingerprints.json`) — no flags, always on with the `takeovers` capability.

```yaml
tools:
  takeovers:
    severities: [high, critical]
    rate_limit: 50
    extra_flags: []
```

### `tools.playwright`

```yaml
tools:
  playwright:
    wait_until: networkidle    # one of: load, domcontentloaded, networkidle, commit
    timeout_ms: 30000          # hard navigation timeout
    user_agent: null           # null = default Chromium UA
    extra_flags: []            # reserved; not currently used by Playwright wrapper
```

### Generating a fresh template

`watchtower init-config` always emits the current canonical example, including all defaults. If you upgrade WatchTower, regenerate to see new fields.

---

## 3. Run Directory Layout

Each invocation of `watchtower scan` creates a fresh directory under `--output-dir`:

```
runs/<UTC-ISO-timestamp>-<root-slug>/
├── config.snapshot.yaml         # exact config used for this run (llm.api_key redacted)
├── versions.json                # tool versions, model, MMDB path, watchtower sha
├── manifest.json                # capability coverage: ran / skipped + reason
├── run.log.jsonl                # always-on structured event log (incl. the run_summary event)
├── errors.json                  # consolidated failures: stage crashes + every per-host error
├── summary.json                 # end-of-run rollup (findings/assets/errors/timings) — RunSummary
├── report.html                  # single-file HTML dashboard (uncompressed)
│
│  --- with --compress (default): ---
├── 01_recon.tar.gz              # was 01_recon/
├── 02_audit.tar.gz              # was 02_audit/
└── 03_ai.tar.gz                 # was 03_ai/
│
│  --- with --no-compress: ---
├── 01_recon/
│   ├── subfinder.txt
│   ├── dnsx.jsonl
│   ├── dnsx-iter1.jsonl … dnsx-iter3.jsonl   # if tlsx loop iterated
│   ├── tlsx-iter1.jsonl … tlsx-iter3.jsonl
│   ├── triage.json
│   └── httpx.jsonl
├── 02_audit/
│   ├── takeovers/nuclei-takeovers.jsonl
│   ├── sslscan/<host>.xml                    # raw sslscan XML, one per host
│   ├── nuclei/findings.jsonl
│   └── playwright/<host>.json                # crawler artifact per host
└── 03_ai/
    ├── profile/<host>.json       # AppProfile (omitted when ai.profiling: false)
    ├── headers/<host>.json
    └── supply_chain/<host>.json
```

The top-level files (`config.snapshot.yaml`, `versions.json`, `manifest.json`, `run.log.jsonl`, `errors.json`, `summary.json`, `report.html`) always stay uncompressed so post-run tooling (CI, downstream parsers, the report itself) can read them without unpacking. Only the bulk per-stage subdirectories get archived.

### Inspecting a compressed run

```sh
# List members:
tar tzf 02_audit.tar.gz

# Extract one file:
tar xzf 02_audit.tar.gz 02_audit/nuclei/findings.jsonl

# Stream + jq a JSONL file in place:
tar xzOf 02_audit.tar.gz 02_audit/nuclei/findings.jsonl | jq .
```

---

## 4. Artifact JSON Schemas

All JSONL files are line-delimited JSON; one record per line. All single-JSON files use UTF-8 with `indent=2`.

### `versions.json`

```json
{
  "watchtower": "0.1.0",
  "subfinder": "subfinder version v2.6.6",
  "dnsx": "dnsx version v1.2.1",
  "tlsx": "...",
  "httpx": "...",
  "nuclei": "...",
  "llm_model": "llama3.1:8b-instruct",
  "llm_base_url": "http://host.docker.internal:11434/v1",
  "captured_at": "2026-05-26T10:24:00+00:00"
}
```

### `errors.json`

```json
[
  {"stage": "audit.sslscan", "target": "api.example.com", "message": "..."},
  {"stage": "recon.httpx",  "target": null,              "message": "..."}
]
```

### `manifest.json`

Records which capabilities ran vs. were skipped, and why — the source of the report's coverage strip and the "Not run in this scan" placeholders.

```json
{
  "selection": {"only": ["tls"], "skip": null},
  "capabilities": {
    "recon":        {"ran": true,  "reason": "prerequisite"},
    "takeovers":    {"ran": false, "reason": "user-selected (--only tls)"},
    "tls":          {"ran": true,  "reason": "user-selected"},
    "nuclei":       {"ran": false, "reason": "user-selected (--only tls)"},
    "supply-chain": {"ran": false, "reason": "user-selected (--only tls)"},
    "ai":           {"ran": false, "reason": "user-selected (--only tls)"}
  }
}
```

`reason` is one of `prerequisite`, `user-selected`, `auto-included` (e.g. crawler pulled in by `ai`), or `discovery-only`.

### `01_recon/triage.json`

```json
{
  "live":      [TriagedAsset, …],
  "dead":      [TriagedAsset, …],
  "wildcards": ["*.example.com", …]
}
```

`live` assets resolve to ≥1 A record (fully scanned); `dead` assets are NXDOMAIN / have no A records (takeover-watch only). Each `TriagedAsset` is the Pydantic model dump described in §6.

### `01_recon/dnsx.jsonl`

Raw stdout from `dnsx -json`. Each line has `host`, optional `a` (list of A records), `cname` (list of CNAME targets), `status_code`. WatchTower synthesizes records with empty `a` for names dnsx omitted (treated as NXDOMAIN).

### `01_recon/httpx.jsonl`

Raw stdout from `httpx -json` (invoked with `-include-response` so the raw, pre-JS HTML body is present). Each line has `url`, `host`, `status_code`, `title`, `tech` (list), response headers, and the response body. From the body, the httpx stage parses a `PageSignals` record per host (title, meta description, OpenGraph tags, a `≤2 KB` stripped body snippet, `form_count`, `has_password_input`) which feeds the `ai.profile` stage. See §6 for `PageSignals`.

### `02_audit/takeovers/nuclei-takeovers.jsonl` and `02_audit/nuclei/findings.jsonl`

Raw `nuclei -jsonl` output. WatchTower parses into `Finding` objects but persists the raw form for forensics.

### `02_audit/sslscan/<host>.xml`

Raw `sslscan --xml` output, one file per host. WatchTower parses each `<ssltest>` element into the per-host TLS scorecard (`TLSHostReport`): insecure protocols disabled, no weak ciphers, certificate valid >30 days, key strength, signature algorithm, and secure renegotiation (see `tools.sslscan`).

### `02_audit/playwright/<host>.json`

```json
{
  "host": "www.example.com",
  "url": "https://www.example.com",
  "status": 200,
  "headers": {"content-type": "text/html; charset=utf-8", ...},
  "scripts": [
    {"url": "https://example.com/app.js", "status": 200,
     "initiator_url": "https://www.example.com/", "method": "GET"}
  ],
  "errors": []
}
```

### `03_ai/profile/<host>.json`

Written only when `ai.profiling: true`. The `AppProfile` inferred for the host (see §6). On a hard profiling failure the file still records the host with `error` set and other fields at defaults; the host then falls back to the default analysis prompts.

```json
{
  "host": "login.example.com",
  "app_type": "customer login portal",
  "audience": "public",
  "confidence": "high",
  "reasoning": "Root page is a sign-in form with SSO; title 'Acme Login'.",
  "handles_auth": true,
  "handles_pii": true,
  "handles_payments": false,
  "has_file_upload": false,
  "is_api": false,
  "expected_controls": ["HSTS", "Content-Security-Policy",
                        "Secure+HttpOnly cookies", "X-Frame-Options"],
  "error": null
}
```

### `03_ai/headers/<host>.json` and `03_ai/supply_chain/<host>.json`

On success — an `AIResponse`:

```json
{
  "findings": [
    {
      "type": "missing-csp",
      "severity": "low",
      "title": "Content-Security-Policy header is absent",
      "description": "…",
      "evidence": {"…": "…"}
    }
  ]
}
```

On LLM/parse failure:

```json
{"error": "<error message>"}
```

The pipeline never fails on AI errors; the artifact simply records the failure.

---

## 5. Python API

WatchTower is usable as a library. Imports below assume the package is installed (`pip install .` from the repo root or via the Docker image).

### `watchtower.config`

```python
from watchtower.config import load_config, WatchTowerConfig

cfg: WatchTowerConfig = load_config("config.yaml")
```

* `load_config(path: str | Path) -> WatchTowerConfig` — Loads YAML, validates with Pydantic, raises `pydantic.ValidationError` on failure.
* `WatchTowerConfig` — root Pydantic model. See §6.

### `watchtower.runner`

```python
import asyncio
from pathlib import Path
from watchtower.runner import run_scan

report_path = asyncio.run(
    run_scan(
        cfg=cfg,
        output_root=Path("./runs"),
        log_mode="plain",        # "plain" | "rich" | "quiet"
        verbose=False,
        compress=True,
        only={"tls"},            # set[str] capability tokens, or None
        skip=None,               # set[str] capability tokens, or None
        stages=None,             # explicit list[Stage] — bypasses only/skip entirely
        run_dir=None,            # pre-created run dir (else a timestamped one is made)
        state=None,              # externally-owned ScanState for live progress
    )
)
```

Returns the absolute path to the rendered `report.html`. Raises on bootstrap failures (e.g., an unwritable output dir or invalid config). `only`/`skip` are mutually exclusive (passing both raises `ValueError`); unknown tokens raise `ValueError` listing the valid set.

`run_dir` and `state` exist for embedders that need to observe a scan as it runs (the Web API uses them): pass a `ScanState()` you keep a reference to and poll its `current_stage` / `completed_stages` / findings live, and pass a `run_dir` (e.g. from `make_run_dir`) to reserve the id up front. Both default to internal creation, so existing callers are unaffected.

### `watchtower.stages.pipeline` — capability registry & builder

```python
from watchtower.stages.pipeline import build_pipeline, CAPABILITIES, default_pipeline

# The tokens both CLI and API understand:
list(CAPABILITIES)          # ["recon", "takeovers", "tls", "nuclei", "headers", "supply-chain", "ai"]

# Build a stage list from tokens (dependency resolution applied in one place):
stages, coverage = build_pipeline(
    cfg,
    only={"tls", "nuclei"},        # or skip=..., not both
    include_report=report_stage,   # the ReportStage instance (needs run_meta + versions)
    include_compress=compress_stage,  # CompressStage or None
)
# `coverage` is the capability manifest (-> manifest.json + the report coverage strip).
```

`build_pipeline` is the single place the token→stage mapping and dependency resolution live; both `cli.py` and `runner.py` route through it. `default_pipeline()` remains as the no-selection convenience wrapper.

### Stage entry points

Each stage is callable directly for embedding into other pipelines:

```python
# Recon
from watchtower.recon.subdomains import run_subfinder
from watchtower.recon.resolve    import run_dnsx
from watchtower.recon.triage     import triage_records
from watchtower.recon.tls_san    import tlsx_refeed_loop
from watchtower.recon.web_probe  import run_httpx

# Audit
from watchtower.audit.takeovers       import run_takeovers
from watchtower.audit.sslscan_runner  import run_sslscan
from watchtower.audit.nuclei_runner   import run_nuclei
from watchtower.audit.crawler        import run_crawler

# AI
from watchtower.ai.analyzer import analyze_all
from watchtower.ai.client   import LLMClient
from watchtower.ai.prompts  import (
    build_profile_prompt, build_headers_prompt, build_supply_chain_prompt,
)

# Report
from watchtower.report.aggregator import build_report_context
from watchtower.report.renderer   import render_report

# Stage plugin API
from watchtower.stages import Stage, ParallelStage, ScanState, execute_stages
from watchtower.stages.profile  import AIProfileStage
from watchtower.stages.pipeline import build_pipeline, CAPABILITIES, default_pipeline

# Preflight
from watchtower.preflight import run_preflight, format_report
```

All `run_*` and `analyze_all` functions are `async`. Each takes a `RunLogger`; for ad-hoc use, instantiate one bound to a writable directory:

```python
from watchtower.logging import RunLogger
log = RunLogger(run_dir=Path("./scratch"), mode="plain", verbose=False)
```

### `watchtower.api` — Web API

The FastAPI layer (see `WEB_API_PLAN.md` for the full design). Useful entry
points for embedding or testing:

```python
from watchtower.api.config import load_server_config, ServerConfig
from watchtower.api.server import create_app, create_combined_app, serve

config = load_server_config("server.yaml")     # structure + env secrets
app = create_app(config)                        # API at root (FastAPI app)
app = create_combined_app(config, "web/out")    # UI at /, API under /api
serve("server.yaml", host="0.0.0.0", port=8080) # load + build + uvicorn.run
```

* `create_app(config)` returns a FastAPI app and is what the tests drive via
  `fastapi.testclient.TestClient`.
* The `JobManager` (`watchtower.api.jobs`) owns the semaphore/queue, `job.json`
  persistence, startup reindex, idempotency, and cancellation (process-group
  kill). It calls `run_scan` with an injected `run_dir`+`state`.

### `watchtower.util.subproc`

Generic async subprocess helpers used by all tool wrappers.

```python
from watchtower.util.subproc import run_tool, ProcResult, ToolError, tool_version

res: ProcResult = await run_tool(
    ["nuclei", "-version"],
    stdin=None,
    timeout=10,
    check=False,           # set True to raise ToolError on non-zero exit
)
```

### `watchtower.util.ipinfo`

```python
from watchtower.util.ipinfo import IPInfoLookup

ipinfo = IPInfoLookup(
    mmdb_path="/data/mmdb/GeoLite2-ASN.mmdb",   # optional; None = no ASN/org enrichment
)
ipinfo.is_ipv4("1.2.3.4")               # bool
ipinfo.asn_info("1.2.3.4")              # ASNInfo(asn=15169, organization="...") — display-only
ipinfo.close()
```

### `watchtower.util.domains`

```python
from watchtower.util.domains import etld_plus_one, under_any_root, is_wildcard, strip_wildcard

etld_plus_one("foo.bar.example.co.uk")     # "example.co.uk"
under_any_root("api.example.com", ["example.com"])  # True
is_wildcard("*.example.com")               # True
strip_wildcard("*.example.com")            # "example.com"
```

### Report rendering only

If you want to drive the pipeline yourself and just use WatchTower's renderer:

```python
from watchtower.report.aggregator import build_report_context
from watchtower.report.renderer   import render_report

context = build_report_context(
    run_meta={"label": "ad-hoc", "roots": ["example.com"],
              "started_at": "...", "finished_at": "...",
              "duration": "0.0s", "watchtower_version": "0.1.0"},
    triaged=[...],          # list[TriagedAsset]
    wildcards=[],           # list[str]
    live_servers=[...],     # list[LiveWebServer]
    nuclei_findings=[],     # list[Finding]
    takeover_findings=[],
    tls_findings=[],        # list[Finding] — from sslscan
    tls_reports=[],         # list[TLSHostReport]
    ai_headers_findings=[],
    ai_supply_findings=[],
    app_profiles={},        # dict[host, AppProfile] — drives the per-host profile cards
    crawler_artifacts=[],   # list[CrawlerArtifact]
    coverage={},            # capability manifest — coverage strip + "Not run" placeholders
    errors=[],
    versions={"watchtower": "0.1.0"},
)
render_report(context, out_path=Path("report.html"))
```

---

## 6. Data Models

All models are Pydantic v2. Every field is typed; unknown fields are rejected.

### `TriagedAsset`

```python
class TriagedAsset(BaseModel):
    fqdn: str
    a_records: list[str]            # IPv4 only
    cname_chain: list[str]
    asn: int | None                 # display-only ASN (None when no MMDB)
    as_org: str | None              # display-only AS org (None when no MMDB)
    status: Literal["live", "dead"] # live = resolves to ≥1 A record; dead = NXDOMAIN / no A records
    reason: str                     # human-readable liveness reason
```

### `LiveWebServer`

```python
class LiveWebServer(BaseModel):
    url: str                        # full URL httpx settled on (after redirects)
    host: str
    status_code: int | None
    title: str | None
    tech: list[str]
```

### `Finding`

```python
class Finding(BaseModel):
    source: Literal["nuclei", "takeover", "sslscan",
                    "headers", "csp",            # deterministic header checks
                    "js_lib",                    # vulnerable JS library (retire.js-style)
                    "ai_headers", "ai_supply_chain"]
    host: str | None
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str
    evidence: dict[str, Any]        # source-specific structured fields
    check_id: str | None            # stable id for rule findings (AI suppression ref)
    ai_verdict: AIFindingVerdict | None   # soft-suppression; suppressed → hidden + uncounted
```

A finding with `ai_verdict.suppressed == true` was judged a false-positive by the AI: it stays in the payload + `findings.json` but is excluded from `histogram`/`histogram_totals` and `finding_count`, and the UI/report show it in a collapsible "Suppressed" section.

### `TLSCheck` / `TLSHostReport`

```python
class TLSCheck(BaseModel):
    name: str
    passed: bool
    detail: str

class TLSHostReport(BaseModel):
    host: str
    checks: list[TLSCheck]
    error: str | None
    # computed: pass_count, total
```

### `CrawlerArtifact`

```python
class CrawlerArtifact(BaseModel):
    host: str
    url: str
    status: int | None
    headers: dict[str, str]         # lower-cased keys
    scripts: list[dict[str, Any]]   # {url, status, initiator_url, method}
    errors: list[str]
```

### `AIFinding` / `AIResponse`

```python
class AIFinding(BaseModel):
    type: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    description: str
    evidence: dict[str, Any]

class AIResponse(BaseModel):
    findings: list[AIFinding]
```

### `PageSignals`

Parsed from the httpx response (raw, pre-JS HTML) per host; the input to the profiler.

```python
class PageSignals(BaseModel):
    host: str
    headers: dict[str, str] = {}        # response headers, lower-cased keys
    title: str | None = None
    meta_description: str | None = None
    og_tags: dict[str, str] = {}
    body_snippet: str = ""              # stripped visible text, <= 2 KB, pre-JS
    form_count: int = 0
    has_password_input: bool = False
    tech: list[str] = []                # carried from httpx tech-detect
```

### `AppProfile`

The AI-inferred, Pydantic-validated per-app context. Persisted to `03_ai/profile/<host>.json`.

```python
class AppProfile(BaseModel):
    host: str
    app_type: str                       # free text, e.g. "customer login portal"
    audience: Literal["public", "internal", "partner", "unknown"]
    confidence: Literal["low", "medium", "high"]
    reasoning: str
    handles_auth: bool = False
    handles_pii: bool = False
    handles_payments: bool = False
    has_file_upload: bool = False
    is_api: bool = False
    expected_controls: list[str] = []   # controls this app *should* have; graded by the header prompt
    error: str | None = None            # set when profiling hard-failed for the host
```

### `StageError`

```python
class StageError(BaseModel):
    stage: str
    target: str | None
    message: str
```

---

## 7. Extension Points

### Adding a new scanner — the Stage plugin pattern

The pipeline is a list of `Stage` objects driven uniformly by `execute_stages`. Adding a new scanner is **one file + one line**:

1. Add a config block in `watchtower/config.py` (only if your tool has config knobs):

    ```python
    class MyToolConfig(ToolBlock):
        my_option: int = 42
    ```

    and wire it into `ToolsConfig`.

2. Create `watchtower/stages/my_stage.py`:

    ```python
    from pathlib import Path
    from watchtower.stages.base import Stage
    from watchtower.models import Finding

    class MyStage(Stage):
        name = "audit.mytool"

        def _path(self, run_dir: Path) -> Path:
            return run_dir / "02_audit" / "mytool" / "findings.jsonl"

        async def run(self, state, run_dir, cfg, ipinfo, log) -> None:
            findings = await my_tool_subprocess(state.live_servers, ...)
            state.my_findings = findings   # add a slot to ScanState if needed
    ```

3. Register it in `watchtower/stages/pipeline.py`. To make it appear in the default run, add it to the pipeline assembly; to make it independently selectable via `--only`/`--skip`, add a capability token to the `CAPABILITIES` registry mapping the token to your stage factory (and declare any dependency so resolution can auto-include prerequisites):

    ```python
    CAPABILITIES["mytool"] = Capability(
        factory=lambda cfg: MyStage(),
        phase="audit",            # placed in the audit fan-out
        # depends_on=("supply-chain",)  # if it needs another capability's output
    )
    ```

    Without a token it still runs in the default pipeline but can't be individually selected.

4. Extend the report: add a section to `watchtower/report/templates/report.html.j2` and update `report/aggregator.build_report_context` to thread your findings through.

You get for free:
- Uniform error capture (failures become `StageError` entries, pipeline continues)
- Concurrency budgeting (place in `ParallelStage` or run sequentially)
- Logging (`log.stage_start`/`stage_end` handled by `execute_stages`)

### Custom pipelines

`default_pipeline()` is just a list. Build your own:

```python
from watchtower.stages import execute_stages, ScanState
from watchtower.stages.recon import SubfinderStage, DnsxAndTriageStage
from watchtower.stages.audit import NucleiStage
from watchtower.stages.report_stage import ReportStage

stages = [
    SubfinderStage(),
    DnsxAndTriageStage(),
    NucleiStage(),
    ReportStage(run_meta, versions),
]
await execute_stages(stages, ScanState(), run_dir, cfg, ipinfo, log)
```

### Adding a new AI prompt

1. Define a Pydantic schema if the response shape differs from `AIResponse`.
2. Add a `build_<topic>_prompt(...)` helper in `watchtower/ai/prompts.py` returning `(system, user)`.
3. Call it from `analyze_all` (or a new analyzer function) inside the per-host coroutine, using `_validated_call` for built-in retry + graceful degrade.
4. Surface findings in the report context and template.

### Replacing the LLM client

`LLMClient` is a thin wrapper around `httpx.AsyncClient`. Any client exposing an `async chat(system: str, user: str) -> str` method is a drop-in:

```python
class MyClient:
    async def chat(self, system: str, user: str, *, temperature: float = 0.0) -> str:
        ...
    async def close(self) -> None:
        ...
```

Pass an instance into `_validated_call` (currently constructed inside `analyze_all` — refactor if needed for injection).

### Replacing the MMDB

Anything implementing the `IPInfoLookup` shape (`is_ipv4`, `asn_info`, `close`) can be substituted. The triage router calls only these methods, and the MMDB is optional (display-only ASN/org enrichment) — with no MMDB, `asn_info` simply returns empty ASN/org.

---

## 8. Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success. The path to `report.html` is on stdout. |
| `1` | `init-config` refused to overwrite (use `--force`). |
| `2` | Unknown command, argparse failure, or invalid stage selection (`--only` + `--skip` together, or an unknown capability token). |
| `3` | `--strict` only: the scan completed and emitted a full report, but at least one stage crash or per-host failure was recorded. |
| `130` | Interrupted (Ctrl-C). |
| *(other non-zero)* | Bootstrap failure: YAML parse/validation error, unwritable output dir, etc. (the MMDB is optional and no longer gates a run). The traceback prints to stderr. |

By default a completed scan exits 0 even if individual tools or hosts failed — partial failures are captured in `errors.json` / `summary.json` and surfaced in the report. The pipeline philosophy is "always emit a complete artifact set" (DESIGN.md §2.4). Pass `--strict` to turn any recorded failure into a non-zero exit (code `3`) for CI / programmatic callers; the report is still written.

---

## 9. Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `WATCHTOWER_MMDB_PATH` | `/data/mmdb/GeoLite2-ASN.mmdb` | Set in the Docker image as a hint; WatchTower itself reads the **optional** `mmdb_path` from the YAML (display-only ASN/org enrichment — it does not gate a run). |
| `PATH` | `/opt/tools/bin:…` | The Docker image installs all Go binaries here. |
| `PYTHONUNBUFFERED` | `1` | Set in the image so logs flush in real time. |
| `WATCHTOWER_API_KEYS` | *(unset)* | **`serve` only.** Comma-separated API keys for `Authorization: Bearer`. **If unset the API runs OPEN.** |
| `WATCHTOWER_WEBHOOK_SECRET` | *(unset)* | **`serve` only.** HMAC-SHA256 signing secret for webhook callbacks (`X-WatchTower-Signature`). |
| `WATCHTOWER_LLM_API_KEY` | *(unset)* | **`serve` only.** *Seeds* `base_config.llm.api_key` on first boot; thereafter the key is UI-managed and persists in the config store (masked on `GET /config`). |
| `WATCHTOWER_CONFIG_STORE` | `<output_root>/.config/server-config.json` | **`serve` only.** Path to the writable runtime config store (the UI-managed source of truth that overlays `server.yaml`). Written `0600`. |
| `WATCHTOWER_DB_PATH` | `<output_root>/watchtower.db` | **`serve` only.** Path to the SQLite DB (the cross-run relational layer — assets inventory, and later phases). Server-only; the engine/CLI never use it. |
| `WATCHTOWER_UI_DIR` | `/app/web-dist` (image) | **`serve` only.** If it points at a built UI, the UI is served at `/` and the API under `/api`. |

For the CLI (`scan`) no secrets flow through env vars: the LLM API key lives in the YAML config and is **redacted to `***REDACTED***`** in `config.snapshot.yaml`, so the run directory never persists it. For `serve`, the API's own auth secrets (`WATCHTOWER_API_KEYS`, `WATCHTOWER_WEBHOOK_SECRET`) stay env-only, but the **scan config — including `llm.api_key` — is UI-managed and persisted at rest in the config store** (`GET`/`PUT /config`); `server.yaml` only seeds first boot. The store holds the LLM key, so protect the store path (it is written `0600`). There is no scan-target allowlist — the per-scan `roots` is the only scope.

---

## 10. Runtime Behavior Reference

### Stage ordering (`default_pipeline`, no selection)

```
1.  recon.subfinder
2.  recon.dnsx-triage        (initial pass)
3.  recon.tlsx-loop          (iterations 1..3 — each runs dnsx + triage on new SANs)
4.  recon.httpx              (-include-response; parses PageSignals from the body)
5.  ai.profile               (per host; only when ai.profiling: true)
6.  audit.takeovers
7.  audit.parallel           (sslscan + nuclei + crawler + headers concurrently)
8.  ai.analyze               (header + supply analysis; consumes AppProfile + the
                              deterministic header findings, soft-suppresses FPs)
9.  report
10. compress                 (if --compress)
```

`ai.profile` runs **before** the audit fan-out so the profile is available to the
analysis prompts; it never gates the deterministic scanners. The deterministic
`audit.headers` stage runs in the audit group, so its findings exist before
`ai.analyze` can attach soft-suppression verdicts.

### Stage selection & capability resolution

When `--only`/`--skip` (or the `only=`/`skip=` API params) are supplied, `build_pipeline`
filters the stage list by capability token and resolves dependencies:

* The **recon spine** (subfinder → dnsx → triage → tlsx → httpx) is always retained as a
  prerequisite unless the selection is exactly `--only recon` (discovery-only: spine +
  report, stop).
* Selecting `ai` **auto-includes** the crawler (`supply-chain`) and logs it.
* `--skip supply-chain` while `ai` runs keeps `ai.profile` + header analysis and disables
  only the supply-chain analysis half.
* The resulting coverage map is written to `manifest.json` and threaded into the report
  (coverage strip + "Not run in this scan" placeholders).
* Invalid input — both flags together, or an unknown token — is rejected before any work
  starts (exit code `2`).

### Failure isolation

Each stage's top-level error handler in `runner.py` catches exceptions, records a `StageError`, and lets the pipeline continue. Stage outputs default to empty (`[]`) on failure so downstream stages have a well-defined input.

### Concurrency caps

| Stage | Source of cap | Default |
|---|---|---|
| sslscan fan-out | `cfg.concurrency.tls` | 5 |
| Playwright | `cfg.concurrency.playwright` | 5 |
| AI analysis | `cfg.concurrency.llm` | 4 |
| nuclei / nuclei-takeovers | nuclei's own `-rl` | per-tool |
| httpx / dnsx | each tool's own `-rl` | per-tool |
| tlsx | `-c` concurrency (`tools.tlsx.concurrency`; tlsx has no `-rl`) | 100 |
| subfinder | unbounded within a single subprocess | n/a |

All of the above are scaled down together by `throttle: gentle` and up by `throttle: aggressive` (see §2 [`throttle`](#throttle)).

### Rate-limit observability (log events)

Every subprocess flows through `run_tool`, which writes structured events to `run.log.jsonl`. To locate where a scan was throttled/blocked, grep these `event` values:

| `event` | Emitted when | Key fields |
|---|---|---|
| `throttle` | once at run start | resolved profile + effective per-tool rates |
| `tool_timeout` | a tool is killed at its timeout (**primary rate-limit/WAF signal**) | `tool`, `elapsed_s`, `timeout_s` |
| `tool_nonzero` | a tool exits non-zero | `tool`, `returncode`, `stderr_tail` |
| `tool_done` | a tool completes (debug level) | `tool`, `elapsed_s`, `returncode` |
| `rate_limit_signal` | httpx sees a burst of `403/429/503` | `tool`, `hosts` |
| `sslscan_host_done` / `sslscan_summary` | per-host result / run rollup | `passed`, `total`, `ok`, `errored` |

```sh
# What got throttled, and against what limits?
jq -r 'select(.event=="throttle" or .event=="tool_timeout" or .event=="rate_limit_signal")' run.log.jsonl
```

### tlsx re-feed loop

* Max iterations: **3** (hard-coded; see `watchtower.recon.tls_san.MAX_ITERATIONS`).
* Dedup: global `seen` set across iterations.
* SAN filter: only SANs whose FQDN falls under `cfg.roots` (eTLD/zone match) are re-fed.
* Wildcards (`*.foo.com`): recorded in `triage.json.wildcards`, **never** re-fed.
* Early termination: stops as soon as an iteration yields zero new in-root names.

### Triage rules (DESIGN.md §2.1.1)

For each subdomain, liveness is the only classification:

1. **No A record** (NXDOMAIN / dangling CNAME) → `dead` — takeover-watch only, not actively scanned.
2. **≥1 A record** → `live` — fully scanned, and its certificate SANs feed the DNS→TLS re-discovery loop.

The configured `roots` are the **only** scope — every name resolving under a root is scanned regardless of where it's hosted (there is no sanctioned-ownership gate). When an MMDB is configured, each live asset is additionally annotated with display-only ASN/org. IPv4 only; AAAA records are ignored entirely.

### Compression

`--compress` (default) creates `01_recon.tar.gz`, `02_audit.tar.gz`, `03_ai.tar.gz` and removes the originals. Top-level files (`report.html`, `versions.json`, `errors.json`, `config.snapshot.yaml`, `run.log.jsonl`) remain uncompressed.

Compression failures are logged as warnings; the originals are kept and the partial archive is removed. This means `--compress` is safe to set even if the filesystem fills up or `tarfile` errors out — you'll still have your raw artifacts.

### Determinism

A WatchTower run is **not** deterministic across days:

* Nuclei templates pull `latest` (not pinned).
* DNS resolutions, certificate SANs, and live web responses change.
* LLM responses depend on the model and its server's sampling.

Use `versions.json` to attribute differences between runs after the fact.
