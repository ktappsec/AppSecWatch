# WatchTower

**Point-in-time, single-run external AppSec audit orchestrator.** A modular async
pipeline — recon → triage → audit fan-out → AI analysis → aggregate → a single
self-contained `report.html`. **No database, no state across runs**: every scan
writes a complete, standalone artifact set under `runs/<id>/`. Driven by a CLI, a
Python API, and an authenticated Web API + UI. Ships as one Docker image.

```
recon spine ─▶ triage ─▶ audit fan-out ─▶ AI analysis ─▶ aggregate ─▶ report.html
```

---

## Highlights

- **Recon spine** — `subfinder → dnsx → triage → tlsx → httpx`. The `tlsx`
  cert-grab harvests SANs (re-feed loop) **and**, in the same handshake, a passive
  **cert inventory** (expiry, issuer, self-signed/wildcard, fingerprint).
- **Audit capabilities** — subdomain takeovers, TLS scorecard (sslyze), web-CVE
  scan (nuclei), Playwright supply-chain crawler, and a deterministic
  **security-headers** analysis (OWASP best-practice + structured CSP).
- **AI layer (pluggable local/OpenAI-compatible LLM)** — per-app profiling that
  makes header/supply-chain analysis context-aware, and soft-suppression of
  false-positive header findings. The AI **never gates** the deterministic
  scanners; all LLM output is Pydantic-validated with graceful degradation.
- **One self-contained report** — `report.html` with everything inlined; plus
  machine-readable JSON via the Web API.
- **Web API + UI** — submit/track/retrieve scans; **config is UI-managed**
  (edit the LLM endpoint, MMDB path, throttle, etc. in the browser).
- **Asset inventory** — a persistent inventory (SQLite) grouped by **iştirak**:
  import roots via CSV (`domain,group`), recon writes discovered subdomains back,
  bulk edit/delete, and re-evaluate buckets when your sanctioned CIDRs/ASNs change.
  Scans target a `group` / specific assets / `all` (not just ad-hoc roots).
- **Scheduling** — recurring scans (hourly/daily/weekly) of an iştirak, run by an
  in-process scheduler.
- **Finding suppression** — manually suppress a finding (per-host or global);
  hidden + uncounted on every future scan, never deleted.
- **Vulnerable JS libraries** — retire.js-style detection over crawled scripts.
- **Nuclei catalog & custom templates** — searchable template catalog, granular
  selection (tags/categories/ids), plus a custom-template editor + **AI generator**.
- **Stealth identity** — browser presets (UA + coherent headers + locale) and
  free-form/decoy headers applied to httpx/nuclei/the crawler, for authorized
  testing of your own assets. (Defeats UA/header WAF rules, not TLS-fingerprint or
  IP-reputation blocking — the durable fix for those is an allowlisted scanner IP.)
- **Selective scans** — `--only` / `--skip` capability tokens with finer
  sub-tokens (e.g. `--only nuclei.high,headers.csp`); **subfinder is optional**, so
  `--skip recon.subfinder` is a quick scan of exactly the roots you gave.
- **nmap-like throttle tiers** — `paranoid / gentle / normal / aggressive / insane`
  (each tuning concurrency + rates); the UI shows what each tier actually does.

See **[DOCS.md](DOCS.md)** for a fuller overview and **[DESIGN.md](DESIGN.md)**
for the canonical spec.

---

## Capabilities & tokens

`--only` / `--skip` take stable capability tokens; four split into dotted sub-tokens.

| Token | What it runs |
|---|---|
| `recon` | discovery spine (always a prerequisite). Sub: `recon.subfinder|dns|tlsx|httpx` |
| `takeovers` | nuclei takeover templates vs dead assets |
| `tls` | sslyze per-host TLS pass/fail scorecard |
| `nuclei` | nuclei web-CVE scan. Sub: `nuclei.critical|high|medium|low|info` |
| `headers` | deterministic OWASP header + CSP analysis (passive). Sub: `headers.csp|best-practice` |
| `supply-chain` | Playwright crawler (scripts + headers) |
| `ai` | profiling + header/supply-chain reasoning. Sub: `ai.profile|headers|supply-chain` |

`--only recon` is discovery-only. The recon spine always runs as a prerequisite
when any audit/AI capability is selected.

---

## Quickstart

A local venv lives at `.venv` (Python 3.11+).

### Tests (no external tools needed — they're mocked)
```sh
./.venv/bin/python -m pytest -q          # full suite
```

### CLI scan
Needs the toolchain (`subfinder dnsx tlsx httpx nuclei`, `sslyze`, Playwright +
Chromium) and a MaxMind GeoLite2-ASN MMDB — easiest via the Docker image below.
Check readiness with `watchtower verify-deps`.
```sh
cp example.config.yaml config.yaml      # edit roots / llm / mmdb_path
./.venv/bin/python -m watchtower scan -c config.yaml -o ./runs --progress rich
# → ./runs/<id>/report.html
```

### Web API + UI (local dev)
The API boots **without a config file** — config is managed from the UI.
```sh
# Terminal A — API on :8099 (OPEN if WATCHTOWER_API_KEYS unset; -o sets the data dir)
./.venv/bin/python -m watchtower serve -o ./runs --host 127.0.0.1 --port 8099

# Terminal B — UI on :3000 (talks to :8099 by default)
cd web && npm install && npm run dev
```
Open `http://localhost:3000` → **Settings** to set the LLM endpoint, MMDB path,
throttle, etc., then **New Scan**.

### Docker (single image: tools + API + UI)
The build is layer-cached — a code edit rebuilds in ~10s (no dep reinstall). Use
**docker-compose** so a named volume persists state across rebuilds (config +
assets + `watchtower.db` live under `/data/runs`):
```sh
echo "my-secret-key" > api.key
WATCHTOWER_API_KEYS="$(cat api.key)" docker compose up --build
# → UI at http://localhost:8080/ , API at http://localhost:8080/api/...
```
Or plain `docker run` (use a **named volume**, not a fresh dir, so a rebuild
doesn't wipe config/assets):
```sh
docker build -t watchtower .
docker run --rm -p 8080:8080 -e WATCHTOWER_API_KEYS="$(cat api.key)" \
  -v watchtower-data:/data/runs -v "$PWD/mmdb:/data/mmdb:ro" \
  watchtower serve --host 0.0.0.0 --port 8080
```
`-c /path/server.yaml` is optional (seeds first boot only). The Settings page shows
the live config-store/DB paths so you know what to persist.

---

## Configuration

- **UI-managed, store-primary.** `server.yaml` only *seeds* first boot; a writable
  JSON store (`WATCHTOWER_CONFIG_STORE`, default `<output_root>/.config/`) is the
  source of truth and is edited at runtime via `GET`/`PUT /config` (the Settings
  page). The CLI (`watchtower scan`) still takes a YAML config directly.
- **Secrets.** The API's own auth (`WATCHTOWER_API_KEYS`) and the webhook secret are
  env-only. The **LLM api_key is UI-managed** and persists in the store
  (write-only: masked on read).
- **No scan-target allowlist.** The per-scan `roots` is the only scope. ⚠️ With
  auth **OPEN** (no `WATCHTOWER_API_KEYS`) there is no server-side scope ceiling —
  set API keys before exposing the server.

See `example.config.yaml` / `example.server.yaml` and **[API.md](API.md)** §2,
**[WEB_API_PLAN.md](WEB_API_PLAN.md)** §4.

---

## Repo layout

```
watchtower/   Python engine (cli, runner, config, models, stages/, recon/ audit/ ai/, report/, api/)
web/        Next.js 16 UI over the Web API
tests/      pytest suite (external tools mocked)
Dockerfile  multi-stage, layer-cached: Node builds the UI → Python serves it
```

## Documentation

| File | Purpose |
|---|---|
| **[DESIGN.md](DESIGN.md)** | Canonical spec — locked decisions, data model, module layout. **Wins on conflict.** |
| [API.md](API.md) | CLI, YAML config, run-dir layout, Python API |
| [WEB_API_PLAN.md](WEB_API_PLAN.md) | Web API contract & design |
| [UI-SPEC.md](UI-SPEC.md) | UI stack & design system |
| [DOCS.md](DOCS.md) | Top-level overview |
| [AGENTS.md](AGENTS.md) | Orientation for AI agents working in the repo |
