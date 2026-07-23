# DEPLOYMENT.md — running AppSecWatch on a server

Two scripts do everything. `provision.sh` prepares a bare VM once; `deploy.sh`
is what you run for every update thereafter.

| Script | When | What it does |
|---|---|---|
| `scripts/provision.sh` | once, on a fresh VM | packages + Docker Engine, source → `/opt/appsecwatch`, generates `.env` with an API key, creates `mmdb/` |
| `scripts/deploy.sh` | every update | `git pull` → `docker compose build` → `up -d` → health check |
| `scripts/backup.sh` | scheduled / before risky ops | archives the `appsecwatch-data` volume (`--restore` to put it back) |

Both are idempotent and run as root. Neither ever touches `.env` or the
`appsecwatch-data` volume.

## 1. Requirements

A Debian/Ubuntu VM. **The image build needs ~12 GB of free disk** — it carries
Chromium, the nuclei template set, five ProjectDiscovery Go binaries and a Node
build stage. `provision.sh` warns if the disk is smaller; a build that fills the
disk leaves a half-written layer you have to clear with `docker system prune -af`.

### Sizing

2 vCPU / 4 GB runs the default `normal` throttle tier. The crawler launches **one**
Chromium process and gates concurrent contexts with a semaphore
(`conc_playwright`), so memory scales with the tier, not the host count:

| tier | `conc_playwright` | rough crawler peak |
|---|---|---|
| paranoid | 1 | ~0.3 GB |
| gentle | 2 | ~0.5 GB |
| **normal** (default) | **5** | **~0.7–1.2 GB** |
| aggressive | 8 | ~1.5 GB |
| insane | 15 | ~2.5 GB+ |

Add nuclei (~0.3–0.8 GB with the full template set) and the engine itself
(~0.2–0.5 GB on a large estate). On 4 GB, `normal` fits with headroom;
**`aggressive` and `insane` risk an OOM kill** — and they are the loud tiers
anyway, so raising throttle costs you memory *and* stealth at once.

CPU is the throughput limit, not a correctness one: rendering 5 pages on 2 cores
with `wait_until: networkidle` makes the crawl the slowest stage of a scan.

Two host-level notes:

- **`shm_size: 1gb` is set in `docker-compose.yml` and is load-bearing.** Docker's
  64 MB `/dev/shm` default crashes Chromium's renderer on heavy pages, and the
  crawler catches that into `artifact.errors` — so the host silently reports no
  scripts and no resources, indistinguishable from a script-free page. Don't
  remove it.
- **GCP images ship with no swap.** An OOM kills the container outright rather
  than degrading. If you plan to run `aggressive`, add a swapfile first:
  ```sh
  sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  ```

## 2. First deploy

On a bare box:

```sh
curl -fsSL https://raw.githubusercontent.com/ktappsec/AppSecWatch/main/scripts/provision.sh | sudo bash
sudo bash /opt/appsecwatch/scripts/deploy.sh
```

`provision.sh` prints the generated API key — you need it to log in. It lives in
`/opt/appsecwatch/.env` (mode 600) and is never regenerated on a re-run.

The first build is slow (10–25 min on a small VM: Chromium, the toolchain, the
UI). Every build after that is fast — deps are keyed on `pyproject.toml` /
`package-lock.json` and the source is copied last, so a code-only change rebuilds
in about ten seconds.

## 3. Exposure

The port is published on **`127.0.0.1:8080` by default**
(`APPSECWATCH_BIND` in `.env`), so nothing is reachable from outside the box
until you put a tunnel in front of it. That default is deliberate: **auth is
this server's only scope ceiling.** There is no target allowlist — an
authenticated caller can scan any root they name — so an unauthenticated or
publicly-bound instance is a genuine hazard, not just untidy.

Point a Cloudflare Tunnel at `http://localhost:8080`. To expose the port
directly instead, set `APPSECWATCH_BIND=0.0.0.0` in `.env`, re-run `deploy.sh`,
and firewall it yourself.

### The two credentials

They cover **different surfaces**, which is why both exist:

| | `APPSECWATCH_API_KEYS` | `APPSECWATCH_BASIC_AUTH` |
|---|---|---|
| form | `Bearer` / `X-API-Key` / `?api_key=` | HTTP Basic (`user:password`) |
| covers | `/api/*` only | **everything, including the static UI** |
| for | scripts, CI, report links | humans in a browser |

The API key is a per-route dependency, and the built UI is mounted as plain
static files with no dependency at all — so **the API key alone leaves the whole
SPA shell readable** by anyone who can reach the port. `APPSECWATCH_BASIC_AUTH`
is the front door that closes that, and it is what makes a public tunnel safe.
`deploy.sh` hard-fails on an empty API key and warns on a missing Basic pair.

Either credential is sufficient on its own:

- a request with a valid API key is **never** challenged, so `curl`, CI, and the
  `?api_key=` report/executive links keep working un-prompted;
- clearing the Basic prompt **also** satisfies the API, so a browser user does
  not additionally have to paste the 64-char key into Settings.

Both authorise the same thing (driving scans), so neither grants more than the
other. `provision.sh` generates both and prints them.

`GET /healthz` is deliberately never challenged — `deploy.sh` and container
probes poll it, and a health check that needs credentials reports the wrong thing
exactly when credentials are what broke. It returns only status and version.

Only the **first** colon in `APPSECWATCH_BASIC_AUTH` separates user from
password, so the password may contain colons. A malformed value (no colon, empty
half) disables the gate rather than creating one nobody can pass.

To rotate either, edit `.env` and `docker compose restart appsecwatch` — no
rebuild. Cloudflare Access in front of the tunnel stacks cleanly on top of both.

## 4. Configure before scanning

A scan is gated at submit on a valid base config, so a freshly-deployed server
returns `409 not_configured` until you set one. In the UI:

- **Settings → LLM** — endpoint + key. This is the only hard gate.
- **Settings → mmdb path** — optional. ASN/org enrichment is display-only and
  degrades to "no ASN" when absent, so you can skip it. To enable it, drop
  `GeoLite2-ASN.mmdb` into `/opt/appsecwatch/mmdb/` and set the path to
  `/data/mmdb/GeoLite2-ASN.mmdb`.

## 5. State and persistence

Everything durable lives in the **`appsecwatch-data` named volume** at
`/data/runs`:

- `runs/<id>/` — the scan artifacts, and the source of truth for every scan
- `.config/server-config.json` — the runtime config store, including the LLM key
- `appsecwatch.db` — assets, schedules, finding state, history

A named volume survives `docker compose up --build`, `docker rm`, and a full
image rebuild. It does **not** survive `docker compose down -v` — never use the
`-v` flag here.

`runs/` is authoritative and the DB is derived from it: the server replays any
completed run not yet reflected in `finding_state` on every boot, so a rebuilt DB
over a surviving volume repairs itself. The config store does **not** have that
property — it is the one thing only `backup.sh` can bring back.

```sh
sudo bash /opt/appsecwatch/scripts/backup.sh                       # → /var/backups/appsecwatch
sudo bash /opt/appsecwatch/scripts/backup.sh --restore <file.tar.gz>
```

To run it nightly:

```sh
sudo tee /etc/cron.d/appsecwatch-backup >/dev/null <<'EOF'
30 2 * * * root bash /opt/appsecwatch/scripts/backup.sh >/dev/null 2>&1
EOF
```

## 6. Day-2 operations

```sh
cd /opt/appsecwatch
docker compose logs -f appsecwatch          # follow logs
docker compose ps                           # what's running
docker compose restart appsecwatch          # apply a .env edit
sudo bash scripts/deploy.sh                 # pull + rebuild + restart
sudo bash scripts/deploy.sh --no-pull       # rebuild the current checkout
sudo bash scripts/deploy.sh --no-cache      # cold rebuild
```

The stack comes back after a reboot on its own: `restart: unless-stopped` plus an
enabled `docker.service`. There is no systemd unit of our own to manage.

### Optional: the ZAP sidecar

`zap` is the one capability that is actively intrusive, so it is opt-in at every
layer — including here, where the sidecar sits behind a compose profile and a
plain `up -d` never starts it:

```sh
# set ZAP_API_KEY in .env first
cd /opt/appsecwatch && docker compose --profile zap up -d
```

Then in the UI Settings set the zap block: `enabled: true`,
`base_url: http://zap:8090`, `api_key: <ZAP_API_KEY>`. The daemon is not
published to the host — appsecwatch reaches it over the compose network.

## 7. Troubleshooting

**Health check fails after deploy.** `docker compose logs --tail 100 appsecwatch`.
The first boot runs DB migrations and FTS init, so give it the full ~60s the
script already waits.

**Build dies partway through.** Almost always disk. `df -h /`, then
`docker system prune -af` to clear orphaned layers and retry.

**Scans return 0 live servers.** That is a scan-side diagnosis, not a deployment
one — the server records *why* (blocked edge vs. an estate that serves no HTTP)
on the run itself. See the throttle/blocking notes in `AGENTS.md`; use the
`gentle` profile for hardened targets.
