# AppSecWatch UI

A web front-end for AppSecWatch, built to the **AppSecMan** design system
(`UI-SPEC.md`): Next.js 16 (App Router) · React 19 · Tailwind v4 (oklch tokens) ·
shadcn/ui pattern over Radix · lucide icons · recharts · sonner. Dark-first.

It talks to the AppSecWatch FastAPI backend (`appsecwatch serve`) over the REST
contract in `../WEB_API_PLAN.md`.

## Quick start

**1. Start the backend** (from the repo root):

```bash
# auth disabled (handy for local dev — the API runs OPEN):
appsecwatch serve -c example.server.yaml --host 127.0.0.1 --port 8099

# …or with an API key:
APPSECWATCH_API_KEYS=devkey123 appsecwatch serve -c example.server.yaml --port 8099
```

**2. Start the UI**:

```bash
cd web
npm install
cp .env.local.example .env.local   # point NEXT_PUBLIC_API_BASE at the backend
npm run dev                         # http://localhost:3000
```

Open <http://localhost:3000>. If the backend uses an API key, set it under
**Settings** (stored in `localStorage`) — or via `NEXT_PUBLIC_API_KEY`.

## Pages

| Route | What |
| --- | --- |
| `/` | Dashboard — KPIs + severity charts (recharts) + recent scans |
| `/scans` | All scans — filterable table, live polling, inline cancel |
| `/scans/new` | New scan form (quick/full, capability selection, throttle) |
| `/scans/[id]` | Scan detail — live progress + tabs: Findings, Recon, TLS, AI, Log, Report |
| `/settings` | Configure API base URL + key, test connectivity |

## How it maps to the design system

- **Tokens** — `src/app/globals.css` defines the oklch palette (`:root` light,
  `.dark` dark) and binds them to Tailwind utilities via `@theme inline`. Change
  `--primary` / `--accent` to re-skin everything.
- **`cn()`** — `src/lib/utils.ts` (clsx + tailwind-merge). Used for every dynamic
  className.
- **Theme** — `src/components/theme-provider.tsx`, a minimal next-themes-compatible
  provider; `defaultTheme="dark"`, persists to `localStorage`.
- **Shell** — `layout.tsx` → `layout-wrapper.tsx` (256px sidebar + sticky topbar +
  scrollable `main p-6`).
- **Primitives** — `src/components/ui/*` (Button with 6 variants/sizes +
  `dark:hover:brightness-110`, Card `rounded-xl`, Badge, Tabs, Dialog, Select, …).
- **App components** — `StatCard` (KPI), `ChartCard`, `SeverityBadge`/`StateBadge`.

## API client

`src/lib/api.ts` is the single typed client; `src/lib/types.ts` mirrors the
Pydantic models in `appsecwatch/api/models.py`. Base URL + key resolve from
`localStorage` (Settings) first, then `NEXT_PUBLIC_*`. Swapping to a different
backend is a one-line change in Settings.

## Build

```bash
npm run build && npm run start            # Node server (port 3000)
NEXT_OUTPUT=export npm run build          # static export → out/ (served by FastAPI)
```

## Docker — single image (UI + API together)

The repo `Dockerfile` is multi-stage: a Node stage runs `NEXT_OUTPUT=export
npm run build` and the Python stage copies the result to `/app/web-dist`. At
runtime `appsecwatch serve` detects `APPSECWATCH_UI_DIR` and serves the UI at `/` with
the API mounted under `/api` (same origin → no CORS, no baked URL).

```bash
docker build -t appsecwatch .
docker run --rm -p 8080:8080 \
  -v "$PWD/mmdb:/data/mmdb:ro" -v "$PWD/runs:/data/runs" \
  -v "$PWD/example.server.yaml:/etc/appsecwatch/server.yaml:ro" \
  -e APPSECWATCH_API_KEYS="$(cat api.key)" \
  appsecwatch serve -c /etc/appsecwatch/server.yaml --host 0.0.0.0 --port 8080
# → UI:  http://localhost:8080/        API: http://localhost:8080/api/...
```

To run the combined app locally without Docker (after a static export build):

```bash
appsecwatch serve -c example.server.yaml --port 8080 --ui-dir web/out
```
