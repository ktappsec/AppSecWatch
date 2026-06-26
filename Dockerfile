# syntax=docker/dockerfile:1.7
#
# WatchTower — single-image deploy.
# All recon/audit binaries pinned. Python deps installed via pip.
# The Next.js UI is built in a Node stage and served by FastAPI (watchtower serve).
# GeoLite2-ASN MMDB is NOT baked in: bind-mount /data/mmdb at runtime.
#
# Build caching: dependencies are installed in layers keyed ONLY on their
# manifests (pyproject.toml / package-lock.json), and source is copied LAST, so
# editing engine/UI code re-runs only a fast no-deps reinstall — it never
# re-installs Python deps, re-downloads Chromium, or re-fetches the toolchain.
# BuildKit cache mounts (pip/npm/apt/downloads) make even cold layers near-free.

# --- UI build (Next.js static export) --------------------------------------
FROM node:22-slim AS ui-build
WORKDIR /web
# Deps layer — keyed only on the lockfile (cached across UI source edits).
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
# Source + build (Next build cache persists across builds via the cache mount).
COPY web/ ./
ENV NEXT_OUTPUT=export \
    NEXT_PUBLIC_API_BASE=/api
RUN --mount=type=cache,target=/web/.next/cache npm run build

# --- Runtime base ----------------------------------------------------------
FROM python:3.11-slim-bookworm AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/tools/bin:${PATH}"

# Keep apt's downloaded .debs + lists in cache mounts (don't auto-clean them), so
# tweaking the package list doesn't re-download the world.
RUN rm -f /etc/apt/apt.conf.d/docker-clean \
    && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl tar unzip \
        # TLS scorecard scanner (replaces the sslyze pip dep)
        sslscan \
        # Playwright/Chromium runtime deps
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
        libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
        libgbm1 libpango-1.0-0 libcairo2 libasound2 libatspi2.0-0 \
        fonts-liberation libappindicator3-1 libxss1 libxshmfence1 \
        libglib2.0-0 libgtk-3-0 libxext6 libxi6 libxtst6

# --- ProjectDiscovery Go binaries (pinned versions) -------------------------
# Cached unless a version ARG changes; the download cache mount means bumping ONE
# tool re-fetches only that tool, not all five.
ARG SUBFINDER_VERSION=2.6.6
ARG DNSX_VERSION=1.2.1
ARG TLSX_VERSION=1.1.7
ARG HTTPX_VERSION=1.6.7
ARG NUCLEI_VERSION=3.2.9

RUN --mount=type=cache,target=/tmp/dl set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) pd_arch="linux_amd64" ;; \
        arm64) pd_arch="linux_arm64" ;; \
        *) echo "Unsupported arch: $arch" && exit 1 ;; \
    esac; \
    mkdir -p /opt/tools/bin; \
    cd /tmp/dl; \
    for pkg in \
        "subfinder:${SUBFINDER_VERSION}" \
        "dnsx:${DNSX_VERSION}" \
        "tlsx:${TLSX_VERSION}" \
        "httpx:${HTTPX_VERSION}" \
        "nuclei:${NUCLEI_VERSION}" ; do \
        name="${pkg%:*}"; ver="${pkg##*:}"; \
        zip="${name}_${ver}_${pd_arch}.zip"; \
        [ -s "$zip" ] || curl -fsSL "https://github.com/projectdiscovery/${name}/releases/download/v${ver}/${zip}" -o "$zip"; \
        unzip -o "$zip" "${name}" -d /opt/tools/bin/; \
        chmod +x "/opt/tools/bin/${name}"; \
    done

# Nuclei templates — cached with the nuclei binary (not the app source); the
# engine also self-updates at runtime.
RUN nuclei -update-templates -silent || true

# --- Python dependencies (layer keyed ONLY on pyproject.toml) --------------
WORKDIR /app
# Extract the dependency lists from pyproject and install JUST those (no app
# source, no package stub) — so editing engine code never re-runs this heavy
# layer or re-downloads deps. tomllib is stdlib on 3.11.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/pip python - <<'PY'
import tomllib, subprocess, sys
proj = tomllib.load(open("pyproject.toml", "rb"))["project"]
deps = list(proj.get("dependencies", [])) \
     + list(proj.get("optional-dependencies", {}).get("web", []))
subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
subprocess.check_call([sys.executable, "-m", "pip", "install", *deps])
PY

# Chromium — its own layer, depends only on the playwright dep above (so it is
# cached across source edits). OS deps already installed via apt → no --with-deps.
RUN python -m playwright install chromium

# --- Application source (LAST — edits only re-run this fast reinstall) ------
# Install the real package. The version is static (0.1.0), so --force-reinstall
# + --no-cache-dir guarantee the wheel is rebuilt from the CURRENT source on each
# code edit (else pip treats 0.1.0 as already-satisfied / reuses a stale wheel).
# Deps are already present (--no-deps), so this is a quick local build.
COPY watchtower ./watchtower
RUN pip install --no-deps --force-reinstall --no-cache-dir .

# --- Bundled UI ------------------------------------------------------------
# Static export from the Node stage; `watchtower serve` serves it at / (API → /api)
# when WATCHTOWER_UI_DIR is set.
COPY --from=ui-build /web/out /app/web-dist
ENV WATCHTOWER_UI_DIR=/app/web-dist

# Runtime expects the MMDB at this path (bind-mount).
ENV WATCHTOWER_MMDB_PATH=/data/mmdb/GeoLite2-ASN.mmdb

VOLUME ["/data/mmdb", "/data/runs"]

# Web API + UI (watchtower serve). No-op for the CLI subcommands.
EXPOSE 8080

ENTRYPOINT ["watchtower"]
CMD ["--help"]
