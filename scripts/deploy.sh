#!/usr/bin/env bash
# Update an ALREADY-PROVISIONED AppSecWatch box: pull → rebuild the image →
# restart the stack → health check.
#
# Run ON THE VM, as root:
#     sudo bash /opt/appsecwatch/scripts/deploy.sh
#
# It NEVER touches your state:
#   • .env is left alone (a restart picks up any edits you made to it)
#   • the `appsecwatch-data` named volume — runs/<id>/ artifacts, the config store
#     and appsecwatch.db — survives a rebuild. `up -d` recreates the CONTAINER,
#     not the volume. (Only `docker compose down -v` would destroy it. Don't.)
#
# First run on a fresh box: scripts/provision.sh, then this.
# Flags:  --no-pull   rebuild the current checkout without fetching
#         --no-cache  force a cold image build
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/appsecwatch}"
REPO_REF="${REPO_REF:-main}"
PORT="${PORT:-8080}"
HEALTH_RETRIES="${HEALTH_RETRIES:-30}"   # ~60s: first boot runs migrations + FTS init

PULL=1; BUILD_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --no-pull)  PULL=0 ;;
    --no-cache) BUILD_ARGS+=(--no-cache) ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$1" >&2; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root:  sudo bash ${INSTALL_DIR}/scripts/deploy.sh" >&2; exit 1; }
[ -f "$INSTALL_DIR/docker-compose.yml" ] || { echo "No ${INSTALL_DIR}/docker-compose.yml — run scripts/provision.sh first." >&2; exit 1; }
[ -f "$INSTALL_DIR/.env" ] || { echo "No ${INSTALL_DIR}/.env — run scripts/provision.sh first." >&2; exit 1; }

# An empty APPSECWATCH_API_KEYS means auth is OPEN, and an open server has no
# scan-scope ceiling whatsoever. Refuse rather than quietly deploy that, since the
# whole point of this box is to sit behind a public tunnel.
if ! grep -qE '^APPSECWATCH_API_KEYS=.+' "$INSTALL_DIR/.env"; then
  echo "ERROR: APPSECWATCH_API_KEYS is empty/missing in ${INSTALL_DIR}/.env." >&2
  echo "       Auth would be OPEN — any caller could scan any target. Set it first:" >&2
  echo "         openssl rand -hex 32" >&2
  exit 1
fi

# Not fatal (the API is still key-protected), but the static UI is not: the API
# key is a per-route dependency and the SPA mount carries none.
if ! grep -qE '^APPSECWATCH_BASIC_AUTH=.+:.+' "$INSTALL_DIR/.env"; then
  warn "APPSECWATCH_BASIC_AUTH is not set — the built UI at / will be served"
  warn "anonymously. Set it to 'user:password' in .env if this host is reachable"
  warn "from anywhere untrusted (a Cloudflare Tunnel counts)."
fi

cd "$INSTALL_DIR"

# --- 1. pull ---
if [ "$PULL" = "1" ] && [ -d .git ]; then
  say "Pulling ${REPO_REF}…"
  git fetch --prune origin
  # Refuse to blow away uncommitted edits made directly on the box.
  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "Uncommitted local changes in ${INSTALL_DIR} — leaving them in place."
    warn "Skipping the pull; deploying the working tree as-is."
  else
    git checkout "$REPO_REF"
    git pull --ff-only origin "$REPO_REF"
  fi
  echo "  now at: $(git log --oneline -1)"
elif [ "$PULL" = "1" ]; then
  warn "${INSTALL_DIR} is not a git checkout — nothing to pull, building as-is."
fi

# --- 2. build ---
# Layer caching means a code-only change rebuilds in ~10s: deps are keyed on
# pyproject.toml / package-lock.json and the source is copied last.
say "Building the image…"
docker compose build "${BUILD_ARGS[@]}"

# --- 3. start ---
# No `--profile zap`, so the optional OWASP ZAP sidecar stays down. Turn it on with
#   docker compose --profile zap up -d
say "Starting the stack…"
docker compose up -d --remove-orphans

# --- 4. health ---
# Combined image → the API is mounted under /api, so healthz is /api/healthz.
say "Waiting for health…"
HEALTH_URL="http://127.0.0.1:${PORT}/api/healthz"
for i in $(seq 1 "$HEALTH_RETRIES"); do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    say "Deployed ✓  $(curl -fsS "$HEALTH_URL")"
    docker image prune -f >/dev/null 2>&1 || true   # drop layers the rebuild orphaned
    echo
    echo "  UI/API : http://127.0.0.1:${PORT}/   (bound per APPSECWATCH_BIND in .env)"
    echo "  logs   : docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f appsecwatch"
    exit 0
  fi
  sleep 2
done

echo "ERROR: health check failed after $((HEALTH_RETRIES * 2))s at ${HEALTH_URL}" >&2
echo "Recent logs:" >&2
docker compose logs --tail 60 appsecwatch >&2 || true
exit 1
