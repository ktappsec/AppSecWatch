#!/usr/bin/env bash
# Back up the `appsecwatch-data` volume — runs/<id>/ artifacts, the config store
# (.config/server-config.json, which holds the LLM key) and appsecwatch.db.
#
#     sudo bash /opt/appsecwatch/scripts/backup.sh            # → /var/backups/appsecwatch
#     sudo bash /opt/appsecwatch/scripts/backup.sh --restore <file.tar.gz>
#
# The volume survives rebuilds, so this is insurance against the VM itself, not
# against deploys. runs/ is the source of truth for every scan ever done here and
# the DB is derived from it — but the config store is NOT reconstructible, so a
# backup is the only copy of the server's own settings.
set -euo pipefail

VOLUME="${VOLUME:-appsecwatch_appsecwatch-data}"   # compose prefixes with the project name
BACKUP_DIR="${BACKUP_DIR:-/var/backups/appsecwatch}"
KEEP="${KEEP:-10}"
INSTALL_DIR="${INSTALL_DIR:-/opt/appsecwatch}"

say() { printf '\n\033[1;36m==>\033[0m %s\n' "$1"; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

# Resolve the real volume name (project prefix depends on the install dir name).
if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
  FOUND="$(docker volume ls -q --filter name=appsecwatch-data | head -1 || true)"
  [ -n "$FOUND" ] || { echo "ERROR: no appsecwatch-data volume found." >&2; exit 1; }
  VOLUME="$FOUND"
fi

if [ "${1:-}" = "--restore" ]; then
  ARCHIVE="${2:?usage: backup.sh --restore <file.tar.gz>}"
  [ -f "$ARCHIVE" ] || { echo "No such archive: $ARCHIVE" >&2; exit 1; }
  # Restoring over a running server would race the DB; stop it first.
  say "Stopping the stack…"
  docker compose -f "$INSTALL_DIR/docker-compose.yml" stop appsecwatch || true
  say "Restoring ${ARCHIVE} → ${VOLUME} (existing contents are REPLACED)…"
  docker run --rm -v "$VOLUME:/data" -v "$(cd "$(dirname "$ARCHIVE")" && pwd):/backup:ro" \
    alpine sh -c "rm -rf /data/* /data/..?* /data/.[!.]* 2>/dev/null; tar xzf /backup/$(basename "$ARCHIVE") -C /data"
  say "Restarting…"
  docker compose -f "$INSTALL_DIR/docker-compose.yml" up -d appsecwatch
  say "Restored ✓"
  exit 0
fi

install -d -m 700 "$BACKUP_DIR"      # 0700: the config store holds the LLM API key
OUT="appsecwatch-data-$(date +%Y%m%d-%H%M%S).tar.gz"
say "Archiving volume ${VOLUME} → ${BACKUP_DIR}/${OUT}…"
docker run --rm -v "$VOLUME:/data:ro" -v "$BACKUP_DIR:/backup" \
  alpine tar czf "/backup/${OUT}" -C /data .
chmod 600 "${BACKUP_DIR}/${OUT}"

# Prune: keep only the newest $KEEP archives so these never fill the disk.
ls -1t "${BACKUP_DIR}"/appsecwatch-data-*.tar.gz 2>/dev/null | tail -n "+$((KEEP + 1))" | xargs -r rm -f

say "Backed up ✓  $(du -h "${BACKUP_DIR}/${OUT}" | cut -f1)"
ls -1t "${BACKUP_DIR}"/appsecwatch-data-*.tar.gz | head -5
