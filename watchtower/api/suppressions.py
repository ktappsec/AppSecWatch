"""Manual finding suppressions (SQLite `suppressions` table, server-side).

CRUD + the fingerprint set the JobManager injects into run_scan. A suppression is
keyed by `source|host|key` (host '*' = global). Cross-run: once added, every
future scan hides the matching finding (uncounted, never deleted).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from watchtower.api.db import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SuppressionManager:
    def __init__(self, db: Database) -> None:
        self.db = db

    def list(self) -> list[dict[str, Any]]:
        return self.db.query("SELECT * FROM suppressions ORDER BY created_at DESC")

    def add(self, *, source: str, host: str | None, key: str,
            scope: str = "host", reason: str = "") -> dict[str, Any]:
        if scope == "global":
            host = "*"
        host = host or "*"
        fp = f"{source}|{host}|{key}"
        self.db.execute(
            "INSERT INTO suppressions (fingerprint, source, host, key, scope, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET reason=excluded.reason, scope=excluded.scope",
            (fp, source, host, key, scope, reason, _now()),
        )
        return self.db.query("SELECT * FROM suppressions WHERE fingerprint=?", (fp,))[0]

    def delete(self, fingerprint: str) -> bool:
        return self.db.execute("DELETE FROM suppressions WHERE fingerprint=?", (fingerprint,)) > 0

    def fingerprints(self) -> set[str]:
        return {r["fingerprint"] for r in self.db.query("SELECT fingerprint FROM suppressions")}
