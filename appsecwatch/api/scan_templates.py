"""Reusable scan-option presets (SQLite `scan_templates`). Options only — no
target; the target is chosen at launch. CRUD over the table."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from appsecwatch.api.db import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanTemplateManager:
    def __init__(self, db: Database) -> None:
        self.db = db

    def _row(self, r: dict[str, Any]) -> dict[str, Any]:
        r = dict(r)
        r["only"] = json.loads(r["only"]) if r.get("only") else None
        r["skip"] = json.loads(r["skip"]) if r.get("skip") else None
        r["compress"] = bool(r.get("compress"))
        return r

    def list(self) -> list[dict[str, Any]]:
        return [self._row(r) for r in self.db.query("SELECT * FROM scan_templates ORDER BY name")]

    def create(self, d: dict[str, Any]) -> dict[str, Any]:
        tid = uuid.uuid4().hex[:12]
        self.db.execute(
            'INSERT INTO scan_templates (id, name, "only", skip, throttle, compress, created_at) '
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tid, d.get("name") or tid,
             json.dumps(d.get("only")) if d.get("only") else None,
             json.dumps(d.get("skip")) if d.get("skip") else None,
             d.get("throttle"), 1 if d.get("compress", True) else 0, _now()),
        )
        return self._row(self.db.query("SELECT * FROM scan_templates WHERE id=?", (tid,))[0])

    def delete(self, tid: str) -> bool:
        return self.db.execute("DELETE FROM scan_templates WHERE id=?", (tid,)) > 0
