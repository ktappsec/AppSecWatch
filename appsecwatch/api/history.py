"""Scans history index (SQLite `scans` table).

Terminal scans are recorded here for queryable cross-run history (per group/asset,
survives job.json pruning). Live jobs (queued/running) still come from the
JobManager; this is the durable record + the relational join target.
"""
from __future__ import annotations

import json
from typing import Any

from appsecwatch.api.db import Database


class ScanHistory:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(self, rec, finding_count: int = 0) -> None:
        """Upsert a scan's terminal/lifecycle row from a JobRecord."""
        self.db.execute(
            'INSERT INTO scans (id, state, roots, "group", "only", skip, throttle, '
            "submitted_at, started_at, finished_at, finding_count, source, schedule_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET state=excluded.state, "
            "started_at=COALESCE(excluded.started_at, scans.started_at), "
            "finished_at=excluded.finished_at, finding_count=excluded.finding_count",
            (
                rec.id, rec.state, json.dumps(rec.roots or []), rec.group,
                json.dumps(rec.only or []), json.dumps(rec.skip or []), rec.throttle,
                rec.submitted_at, rec.started_at, rec.finished_at,
                finding_count, getattr(rec, "source", "manual") or "manual",
                getattr(rec, "schedule_id", None),
            ),
        )

    def list(self, *, group: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM scans"
        p: list[Any] = []
        if group:
            sql += ' WHERE "group" = ?'
            p.append(group)
        sql += " ORDER BY COALESCE(finished_at, submitted_at) DESC LIMIT ?"
        p.append(limit)
        out = []
        for r in self.db.query(sql, tuple(p)):
            r = dict(r)
            r["roots"] = json.loads(r["roots"]) if r.get("roots") else []
            r["only"] = json.loads(r["only"]) if r.get("only") else None
            r["skip"] = json.loads(r["skip"]) if r.get("skip") else None
            out.append(r)
        return out
