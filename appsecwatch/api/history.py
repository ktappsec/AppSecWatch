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

    _SEV = ("critical", "high", "medium", "low", "info")

    def record(
        self,
        rec,
        finding_count: int = 0,
        *,
        by_severity: dict[str, int] | None = None,
        risk_score: int | None = None,
    ) -> None:
        """Upsert a scan's terminal/lifecycle row from a JobRecord. The optional
        per-severity breakdown + risk score power the trend charts."""
        bs = by_severity or {}
        sev = {s: int(bs.get(s, 0) or 0) for s in self._SEV}
        self.db.execute(
            'INSERT INTO scans (id, state, roots, "group", "only", skip, throttle, '
            "submitted_at, started_at, finished_at, finding_count, "
            "sev_critical, sev_high, sev_medium, sev_low, sev_info, risk_score, "
            "source, schedule_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET state=excluded.state, "
            "started_at=COALESCE(excluded.started_at, scans.started_at), "
            "finished_at=excluded.finished_at, finding_count=excluded.finding_count, "
            "sev_critical=excluded.sev_critical, sev_high=excluded.sev_high, "
            "sev_medium=excluded.sev_medium, sev_low=excluded.sev_low, "
            "sev_info=excluded.sev_info, risk_score=excluded.risk_score",
            (
                rec.id, rec.state, json.dumps(rec.roots or []), rec.group,
                json.dumps(rec.only or []), json.dumps(rec.skip or []), rec.throttle,
                rec.submitted_at, rec.started_at, rec.finished_at,
                finding_count,
                sev["critical"], sev["high"], sev["medium"], sev["low"], sev["info"],
                risk_score,
                getattr(rec, "source", "manual") or "manual",
                getattr(rec, "schedule_id", None),
            ),
        )

    def _entry(self, r: dict[str, Any]) -> dict[str, Any]:
        r = dict(r)
        r["roots"] = json.loads(r["roots"]) if r.get("roots") else []
        r["only"] = json.loads(r["only"]) if r.get("only") else None
        r["skip"] = json.loads(r["skip"]) if r.get("skip") else None
        r["by_severity"] = {s: int(r.get(f"sev_{s}") or 0) for s in self._SEV}
        return r

    def list(self, *, group: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM scans"
        p: list[Any] = []
        if group:
            sql += ' WHERE "group" = ?'
            p.append(group)
        sql += " ORDER BY COALESCE(finished_at, submitted_at) DESC LIMIT ?"
        p.append(limit)
        return [self._entry(r) for r in self.db.query(sql, tuple(p))]

    def trends(self, *, group: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
        """Chronological (oldest→newest) completed-scan points for trend charts."""
        sql = "SELECT * FROM scans WHERE state = 'completed'"
        p: list[Any] = []
        if group:
            sql += ' AND "group" = ?'
            p.append(group)
        sql += " ORDER BY COALESCE(finished_at, submitted_at) DESC LIMIT ?"
        p.append(limit)
        rows = [self._entry(r) for r in self.db.query(sql, tuple(p))]
        rows.reverse()  # oldest first for plotting
        out = []
        for r in rows:
            bs = r["by_severity"]
            out.append({
                "id": r["id"],
                "label": (r.get("finished_at") or r.get("submitted_at") or "")[:10],
                "finished_at": r.get("finished_at"),
                "finding_count": int(r.get("finding_count") or 0),
                "risk_score": r.get("risk_score"),
                **bs,
            })
        return out
