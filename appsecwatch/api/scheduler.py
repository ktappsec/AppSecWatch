"""In-process scan scheduler (friendly cadence; no cron dep).

A background asyncio task ticks every ~30s; due, enabled schedules enqueue a
normal scan via the JobManager (resolving their target selector → roots).
skip-if-running (the schedule's last job still queued/running); run-overdue-once
on boot (the first tick fires anything past due). Times are UTC.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from appsecwatch.api.assets import AssetManager
from appsecwatch.api.db import Database
from appsecwatch.api.models import ScanRequest

log = logging.getLogger("appsecwatch.api")

CADENCES = ("hourly", "daily", "weekly")
_TICK_SECONDS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def compute_next(cadence: str, at_time: str | None, weekday: int | None,
                 now: datetime | None = None) -> str:
    """Next UTC ISO timestamp for a cadence. at_time='HH:MM'; weekday 0=Mon..6=Sun."""
    now = now or _now()
    hh = mm = 0
    if at_time and ":" in at_time:
        try:
            hh, mm = (int(x) for x in at_time.split(":")[:2])
        except ValueError:
            hh = mm = 0
    if cadence == "hourly":
        c = now.replace(minute=mm, second=0, microsecond=0)
        if c <= now:
            c += timedelta(hours=1)
        return c.isoformat()
    if cadence == "weekly":
        c = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        wd = weekday if weekday is not None else 0
        c += timedelta(days=(wd - c.weekday()) % 7)
        if c <= now:
            c += timedelta(days=7)
        return c.isoformat()
    # daily (default)
    c = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if c <= now:
        c += timedelta(days=1)
    return c.isoformat()


class ScheduleManager:
    def __init__(self, db: Database, assets: AssetManager, jobs) -> None:
        self.db = db
        self.assets = assets
        self.jobs = jobs
        self._task: asyncio.Task | None = None

    # ----- lifecycle ------------------------------------------------------- #
    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ----- CRUD ----------------------------------------------------------- #
    def _row(self, r: dict[str, Any]) -> dict[str, Any]:
        r = dict(r)
        r["target"] = json.loads(r["target"]) if r.get("target") else {}
        r["only"] = json.loads(r["only"]) if r.get("only") else None
        r["skip"] = json.loads(r["skip"]) if r.get("skip") else None
        r["compress"] = bool(r.get("compress"))
        r["enabled"] = bool(r.get("enabled"))
        return r

    def list(self) -> list[dict[str, Any]]:
        return [self._row(r) for r in self.db.query("SELECT * FROM schedules ORDER BY name")]

    def get(self, sid: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM schedules WHERE id=?", (sid,))
        return self._row(rows[0]) if rows else None

    def create(self, d: dict[str, Any]) -> dict[str, Any]:
        if d.get("cadence") not in CADENCES:
            raise ValueError(f"cadence must be one of {CADENCES}")
        sid = uuid.uuid4().hex[:12]
        nxt = compute_next(d["cadence"], d.get("at_time"), d.get("weekday"))
        self.db.execute(
            'INSERT INTO schedules (id, name, target, "only", skip, throttle, compress, '
            "cadence, at_time, weekday, enabled, next_run_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sid, d.get("name") or sid, json.dumps(d.get("target") or {}),
             json.dumps(d.get("only")) if d.get("only") else None,
             json.dumps(d.get("skip")) if d.get("skip") else None,
             d.get("throttle"), 1 if d.get("compress", True) else 0,
             d["cadence"], d.get("at_time"), d.get("weekday"),
             1 if d.get("enabled", True) else 0, nxt, _now().isoformat()),
        )
        return self.get(sid)

    def update(self, sid: str, d: dict[str, Any]) -> dict[str, Any] | None:
        cur = self.get(sid)
        if cur is None:
            return None
        cadence = d.get("cadence", cur["cadence"])
        if cadence not in CADENCES:
            raise ValueError(f"cadence must be one of {CADENCES}")
        at_time = d.get("at_time", cur.get("at_time"))
        weekday = d.get("weekday", cur.get("weekday"))
        self.db.execute(
            'UPDATE schedules SET name=?, target=?, "only"=?, skip=?, throttle=?, '
            "compress=?, cadence=?, at_time=?, weekday=?, enabled=?, next_run_at=? WHERE id=?",
            (d.get("name", cur["name"]), json.dumps(d.get("target", cur["target"])),
             json.dumps(d.get("only", cur["only"])) if d.get("only", cur["only"]) else None,
             json.dumps(d.get("skip", cur["skip"])) if d.get("skip", cur["skip"]) else None,
             d.get("throttle", cur["throttle"]),
             1 if d.get("compress", cur["compress"]) else 0,
             cadence, at_time, weekday,
             1 if d.get("enabled", cur["enabled"]) else 0,
             compute_next(cadence, at_time, weekday), sid),
        )
        return self.get(sid)

    def delete(self, sid: str) -> bool:
        return self.db.execute("DELETE FROM schedules WHERE id=?", (sid,)) > 0

    # ----- the tick ------------------------------------------------------- #
    def tick(self) -> int:
        """Fire any due schedules. Returns the number enqueued. Synchronous —
        safe to call from a test or the loop (off the event loop)."""
        now = _now().isoformat()
        due = self.db.query(
            "SELECT * FROM schedules WHERE enabled=1 AND next_run_at IS NOT NULL "
            "AND next_run_at <= ?",
            (now,),
        )
        fired = 0
        for s in due:
            s = self._row(s)
            nxt = compute_next(s["cadence"], s.get("at_time"), s.get("weekday"))
            last = s.get("last_job_id")
            running = last in self.jobs.index and self.jobs.index[last].state in ("queued", "running")
            if running:  # skip-if-running; just reschedule
                self.db.execute("UPDATE schedules SET next_run_at=? WHERE id=?", (nxt, s["id"]))
                continue
            target = s["target"] or {}
            roots = target.get("roots") or self.assets.resolve_roots(
                group=target.get("group"), assets=target.get("assets"),
                all_assets=target.get("all_assets", False),
            )
            if not roots:
                self.db.execute(
                    "UPDATE schedules SET next_run_at=?, last_run_at=? WHERE id=?",
                    (nxt, now, s["id"]),
                )
                continue
            try:
                req = ScanRequest(
                    roots=roots, only=s.get("only"), skip=s.get("skip"),
                    throttle=s.get("throttle"), compress=s.get("compress", True),
                )
                if target.get("group"):  # tag for the recon→assets sync (no re-validate)
                    req = req.model_copy(update={"group": target["group"]})
                rec, _ = self.jobs.submit(req, source="schedule", schedule_id=s["id"])
                self.db.execute(
                    "UPDATE schedules SET last_run_at=?, last_job_id=?, next_run_at=? WHERE id=?",
                    (now, rec.id, nxt, s["id"]),
                )
                fired += 1
            except Exception as e:  # noqa: BLE001 — never let one schedule break the tick
                log.warning("schedule %s failed to enqueue: %r", s["id"], e)
                self.db.execute("UPDATE schedules SET next_run_at=? WHERE id=?", (nxt, s["id"]))
        return fired

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.tick)
            except Exception as e:  # noqa: BLE001
                log.warning("scheduler tick error: %r", e)
            await asyncio.sleep(_TICK_SECONDS)
