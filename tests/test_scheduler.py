"""Scheduler cadence math, CRUD, the tick, and the scans-history index."""
from __future__ import annotations

import types
from datetime import datetime, timezone

from watchtower.api.assets import AssetManager
from watchtower.api.db import Database
from watchtower.api.history import ScanHistory
from watchtower.api.scheduler import ScheduleManager, compute_next


def _now():
    return datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)  # a Wed


# --- compute_next -----------------------------------------------------------
def test_compute_next_daily():
    n = compute_next("daily", "02:00", None, now=_now())
    dt = datetime.fromisoformat(n)
    assert dt > _now() and dt.hour == 2 and dt.minute == 0
    # 02:00 already passed today (now=12:00) → tomorrow
    assert dt.day == 11


def test_compute_next_daily_later_today():
    n = compute_next("daily", "18:30", None, now=_now())
    dt = datetime.fromisoformat(n)
    assert dt.day == 10 and dt.hour == 18 and dt.minute == 30


def test_compute_next_weekly():
    # Wed (2) now; ask for Mon (0) 09:00 → next Monday
    n = compute_next("weekly", "09:00", 0, now=_now())
    dt = datetime.fromisoformat(n)
    assert dt.weekday() == 0 and dt.hour == 9 and dt > _now()


def test_compute_next_hourly():
    n = compute_next("hourly", "00:15", None, now=_now())  # uses minute 15
    dt = datetime.fromisoformat(n)
    assert dt.minute == 15 and dt > _now()


# --- CRUD -------------------------------------------------------------------
class _FakeJobs:
    def __init__(self):
        self.index = {}
        self.submitted = []

    def submit(self, req, *, source="manual", schedule_id=None):
        rec = types.SimpleNamespace(id=f"job-{len(self.submitted)}", state="queued")
        self.index[rec.id] = rec
        self.submitted.append((req, source, schedule_id))
        return rec, True


def _sm(tmp_path):
    db = Database(tmp_path / "t.db")
    am = AssetManager(db)
    jobs = _FakeJobs()
    return ScheduleManager(db, am, jobs), am, jobs, db


def test_schedule_crud(tmp_path):
    sm, *_ = _sm(tmp_path)
    s = sm.create({"name": "weekly bank", "target": {"group": "Bank"},
                   "cadence": "weekly", "at_time": "02:00", "weekday": 6})
    assert s["cadence"] == "weekly" and s["next_run_at"]
    assert [x["id"] for x in sm.list()] == [s["id"]]
    u = sm.update(s["id"], {"cadence": "daily", "at_time": "03:00", "enabled": False})
    assert u["cadence"] == "daily" and u["enabled"] is False
    assert sm.delete(s["id"]) is True and sm.get(s["id"]) is None


def test_create_bad_cadence_raises(tmp_path):
    sm, *_ = _sm(tmp_path)
    import pytest
    with pytest.raises(ValueError):
        sm.create({"cadence": "fortnightly"})


# --- tick -------------------------------------------------------------------
def _due(db, sid):
    db.execute("UPDATE schedules SET next_run_at=? WHERE id=?",
               ("2000-01-01T00:00:00+00:00", sid))


def test_tick_fires_due_group_schedule(tmp_path):
    sm, am, jobs, db = _sm(tmp_path)
    am.upsert_imported("root.com", "Bank")
    s = sm.create({"target": {"group": "Bank"}, "cadence": "daily"})
    _due(db, s["id"])
    assert sm.tick() == 1
    req, source, sid = jobs.submitted[0]
    assert source == "schedule" and sid == s["id"]
    assert req.roots == ["root.com"] and req.group == "Bank"
    row = sm.get(s["id"])
    assert row["last_job_id"] == "job-0" and row["next_run_at"] > _now().isoformat()


def test_tick_skips_if_running(tmp_path):
    sm, am, jobs, db = _sm(tmp_path)
    am.upsert_imported("root.com", "Bank")
    s = sm.create({"target": {"group": "Bank"}, "cadence": "daily"})
    # pretend the schedule's last job is still running
    jobs.index["prev"] = types.SimpleNamespace(id="prev", state="running")
    db.execute("UPDATE schedules SET last_job_id='prev' WHERE id=?", (s["id"],))
    _due(db, s["id"])
    assert sm.tick() == 0 and jobs.submitted == []


def test_tick_empty_target_no_submit(tmp_path):
    sm, am, jobs, db = _sm(tmp_path)
    s = sm.create({"target": {"group": "Nope"}, "cadence": "daily"})
    _due(db, s["id"])
    assert sm.tick() == 0 and jobs.submitted == []
    assert sm.get(s["id"])["next_run_at"] > _now().isoformat()  # rescheduled


# --- scans history ----------------------------------------------------------
def test_scan_history_record_and_list(tmp_path):
    db = Database(tmp_path / "t.db")
    h = ScanHistory(db)
    rec = types.SimpleNamespace(
        id="S1", state="completed", roots=["a.com"], group="Bank",
        only=None, skip=None, throttle=None, submitted_at="2026-06-10T10:00:00+00:00",
        started_at="2026-06-10T10:00:01+00:00", finished_at="2026-06-10T10:05:00+00:00",
        source="schedule", schedule_id="sch1",
    )
    h.record(rec, 7)
    rows = h.list()
    assert len(rows) == 1 and rows[0]["id"] == "S1" and rows[0]["finding_count"] == 7
    assert rows[0]["group"] == "Bank" and rows[0]["roots"] == ["a.com"]
    assert h.list(group="Other") == []
