"""Backfill: reconstruct finding_state + scans severity index from runs/ artifacts.

Guards the regression where scans that completed BEFORE finding_state sync existed
never landed in the DB, so Analytics showed only the most recent audit.
"""
from __future__ import annotations

import json
from pathlib import Path

from appsecwatch.api.backfill import reconcile_finding_state
from appsecwatch.api.db import Database


def _write_run(runs: Path, scan_id: str, *, findings: list[dict],
               hosts: list[str], group: str | None,
               histogram_totals: dict | None = None) -> None:
    d = runs / scan_id
    d.mkdir(parents=True)
    result = {
        "id": scan_id,
        "state": "completed",
        "coverage": {"headers": {"ran": True}, "tls": {"ran": True}},
        "findings": findings,
        "live_servers": [{"host": h} for h in hosts],
        "assets": [{"fqdn": h} for h in hosts],
        "histogram_totals": histogram_totals or {},
    }
    (d / "result.json").write_text(json.dumps(result))
    (d / "job.json").write_text(json.dumps({"id": scan_id, "group": group,
                                            "state": "completed"}))


def _finding(host: str, title: str, sev: str, check_id: str,
             source: str = "headers") -> dict:
    # No finding_class/category — mirrors pre-taxonomy result.json, so the test
    # exercises the classify_findings() pass in the backfill.
    return {"source": source, "host": host, "severity": sev, "title": title,
            "check_id": check_id}


def test_reconcile_replays_unsynced_completed_runs(tmp_path):
    runs = tmp_path / "runs"
    db = Database(runs / "appsecwatch.db")
    # A completed run whose findings were never synced (pre-feature scan).
    _write_run(
        runs, "2026-07-02T00-00-00Z-big",
        findings=[
            _finding("a.kt.com.tr", "Weak HSTS", "medium", "headers.hsts"),
            _finding("b.kt.com.tr", "Weak HSTS", "medium", "headers.hsts"),
            _finding("c.other.com", "XCTO missing", "low", "headers.xcto"),
        ],
        hosts=["a.kt.com.tr", "b.kt.com.tr", "c.other.com"], group=None,
        histogram_totals={"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 0},
    )
    # The scans-index row exists (recorded at scan end) but with zero sev counts,
    # the exact pre-feature state the trend chart reads.
    db.execute(
        'INSERT INTO scans (id, state, finding_count, sev_medium, risk_score) '
        "VALUES ('2026-07-02T00-00-00Z-big', 'completed', 3, 0, NULL)"
    )
    # Group the two kt hosts in the inventory (drives group-resolved analytics).
    for fqdn in ("a.kt.com.tr", "b.kt.com.tr"):
        db.execute('INSERT INTO assets (fqdn, "group") VALUES (?, ?)', (fqdn, "kt"))

    stats = reconcile_finding_state(runs, db)
    assert stats == {"replayed": 1, "findings": 3}

    from appsecwatch.api.finding_state import FindingStateManager
    m = FindingStateManager(db)
    stats_all = m.analytics()
    assert stats_all["open_total"] == 3
    assert m.analytics(group="kt")["open_total"] == 2       # resolved via asset join
    assert m.analytics(group="nope")["open_total"] == 0
    # Backfilled findings are classified into real taxonomy categories, not "Other".
    assert "headers" in stats_all["by_category"]
    assert "other" not in stats_all["by_category"]

    # scans severity index repaired → trend chart has real numbers.
    row = db.query("SELECT sev_medium, sev_low, risk_score FROM scans WHERE id=?",
                   ("2026-07-02T00-00-00Z-big",))[0]
    assert row["sev_medium"] == 2 and row["sev_low"] == 1
    assert row["risk_score"] is not None


def test_reconcile_is_idempotent_and_skips_reflected(tmp_path):
    runs = tmp_path / "runs"
    db = Database(runs / "appsecwatch.db")
    _write_run(runs, "2026-07-02T00-00-00Z-s1",
               findings=[_finding("h.com", "Weak HSTS", "medium", "headers.hsts")],
               hosts=["h.com"], group=None)
    first = reconcile_finding_state(runs, db)
    assert first["replayed"] == 1
    # Second pass: the run is now reflected in finding_state → skipped, no dup rows.
    second = reconcile_finding_state(runs, db)
    assert second["replayed"] == 0
    n = db.query("SELECT COUNT(*) AS n FROM finding_state")[0]["n"]
    assert n == 1


def test_reconcile_ignores_incomplete_runs(tmp_path):
    runs = tmp_path / "runs"
    db = Database(runs / "appsecwatch.db")
    d = runs / "2026-07-02T00-00-00Z-running"
    d.mkdir(parents=True)
    (d / "result.json").write_text(json.dumps({"id": "x", "state": "running",
                                               "findings": []}))
    assert reconcile_finding_state(runs, db) == {"replayed": 0, "findings": 0}
