"""Rebuild the DB-derived analytics layer from the authoritative runs/ artifacts.

`finding_state` (the cross-scan finding lifecycle) and the `scans` severity index
are DERIVED data — every completed run is self-describing in
`runs/<id>/result.json`. This module replays those artifacts so Analytics reflects
EVERY completed scan, not just the most recent. It repairs two cases:

  * scans that completed BEFORE `finding_state` sync existed — their findings were
    never persisted, so Analytics (fed entirely by `finding_state`) showed only
    the latest audit;
  * a lost / rebuilt DB while the `runs/` volume survived (see the persistence
    note in AGENTS.md — the DB lives under `output_root`).

`reconcile_finding_state` is CHEAP on a healthy DB (one membership query + a dir
scan) and only opens `result.json` for runs not yet reflected, so it is safe to
run on every server boot. Replay is idempotent: a re-run re-stamps the same rows
through the sync upsert (`FindingStateManager.sync`).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from appsecwatch.api.db import Database
from appsecwatch.api.finding_state import FindingStateManager
from appsecwatch.audit.taxonomy import classify_findings
from appsecwatch.models import Finding
from appsecwatch.report.aggregator import risk_score as _risk_score

log = logging.getLogger("appsecwatch.api.backfill")

_SEV = ("critical", "high", "medium", "low", "info")


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _scanned_hosts(result: dict, findings: list[Finding]) -> set[str]:
    """Reconstruct the scan's host set exactly as `jobs._sync_finding_state` does:
    HTTP-live servers ∪ DNS-triaged assets ∪ any finding host. Bounds which stored
    findings the resolve engine may mark absent."""
    return (
        {s["host"] for s in (result.get("live_servers") or []) if s.get("host")}
        | {a["fqdn"] for a in (result.get("assets") or []) if a.get("fqdn")}
        | {f.host for f in findings if f.host}
    )


def _replay_run(fs: FindingStateManager, db: Database, run_dir: Path,
                result: dict) -> int:
    """Sync one completed run's `result.json` into finding_state and repair its
    `scans` severity index. Returns the number of findings synced."""
    scan_id = result.get("id") or run_dir.name
    job = _load_json(run_dir / "job.json") or {}
    group = job.get("group")
    findings = [Finding(**f) for f in (result.get("findings") or [])]
    # Stamp finding_class/category exactly as jobs._sync_finding_state does —
    # pre-taxonomy result.json rows carry neither, so without this the analytics
    # category breakdown collapses every backfilled finding into "Other".
    classify_findings(findings)
    fs.sync(findings, scanned_hosts=_scanned_hosts(result, findings),
            coverage=result.get("coverage"), group=group, scan_id=scan_id)
    # Repair the scans-index severity counts (pre-feature rows stored zeros).
    # Only updates an existing row; a wholly-missing row is left to ScanHistory.
    totals = result.get("histogram_totals") or {}
    by_sev = {s: int(totals.get(s, 0) or 0) for s in _SEV}
    db.execute(
        "UPDATE scans SET sev_critical=?, sev_high=?, sev_medium=?, sev_low=?, "
        "sev_info=?, risk_score=COALESCE(risk_score, ?) WHERE id=?",
        (by_sev["critical"], by_sev["high"], by_sev["medium"], by_sev["low"],
         by_sev["info"], _risk_score(by_sev), scan_id),
    )
    return len(findings)


def _reflected_scan_ids(db: Database) -> set[str]:
    """Scan ids already represented in finding_state (via first/last-seen). A run
    whose id appears here has been synced, so reconcile skips it without reading
    its (large) result.json."""
    ids: set[str] = set()
    for col in ("first_seen_scan", "last_seen_scan"):
        for r in db.query(
            f"SELECT DISTINCT {col} AS s FROM finding_state WHERE {col} IS NOT NULL"
        ):
            if r["s"]:
                ids.add(r["s"])
    return ids


def reconcile_finding_state(runs_root: Path | str, db: Database) -> dict[str, Any]:
    """Replay every completed run NOT yet reflected in finding_state, oldest-first
    (run-dir names are sortable UTC-timestamp prefixes). Best-effort per run — one
    unreadable/malformed run never blocks the rest (or server boot)."""
    runs_root = Path(runs_root)
    if not runs_root.is_dir():
        return {"replayed": 0, "findings": 0}
    reflected = _reflected_scan_ids(db)
    fs = FindingStateManager(db)
    replayed = findings = 0
    for run_dir in sorted(p for p in runs_root.iterdir() if p.is_dir()):
        if run_dir.name in reflected:
            continue
        result = _load_json(run_dir / "result.json")
        if not result or result.get("state") != "completed":
            continue
        try:
            findings += _replay_run(fs, db, run_dir, result)
            replayed += 1
        except Exception as e:  # noqa: BLE001 — one bad run must not block boot
            log.warning("finding-state reconcile failed for %s: %r", run_dir.name, e)
    if replayed:
        log.info("finding-state reconcile: replayed %d run(s), %d finding(s)",
                 replayed, findings)
    return {"replayed": replayed, "findings": findings}
