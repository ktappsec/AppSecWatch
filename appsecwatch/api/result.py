"""Build the machine-readable ScanResult, and render a partial report on cancel.

The run dir is the durable record (no DB). When a scan reaches a terminal state
the JobManager — which holds the live ScanState — serializes a `result.json`
into the run dir, so `/result` can be served straight from disk and survives a
process restart (the in-memory state does not).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from appsecwatch.audit.taxonomy import classify_findings
from appsecwatch.report.aggregator import posture_rating, risk_score, severity_histogram
from appsecwatch.stages.state import ScanState

RESULT_FILENAME = "result.json"


def count_findings(state: ScanState) -> int:
    """Visible findings across all sources — the live `finding_count` for polling
    (soft-suppressed findings are excluded, matching the severity histogram)."""
    return sum(1 for f in _all_findings(state) if not f.suppressed)


def _all_findings(state: ScanState) -> list:
    return state.all_findings()


def build_scan_result(
    job_id: str, state: ScanState, *, report_url: str, job_state: str,
    executive_url: str | None = None, executive_pdf_url: str | None = None,
) -> dict[str, Any]:
    """Project the final ScanState into the ScanResult JSON shape (a plain dict so
    it round-trips through job.json/result.json without import cycles).

    executive_pdf_url is None when the PDF wasn't rendered (toggle off / best-effort
    render skipped); the executive HTML is always produced alongside report.html."""
    findings = _all_findings(state)
    # Stamp the controlled-taxonomy category/class on every finding so result.json
    # carries them (matches the report context; idempotent with the report pass).
    classify_findings(findings)
    # Suppressed findings stay in the payload (UI shows them collapsed) but are
    # excluded from the severity histogram, matching the HTML report.
    histogram = severity_histogram([f for f in findings if not f.suppressed])
    totals = {sev: sum(by.values()) for sev, by in histogram.items()}
    return {
        "id": job_id,
        "state": job_state,
        "coverage": state.coverage,
        "histogram": histogram,
        "histogram_totals": totals,
        "risk_score": risk_score(totals),
        "posture": posture_rating(totals)[0],
        "findings": [f.model_dump() for f in findings],
        "tls": [t.model_dump() for t in state.tls_reports],
        "tls_certs": [c.model_dump() for c in state.tls_certs],
        "app_profiles": {h: p.model_dump() for h, p in state.app_profiles.items()},
        "assets": [a.model_dump() for a in state.triaged],
        "live_servers": [s.model_dump() for s in state.live_servers],
        "wildcards": list(state.wildcards),
        "summary": state.summary.model_dump() if state.summary else None,
        "report_url": report_url,
        "executive_url": executive_url,
        "executive_pdf_url": executive_pdf_url,
    }


def write_scan_result(run_dir: Path, result: dict[str, Any]) -> None:
    (run_dir / RESULT_FILENAME).write_text(json.dumps(result, indent=2))


def load_scan_result(run_dir: Path) -> dict[str, Any] | None:
    """Read a persisted result.json, or None if absent/unreadable."""
    p = run_dir / RESULT_FILENAME
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


class _PartialReportLog:
    """Minimal stand-in for RunLogger that ReportStage needs only for counts().

    The run's real logger is already closed by the time a cancel renders a
    partial report, so we feed empty counters — the partial summary reports the
    findings that survived, not log-level rollups."""

    verbose = False

    def counts(self) -> dict[str, dict[str, int]]:
        return {"levels": {}, "events": {}}


async def render_partial_report(
    state: ScanState,
    run_dir: Path,
    *,
    run_meta: dict,
    versions: dict,
    cfg,
) -> None:
    """Render report.html (+ summary.json/errors.json) from a partial ScanState.

    Reuses the engine's ReportStage so a cancelled scan still produces the same
    artifact shape, capturing whatever ran before the kill. Best-effort: a render
    failure must not stop the cancel from completing."""
    from appsecwatch.stages.report_stage import ReportStage

    stage = ReportStage(run_meta, versions)
    await stage.run(state, run_dir, cfg, None, _PartialReportLog())
