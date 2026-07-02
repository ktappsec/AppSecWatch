"""Render smoke tests: report.html and executive.html both extend the themeable
base, preserve the technical report's JS hooks, and render the exec one-pager from
the deterministic core (no AI overlay required)."""
from __future__ import annotations

from appsecwatch.models import ExecutiveSummary, ExecRiskNote, Finding
from appsecwatch.report.aggregator import build_report_context, select_top_risks
from appsecwatch.report.renderer import render_executive, render_report

_RUN = {
    "label": "2026-06-30T00-00-00Z-example_com",
    "roots": ["example.com"],
    "started_at": "2026-06-30T00:00:00+00:00",
    "finished_at": "2026-06-30T00:10:00+00:00",
    "duration": "600.0s",
    "appsecwatch_version": "9.9.9",
}


def _findings() -> list[Finding]:
    return [
        Finding(source="nuclei", host="a.example.com", severity="high", title="Exposed admin panel"),
        Finding(source="nuclei", host="b.example.com", severity="high", title="Exposed admin panel"),
        Finding(source="headers", host="a.example.com", severity="medium", title="Missing HSTS"),
        Finding(source="csp", host="a.example.com", severity="low", title="Weak CSP"),
    ]


def _ctx(exec_summary=None):
    return build_report_context(
        run_meta=_RUN,
        triaged=[],
        wildcards=[],
        live_servers=[],
        nuclei_findings=[f for f in _findings() if f.source == "nuclei"],
        takeover_findings=[],
        tls_findings=[],
        tls_reports=[],
        ai_headers_findings=[],
        ai_supply_findings=[],
        crawler_artifacts=[],
        errors=[],
        versions={"nuclei": "3.0"},
        header_findings=[f for f in _findings() if f.source in ("headers", "csp")],
        coverage={"recon": {"ran": True, "reason": "prerequisite"},
                  "headers": {"ran": True, "reason": "selected"}},
        exec_summary=exec_summary,
    )


def test_report_html_extends_base_and_keeps_hooks(tmp_path):
    out = tmp_path / "report.html"
    render_report(_ctx(), out)
    html = out.read_text()
    # base furniture
    assert "<!doctype html>" in html
    assert "data-theme" in html and "prefers-color-scheme" in html  # theme-init
    assert "function toggleTheme()" in html
    assert "theme-toggle" in html
    # technical sections + interactive JS hooks preserved
    for anchor in ('id="summary"', 'id="recon"', 'id="vulns"', 'id="headers"',
                   "toggleSection(", 'data-table="vulns"', 'class="sortable"'):
        assert anchor in html, anchor
    assert "Exposed admin panel" in html


def _zap_ctx(*, ran: bool):
    return build_report_context(
        run_meta=_RUN, triaged=[], wildcards=[], live_servers=[],
        nuclei_findings=[], takeover_findings=[], tls_findings=[], tls_reports=[],
        ai_headers_findings=[], ai_supply_findings=[], crawler_artifacts=[],
        errors=[], versions={},
        zap_findings=[Finding(source="zap", host="app.example.com", severity="high",
                              title="SQL Injection", check_id="zap.40018",
                              evidence={"plugin_id": "40018", "risk": "High",
                                        "instance_count": 2})],
        coverage={"recon": {"ran": True, "reason": "prerequisite"},
                  "zap": {"ran": ran, "reason": "user-selected" if ran else "not run"}},
    )


def test_report_renders_zap_section_when_run(tmp_path):
    out = tmp_path / "report.html"
    render_report(_zap_ctx(ran=True), out)
    html = out.read_text()
    assert 'id="zap"' in html
    assert "Active Scan (OWASP ZAP)" in html
    assert "SQL Injection" in html
    assert 'data-table="zap"' in html


def test_report_hides_zap_section_when_not_run(tmp_path):
    out = tmp_path / "report.html"
    render_report(_zap_ctx(ran=False), out)
    assert 'id="zap"' not in out.read_text()


def test_executive_html_renders_deterministic_only(tmp_path):
    out = tmp_path / "executive.html"
    render_executive(_ctx(exec_summary=None), out)
    html = out.read_text()
    assert "data-theme" in html              # shares the themeable base
    assert "Executive Summary" in html
    assert "example.com" in html             # org falls back to root
    assert "Confidential" in html            # default classification
    assert ">HIGH<" in html or "HIGH" in html  # posture rating
    assert "Exposed admin panel" in html     # top risk surfaced
    assert "technical report" in html        # pointer to the full report
    # deterministic note shown when AI not used
    assert "deterministically" in html


def test_executive_html_uses_ai_overlay_when_present(tmp_path):
    target = select_top_risks([f for f in _findings()])[0]
    summary = ExecutiveSummary(
        posture_narrative="The estate exposes an administrative interface to the internet.",
        risk_notes=[ExecRiskNote(ref=target.ref, key=target.key,
                                 why="Anyone on the internet can reach the admin panel.")],
        recommendations=["Put the admin panel behind the VPN."],
    )
    out = tmp_path / "executive.html"
    render_executive(_ctx(exec_summary=summary), out)
    html = out.read_text()
    assert "The estate exposes an administrative interface" in html
    assert "Anyone on the internet can reach the admin panel." in html
    assert "Put the admin panel behind the VPN." in html
    assert "deterministically" not in html   # AI was used
