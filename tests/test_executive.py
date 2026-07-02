"""Executive-report deterministic core: top-risk selection, posture rating, and
the context builder's AI-overlay merge + deterministic fallback."""
from __future__ import annotations

import random

from appsecwatch.models import ExecutiveSummary, ExecRiskNote, Finding
from appsecwatch.report.aggregator import (
    build_executive_context,
    posture_rating,
    select_top_risks,
)


def _f(source: str, severity: str, title: str, host: str) -> Finding:
    return Finding(source=source, host=host, severity=severity, title=title)


def _sample() -> list[Finding]:
    return [
        _f("headers", "medium", "Missing HSTS", "a.example.com"),
        _f("headers", "medium", "Missing HSTS", "b.example.com"),
        _f("headers", "medium", "Missing HSTS", "c.example.com"),
        _f("nuclei", "high", "Exposed admin panel", "a.example.com"),
        _f("nuclei", "high", "Exposed admin panel", "d.example.com"),
        _f("csp", "low", "Weak CSP", "a.example.com"),
        _f("js_lib", "high", "jQuery < 3.5", "e.example.com"),
    ]


# ---- select_top_risks ------------------------------------------------------

def test_top_risks_grouping_and_ranking():
    risks = select_top_risks(_sample())
    # 4 distinct (source,title) groups
    assert len(risks) == 4
    # refs are a dense 0..n-1 sequence in display order
    assert [r.ref for r in risks] == [0, 1, 2, 3]
    # high before medium before low; within high, more hosts first
    assert risks[0].key == "nuclei|Exposed admin panel"  # high, 2 hosts
    assert risks[1].key == "js_lib|jQuery < 3.5"          # high, 1 host
    assert risks[2].key == "headers|Missing HSTS"         # medium, 3 hosts
    assert risks[3].severity == "low"
    # host aggregation is distinct + counted
    hsts = next(r for r in risks if r.source == "headers")
    assert hsts.host_count == 3
    assert hsts.hosts == ("a.example.com", "b.example.com", "c.example.com")


def test_top_risks_group_ai_findings_by_check_id_not_title():
    # Same AI check_id, different free-text titles + hosts → ONE group (the dedup
    # fix). Without stable check_ids these would be 2 separate risks.
    findings = [
        Finding(source="ai_headers", host="a.example.com", severity="medium",
                title="TS cookie on a.example.com lacks HttpOnly",
                check_id="ai_headers.cookie-missing-httponly-flag"),
        Finding(source="ai_headers", host="b.example.com", severity="high",
                title="Session cookie on b lacks HttpOnly",
                check_id="ai_headers.cookie-missing-httponly-flag"),
    ]
    risks = select_top_risks(findings)
    assert len(risks) == 1
    assert risks[0].key == "ai_headers|ai_headers.cookie-missing-httponly-flag"
    assert risks[0].host_count == 2
    assert risks[0].severity == "high"          # worst severity wins in the group


def test_top_risks_is_order_independent():
    base = select_top_risks(_sample())
    for seed in range(8):
        shuffled = _sample()
        random.Random(seed).shuffle(shuffled)
        out = select_top_risks(shuffled)
        assert [(r.ref, r.key, r.severity) for r in out] == \
               [(r.ref, r.key, r.severity) for r in base]


def test_top_risks_limit():
    findings = [_f("nuclei", "high", f"Bug {i}", f"h{i}.example.com") for i in range(12)]
    assert len(select_top_risks(findings, limit=5)) == 5
    assert len(select_top_risks(findings, limit=3)) == 3


# ---- posture_rating --------------------------------------------------------

def test_posture_ladder():
    assert posture_rating({"critical": 2, "high": 5})[0] == "CRITICAL"
    assert posture_rating({"high": 5, "medium": 9})[0] == "HIGH"
    assert posture_rating({"medium": 9, "low": 3})[0] == "MODERATE"
    assert posture_rating({"low": 3, "info": 7})[0] == "LOW"
    rating, note = posture_rating({})
    assert rating == "LOW" and note == "no findings"


def test_posture_volume_note_counts_dominant_bucket():
    rating, note = posture_rating({"high": 24, "medium": 66})
    assert rating == "HIGH"
    assert note == "24 high-severity findings"
    # singular
    assert posture_rating({"high": 1})[1] == "1 high-severity finding"


# ---- build_executive_context ----------------------------------------------

_RUN = {"roots": ["example.com"], "finished_at": "2026-06-30T00:00:00Z"}
_RECON = {"live": [1, 2, 3], "dead": [1, 2], "wildcards": [], "live_servers": [1]}


def _ctx(exec_summary=None):
    visible = _sample()
    totals = {"critical": 0, "high": 3, "medium": 3, "low": 1, "info": 0}
    return build_executive_context(
        run_meta=_RUN, histogram_totals=totals, visible=visible,
        recon=_RECON, coverage_strip=[], report_cfg=None, exec_summary=exec_summary,
    )


def test_exec_context_deterministic_fallback_when_no_ai():
    ctx = _ctx(exec_summary=None)
    assert ctx["ai_used"] is False
    assert ctx["rating"] == "HIGH"
    assert "host" in ctx["volume_note"]  # enriched with host count
    # scale exposes DNS-live vs HTTP-responding distinctly
    assert ctx["scale"] == {"live": 3, "dead": 2, "live_servers": 1}
    # every top risk has a non-empty deterministic "why"
    assert ctx["risks"] and all(r.why for r in ctx["risks"])
    # deterministic recommendations derived from the risks' sources
    assert ctx["recommendations"]
    # org falls back to the root, classification defaults
    assert ctx["org_name"] == "example.com"
    assert ctx["classification"] == "Confidential"


def test_exec_context_degraded_ai_falls_back():
    ctx = _ctx(exec_summary=ExecutiveSummary(error="LLM HTTP 402"))
    assert ctx["ai_used"] is False
    assert all(r.why for r in ctx["risks"])  # deterministic fallback prose


def test_exec_context_merges_ai_notes_by_key():
    risks = select_top_risks(_sample())
    target = risks[0]  # nuclei|Exposed admin panel
    summary = ExecutiveSummary(
        posture_narrative="Overall the estate is exposed.",
        risk_notes=[ExecRiskNote(ref=target.ref, why="Anyone can reach the admin panel.",
                                 key=target.key)],
        recommendations=["Restrict admin access by network policy."],
    )
    ctx = _ctx(exec_summary=summary)
    assert ctx["ai_used"] is True
    assert ctx["narrative"] == "Overall the estate is exposed."
    assert ctx["recommendations"] == ["Restrict admin access by network policy."]
    merged = next(r for r in ctx["risks"] if r.key == target.key)
    assert merged.why == "Anyone can reach the admin panel."
    # a risk with no AI note keeps its deterministic fallback
    other = next(r for r in ctx["risks"] if r.key != target.key)
    assert other.why and other.why != "Anyone can reach the admin panel."


def test_exec_context_stale_ai_note_key_is_dropped():
    # An AI note whose key no longer matches any displayed risk must be ignored
    # (the timing-safe merge guarantee).
    summary = ExecutiveSummary(
        risk_notes=[ExecRiskNote(ref=0, why="stale", key="nuclei|Gone after suppression")],
    )
    ctx = _ctx(exec_summary=summary)
    assert all(r.why != "stale" for r in ctx["risks"])
