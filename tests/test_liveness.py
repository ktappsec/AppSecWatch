"""Assessability classifier + coverage-suppression + degraded-run detection.

Covers the fix for the two output-correctness defects observed in real scans:
error/WAF-block responses being audited as real apps (fake criticals + noise), and
a fully-blocked httpx run (0 live servers) reading as a clean, finding-free scan.
"""
from __future__ import annotations

import pytest

from appsecwatch.audit.liveness import (
    apply_coverage_suppressions,
    classify_assessability,
    not_assessed_hosts,
)
from appsecwatch.models import Finding, LiveWebServer, PageSignals
from appsecwatch.stages.suppress_stage import LivenessGateStage
from appsecwatch.stages.state import ScanState


def _sig(**kw) -> PageSignals:
    kw.setdefault("host", "h.example.com")
    return PageSignals(**kw)


# --------------------------------------------------------------------------- #
# classify_assessability truth table
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "signals,expected_assessed,reason_contains",
    [
        # A real 200 app with content → assessed.
        (_sig(status_code=200, body_snippet="Welcome to internet banking. Log in to continue."),
         True, None),
        # A login form even at an odd status → assessed.
        (_sig(status_code=403, has_password_input=True, body_snippet=""), True, None),
        (_sig(status_code=200, form_count=2, body_snippet="x" * 5), True, None),
        # 5xx gateway timeouts (the fake-critical hosts) → not assessed.
        (_sig(status_code=504), False, "server error"),
        (_sig(status_code=503, body_snippet="unavailable"), False, "server error"),
        # No response at all → not assessed.
        (_sig(status_code=None), False, "no HTTP response"),
        # WAF block page answering 200 (the 'Request Rejected' case) → not assessed.
        (_sig(status_code=200, title="Request Rejected"), False, "WAF/block"),
        (_sig(status_code=200, title="Aradığınız sayfaya ulaşılamıyor"), False, "WAF/block"),
        (_sig(status_code=200, body_snippet="Sorry, you have been blocked"), False, "WAF/block"),
        # 403/401/429 with an empty/tiny body → blocked stub, not assessed.
        (_sig(status_code=403, body_snippet=""), False, "blocked/forbidden"),
        (_sig(status_code=401, body_snippet="  "), False, "blocked/forbidden"),
        # 403 that serves a real body (no form) → still assessed (conservative).
        (_sig(status_code=403, body_snippet="y" * 200), True, None),
        # 3xx/2xx with plain content → assessed.
        (_sig(status_code=301, body_snippet="Moved to https://example.com/new-home-page"),
         True, None),
    ],
)
def test_classify_truth_table(signals, expected_assessed, reason_contains):
    assessed, reason = classify_assessability(signals)
    assert assessed is expected_assessed
    if reason_contains is None:
        assert reason is None
    else:
        assert reason and reason_contains in reason


# --------------------------------------------------------------------------- #
# coverage suppression
# --------------------------------------------------------------------------- #
def test_apply_coverage_suppressions_hides_not_assessed_only():
    servers = [
        LiveWebServer(url="https://ok.example.com", host="ok.example.com", assessed=True),
        LiveWebServer(url="http://dead.example.com", host="dead.example.com",
                      assessed=False, not_assessed_reason="server error (504)"),
    ]
    findings = [
        Finding(source="headers", host="ok.example.com", severity="medium",
                title="missing csp", check_id="csp.missing"),
        Finding(source="ai_headers", host="dead.example.com", severity="high",
                title="Bank login served over plain HTTP", check_id="ai_headers.x"),
        Finding(source="headers", host="dead.example.com", severity="low",
                title="referrer", check_id="referrer-policy.missing"),
    ]
    n = apply_coverage_suppressions(findings, servers)
    assert n == 2
    # The assessed host's finding stays visible.
    assert findings[0].ai_verdict is None
    # Both findings on the not-assessed host are suppressed with a coverage verdict.
    for f in findings[1:]:
        assert f.suppressed
        assert f.ai_verdict.source == "coverage"
        assert "not assessed" in f.ai_verdict.reason
    assert not_assessed_hosts(servers) == {"dead.example.com": "server error (504)"}


def test_coverage_suppression_never_overwrites_existing_verdict():
    from appsecwatch.models import AIFindingVerdict
    servers = [LiveWebServer(url="http://x", host="x", assessed=False,
                             not_assessed_reason="blocked/forbidden (403)")]
    existing = AIFindingVerdict(suppressed=False, source="ai_triage", reason="advisory")
    f = Finding(source="headers", host="x", severity="low", title="t",
                check_id="c", ai_verdict=existing)
    n = apply_coverage_suppressions([f], servers)
    assert n == 0
    assert f.ai_verdict is existing  # untouched


# --------------------------------------------------------------------------- #
# degraded-run detection (LivenessGateStage)
# --------------------------------------------------------------------------- #
class _Log:
    def info(self, *a, **k): pass
    def warn(self, *a, **k): pass
    def debug(self, *a, **k): pass
    def error(self, *a, **k): pass


def _state_with_live_assets(n_live: int) -> ScanState:
    from appsecwatch.models import TriagedAsset
    st = ScanState()
    st.triaged = [
        TriagedAsset(fqdn=f"a{i}.example.com", status="live", reason="A record")
        for i in range(n_live)
    ]
    st.coverage = {"recon": {"sub": {"recon.httpx": {"ran": True}}}}
    return st


@pytest.mark.asyncio
async def test_degraded_flag_when_zero_servers_but_live_assets(tmp_path):
    st = _state_with_live_assets(5)          # resolved 5 live assets
    st.live_servers = []                     # httpx returned nothing
    await LivenessGateStage().run(st, tmp_path, None, None, _Log())
    assert st.degraded is True
    assert st.degraded_reason and "0 live web servers" in st.degraded_reason
    # A StageError is recorded so --strict (which reads errors.json) exits non-zero.
    assert any(e.stage == "recon.httpx" for e in st.errors)


@pytest.mark.asyncio
async def test_not_degraded_when_servers_present(tmp_path):
    st = _state_with_live_assets(5)
    st.live_servers = [LiveWebServer(url="https://a0.example.com", host="a0.example.com")]
    await LivenessGateStage().run(st, tmp_path, None, None, _Log())
    assert st.degraded is False
    assert not st.errors


@pytest.mark.asyncio
async def test_not_degraded_when_httpx_did_not_run(tmp_path):
    st = _state_with_live_assets(5)
    st.live_servers = []
    st.coverage = {"recon": {"sub": {"recon.httpx": {"ran": False}}}}
    await LivenessGateStage().run(st, tmp_path, None, None, _Log())
    assert st.degraded is False
