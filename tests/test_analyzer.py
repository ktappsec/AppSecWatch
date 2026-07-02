"""Analyzer: work-map merge + profile/analysis flow with a stubbed LLM client."""
from __future__ import annotations

from appsecwatch.ai import analyzer
from appsecwatch.ai.analyzer import _build_work_map, analyze_all, profile_all, summarize_run
from appsecwatch.config import LLMConfig
from appsecwatch.models import AppProfile, CrawlerArtifact, LiveWebServer, PageSignals


class _Log:
    def info(self, *a, **k): pass
    def warn(self, *a, **k): pass
    def debug(self, *a, **k): pass
    def error(self, *a, **k): pass


def _llm() -> LLMConfig:
    return LLMConfig(base_url="http://localhost/v1", model="m")


def _make_fake_client(response: str, sink: list | None = None):
    class _Fake:
        def __init__(self, cfg):
            self.cfg = cfg

        async def chat(self, system, user, *, temperature=0.0, label=None):
            if sink is not None:
                sink.append((system, user))
            return response

        async def close(self):
            pass

    return _Fake


# ---- work-map merge ------------------------------------------------------

def test_work_map_prefers_httpx_headers_over_crawler():
    live = [LiveWebServer(url="https://h", host="h")]
    sig = {"h": PageSignals(host="h", headers={"server": "from-httpx"})}
    arts = [CrawlerArtifact(host="h", url="https://h", headers={"server": "from-crawler"}, scripts=[])]
    work = _build_work_map(live, sig, arts)
    assert work["h"]["headers"]["server"] == "from-httpx"
    assert work["h"]["scripts"] == []          # crawler ran (empty list, not None)


def test_work_map_header_only_when_no_crawler():
    live = [LiveWebServer(url="https://h", host="h")]
    sig = {"h": PageSignals(host="h", headers={"x": "y"})}
    work = _build_work_map(live, sig, [])
    assert work["h"]["headers"] == {"x": "y"}
    assert work["h"]["scripts"] is None        # no crawler → supply analysis skipped


# ---- profile_all ---------------------------------------------------------

async def test_profile_all_happy(tmp_path, monkeypatch):
    resp = ('{"app_type":"REST API","audience":"public","confidence":"high",'
            '"reasoning":"json endpoints","is_api":true,"expected_controls":["HSTS"]}')
    monkeypatch.setattr(analyzer, "LLMClient", _make_fake_client(resp))
    sigs = {"api.x.com": PageSignals(host="api.x.com", title="API")}
    profiles = await profile_all(sigs, tmp_path, _llm(), _Log(), concurrency=2)
    p = profiles["api.x.com"]
    assert p.usable is True
    assert p.is_api is True
    assert p.host == "api.x.com"               # host stamped post-validation
    assert (tmp_path / "api.x.com.json").is_file()


async def test_profile_all_degrades_on_garbage(tmp_path, monkeypatch):
    monkeypatch.setattr(analyzer, "LLMClient", _make_fake_client("not json at all"))
    sigs = {"x": PageSignals(host="x")}
    profiles = await profile_all(sigs, tmp_path, _llm(), _Log(), concurrency=1)
    assert profiles["x"].usable is False        # error set → downstream uses defaults
    assert profiles["x"].error
    assert (tmp_path / "x.json").is_file()


# ---- summarize_run (ai.summary) ------------------------------------------

def _make_label_capturing_client(response: str, labels: list):
    class _Fake:
        def __init__(self, cfg):
            self.cfg = cfg

        async def chat(self, system, user, *, temperature=0.0, label=None):
            labels.append(label)
            return response

        async def close(self):
            pass

    return _Fake


async def test_summarize_run_happy(monkeypatch):
    resp = ('{"posture_narrative":"The estate is exposed.",'
            '"risk_notes":[{"ref":0,"why":"Admin panel reachable."}],'
            '"recommendations":["Restrict admin access."]}')
    labels: list = []
    monkeypatch.setattr(analyzer, "LLMClient", _make_label_capturing_client(resp, labels))
    out = await summarize_run(
        posture={"rating": "HIGH", "volume_note": "3 high-severity findings"},
        counts={"critical": 0, "high": 3, "medium": 0, "low": 0, "info": 0},
        scale={"live": 5, "live_servers": 3, "dead": 1},
        risks=[{"ref": 0, "title": "Admin panel", "source": "nuclei",
                "severity": "high", "host_count": 2}],
        cfg=_llm(), log=_Log(),
    )
    assert out.usable is True
    assert out.posture_narrative == "The estate is exposed."
    assert out.risk_notes[0].ref == 0 and out.risk_notes[0].why == "Admin panel reachable."
    assert out.recommendations == ["Restrict admin access."]
    # call is labeled "summary" so the per-call models map can route it
    assert labels == ["summary"]


async def test_summarize_run_degrades_on_garbage(monkeypatch):
    monkeypatch.setattr(analyzer, "LLMClient", _make_fake_client("not json"))
    out = await summarize_run(
        posture={"rating": "LOW", "volume_note": "no findings"},
        counts={}, scale={}, risks=[], cfg=_llm(), log=_Log(),
    )
    assert out.usable is False and out.error          # degrade → renderer falls back
    assert out.risk_notes == []


# ---- analyze_all ---------------------------------------------------------

async def test_analyze_headers_without_crawler(tmp_path, monkeypatch):
    resp = '{"findings":[{"type":"missing-hsts","severity":"low","title":"no HSTS"}]}'
    monkeypatch.setattr(analyzer, "LLMClient", _make_fake_client(resp))
    live = [LiveWebServer(url="https://h", host="h")]
    sigs = {"h": PageSignals(host="h", headers={"server": "nginx"})}
    hdr_dir, sup_dir = tmp_path / "headers", tmp_path / "supply"
    h, s, errs = await analyze_all(
        live_servers=live, page_signals=sigs, artifacts=[], profiles={},
        cfg=_llm(), triage_dir=hdr_dir, supply_dir=sup_dir, log=_Log(), concurrency=2,
    )
    assert len(h) == 1 and h[0].source == "ai_headers"
    assert s == []                              # no crawler → no supply findings
    assert errs == []                           # clean call → no degraded entries
    assert (hdr_dir / "h.json").is_file()
    assert not any(sup_dir.glob("*.json"))


async def test_analyze_supply_with_crawler(tmp_path, monkeypatch):
    resp = '{"findings":[{"type":"untrusted-cdn","severity":"medium","title":"3p cdn"}]}'
    monkeypatch.setattr(analyzer, "LLMClient", _make_fake_client(resp))
    arts = [CrawlerArtifact(host="h", url="https://h",
                            scripts=[{"url": "https://cdn.evil.com/a.js"}])]
    h, s, errs = await analyze_all(
        live_servers=[], page_signals={}, artifacts=arts, profiles={},
        cfg=_llm(), triage_dir=tmp_path / "h", supply_dir=tmp_path / "s",
        log=_Log(), concurrency=2,
    )
    assert any(f.source == "ai_supply_chain" for f in s)


async def test_analyze_headers_degrades_on_garbage(tmp_path, monkeypatch):
    # Unparseable reply (after the one retry) => no findings, but an error-marked
    # AIResponse artifact is still written for the host.
    import json as _json

    monkeypatch.setattr(analyzer, "LLMClient", _make_fake_client("not json at all"))
    live = [LiveWebServer(url="https://h", host="h")]
    sigs = {"h": PageSignals(host="h", headers={"server": "nginx"})}
    hdr_dir = tmp_path / "headers"
    h, s, errs = await analyze_all(
        live_servers=live, page_signals=sigs, artifacts=[], profiles={},
        cfg=_llm(), triage_dir=hdr_dir, supply_dir=tmp_path / "s",
        log=_Log(), concurrency=1,
    )
    assert h == [] and s == []
    assert errs and errs[0][0] == "h"       # degraded call surfaced (host, message)
    written = _json.loads((hdr_dir / "h.json").read_text())
    assert written["error"]                 # error field populated
    assert written["findings"] == []


async def test_analyze_uses_profiled_prompt(tmp_path, monkeypatch):
    sink: list = []
    resp = '{"findings":[]}'
    monkeypatch.setattr(analyzer, "LLMClient", _make_fake_client(resp, sink))
    profile = AppProfile(host="h", app_type="login portal", audience="public",
                         confidence="high", handles_auth=True, expected_controls=["HSTS"])
    live = [LiveWebServer(url="https://h", host="h")]
    sigs = {"h": PageSignals(host="h", headers={"server": "nginx"})}
    await analyze_all(
        live_servers=live, page_signals=sigs, artifacts=[], profiles={"h": profile},
        cfg=_llm(), triage_dir=tmp_path / "h", supply_dir=tmp_path / "s",
        log=_Log(), concurrency=1,
    )
    # The header call's system prompt should be the profiled (uses the app profile) variant.
    assert any("application profile" in system for system, _ in sink)


# ---- AI cross-source soft-suppression (the ai.triage pass) ----------------

def _det_finding(check_id="hsts.missing", host="h", severity="medium", source="headers"):
    from appsecwatch.models import Finding
    return Finding(source=source, host=host, severity=severity,
                   title="Missing HSTS", check_id=check_id,
                   evidence={"check_id": check_id, "header": "strict-transport-security"})


def _hi_profile(host="h"):
    return AppProfile(host=host, app_type="api", audience="public", confidence="high")


async def _run_with_suppression(tmp_path, monkeypatch, *, resp, profile, det,
                                suppress=True, min_conf="medium",
                                max_sev="medium", require_profile=False):
    monkeypatch.setattr(analyzer, "LLMClient", _make_fake_client(resp))
    live = [LiveWebServer(url="https://h", host="h")]
    sigs = {"h": PageSignals(host="h", headers={"server": "nginx"})}
    await analyze_all(
        live_servers=live, page_signals=sigs, artifacts=[],
        profiles={"h": profile} if profile else {},
        cfg=_llm(), triage_dir=tmp_path / "h", supply_dir=tmp_path / "s",
        log=_Log(), concurrency=1,
        findings_by_host={"h": det}, suppress=suppress,
        suppress_min_confidence=min_conf, suppress_max_severity=max_sev,
        require_profile=require_profile,
    )
    return det


async def test_suppression_hides_without_profile_by_default(tmp_path, monkeypatch):
    # New default: require_profile=False, so suppression works even with no profile.
    det = [_det_finding()]
    resp = ('{"findings":[],"suppressions":[{"ref":0,'
            '"confidence":"high","reason":"internal-only host"}]}')
    await _run_with_suppression(tmp_path, monkeypatch, resp=resp, profile=None, det=det)
    assert det[0].suppressed is True
    assert det[0].ai_verdict.reason == "internal-only host"
    assert det[0].ai_verdict.source == "ai_triage"


async def test_below_min_confidence_stays_visible_as_advisory(tmp_path, monkeypatch):
    det = [_det_finding()]
    resp = ('{"findings":[],"suppressions":[{"ref":0,'
            '"confidence":"low","reason":"maybe"}]}')
    await _run_with_suppression(tmp_path, monkeypatch, resp=resp,
                                profile=_hi_profile(), det=det, min_conf="medium")
    assert det[0].suppressed is False          # low < medium gate
    assert det[0].ai_verdict is not None       # advisory verdict still attached


async def test_require_profile_blocks_without_profile(tmp_path, monkeypatch):
    det = [_det_finding()]
    resp = ('{"findings":[],"suppressions":[{"ref":0,'
            '"confidence":"high","reason":"x"}]}')
    await _run_with_suppression(tmp_path, monkeypatch, resp=resp, profile=None,
                                det=det, require_profile=True)
    assert det[0].suppressed is False          # require_profile → no profile, no hide


async def test_require_profile_low_confidence_profile_blocks(tmp_path, monkeypatch):
    det = [_det_finding()]
    resp = ('{"findings":[],"suppressions":[{"ref":0,'
            '"confidence":"high","reason":"x"}]}')
    low = AppProfile(host="h", app_type="api", audience="public", confidence="low")
    await _run_with_suppression(tmp_path, monkeypatch, resp=resp, profile=low,
                                det=det, require_profile=True)
    assert det[0].suppressed is False


async def test_above_ceiling_never_offered(tmp_path, monkeypatch):
    # A high finding with a medium ceiling is not in the payload → ref 0 unmapped.
    det = [_det_finding(severity="high", source="nuclei")]
    resp = ('{"findings":[],"suppressions":[{"ref":0,'
            '"confidence":"high","reason":"x"}]}')
    await _run_with_suppression(tmp_path, monkeypatch, resp=resp,
                                profile=_hi_profile(), det=det, max_sev="medium")
    assert det[0].suppressed is False
    assert det[0].ai_verdict is None           # never offered, no verdict


async def test_cross_source_suppression_of_nuclei(tmp_path, monkeypatch):
    det = [_det_finding(severity="low", source="nuclei", check_id=None)]
    resp = ('{"findings":[],"suppressions":[{"ref":0,'
            '"confidence":"high","reason":"expected tech banner"}]}')
    await _run_with_suppression(tmp_path, monkeypatch, resp=resp,
                                profile=_hi_profile(), det=det)
    assert det[0].suppressed is True           # nuclei finding hidden by triage


async def test_suppress_disabled_keeps_everything(tmp_path, monkeypatch):
    det = [_det_finding()]
    resp = ('{"findings":[],"suppressions":[{"ref":0,'
            '"confidence":"high","reason":"x"}]}')
    await _run_with_suppression(tmp_path, monkeypatch, resp=resp,
                                profile=_hi_profile(), det=det, suppress=False)
    assert det[0].suppressed is False


async def test_degraded_ai_suppresses_nothing(tmp_path, monkeypatch):
    det = [_det_finding()]
    # unparseable after retry → AIResponse.error set → suppressions never applied
    await _run_with_suppression(tmp_path, monkeypatch, resp="not json",
                                profile=_hi_profile(), det=det)
    assert det[0].suppressed is False
    assert det[0].ai_verdict is None           # invariant: degrade leaves finding intact


# --------------------------------------------------------------------------- #
# AI finding shaping: stable check_id + non-vuln / infra-cookie drop
# --------------------------------------------------------------------------- #
def _ai_resp(*findings):
    from appsecwatch.ai.schemas import AIFinding, AIResponse
    return AIResponse(findings=[AIFinding(**f) for f in findings])


def test_ai_finding_gets_stable_check_id():
    resp = _ai_resp({"type": "cookie-missing-httponly-flag", "severity": "medium",
                     "title": "Session cookie missing HttpOnly", "evidence": {"cookie": "JSESSIONID"}})
    out = analyzer._ai_findings_to_findings("h", "ai_headers", resp)
    assert len(out) == 1
    # The grouping id is derived from the TITLE (cross-host-stable), not the type.
    assert out[0].check_id == "ai_headers.session-cookie-missing-httponly"
    assert out[0].group_key == "ai_headers.session-cookie-missing-httponly"


def test_ai_finding_same_title_collapses_despite_differing_type():
    """Regression: the per-host LLM calls keep the human title identical but can
    emit a different `type` slug. Grouping on the title (not the type) keeps the
    two visibly-identical findings on one key so they collapse to one report row."""
    title = "Third-party script loaded without Subresource Integrity (SRI)"
    a = analyzer._ai_findings_to_findings(
        "apex.com", "ai_supply_chain", _ai_resp({"type": "missing-sri", "severity": "medium", "title": title}))
    b = analyzer._ai_findings_to_findings(
        "www.apex.com", "ai_supply_chain", _ai_resp({"type": "sri-not-applied", "severity": "medium", "title": title}))
    assert a[0].group_key == b[0].group_key      # same title → same key → one row


def test_ai_check_id_slugifies_punctuation_and_case():
    assert analyzer._ai_check_id("ai_headers", "Session cookies lack SameSite attribute") == \
        "ai_headers.session-cookies-lack-samesite-attribute"
    assert analyzer._ai_check_id("ai_headers", "  ") is None       # blank → None
    # Very long titles are length-capped (still deterministic + collapsing).
    long_id = analyzer._ai_check_id("ai_supply_chain", "x " * 80)
    assert long_id is not None and len(long_id.split(".", 1)[1]) <= 80


def test_ai_nonfinding_types_dropped():
    resp = _ai_resp(
        {"type": "positive-observation", "severity": "info", "title": "No scripts = good"},
        {"type": "no-scripts-loaded", "severity": "info", "title": "No scripts detected"},
        {"type": "best-practice-reminder", "severity": "medium", "title": "Verify HSTS"},
        {"type": "sri-missing", "severity": "low", "title": "Real finding"},
    )
    out = analyzer._ai_findings_to_findings("h", "ai_supply_chain", resp)
    assert [f.title for f in out] == ["Real finding"]


def test_ai_infra_cookie_findings_dropped():
    resp = _ai_resp(
        {"type": "cookie-missing-httponly-flag", "severity": "medium",
         "title": "F5 TS cookie missing HttpOnly", "evidence": {"cookie_name": "TS01a5e83e"}},
        {"type": "server-technology-leak", "severity": "low",
         "title": "F5 fingerprint", "evidence": {"cookie": "f5avraaaa_session_=x; HttpOnly"}},
        {"type": "cookie-missing-httponly-flag", "severity": "high",
         "title": "Real session cookie missing HttpOnly", "evidence": {"cookie": "JSESSIONID=abc"}},
    )
    out = analyzer._ai_findings_to_findings("h", "ai_headers", resp)
    assert [f.title for f in out] == ["Real session cookie missing HttpOnly"]
