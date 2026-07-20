"""Deterministic triage policy (pass-2 AI calibration).

Covers the four defects a cross-scan audit of real banking scans found in the AI
triage layer, and the guard rails that now make them impossible:
  - keep/suppress FLIP on low-value header classes  → withheld from the LLM entirely
  - AI hiding HSTS on banking hosts (invented preload threshold) → expected-control guard
  - AI re-emitting the deterministic csp scanner's findings → CSP duplicate drop
  - hostname-driven severity → prompt evidence rules (asserted in test_ai_prompts)
"""
from __future__ import annotations

from appsecwatch.ai import analyzer
from appsecwatch.ai.analyzer import _suppressable_payload, analyze_all
from appsecwatch.ai.policy import (
    POLICY_CHECK_IDS,
    expected_control_for,
    looks_like_csp,
    policy_verdict,
    protected_control,
)
from appsecwatch.config import LLMConfig
from appsecwatch.models import AppProfile, Finding, LiveWebServer, PageSignals


class _Log:
    def info(self, *a, **k): pass
    def warn(self, *a, **k): pass
    def debug(self, *a, **k): pass
    def error(self, *a, **k): pass


def _llm() -> LLMConfig:
    return LLMConfig(base_url="http://localhost/v1", model="m")


def _fake_client(response: str, sink: list | None = None):
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


def _finding(check_id: str, *, source="headers", severity="medium", host="h") -> Finding:
    return Finding(source=source, host=host, severity=severity,
                   title=check_id, check_id=check_id)


def _api_profile(host="h") -> AppProfile:
    return AppProfile(host=host, app_type="REST API", audience="public",
                      confidence="high", is_api=True)


def _bank_profile(host="h") -> AppProfile:
    return AppProfile(host=host, app_type="customer login portal", audience="public",
                      confidence="high", handles_auth=True, handles_pii=True,
                      expected_controls=["HSTS", "Content-Security-Policy"])


async def _run(tmp_path, monkeypatch, *, resp, det, profile=None, sink=None,
               suppress=True, protect=True, csp_covered=False):
    monkeypatch.setattr(analyzer, "LLMClient", _fake_client(resp, sink))
    t, s, _errs = await analyze_all(
        live_servers=[LiveWebServer(url="https://h", host="h")],
        page_signals={"h": PageSignals(host="h", headers={"server": "nginx"})},
        artifacts=[], profiles={"h": profile} if profile else {},
        cfg=_llm(), triage_dir=tmp_path / "t", supply_dir=tmp_path / "s",
        log=_Log(), concurrency=1, findings_by_host={"h": det},
        suppress=suppress, protect_expected_controls=protect, csp_covered=csp_covered,
    )
    return t


# ---- 1. flip-prone classes are withheld from the LLM ----------------------

def test_policy_classes_never_reach_the_prompt():
    det = [_finding(c) for c in sorted(POLICY_CHECK_IDS)] + [_finding("hsts.weak")]
    payload, ref_map = _suppressable_payload(det, max_sev_rank=2)
    assert [p["check_id"] for p in payload] == ["hsts.weak"]
    assert [f.check_id for f in ref_map.values()] == ["hsts.weak"]


async def test_ai_cannot_suppress_a_withheld_class(tmp_path, monkeypatch):
    # The model tries to suppress ref 0. Only `hsts.weak` is in the payload, so ref 0
    # is hsts.weak — the withheld clickjacking finding is untouchable, not shifted.
    det = [_finding("clickjacking.missing"), _finding("hsts.weak", severity="low")]
    resp = ('{"findings":[],"suppressions":[{"ref":0,"confidence":"high",'
            '"reason":"not framed"}]}')
    await _run(tmp_path, monkeypatch, resp=resp, det=det)
    assert det[0].suppressed is False          # withheld → LLM has no handle on it
    assert det[0].ai_verdict is None
    assert det[1].suppressed is True           # ref 0 was hsts.weak (no profile → no guard)


# ---- 2. the deterministic verdict that replaces the LLM's ------------------

def test_clickjacking_suppressed_only_on_a_non_browser_api():
    f = _finding("clickjacking.missing")
    v = policy_verdict(f, _api_profile())
    assert v is not None and v.suppressed is True and v.source == "policy"
    assert "non-browser API" in v.reason
    # A browser-rendered app keeps it — deterministically, every run.
    assert policy_verdict(_finding("clickjacking.missing"), _bank_profile()) is None
    assert policy_verdict(_finding("clickjacking.missing"), None) is None


def test_nosniff_and_missing_csp_are_never_auto_suppressed():
    # Both are withheld from the LLM, but neither is N/A on an API: a JSON body
    # sniffed as HTML is an XSS vector, and a missing CSP is a real gap.
    for cid in ("xcto.missing", "csp.missing"):
        assert policy_verdict(_finding(cid), _api_profile()) is None


def test_low_confidence_api_profile_does_not_trigger_the_api_rule():
    weak = AppProfile(host="h", app_type="maybe api", audience="unknown",
                      confidence="low", is_api=True)
    assert policy_verdict(_finding("referrer-policy.missing"), weak) is None


async def test_policy_verdict_applied_end_to_end(tmp_path, monkeypatch):
    det = [_finding("clickjacking.missing"), _finding("xcto.missing", severity="low")]
    await _run(tmp_path, monkeypatch, resp='{"findings":[],"suppressions":[]}',
               det=det, profile=_api_profile())
    assert det[0].suppressed is True and det[0].ai_verdict.source == "policy"
    assert det[1].suppressed is False          # nosniff stays visible on an API


async def test_policy_does_not_overwrite_an_existing_verdict(tmp_path, monkeypatch):
    from appsecwatch.models import AIFindingVerdict
    det = [_finding("clickjacking.missing")]
    det[0].ai_verdict = AIFindingVerdict(suppressed=True, reason="blocked host",
                                         source="coverage")
    await _run(tmp_path, monkeypatch, resp='{"findings":[],"suppressions":[]}',
               det=det, profile=_api_profile())
    assert det[0].ai_verdict.source == "coverage"   # liveness gate owns it


async def test_policy_off_when_suppression_disabled(tmp_path, monkeypatch):
    det = [_finding("clickjacking.missing")]
    await _run(tmp_path, monkeypatch, resp='{"findings":[],"suppressions":[]}',
               det=det, profile=_api_profile(), suppress=False)
    assert det[0].suppressed is False


# ---- 3. expected controls on a sensitive app are un-hideable ---------------

def test_expected_control_mapping():
    assert expected_control_for("hsts.weak") == "HSTS"
    assert expected_control_for("csp.unsafe-inline.script-src") == "Content-Security-Policy"
    assert expected_control_for("cookie.httponly") == "HttpOnly-cookies"
    assert expected_control_for("info-disclosure.server") is None
    assert expected_control_for(None) is None


def test_protected_only_on_sensitive_hosts():
    assert protected_control(_finding("hsts.weak"), _bank_profile()) == "HSTS"
    # Implied for any sensitive app even when the profiler forgot to list it.
    lean = AppProfile(host="h", app_type="portal", audience="public",
                      confidence="high", handles_payments=True, expected_controls=[])
    assert protected_control(_finding("cookie.secure"), lean) == "Secure-cookies"
    # Non-sensitive app, or a check that isn't a named control → not protected.
    assert protected_control(_finding("hsts.weak"), _api_profile()) is None
    assert protected_control(_finding("info-disclosure.server"), _bank_profile()) is None


async def test_ai_may_not_hide_hsts_on_a_banking_host(tmp_path, monkeypatch):
    # The real regression: the model suppressed hsts.weak on ~79 banking hosts by
    # inventing a "120-day preload minimum".
    det = [_finding("hsts.weak", severity="low")]
    resp = ('{"findings":[],"suppressions":[{"ref":0,"confidence":"high",'
            '"reason":"max-age exceeds the 120-day preload minimum"}]}')
    await _run(tmp_path, monkeypatch, resp=resp, det=det, profile=_bank_profile())
    assert det[0].suppressed is False                       # stays visible + counted
    assert det[0].ai_verdict is not None                    # verdict kept, advisory
    assert "declined" in det[0].ai_verdict.reason
    assert "HSTS" in det[0].ai_verdict.reason
    assert "120-day" in det[0].ai_verdict.reason            # the AI's own reason retained


async def test_protection_can_be_turned_off(tmp_path, monkeypatch):
    det = [_finding("hsts.weak", severity="low")]
    resp = ('{"findings":[],"suppressions":[{"ref":0,"confidence":"high","reason":"x"}]}')
    await _run(tmp_path, monkeypatch, resp=resp, det=det, profile=_bank_profile(),
               protect=False)
    assert det[0].suppressed is True


async def test_non_control_findings_still_suppressible_on_a_bank(tmp_path, monkeypatch):
    det = [_finding("info-disclosure.server", severity="low")]
    resp = ('{"findings":[],"suppressions":[{"ref":0,"confidence":"high",'
            '"reason":"banner only"}]}')
    await _run(tmp_path, monkeypatch, resp=resp, det=det, profile=_bank_profile())
    assert det[0].suppressed is True    # the guard is scoped to expected controls


# ---- 4. AI CSP findings duplicate the deterministic csp scanner ------------

def test_looks_like_csp():
    assert looks_like_csp("csp-weak", "", "Weak policy") is True
    assert looks_like_csp("", "", "Content-Security-Policy allows unsafe-inline") is True
    assert looks_like_csp("cookie-flags", "headers.cookie-security", "Cookie") is False


async def test_ai_csp_findings_dropped_when_the_csp_scanner_ran(tmp_path, monkeypatch):
    resp = ('{"findings":[{"type":"csp-weak","severity":"medium",'
            '"title":"CSP allows unsafe-inline","description":"d"},'
            '{"type":"cors-misconfig","severity":"low","title":"Permissive CORS",'
            '"description":"d"}],"suppressions":[]}')
    kept = await _run(tmp_path, monkeypatch, resp=resp, det=[], csp_covered=True)
    assert [f.title for f in kept] == ["Permissive CORS"]


async def test_ai_csp_findings_kept_when_the_csp_scanner_did_not_run(tmp_path, monkeypatch):
    resp = ('{"findings":[{"type":"csp-weak","severity":"medium",'
            '"title":"CSP allows unsafe-inline","description":"d"}],"suppressions":[]}')
    kept = await _run(tmp_path, monkeypatch, resp=resp, det=[], csp_covered=False)
    assert [f.title for f in kept] == ["CSP allows unsafe-inline"]
