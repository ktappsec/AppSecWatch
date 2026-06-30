"""Deterministic security-header checks (the `headers` capability).

Pure functions over PageSignals — no network, no mocks needed.
"""
from __future__ import annotations

from watchtower.audit.header_checks import parse_csp, run_header_checks
from watchtower.config import HeadersConfig
from watchtower.models import PageSignals


def _sig(host="h", headers=None, set_cookies=None, **kw) -> PageSignals:
    return PageSignals(host=host, headers=headers or {}, set_cookies=set_cookies or [], **kw)


def _run(url, sig, *, do_csp=True, do_best_practice=True, cfg=None):
    cfg = cfg or HeadersConfig()
    return run_header_checks(url, sig, do_csp=do_csp, do_best_practice=do_best_practice, cfg=cfg)


def _by_id(findings) -> dict[str, object]:
    return {f.check_id: f for f in findings}


# --------------------------------------------------------------------------- #
# HSTS
# --------------------------------------------------------------------------- #
def test_hsts_missing_on_https():
    fs = _by_id(_run("https://h", _sig(headers={})))
    assert "hsts.missing" in fs
    assert fs["hsts.missing"].severity == "medium"
    assert fs["hsts.missing"].source == "headers"


def test_hsts_not_flagged_on_http():
    fs = _by_id(_run("http://h", _sig(headers={})))
    assert "hsts.missing" not in fs  # N/A without TLS


def test_hsts_weak_short_max_age():
    fs = _by_id(_run("https://h", _sig(headers={
        "strict-transport-security": "max-age=600"})))
    assert "hsts.missing" not in fs
    assert "hsts.weak" in fs


def test_hsts_strong_is_clean():
    fs = _by_id(_run("https://h", _sig(headers={
        "strict-transport-security": "max-age=31536000; includeSubDomains"})))
    assert "hsts.missing" not in fs and "hsts.weak" not in fs


# --------------------------------------------------------------------------- #
# nosniff / clickjacking / referrer / permissions
# --------------------------------------------------------------------------- #
def test_xcto_missing():
    fs = _by_id(_run("https://h", _sig(headers={})))
    assert "xcto.missing" in fs


def test_clickjacking_html_medium_json_info():
    html = _by_id(_run("https://h", _sig(headers={"content-type": "text/html"})))
    assert html["clickjacking.missing"].severity == "medium"
    js = _by_id(_run("https://h", _sig(headers={"content-type": "application/json"})))
    assert js["clickjacking.missing"].severity == "info"


def test_clickjacking_satisfied_by_xfo_or_csp():
    xfo = _by_id(_run("https://h", _sig(headers={
        "content-type": "text/html", "x-frame-options": "DENY"})))
    assert "clickjacking.missing" not in xfo
    csp = _by_id(_run("https://h", _sig(headers={
        "content-type": "text/html",
        "content-security-policy": "frame-ancestors 'none'"})))
    assert "clickjacking.missing" not in csp


def test_referrer_policy_missing_and_weak():
    assert "referrer-policy.missing" in _by_id(_run("https://h", _sig(headers={})))
    weak = _by_id(_run("https://h", _sig(headers={"referrer-policy": "unsafe-url"})))
    assert "referrer-policy.weak" in weak


def test_permissions_policy_missing_is_info():
    fs = _by_id(_run("https://h", _sig(headers={})))
    assert fs["permissions-policy.missing"].severity == "info"


def test_xss_protection_legacy_flagged_when_enabled():
    on = _by_id(_run("https://h", _sig(headers={"x-xss-protection": "1; mode=block"})))
    assert "xss-protection.legacy" in on
    off = _by_id(_run("https://h", _sig(headers={"x-xss-protection": "0"})))
    assert "xss-protection.legacy" not in off


# --------------------------------------------------------------------------- #
# cookies (per cookie, list preserved)
# --------------------------------------------------------------------------- #
def test_cookie_flags_per_cookie():
    fs = _by_id(_run("https://h", _sig(set_cookies=["SID=abc; Path=/"])))
    assert "cookie.secure.SID" in fs
    assert "cookie.httponly.SID" in fs
    assert "cookie.samesite.SID" in fs
    # a session-like cookie missing HttpOnly is escalated
    assert fs["cookie.httponly.SID"].severity == "medium"


def test_cookie_fully_flagged_is_clean():
    fs = _by_id(_run("https://h", _sig(set_cookies=[
        "SID=abc; Secure; HttpOnly; SameSite=Lax"])))
    assert not any(k.startswith("cookie.") for k in fs)


def test_multiple_cookies_each_checked():
    fs = _by_id(_run("https://h", _sig(set_cookies=[
        "a=1; Secure; HttpOnly; SameSite=Lax",
        "tracker=2"])))
    assert "cookie.secure.tracker" in fs
    assert "cookie.secure.a" not in fs


def test_cookie_secure_only_relevant_on_https():
    fs = _by_id(_run("http://h", _sig(set_cookies=["a=1"])))
    assert "cookie.secure.a" not in fs        # no Secure expectation over http
    assert "cookie.httponly.a" in fs          # but HttpOnly still applies


def test_infra_cookies_emit_no_findings():
    # F5 BIG-IP / WAF / RUM cookies carry no app state → no flag findings, even
    # bare (no Secure/HttpOnly/SameSite). f5avr*_session_ would otherwise match
    # the session regex and escalate.
    fs = _by_id(_run("https://h", _sig(set_cookies=[
        "TS01a5e83e=deadbeef",
        "BIGipServerpool=1.2.3.4",
        "f5avraaaaaaaaaaaaaaaa_session_=x",
        "ADRUM_BTa=y"])))
    assert not any(k and k.startswith("cookie.") for k in fs)


def test_real_session_cookie_still_flagged_alongside_infra():
    fs = _by_id(_run("https://h", _sig(set_cookies=[
        "TS0139ccaf=routing",          # infra → dropped
        "JSESSIONID=abc"])))           # real session → still flagged
    assert "cookie.httponly.JSESSIONID" in fs
    assert fs["cookie.httponly.JSESSIONID"].severity == "medium"
    assert not any(k.startswith("cookie.") and "TS0139ccaf" in k for k in fs)


def test_infra_cookie_does_not_mark_page_sensitive():
    # An f5avr*_session_ cookie alone must NOT trip the situational
    # cross-origin-isolation checks (those fire only on apparently-sensitive pages).
    fs = _by_id(_run("https://h", _sig(set_cookies=["f5avraaaaaaaaaaaaaaaa_session_=x"])))
    assert "coop.missing" not in fs


# --------------------------------------------------------------------------- #
# information disclosure
# --------------------------------------------------------------------------- #
def test_info_disclosure_server_version():
    fs = _by_id(_run("https://h", _sig(headers={"server": "nginx/1.25.3"})))
    assert "info-disclosure.server" in fs
    # bare server name (no version) is not flagged
    assert "info-disclosure.server" not in _by_id(_run("https://h", _sig(headers={"server": "cloudflare"})))


def test_info_disclosure_powered_by():
    fs = _by_id(_run("https://h", _sig(headers={"x-powered-by": "PHP/8.2"})))
    assert "info-disclosure.x-powered-by" in fs


# --------------------------------------------------------------------------- #
# situational checks gated by apparent sensitivity
# --------------------------------------------------------------------------- #
def test_cross_origin_isolation_only_on_sensitive():
    plain = _by_id(_run("https://h", _sig(headers={})))
    assert "coop.missing" not in plain
    sensitive = _by_id(_run("https://h", _sig(headers={}, has_password_input=True)))
    assert "coop.missing" in sensitive
    assert "coep.missing" in sensitive
    assert "corp.missing" in sensitive


def test_cache_control_sensitive():
    fs = _by_id(_run("https://h", _sig(headers={}, has_password_input=True)))
    assert "cache-control.sensitive" in fs
    clean = _by_id(_run("https://h", _sig(
        headers={"cache-control": "no-store"}, has_password_input=True)))
    assert "cache-control.sensitive" not in clean


# --------------------------------------------------------------------------- #
# CSP
# --------------------------------------------------------------------------- #
def test_parse_csp():
    d = parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'")
    assert d["default-src"] == ["'self'"]
    assert d["script-src"] == ["'self'", "'unsafe-inline'"]
    assert d["object-src"] == ["'none'"]


def test_csp_missing_html_vs_json():
    html = _by_id(_run("https://h", _sig(headers={"content-type": "text/html"})))
    assert html["csp.missing"].severity == "medium"
    js = _by_id(_run("https://h", _sig(headers={"content-type": "application/json"})))
    assert js["csp.missing"].severity == "info"


def test_csp_report_only_only():
    fs = _by_id(_run("https://h", _sig(headers={
        "content-security-policy-report-only": "default-src 'self'"})))
    assert "csp.report-only" in fs
    assert "csp.missing" not in fs


def test_csp_unsafe_inline_high():
    fs = _by_id(_run("https://h", _sig(headers={
        "content-security-policy": "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"})))
    assert fs["csp.unsafe-inline.script-src"].severity == "high"
    assert fs["csp.unsafe-inline.script-src"].source == "csp"


def test_csp_wildcard_and_scheme_and_eval():
    fs = _by_id(_run("https://h", _sig(headers={
        "content-security-policy": "script-src * data: 'unsafe-eval'; object-src 'none'; base-uri 'self'"})))
    assert "csp.wildcard.script-src" in fs
    assert "csp.insecure-scheme.script-src" in fs
    assert "csp.unsafe-eval" in fs


def test_csp_object_src_and_base_uri():
    fs = _by_id(_run("https://h", _sig(headers={
        "content-security-policy": "script-src 'self'"})))
    assert "csp.object-src" in fs   # not 'none'
    assert "csp.base-uri" in fs     # absent


def test_csp_strong_policy_clean():
    fs = _by_id(_run("https://h", _sig(headers={
        "content-security-policy":
            "default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'; "
            "object-src 'none'; base-uri 'none'"})))
    assert not any(k.startswith("csp.") for k in fs)


# --------------------------------------------------------------------------- #
# config: gating, overrides, disables; check_id uniqueness
# --------------------------------------------------------------------------- #
def test_substep_gating():
    sig = _sig(headers={"content-type": "text/html"})
    only_csp = _run("https://h", sig, do_best_practice=False)
    assert all(f.source == "csp" for f in only_csp)
    only_bp = _run("https://h", sig, do_csp=False)
    assert all(f.source == "headers" for f in only_bp)


def test_severity_override():
    cfg = HeadersConfig(severity_overrides={"hsts.missing": "high"})
    fs = _by_id(_run("https://h", _sig(headers={}), cfg=cfg))
    assert fs["hsts.missing"].severity == "high"


def test_disabled_check_prefix():
    cfg = HeadersConfig(disabled_checks=["permissions-policy", "referrer-policy"])
    fs = _by_id(_run("https://h", _sig(headers={}), cfg=cfg))
    assert "permissions-policy.missing" not in fs
    assert "referrer-policy.missing" not in fs
    assert "hsts.missing" in fs  # unrelated check unaffected


def test_check_ids_unique_per_host():
    findings = _run("https://h", _sig(headers={"content-type": "text/html"},
                                      set_cookies=["a=1", "b=2"]))
    ids = [f.check_id for f in findings]
    assert len(ids) == len(set(ids))
    assert all(f.check_id and f.evidence.get("check_id") == f.check_id for f in findings)
