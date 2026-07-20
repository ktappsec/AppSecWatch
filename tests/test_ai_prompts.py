"""Profile-aware prompt construction + the editable-prompt registry (DESIGN.md §2.3)."""
from __future__ import annotations

from appsecwatch.ai.prompts import (
    PROMPT_SLOTS,
    SLOT_TRIAGE_SYSTEM_DEFAULT,
    assemble_preview,
    build_profile_prompt,
    build_summary_prompt,
    build_supply_chain_prompt,
    build_triage_prompt,
    resolved_prompt,
)
from appsecwatch.models import AppProfile, PageSignals


def _profile(**kw) -> AppProfile:
    base = dict(
        host="login.acme.com",
        app_type="customer login portal",
        audience="public",
        confidence="high",
        reasoning="sign-in form present",
        handles_auth=True,
        expected_controls=["HSTS", "Content-Security-Policy"],
    )
    base.update(kw)
    return AppProfile(**base)


def test_profile_prompt_mentions_pre_js_and_expected_controls():
    sig = PageSignals(host="h", title="Acme Login", has_password_input=True)
    system, user = build_profile_prompt(sig)
    assert "pre-JavaScript" in system or "pre-JS" in system.lower()
    assert "expected_controls" in user
    assert "Acme Login" in user
    assert "do NOT repeat httpx_tech" in user      # detected_tech echo trimmed
    # Without a render, the rendered/observed payload fields are absent.
    assert "rendered_body_text" not in user
    assert "observed_resources" not in user


def test_shape_hints_carry_finding_class_vocabulary():
    # AI findings must emit a class from the controlled taxonomy for stable identity.
    _, user = build_triage_prompt("h", {}, findings=[{"ref": 0, "source": "headers"}])
    assert '"class"' in user and "supply.vulnerable-js-lib" in user


def test_turkish_language_directive_on_profile_and_summary():
    sig = PageSignals(host="h", title="Acme Login")
    sys_en, _ = build_profile_prompt(sig, language="en")
    sys_tr, _ = build_profile_prompt(sig, language="tr")
    assert "TÜRKÇE" not in sys_en
    assert "TÜRKÇE" in sys_tr and "expected_controls" in sys_tr  # enum tokens kept EN

    s_en, _ = build_summary_prompt({"rating": "HIGH"}, {}, {}, [], language="en")
    s_tr, _ = build_summary_prompt({"rating": "HIGH"}, {}, {}, [], language="tr")
    assert "TÜRKÇE" not in s_en and "TÜRKÇE" in s_tr


def test_profile_prompt_includes_rendered_and_surface_when_present():
    sig = PageSignals(host="h", title="App")
    surface = {
        "third_party_domains": ["stripe.com"],
        "endpoints": ["POST api.stripe.com/v1/tokens"],
        "cookie_keys": ["JSESSIONID"],
        "storage_keys": ["access_token"],
    }
    system, user = build_profile_prompt(
        sig, rendered_text="Welcome to the dashboard", surface=surface,
    )
    assert "rendered_body_text" in user and "Welcome to the dashboard" in user
    assert "observed_resources" in user and "stripe.com" in user
    # The system prompt explains how to use the new signals.
    assert "observed_resources" in system or "rendered_body_text" in system


def test_triage_default_when_no_profile():
    system, user = build_triage_prompt("https://h", {"server": "nginx"})
    assert "application profile" not in system.lower()   # default, not profiled
    assert "Application profile" not in user
    assert "Findings recorded by deterministic scanners" in user
    assert "suppressions" in user                  # response shape carries it
    # AI-invented severity is capped: the shape hint no longer offers "critical"
    # (the code clamps ai_headers/ai_supply_chain to high), so the model can't mint
    # its own criticals. It is still offered up to "high".
    assert '"critical"' not in user
    assert '"high"' in user


def test_triage_profiled_uses_profile_and_calibration():
    system, user = build_triage_prompt("https://login.acme.com", {"server": "nginx"}, None, _profile())
    assert "application profile" in system.lower()  # profiled variant
    assert "CALIBRATE" in system                    # pragmatic-reviewer reframe
    assert "Application profile" in user
    assert "HSTS" in user                           # expected_controls surfaced
    assert "do NOT aggressively escalate" not in system  # confidence is high


def test_triage_low_confidence_adds_nudge():
    system, _ = build_triage_prompt("https://h", {"server": "nginx"}, None, _profile(confidence="low"))
    assert "do NOT aggressively escalate" in system


def test_errored_profile_falls_back_to_default():
    p = _profile(error="boom")
    system, user = build_triage_prompt("https://h", {"server": "nginx"}, None, p)
    assert "application profile" not in system.lower()   # default, not profiled
    assert "Application profile" not in user


def test_triage_marks_infra_cookies_and_nonfindings_out_of_scope():
    system, _ = build_triage_prompt("https://h", {"server": "nginx"})
    low = system.lower()
    assert "not findings" in low                      # the rule-5 block
    assert "bigipserver" in low and "adrum" in low    # infra cookie families named
    assert "xsrf-token" in low                        # by-design anti-CSRF token
    assert "verify/ensure" in low                     # reminders excluded


def test_supply_excludes_absence_and_reminders():
    sys_default, _ = build_supply_chain_prompt("https://h", [{"url": "https://x/a.js", "party": "3rd"}])
    low = sys_default.lower()
    assert "absence of scripts is not a finding" in low
    assert "verify/ensure" in low


def test_triage_surfaces_findings_by_ref():
    findings = [{"ref": 0, "source": "headers", "severity": "medium",
                 "title": "Missing HSTS", "check_id": "hsts.missing"}]
    _, user = build_triage_prompt("https://h", {"server": "nginx"}, findings, _profile())
    assert '"ref": 0' in user                       # ephemeral ref passed to the AI
    assert "Missing HSTS" in user
    assert "do NOT restate" in user                 # told not to re-report them


def test_supply_default_vs_profiled():
    scripts = [{"url": "https://cdn.x.com/a.js", "party": "3rd"}]
    sys_default, _ = build_supply_chain_prompt("https://h", scripts)
    assert "application profile" not in sys_default.lower()

    sys_prof, user_prof = build_supply_chain_prompt("https://h", scripts, _profile())
    assert "CALIBRATE severity by the profile" in sys_prof
    assert "Application profile" in user_prof


def test_triage_uses_harm_vector_calibration():
    """Suppression is anchored on real-risk harm vectors, not on list length."""
    system, _ = build_triage_prompt("https://h", {"server": "nginx"})
    low = system.lower()
    assert "harm vector" in low                      # the decisive multi-vector test
    assert "phishing" in low and "brand" in low and "supply-chain exposure" in low
    assert "even at low" in low                       # keep real low-severity risks
    assert "prefer few" not in low                    # volume heuristic removed
    # The example KEEPS a real-risk finding (expired cert), not just suppresses.
    assert "keep ref 2" in low and "expired cert" in low


def test_triage_shape_hint_keeps_real_risk_not_prefer_few():
    _, user = build_triage_prompt("https://h", {"server": "nginx"})
    assert "Prefer FEW" not in user
    assert "carries real risk" in user                # keep-every-real-risk instruction
    assert "<the integer ref" not in user             # invalid-JSON placeholder removed
    assert '"ref": 0' in user                         # realistic value instead


def test_triage_evidence_rules_guard_the_audited_hallucinations():
    """Pass-2 calibration: each rule maps to a defect a real cross-scan audit caught."""
    sys_default, _ = build_triage_prompt("https://h", {"server": "nginx"})
    sys_prof, _ = build_triage_prompt("https://h", {"server": "nginx"}, None, _profile())
    for system in (sys_default, sys_prof):
        low = system.lower()
        # Severity was being read off the hostname instead of the response.
        assert "never infer risk from the hostname" in low
        assert "judge only the observed response" in low
        # The model invented a "120-day" HSTS preload minimum to hide hsts.weak.
        assert "31536000" in system and "do not invent" in low
        # Wildcard CORS + credentials is spec-inert; it was being rated critical.
        assert "access-control-allow-origin: *" in low
        # AI CSP findings duplicated the deterministic csp scanner (~69 rows).
        assert "csp is already covered" in low
        # The withheld low-value classes must not be re-added as new findings.
        assert "deterministic policy" in low

    # The expected-controls rule is profile-dependent → profiled prompt only.
    assert "expected_controls" in sys_prof
    assert "expected_controls" not in sys_default


def test_supply_flags_brand_damage_as_real_risk():
    sys_default, _ = build_supply_chain_prompt("https://h", [{"url": "https://x/a.js", "party": "3rd"}])
    low = sys_default.lower()
    assert "deface" in low and "skim" in low          # brand/user harm made explicit
    assert "no real risk" in low                      # risk-anchored omission
    assert "prefer few" not in low


# ---- editable-prompt registry -------------------------------------------

def test_resolved_prompt_prefers_nonblank_override():
    default = PROMPT_SLOTS[SLOT_TRIAGE_SYSTEM_DEFAULT]["default_text"]
    assert resolved_prompt(SLOT_TRIAGE_SYSTEM_DEFAULT) == default
    assert resolved_prompt(SLOT_TRIAGE_SYSTEM_DEFAULT, {SLOT_TRIAGE_SYSTEM_DEFAULT: "  "}) == default
    assert resolved_prompt(SLOT_TRIAGE_SYSTEM_DEFAULT, {SLOT_TRIAGE_SYSTEM_DEFAULT: "X"}) == "X"


def test_assemble_preview_includes_override_and_shape_hint():
    for slot in PROMPT_SLOTS:
        system, user = assemble_preview(slot, "CANARY-SYSTEM-TEXT")
        assert "CANARY-SYSTEM-TEXT" in system
        assert user                                  # a realistic fixture payload
