"""Profile-aware prompt construction + the editable-prompt registry (DESIGN.md §2.3)."""
from __future__ import annotations

from watchtower.ai.prompts import (
    PROMPT_SLOTS,
    SLOT_TRIAGE_SYSTEM_DEFAULT,
    assemble_preview,
    build_profile_prompt,
    build_supply_chain_prompt,
    build_triage_prompt,
    resolved_prompt,
)
from watchtower.models import AppProfile, PageSignals


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


def test_triage_default_when_no_profile():
    system, user = build_triage_prompt("https://h", {"server": "nginx"})
    assert "application profile" not in system.lower()   # default, not profiled
    assert "Application profile" not in user
    assert "Findings recorded by deterministic scanners" in user
    assert "suppressions" in user                  # response shape carries it
    assert '"critical"' in user                    # severity enum lifted to critical


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
