"""AI prompt templates + the editable system-prompt registry.

All prompts demand strict JSON output; the analyzer validates with Pydantic and
retries once on parse failure.

Editable surface (PROMPT_SLOTS): the **system** strings are addressable by slot
id and may be overridden at runtime (config `ai.prompts`, surfaced in the UI).
The shape-hints and user-message assembly stay in code, so an override can change
tone/judgment but can NEVER break JSON validation. `resolved_prompt(slot, ovr)`
returns the override-or-default for a slot; a blank override falls back to the
built-in default (no frozen copies — improving a default in code is picked up).

Context-awareness (DESIGN.md §2.3): a profiling pass infers an `AppProfile` per
host. When a usable profile is available, the triage prompt becomes an
expectation-gap analysis against the app's `expected_controls` and the
supply-chain prompt weights risk by the app's audience/capabilities. When no
profile is available (profiling off, or a host that hard-failed profiling), both
prompts fall back to their default context-light form.

The triage prompt (formerly "headers") triages ALL deterministic findings for a
host — nuclei/TLS/js_lib/headers/takeover — not just header checks: it suppresses
false-positives (by the ephemeral integer `ref` each finding is given) and may
add new header findings.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from watchtower.models import AppProfile, PageSignals

# Slot ids — stable keys for the editable system prompts (config `ai.prompts`
# field names mirror these; the UI/API address slots by id).
SLOT_PROFILE_SYSTEM = "profile_system"
SLOT_TRIAGE_SYSTEM_DEFAULT = "triage_system_default"
SLOT_TRIAGE_SYSTEM_PROFILED = "triage_system_profiled"
SLOT_SUPPLY_SYSTEM_DEFAULT = "supply_system_default"
SLOT_SUPPLY_SYSTEM_PROFILED = "supply_system_profiled"
SLOT_LOW_CONFIDENCE_NUDGE = "low_confidence_nudge"

# ---------------------------------------------------------------------------
# Shape hints (NOT editable — the JSON contract with the Pydantic validator)
# ---------------------------------------------------------------------------

_SUPPLY_RESPONSE_SHAPE_HINT = """\
Return ONLY a JSON object of this exact shape, no prose, no markdown:
{
  "findings": [
    {
      "type": "string-tag",
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "title": "Short human-readable title",
      "description": "1-3 sentence explanation",
      "evidence": {"any": "structured fields supporting the finding"}
    }
  ]
}
If nothing is wrong, return {"findings": []}.
"""

_TRIAGE_RESPONSE_SHAPE_HINT = """\
Return ONLY a JSON object of this exact shape, no prose, no markdown:
{
  "findings": [
    {
      "type": "string-tag",
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "title": "Short human-readable title",
      "description": "1-3 sentence explanation",
      "evidence": {"any": "structured fields supporting the finding"}
    }
  ],
  "suppressions": [
    {
      "ref": <the integer ref of a finding you judge a false-positive>,
      "confidence": "low" | "medium" | "high",
      "reason": "why it is a false-positive / acceptable for THIS host"
    }
  ]
}
Prefer FEW high-signal findings over many. Add a finding ONLY for a concrete,
exploitable gap the scanners missed — never generic best-practice advice. Suppress
findings (by `ref`) that are false-positives OR acceptable design choices for this
app. If nothing is genuinely actionable to add and nothing to suppress, return
{"findings": [], "suppressions": []}.
"""

_PROFILE_SHAPE_HINT = """\
Return ONLY a JSON object of this exact shape, no prose, no markdown:
{
  "app_type": "short free-text label, e.g. 'customer login portal'",
  "audience": "public" | "internal" | "partner" | "unknown",
  "confidence": "low" | "medium" | "high",
  "reasoning": "1-3 sentences on why you classified it this way",
  "handles_auth": true | false,
  "handles_pii": true | false,
  "handles_payments": true | false,
  "has_file_upload": true | false,
  "is_api": true | false,
  "expected_controls": ["controls/headers this app type SHOULD have, e.g. HSTS, Content-Security-Policy, Secure+HttpOnly cookies"],
  "detected_tech": ["ADDITIONAL technologies/frameworks you can infer beyond the httpx_tech you were given (e.g. 'React', 'WordPress', 'PHP'); do NOT repeat httpx_tech; [] if none to add"]
}
"""

# ---------------------------------------------------------------------------
# Default system prompts (editable via PROMPT_SLOTS / config ai.prompts)
# ---------------------------------------------------------------------------

_DEFAULT_PROFILE_SYSTEM = (
    "You are a senior application security engineer building a concise profile of "
    "a web application so that later analysis can be tailored to it. You are given "
    "signals scraped from the application's root page. IMPORTANT: the HTML is the "
    "RAW pre-JavaScript response — for single-page apps the visible body text may "
    "be sparse or empty; do not conclude the app is trivial just because the body "
    "is thin. Reason from the title, meta description, OpenGraph tags, detected "
    "technology, and any form/login signals. "
    "Infer: what the application is (app_type), who its audience is, what sensitive "
    "capabilities it likely has, and — crucially — which security controls/headers "
    "an application of THIS type ought to have (expected_controls). Set confidence "
    "honestly: 'low' when the signals are too sparse to be sure.\n\n"
    "EXAMPLE — given a title 'Acme Bank — Login', a password input, and httpx_tech "
    "['nginx']: {\"app_type\":\"customer login portal\",\"audience\":\"public\","
    "\"confidence\":\"high\",\"reasoning\":\"public login form collecting credentials\","
    "\"handles_auth\":true,\"handles_pii\":true,\"handles_payments\":false,"
    "\"is_api\":false,\"expected_controls\":[\"HSTS\",\"Content-Security-Policy\","
    "\"Secure+HttpOnly cookies\"],\"detected_tech\":[\"React\"]}"
)

_TRIAGE_INTRO_DEFAULT = (
    "You are a PRAGMATIC senior application security reviewer triaging the findings "
    "that deterministic scanners produced for ONE host — not an exhaustive checklist "
    "auditor. You receive the host URL, its response headers, and a list of findings "
    "(each with an integer `ref`, source, severity, and detail). Your goal is "
    "REALISTIC, high-signal output — quality over quantity:\n"
)

_TRIAGE_INTRO_PROFILED = (
    "You are a PRAGMATIC senior application security reviewer triaging the findings "
    "deterministic scanners produced for ONE host — not an exhaustive checklist "
    "auditor. You get an application profile (what the app is, its audience, "
    "sensitive capabilities, and the controls it OUGHT to have), the host URL, its "
    "response headers, and a list of findings (each with an integer `ref`, source, "
    "severity, and detail). Use the profile to judge what actually matters for THIS "
    "app. Your goal is REALISTIC, high-signal output — quality over quantity:\n"
)

_TRIAGE_RULES = (
    "  1. SUPPRESS findings that are false-positives OR acceptable design choices "
    "for this host — return the finding's `ref`, your confidence, and a short "
    "reason. This is the PRIMARY value: cut the noise the scanners over-report "
    "(e.g. clickjacking on a pure JSON API; an HSTS gap on a non-user-facing host; "
    "a low-severity nuclei tech-disclosure that is expected; a CSP directive the "
    "app genuinely doesn't need).\n"
    "  2. Add a NEW finding ONLY for a concrete, exploitable gap the scanners "
    "missed (a dangerous header COMBINATION, a genuinely abusable CSP allowlist "
    "entry). Do NOT restate existing findings and do NOT emit generic best-practice "
    "advice.\n"
    "  3. CALIBRATE to REAL risk. A JS-heavy SPA or rich web app commonly REQUIRES "
    "'unsafe-eval'/'unsafe-inline' — treat that as expected, not a finding. "
    "Reputable first-party/known CDNs in an allowlist are usually fine.\n"
    "  4. When unsure, prefer SUPPRESSING over adding — a short realistic list "
    "beats a long noisy one.\n\n"
    "EXAMPLE — given findings [{\"ref\":0,\"source\":\"headers\",\"severity\":"
    "\"medium\",\"title\":\"X-Frame-Options missing\"},{\"ref\":1,\"source\":"
    "\"nuclei\",\"severity\":\"info\",\"title\":\"nginx version disclosed\"}] on a "
    "pure JSON API: {\"findings\":[],\"suppressions\":[{\"ref\":0,\"confidence\":"
    "\"high\",\"reason\":\"JSON API not rendered in a frame — clickjacking N/A\"},"
    "{\"ref\":1,\"confidence\":\"medium\",\"reason\":\"version banner is low-value, "
    "not exploitable on its own\"}]}"
)

_DEFAULT_TRIAGE_SYSTEM_DEFAULT = _TRIAGE_INTRO_DEFAULT + _TRIAGE_RULES
_DEFAULT_TRIAGE_SYSTEM_PROFILED = _TRIAGE_INTRO_PROFILED + _TRIAGE_RULES

_DEFAULT_LOW_CONFIDENCE_NUDGE = (
    "\n\nNOTE: the application profile confidence is LOW — the signals were sparse. "
    "Treat the profile as a weak hint only: do NOT aggressively escalate severities "
    "on expectation gaps; cap escalations at 'low'/'medium' and note the uncertainty."
)

_DEFAULT_SUPPLY_SYSTEM_DEFAULT = (
    "You are a PRAGMATIC senior application security reviewer focused on supply-chain "
    "risk — not an exhaustive lister. You receive a host URL and the scripts its root "
    "page loads, each pre-labeled 1st/3rd-party. Surface ONLY concrete supply-chain "
    "RISKS: untrusted/suspicious 3rd-party origins, SRI-less version-mutable scripts, "
    "anomalous sources. Reputable, widely-used providers (major CDNs, well-known "
    "analytics) are normal — do NOT flag them by default and do NOT emit one finding "
    "per script. Do NOT re-classify party-ness. Prefer FEW high-signal findings; when "
    "unsure, omit.\n\n"
    "EXAMPLE — scripts from googletagmanager.com (3rd) and a versioned cdn.jsdelivr.net "
    "bundle with no SRI: flag ONLY the SRI-less mutable script "
    "({\"type\":\"sri-missing\",\"severity\":\"low\",...}); do NOT flag the reputable "
    "analytics script. If all scripts are reputable + integrity-pinned, return "
    "{\"findings\":[]}."
)

_DEFAULT_SUPPLY_SYSTEM_PROFILED = (
    "You are a PRAGMATIC senior application security reviewer focused on supply-chain "
    "risk. You receive an application profile (what the app is, audience, sensitive "
    "capabilities) and the scripts its root page loads, each pre-labeled 1st/3rd-"
    "party. Surface ONLY concrete risks and CALIBRATE severity by the profile — the "
    "same 3rd-party script matters far more on an app handling auth/PII/payments than "
    "on a marketing page. Reputable, widely-used providers are normal; do NOT flag "
    "them by default or emit one finding per script. Do NOT re-classify party-ness. "
    "Prefer FEW high-signal findings; when unsure, omit.\n\n"
    "EXAMPLE — on an auth/PII app, an SRI-less 3rd-party script from a small/unknown "
    "origin warrants medium ({\"type\":\"untrusted-3p-script\",\"severity\":"
    "\"medium\",...}); the same script on a static marketing page is info/omit. "
    "Reputable integrity-pinned CDNs → {\"findings\":[]}."
)


# Editable system-prompt registry. Ordered; the UI/API list slots in this order.
PROMPT_SLOTS: dict[str, dict[str, str]] = {
    SLOT_PROFILE_SYSTEM: {
        "label": "Profiling — system",
        "description": "Infers the per-app AppProfile (type, audience, sensitive "
                       "capabilities, expected controls) from root-page signals.",
        "default_text": _DEFAULT_PROFILE_SYSTEM,
    },
    SLOT_TRIAGE_SYSTEM_DEFAULT: {
        "label": "Triage — system (no profile)",
        "description": "Cross-source false-positive suppression + new header "
                       "findings when no usable app profile is available.",
        "default_text": _DEFAULT_TRIAGE_SYSTEM_DEFAULT,
    },
    SLOT_TRIAGE_SYSTEM_PROFILED: {
        "label": "Triage — system (profiled)",
        "description": "Same as above, calibrated against the inferred app profile "
                       "(expectation-gap analysis).",
        "default_text": _DEFAULT_TRIAGE_SYSTEM_PROFILED,
    },
    SLOT_SUPPLY_SYSTEM_DEFAULT: {
        "label": "Supply-chain — system (no profile)",
        "description": "Surfaces concrete supply-chain risks from loaded scripts "
                       "when no usable app profile is available.",
        "default_text": _DEFAULT_SUPPLY_SYSTEM_DEFAULT,
    },
    SLOT_SUPPLY_SYSTEM_PROFILED: {
        "label": "Supply-chain — system (profiled)",
        "description": "Same as above, weighting risk by the inferred app profile.",
        "default_text": _DEFAULT_SUPPLY_SYSTEM_PROFILED,
    },
    SLOT_LOW_CONFIDENCE_NUDGE: {
        "label": "Low-confidence profile nudge",
        "description": "Appended to the profiled triage/supply prompts when the app "
                       "profile confidence is 'low' — caps severity escalation.",
        "default_text": _DEFAULT_LOW_CONFIDENCE_NUDGE,
    },
}


def resolved_prompt(slot_id: str, overrides: Mapping[str, str] | None = None) -> str:
    """The effective system text for a slot: a non-blank override, else the
    built-in default. Unknown slot ids raise KeyError (programming error)."""
    if overrides:
        v = overrides.get(slot_id)
        if isinstance(v, str) and v.strip():
            return v
    return PROMPT_SLOTS[slot_id]["default_text"]


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_profile_prompt(
    signals: PageSignals,
    overrides: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    payload = {
        "host": signals.host,
        "title": signals.title,
        "meta_description": signals.meta_description,
        "og_tags": signals.og_tags,
        "httpx_tech": signals.tech,
        "form_count": signals.form_count,
        "has_password_input": signals.has_password_input,
        "response_headers": signals.headers,
        "body_text_snippet_pre_js": signals.body_snippet,
    }
    user_msg = (
        f"Application signals (raw pre-JavaScript root page):\n"
        f"```json\n{json.dumps(payload, indent=2, ensure_ascii=False)}\n```\n\n"
        f"{_PROFILE_SHAPE_HINT}"
    )
    return resolved_prompt(SLOT_PROFILE_SYSTEM, overrides), user_msg


def _profile_context_block(profile: AppProfile) -> str:
    ctx = {
        "app_type": profile.app_type,
        "audience": profile.audience,
        "confidence": profile.confidence,
        "handles_auth": profile.handles_auth,
        "handles_pii": profile.handles_pii,
        "handles_payments": profile.handles_payments,
        "has_file_upload": profile.has_file_upload,
        "is_api": profile.is_api,
        "expected_controls": profile.expected_controls,
        "reasoning": profile.reasoning,
    }
    return json.dumps(ctx, indent=2, ensure_ascii=False)


def _findings_block(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "(none)"
    return json.dumps(findings, indent=2, ensure_ascii=False)


def build_triage_prompt(
    host: str,
    headers: dict[str, str],
    findings: list[dict[str, Any]] | None = None,
    profile: AppProfile | None = None,
    overrides: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Per-host triage: suppress false-positives across ALL deterministic findings
    (by ephemeral `ref`) + add concrete header findings the scanners missed.

    `findings` is the ephemeral-ref payload (already filtered to <= the suppression
    severity ceiling). Each entry carries `ref`, `source`, `severity`, `title`,
    optional `detail`/`check_id`.
    """
    findings_block = _findings_block(findings or [])
    if profile is not None and profile.usable:
        system = resolved_prompt(SLOT_TRIAGE_SYSTEM_PROFILED, overrides)
        if profile.confidence == "low":
            system = system + resolved_prompt(SLOT_LOW_CONFIDENCE_NUDGE, overrides)
        user_msg = (
            f"Host: {host}\n\n"
            f"Application profile:\n```json\n{_profile_context_block(profile)}\n```\n\n"
            f"Findings recorded by deterministic scanners (suppress false-positives "
            f"by `ref`; do NOT restate them):\n```json\n{findings_block}\n```\n\n"
            f"Actual response headers (lower-cased keys):\n"
            f"```json\n{json.dumps(headers, indent=2, ensure_ascii=False)}\n```\n\n"
            f"{_TRIAGE_RESPONSE_SHAPE_HINT}"
        )
        return system, user_msg

    user_msg = (
        f"Host: {host}\n\n"
        f"Findings recorded by deterministic scanners (suppress false-positives by "
        f"`ref`; do NOT restate them):\n```json\n{findings_block}\n```\n\n"
        f"Response headers (lower-cased keys):\n"
        f"```json\n{json.dumps(headers, indent=2, ensure_ascii=False)}\n```\n\n"
        f"{_TRIAGE_RESPONSE_SHAPE_HINT}"
    )
    return resolved_prompt(SLOT_TRIAGE_SYSTEM_DEFAULT, overrides), user_msg


def build_supply_chain_prompt(
    host: str,
    scripts: list[dict[str, Any]],
    profile: AppProfile | None = None,
    overrides: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    if profile is not None and profile.usable:
        system = resolved_prompt(SLOT_SUPPLY_SYSTEM_PROFILED, overrides)
        if profile.confidence == "low":
            system = system + resolved_prompt(SLOT_LOW_CONFIDENCE_NUDGE, overrides)
        user_msg = (
            f"Host: {host}\n\n"
            f"Application profile:\n```json\n{_profile_context_block(profile)}\n```\n\n"
            f"Scripts loaded (party already determined; do not change it):\n"
            f"```json\n{json.dumps(scripts, indent=2, ensure_ascii=False)}\n```\n\n"
            f"{_SUPPLY_RESPONSE_SHAPE_HINT}"
        )
        return system, user_msg

    user_msg = (
        f"Host: {host}\n\n"
        f"Scripts loaded (party already determined; do not change it):\n"
        f"```json\n{json.dumps(scripts, indent=2, ensure_ascii=False)}\n```\n\n"
        f"{_SUPPLY_RESPONSE_SHAPE_HINT}"
    )
    return resolved_prompt(SLOT_SUPPLY_SYSTEM_DEFAULT, overrides), user_msg


def assemble_preview(slot_id: str, candidate_text: str) -> tuple[str, str]:
    """Render the EXACT (system, user) message the engine would send for a slot,
    using `candidate_text` as the system override + a representative fixture. No
    LLM call — powers the UI 'Preview' panel.
    """
    ovr = {slot_id: candidate_text}
    fixture_headers = {
        "server": "nginx",
        "content-type": "text/html; charset=utf-8",
        "x-frame-options": "SAMEORIGIN",
    }
    sample_profile = AppProfile(
        host="app.example.com", app_type="customer login portal", audience="public",
        confidence="high", reasoning="public login form collecting credentials",
        handles_auth=True, handles_pii=True,
        expected_controls=["HSTS", "Content-Security-Policy", "Secure+HttpOnly cookies"],
    )
    low_profile = sample_profile.model_copy(update={"confidence": "low"})
    sample_findings = [
        {"ref": 0, "source": "headers", "severity": "medium",
         "title": "X-Frame-Options header missing", "check_id": "x-frame-options.missing"},
        {"ref": 1, "source": "nuclei", "severity": "info",
         "title": "nginx version disclosed", "detail": "template: nginx-version"},
    ]
    sample_scripts = [
        {"url": "https://www.googletagmanager.com/gtm.js", "party": "3rd",
         "etld_plus_one": "googletagmanager.com", "status": 200, "initiator_url": None},
        {"url": "https://app.example.com/static/app.js", "party": "1st",
         "etld_plus_one": "example.com", "status": 200, "initiator_url": None},
    ]
    if slot_id in (SLOT_PROFILE_SYSTEM,):
        return build_profile_prompt(
            PageSignals(host="app.example.com", title="Acme Bank — Login",
                        tech=["nginx"], form_count=1, has_password_input=True,
                        headers=fixture_headers),
            overrides=ovr,
        )
    if slot_id in (SLOT_SUPPLY_SYSTEM_DEFAULT,):
        return build_supply_chain_prompt("https://app.example.com", sample_scripts, None, ovr)
    if slot_id in (SLOT_SUPPLY_SYSTEM_PROFILED,):
        return build_supply_chain_prompt("https://app.example.com", sample_scripts, sample_profile, ovr)
    if slot_id == SLOT_TRIAGE_SYSTEM_DEFAULT:
        return build_triage_prompt("https://app.example.com", fixture_headers, sample_findings, None, ovr)
    if slot_id == SLOT_LOW_CONFIDENCE_NUDGE:
        # The nudge only manifests on a low-confidence profiled prompt.
        return build_triage_prompt("https://app.example.com", fixture_headers, sample_findings, low_profile, ovr)
    # SLOT_TRIAGE_SYSTEM_PROFILED and any future profiled slot
    return build_triage_prompt("https://app.example.com", fixture_headers, sample_findings, sample_profile, ovr)
