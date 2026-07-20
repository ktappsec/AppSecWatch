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

from appsecwatch.audit.taxonomy import vocabulary_hint
from appsecwatch.models import AppProfile, PageSignals

# Injected into the finding shape-hints so AI findings carry a STABLE class from
# the controlled taxonomy (their cross-scan identity keys on (host, class), not
# the drifting title). The analyzer coerces an out-of-vocab class, so this is a
# steer, never a hard validator.
_CLASS_FIELD_LINE = (
    '      "class": "the ONE finding-class from this fixed vocabulary that best '
    'fits — ' + vocabulary_hint() + '",'
)

# Slot ids — stable keys for the editable system prompts (config `ai.prompts`
# field names mirror these; the UI/API address slots by id).
SLOT_PROFILE_SYSTEM = "profile_system"
SLOT_TRIAGE_SYSTEM_DEFAULT = "triage_system_default"
SLOT_TRIAGE_SYSTEM_PROFILED = "triage_system_profiled"
SLOT_SUPPLY_SYSTEM_DEFAULT = "supply_system_default"
SLOT_SUPPLY_SYSTEM_PROFILED = "supply_system_profiled"
SLOT_LOW_CONFIDENCE_NUDGE = "low_confidence_nudge"
SLOT_SUMMARY_SYSTEM = "summary_system"

# ---------------------------------------------------------------------------
# Shape hints (NOT editable — the JSON contract with the Pydantic validator)
# ---------------------------------------------------------------------------

_SUPPLY_RESPONSE_SHAPE_HINT = """\
Return ONLY a JSON object of this exact shape, no prose, no markdown. Output exactly
ONE JSON object and nothing after the final closing brace:
{
  "findings": [
    {
      "type": "string-tag",
""" + _CLASS_FIELD_LINE + """
      "severity": "info" | "low" | "medium" | "high",
      "title": "Short human-readable title",
      "description": "1-3 sentence explanation",
      "evidence": {"any": "structured fields supporting the finding"}
    }
  ]
}
If nothing carries real risk, return {"findings": []}.
"""

_TRIAGE_RESPONSE_SHAPE_HINT = """\
Return ONLY a JSON object of this exact shape, no prose, no markdown. Output exactly
ONE JSON object and nothing after the final closing brace:
{
  "findings": [
    {
      "type": "string-tag",
""" + _CLASS_FIELD_LINE + """
      "severity": "info" | "low" | "medium" | "high",
      "title": "Short human-readable title",
      "description": "1-3 sentence explanation",
      "evidence": {"any": "structured fields supporting the finding"}
    }
  ],
  "suppressions": [
    {"ref": 0, "confidence": "low" | "medium" | "high", "reason": "why it carries no real risk for THIS host"}
  ]
}
Each suppression `ref` MUST be one of the integer refs from the findings you were
given. KEEP every finding that carries real risk under any harm vector (even LOW);
SUPPRESS (by `ref`) only findings that carry none — a false-positive or accepted
design choice for this host. Add a finding ONLY for a concrete gap the scanners missed
that carries real harm — never generic best-practice advice. If there is nothing to
add and nothing to suppress, return {"findings": [], "suppressions": []}.
"""

_EXEC_SUMMARY_SHAPE_HINT = """\
Return ONLY a JSON object of this exact shape, no prose, no markdown. Output exactly
ONE JSON object and nothing after the final closing brace:
{
  "posture_narrative": "2-4 plain-language sentences for a non-technical executive on the overall security posture and what it means for the business",
  "risk_notes": [
    {"ref": 0, "why": "ONE plain-language sentence on why this risk matters to the business"}
  ],
  "recommendations": ["3-5 short, plain-language next steps / remediation themes"]
}
Cover the given top risks by their `ref` (do not invent new refs). If there is
nothing to say, return {"posture_narrative": "", "risk_notes": [], "recommendations": []}.
"""

_PROFILE_SHAPE_HINT = """\
Return ONLY a JSON object of this exact shape, no prose, no markdown. Output exactly
ONE JSON object and nothing after the final closing brace:
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
  "expected_controls": ["controls this app type SHOULD have, as canonical tokens from THIS set only: HSTS, Content-Security-Policy, X-Frame-Options, Secure-cookies, HttpOnly-cookies, SameSite-cookies, Subresource-Integrity; omit any that don't apply"],
  "detected_tech": ["ADDITIONAL technologies/frameworks you can infer beyond the httpx_tech you were given (e.g. 'React', 'WordPress', 'PHP'); do NOT repeat httpx_tech; [] if none to add"]
}
"""

# ---------------------------------------------------------------------------
# Default system prompts (editable via PROMPT_SLOTS / config ai.prompts)
# ---------------------------------------------------------------------------

_DEFAULT_PROFILE_SYSTEM = (
    "You are a senior application security engineer building a concise profile of "
    "a web application so that later analysis can be tailored to it. You are given "
    "signals scraped from the application's root page. NOTE: `body_text_snippet_pre_js` "
    "is the RAW pre-JavaScript response — for single-page apps it may be sparse or "
    "empty; do not conclude the app is trivial just because it is thin. When the page "
    "was rendered in a browser you also get `rendered_body_text` (the rendered visible "
    "text — prefer it over the pre-JS snippet) and `observed_resources`: the "
    "third-party domains, API/data endpoints, and cookie/storage KEY names the page "
    "actually loaded (names only, never values). These are strong tells — e.g. a "
    "'POST api.stripe.com/...' endpoint or a 'stripe' script domain implies payments; "
    "an 'access_token' storage key implies client-side auth. Reason from the title, "
    "meta description, OpenGraph tags, detected technology, form/login signals, and "
    "these observed resources when present. "
    "Infer: what the application is (app_type), who its audience is, what sensitive "
    "capabilities it likely has, and — crucially — which security controls/headers "
    "an application of THIS type ought to have (expected_controls). Set confidence "
    "honestly: 'low' when the signals are too sparse to be sure.\n\n"
    "EXAMPLE — given a title 'Acme Bank — Login', a password input, and httpx_tech "
    "['nginx']: {\"app_type\":\"customer login portal\",\"audience\":\"public\","
    "\"confidence\":\"high\",\"reasoning\":\"public login form collecting credentials\","
    "\"handles_auth\":true,\"handles_pii\":true,\"handles_payments\":false,"
    "\"has_file_upload\":false,\"is_api\":false,\"expected_controls\":[\"HSTS\","
    "\"Content-Security-Policy\",\"Secure-cookies\",\"HttpOnly-cookies\"],"
    "\"detected_tech\":[\"React\"]}"
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

# The decisive test — keep/suppress is judged by REAL harm across several vectors,
# not by severity label or by a bias toward a short list. Shared by both variants.
_TRIAGE_HARM_TEST = (
    "  DECIDE every finding by ONE question — does it contribute REAL risk to THIS "
    "host under ANY of these harm vectors? (a) technical compromise of the host or "
    "its data (RCE, injection, auth bypass, data exposure); (b) harm to its users "
    "(XSS, session/credential theft, a malicious or compromised third-party script — "
    "skimming, defacement); (c) brand / reputational damage (defacement or content "
    "injection, including via a compromised supply chain); (d) phishing / "
    "impersonation enablement (expired, invalid, or weak TLS cert; missing HSTS on a "
    "login host; misconfig that eases lookalike attacks); (e) supply-chain exposure "
    "(version-mutable / SRI-less / untrusted third-party scripts). KEEP a finding when "
    "it contributes to ANY vector, even at LOW severity. SUPPRESS it only when it "
    "contributes to NONE — a false-positive, not applicable to THIS host, or an "
    "accepted by-design choice. Judge by harm, not by severity label or list length.\n"
)

# Anti-hallucination guard rails, shared by both triage variants. Each line exists
# because a cross-scan audit of real runs caught the model doing exactly this: rating
# severity off the HOSTNAME instead of the response; inventing an HSTS preload
# threshold ("120-day minimum") to suppress a real `hsts.weak`; calling a wildcard CORS
# header critical though browsers reject wildcard-with-credentials; and re-emitting the
# deterministic CSP scanner's findings as its own (~69 duplicate rows).
_TRIAGE_EVIDENCE_RULES = (
    "  JUDGE ONLY THE OBSERVED RESPONSE — the status, headers, and finding details you "
    "were given. NEVER infer risk from the HOSTNAME: a name like 'boa', 'admin', 'test', "
    "'payment', 'vpn' or 'internal' tells you NOTHING about what the response is. Do not "
    "claim a host serves plain HTTP, is internal, is unauthenticated, or is high-value "
    "unless the evidence in front of you shows it.\n"
    "  DO NOT INVENT standards, thresholds or version numbers. In particular, HSTS: the "
    "ONLY correct max-age threshold is 31536000 seconds (1 year) — the HSTS-preload "
    "minimum. There is no 120-day, 6-month or any other minimum. A max-age below "
    "31536000 IS a real weakness: never suppress it by citing a threshold you made up.\n"
    "  'Access-Control-Allow-Origin: *' CANNOT be combined with credentials — browsers "
    "reject that combination outright — so a wildcard CORS header is not, on its own, an "
    "account-takeover bug. Rate CORS on what the observed response actually exposes.\n"
    "  CSP IS ALREADY COVERED by a dedicated deterministic scanner (missing, report-only, "
    "unsafe-inline, unsafe-eval, wildcard and insecure-scheme sources, object-src, "
    "base-uri). Do NOT emit any CSP finding of your own — it would duplicate a row that "
    "already exists.\n"
    "  Some low-value header classes (X-Content-Type-Options, Referrer-Policy, "
    "Permissions-Policy, X-Frame-Options, missing-CSP) are decided by a deterministic "
    "policy, not by you. They are deliberately absent from your list — do NOT add them "
    "back as new findings.\n"
)

# Profiled-only: the model repeatedly hid the very controls the app was profiled to
# need (HSTS on ~79 banking hosts). Python enforces this too (ai/policy.py) — the rule
# is here so the model doesn't waste a verdict that will be declined anyway.
_TRIAGE_SENSITIVE_RULE = (
    "  If this app handles AUTHENTICATION, PERSONAL DATA or PAYMENTS, NEVER suppress a "
    "finding on a control the profile lists in `expected_controls` (HSTS, "
    "Content-Security-Policy, cookie flags, ...). Those are the controls this app is "
    "expected to have; a gap in one is a real finding by definition, not an accepted "
    "design choice.\n"
)

_TRIAGE_RULES = (
    "  1. SUPPRESS findings that carry no real harm under any vector (a false-positive "
    "or accepted design choice for this host) — return the finding's `ref`, your "
    "confidence, and a short reason. This is high-value noise-cutting (e.g. "
    "clickjacking on a pure JSON API; an HSTS gap on a non-user-facing host with no "
    "login; a low-severity nuclei tech-disclosure that is expected; a CSP directive "
    "the app genuinely doesn't need).\n"
    "  2. Add a NEW finding ONLY for a concrete gap the scanners missed that carries "
    "real harm (a dangerous header COMBINATION, a genuinely abusable CSP allowlist "
    "entry). Do NOT restate existing findings and do NOT emit generic best-practice "
    "advice.\n"
    "  3. CALIBRATE to REAL risk. A JS-heavy SPA or rich web app commonly REQUIRES "
    "'unsafe-eval'/'unsafe-inline' — treat that as expected, not a finding. "
    "Reputable first-party/known CDNs in an allowlist are usually fine.\n"
    "  4. When a finding carries no real harm under any vector, suppress it; when it "
    "carries real harm even at LOW, keep it. Do not suppress a real risk just to "
    "shorten the report.\n"
    "  5. These are NOT findings — never add them: (a) load-balancer / WAF / RUM "
    "cookies (F5 BIG-IP TS*/BIGipServer*, AWS ALB, Cloudflare __cf*, AppDynamics "
    "ADRUM, Dynatrace) carry no session or auth state, so their missing "
    "HttpOnly/Secure/SameSite flags — and any 'infrastructure disclosed via cookie "
    "name' — are NOT findings; (b) a JS-readable double-submit anti-CSRF token "
    "(XSRF-TOKEN / CSRF-TOKEN) is by-design, not a finding; (c) positive or "
    "absence-of-signal observations ('no scripts loaded', 'headers look fine') and "
    "'verify/ensure X' reminders — report only a concrete, present defect.\n\n"
    "EXAMPLE — given findings [{\"ref\":0,\"source\":\"headers\",\"severity\":"
    "\"medium\",\"title\":\"X-Frame-Options missing\"},{\"ref\":1,\"source\":"
    "\"nuclei\",\"severity\":\"info\",\"title\":\"nginx version disclosed\"},"
    "{\"ref\":2,\"source\":\"sslscan\",\"severity\":\"low\",\"title\":\"TLS "
    "certificate expired\"}] on a pure JSON API: suppress refs 0 and 1 (no real harm "
    "— a JSON API isn't rendered in a frame, and a version banner isn't exploitable "
    "alone) but KEEP ref 2 (an expired cert breaks transport authentication and eases "
    "interception/impersonation — real harm under vectors a/d): {\"findings\":[],"
    "\"suppressions\":[{\"ref\":0,\"confidence\":\"high\",\"reason\":\"clickjacking "
    "N/A — JSON API not framed\"},{\"ref\":1,\"confidence\":\"medium\",\"reason\":"
    "\"version banner is low-value, not exploitable on its own\"}]}"
)

_DEFAULT_TRIAGE_SYSTEM_DEFAULT = (
    _TRIAGE_INTRO_DEFAULT + _TRIAGE_HARM_TEST + _TRIAGE_EVIDENCE_RULES + _TRIAGE_RULES
)
_DEFAULT_TRIAGE_SYSTEM_PROFILED = (
    _TRIAGE_INTRO_PROFILED + _TRIAGE_HARM_TEST + _TRIAGE_EVIDENCE_RULES
    + _TRIAGE_SENSITIVE_RULE + _TRIAGE_RULES
)

_DEFAULT_LOW_CONFIDENCE_NUDGE = (
    "\n\nNOTE: the application profile confidence is LOW — the signals were sparse. "
    "Treat the profile as a weak hint only: do NOT aggressively escalate severities "
    "on expectation gaps; cap escalations at 'low'/'medium' and note the uncertainty."
)

_DEFAULT_SUPPLY_SYSTEM_DEFAULT = (
    "You are a PRAGMATIC senior application security reviewer focused on supply-chain "
    "risk — not an exhaustive lister. You receive a host URL and the scripts its root "
    "page loads, each pre-labeled 1st/3rd-party. Flag a script ONLY when it carries "
    "REAL risk: a version-mutable / SRI-less / untrusted or suspicious third-party "
    "script can be compromised to deface the site, skim data, or inject malicious code "
    "(brand, user, and data harm) — flag it even at LOW. Reputable, widely-used, "
    "integrity-pinned providers (major CDNs, well-known analytics) carry no real risk "
    "→ do NOT flag them and do NOT emit one finding per script. Do NOT re-classify "
    "party-ness. When a script carries no real risk, omit it. The ABSENCE of scripts "
    "is NOT a finding (never report 'no scripts loaded' / 'minimal footprint'); do NOT "
    "emit 'verify/ensure X' reminders or flag load-balancer/WAF/RUM cookies (F5, "
    "ADRUM, …).\n\n"
    "EXAMPLE — scripts from googletagmanager.com (3rd) and a versioned cdn.jsdelivr.net "
    "bundle with no SRI: flag ONLY the SRI-less mutable script "
    "({\"type\":\"sri-missing\",\"severity\":\"low\",...}) — it can be swapped to "
    "deface or skim the page; do NOT flag the reputable analytics script. If all "
    "scripts are reputable + integrity-pinned, return {\"findings\":[]}."
)

_DEFAULT_SUMMARY_SYSTEM = (
    "You are a senior application-security consultant writing the EXECUTIVE SUMMARY "
    "of an external, point-in-time assessment for the client's leadership (e.g. a "
    "CISO and non-technical executives). You are given the deterministically-computed "
    "facts of the scan: the overall risk posture rating, the finding counts by "
    "severity, the scale assessed, and the TOP RISKS (each with an integer `ref`, "
    "title, source, severity, and affected-host count). Write in PLAIN, calm, "
    "business language — no tool names, no jargon, no hype. Explain what the posture "
    "means and, for each top risk, ONE sentence on why it matters to the business "
    "(impact, not mechanics). Then give 3-5 concrete, prioritized next steps phrased "
    "as outcomes ('Restrict the admin interface to the corporate network'), not "
    "ticket text. Do NOT invent findings, numbers, or refs beyond what you are given; "
    "the deterministic facts are authoritative. Keep each field within the limits the "
    "response shape gives you; the report template controls overall length."
)

_DEFAULT_SUPPLY_SYSTEM_PROFILED = (
    "You are a PRAGMATIC senior application security reviewer focused on supply-chain "
    "risk. You receive an application profile (what the app is, audience, sensitive "
    "capabilities) and the scripts its root page loads, each pre-labeled 1st/3rd-"
    "party. Flag a script ONLY when it carries REAL risk and CALIBRATE severity by the "
    "profile — a version-mutable / SRI-less / untrusted third-party script can be "
    "compromised to deface, skim, or inject (brand, user, and data harm), and the same "
    "script matters far more on an app handling auth/PII/payments than on a marketing "
    "page. Reputable, widely-used, integrity-pinned providers carry no real risk → do "
    "NOT flag them or emit one finding per script. Do NOT re-classify party-ness. When "
    "a script carries no real risk, omit it. The ABSENCE of scripts is NOT a finding "
    "(never report 'no scripts loaded'); do NOT emit 'verify/ensure X' reminders or "
    "flag load-balancer/WAF/RUM cookies (F5, ADRUM, …).\n\n"
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
    SLOT_SUMMARY_SYSTEM: {
        "label": "Executive summary — system",
        "description": "Writes the executive.html narrative (posture paragraph, "
                       "per-risk 'why it matters', next steps) from the deterministic "
                       "scan facts. One call per run; degrades to templated prose.",
        "default_text": _DEFAULT_SUMMARY_SYSTEM,
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
# Language directives (report.language == "tr"). Appended to the SYSTEM prompt so
# the AI writes its FREE-TEXT prose in Turkish. Vulnerability/finding NAMES, enum
# tokens and technology names stay English (translating them reads sloppy and
# breaks the enum validators). Only the profile summary + executive summary get
# this; triage/supply-chain finding text stays English.
# ---------------------------------------------------------------------------

_TR_PROFILE_DIRECTIVE = (
    "\n\nÖNEMLİ (dil): `app_type` ve `reasoning` alanlarını TÜRKÇE yaz. Ancak enum "
    "değerlerini (`audience`, `confidence`) ve `expected_controls` token'larını "
    "İngilizce bırak (HSTS, Content-Security-Policy, Secure-cookies, ...). "
    "`detected_tech` teknoloji adları orijinal/İngilizce kalsın."
)

_TR_SUMMARY_DIRECTIVE = (
    "\n\nÖNEMLİ (dil): Tüm serbest metin alanlarını — `posture_narrative`, "
    "`risk_notes[].why` ve `recommendations` — TÜRKÇE yaz; bu yönetici raporu Türk "
    "üst yönetime sunulacak. Ancak güvenlik açığı / bulgu ADLARINI ve teknik "
    "terimleri İngilizce bırak (ör. 'HSTS', 'SQL Injection', 'CSP'); bunları çevirme."
)


def _with_language(system: str, language: str, directive: str) -> str:
    return system + directive if language == "tr" else system


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_profile_prompt(
    signals: PageSignals,
    overrides: Mapping[str, str] | None = None,
    *,
    rendered_text: str | None = None,
    surface: dict | None = None,
    language: str = "en",
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
    # When the page was rendered in a headless browser (render auto/always), attach
    # the rendered visible text and the observed resource/endpoint/cookie/storage
    # manifest (names only). Far richer than the pre-JS snippet for SPAs.
    if rendered_text:
        payload["rendered_body_text"] = rendered_text
    if surface:
        payload["observed_resources"] = surface
    user_msg = (
        f"Application signals (raw pre-JavaScript root page):\n"
        f"```json\n{json.dumps(payload, indent=2, ensure_ascii=False)}\n```\n\n"
        f"{_PROFILE_SHAPE_HINT}"
    )
    system = _with_language(resolved_prompt(SLOT_PROFILE_SYSTEM, overrides),
                            language, _TR_PROFILE_DIRECTIVE)
    return system, user_msg


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


def build_summary_prompt(
    posture: dict[str, Any],
    counts: dict[str, int],
    scale: dict[str, int],
    risks: list[dict[str, Any]],
    overrides: Mapping[str, str] | None = None,
    language: str = "en",
) -> tuple[str, str]:
    """Whole-run executive summary (the `ai.summary` call). The deterministic core
    is supplied as facts; the LLM only writes prose keyed to the given risk `ref`s.

    `risks` is the projected ExecRisk payload: each entry carries `ref`, `title`,
    `source`, `severity`, `host_count`.
    """
    payload = {
        "posture_rating": posture.get("rating"),
        "volume_note": posture.get("volume_note"),
        "finding_counts_by_severity": counts,
        "scale": scale,
        "top_risks": risks,
    }
    user_msg = (
        f"Deterministic assessment facts (authoritative — do not contradict):\n"
        f"```json\n{json.dumps(payload, indent=2, ensure_ascii=False)}\n```\n\n"
        f"{_EXEC_SUMMARY_SHAPE_HINT}"
    )
    system = _with_language(resolved_prompt(SLOT_SUMMARY_SYSTEM, overrides),
                            language, _TR_SUMMARY_DIRECTIVE)
    return system, user_msg


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
    if slot_id == SLOT_SUMMARY_SYSTEM:
        return build_summary_prompt(
            {"rating": "HIGH", "volume_note": "24 high-severity findings, 18 hosts"},
            {"critical": 0, "high": 24, "medium": 66, "low": 47, "info": 7},
            {"live": 156, "live_servers": 35, "dead": 126},
            [
                {"ref": 0, "title": "Exposed admin panel", "source": "nuclei",
                 "severity": "high", "host_count": 3},
                {"ref": 1, "title": "Missing HSTS", "source": "headers",
                 "severity": "medium", "host_count": 18},
            ],
            ovr,
        )
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
