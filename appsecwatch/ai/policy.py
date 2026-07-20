"""Deterministic, profile-driven triage policy — the half of triage the LLM must NOT decide.

Motivated by a cross-scan audit of the AI layer (see DESIGN.md §2.3): re-running the
SAME scan flipped the keep/suppress decision on ~22% of the low-value header classes
(Referrer-Policy, Permissions-Policy, X-Content-Type-Options, X-Frame-Options,
CSP-missing). Those classes have no per-host nuance worth an LLM call — the answer is
a function of the app profile, not of prose judgment — so an independently-sampled
verdict per run is pure noise: the same finding appears in one report and vanishes from
the next. Temperature is already 0, so sampling is not the lever; the fix is to take
the decision away from the model.

Two rules, both deterministic:

  1. WITHHELD CLASSES (`POLICY_CHECK_IDS`) never enter the triage prompt at all
     (`analyzer._suppressable_payload` skips them), so the model can neither hide them
     nor flip on them. `policy_verdict()` decides them instead: kept visible by default,
     and suppressed ONLY for the one case with a real N/A argument — a control that a
     non-browser JSON API structurally cannot benefit from (clickjacking, Referrer-Policy,
     Permissions-Policy on an `is_api` profile). X-Content-Type-Options and a missing CSP
     are NEVER auto-suppressed: `nosniff` still matters to an API (a JSON body sniffed as
     HTML is an XSS vector) and a missing CSP is a real gap on anything a browser renders.

  2. EXPECTED-CONTROL PROTECTION (`protected_control`): on a host whose profile says it
     handles auth / PII / payments, the AI may not suppress a finding on a control the
     app is expected to have. This is what let the model hide `hsts.weak` on ~79 banking
     hosts by inventing a preload threshold ("120-day minimum" — there is no such thing;
     the real HSTS-preload minimum is max-age >= 31536000). The verdict is still attached
     (advisory, `suppressed=False`) so the call stays auditable.

`looks_like_csp()` backstops the CSP prompt rule: the deterministic `csp` scanner already
grades CSP in depth, and the model re-emitted its findings as its own (~69 duplicate rows).

Everything here is pure + synchronous — no LLM, no I/O — so it holds under an AI degrade.
"""
from __future__ import annotations

from appsecwatch.models import AIFindingVerdict, AppProfile, Finding

# Deterministic-only classes: withheld from the triage prompt entirely (never offered
# to the LLM → never LLM-suppressed, never flipped) and decided by `policy_verdict`.
POLICY_CHECK_IDS: frozenset[str] = frozenset({
    "clickjacking.missing",
    "referrer-policy.missing",
    "referrer-policy.weak",
    "permissions-policy.missing",
    "xcto.missing",
    "csp.missing",
})

# The subset of the above that a non-browser JSON API structurally cannot benefit from:
# it is not rendered in a frame, is not a referrer source, and exposes no browser
# features. `xcto.missing` and `csp.missing` are deliberately NOT here — see module docstring.
_API_NA_CHECK_IDS: frozenset[str] = frozenset({
    "clickjacking.missing",
    "referrer-policy.missing",
    "referrer-policy.weak",
    "permissions-policy.missing",
})

# Controls that a sensitive app (auth/PII/payments) is expected to have even when the
# profiler forgot to list them — protection must not hinge on the LLM remembering to
# emit the token. HSTS is the one the model actually hallucinated its way past.
_IMPLIED_SENSITIVE_CONTROLS: frozenset[str] = frozenset({
    "HSTS", "Secure-cookies", "HttpOnly-cookies",
})

_CSP_MARKERS = ("csp", "content-security-policy", "content security policy")


def expected_control_for(check_id: str | None) -> str | None:
    """The canonical `expected_controls` token a deterministic check maps to, if any.

    Mirrors the fixed vocabulary the profiler is allowed to emit (see the profile
    shape-hint in `prompts.py`); returns None for checks that aren't a named control.
    """
    cid = (check_id or "").strip().lower()
    if not cid:
        return None
    if cid.startswith("hsts."):
        return "HSTS"
    if cid.startswith("csp."):
        return "Content-Security-Policy"
    if cid.startswith("clickjacking."):
        return "X-Frame-Options"
    if cid == "cookie.secure":
        return "Secure-cookies"
    if cid == "cookie.httponly":
        return "HttpOnly-cookies"
    if cid == "cookie.samesite":
        return "SameSite-cookies"
    return None


def is_sensitive(profile: AppProfile | None) -> bool:
    """The app handles authentication, personal data, or payments (per its profile)."""
    return bool(
        profile is not None
        and profile.usable
        and (profile.handles_auth or profile.handles_pii or profile.handles_payments)
    )


def _is_non_browser_api(profile: AppProfile | None) -> bool:
    return bool(
        profile is not None
        and profile.usable
        and profile.is_api
        and profile.confidence != "low"
    )


def protected_control(finding: Finding, profile: AppProfile | None) -> str | None:
    """The expected-control token that makes this finding un-suppressible on this host.

    Returns the control name (for the audit trail) when the host is sensitive AND the
    finding maps to a control the app is expected to have — either listed in the
    profile's `expected_controls` or implied for any sensitive app. None otherwise
    (the AI's verdict is free to apply).
    """
    if not is_sensitive(profile):
        return None
    control = expected_control_for(finding.check_id)
    if control is None:
        return None
    assert profile is not None  # is_sensitive
    expected = {c.strip().lower() for c in profile.expected_controls}
    if control.lower() in expected or control in _IMPLIED_SENSITIVE_CONTROLS:
        return control
    return None


def policy_verdict(finding: Finding, profile: AppProfile | None) -> AIFindingVerdict | None:
    """The deterministic verdict for a withheld class, or None to leave it visible.

    Only ever returns a SUPPRESSING verdict — "keep" needs no verdict (an untouched
    finding is a visible finding). Findings outside `POLICY_CHECK_IDS` are not this
    function's business and always return None.
    """
    cid = (finding.check_id or "").strip().lower()
    if cid not in POLICY_CHECK_IDS:
        return None
    if cid in _API_NA_CHECK_IDS and _is_non_browser_api(profile):
        assert profile is not None  # _is_non_browser_api
        app = profile.app_type or "non-browser API"
        return AIFindingVerdict(
            suppressed=True,
            confidence="high",
            reason=(
                f"not applicable — this host is profiled as a non-browser API ({app}); "
                f"the control only protects browser-rendered pages"
            ),
            source="policy",
        )
    return None


def looks_like_csp(*texts: str) -> bool:
    """True when an AI finding is about CSP (so it duplicates the deterministic `csp`
    scanner, which grades missing / report-only / unsafe-inline / unsafe-eval / wildcard
    / insecure-scheme / object-src / base-uri and owns those rows)."""
    blob = " ".join(t for t in texts if t).lower()
    return any(m in blob for m in _CSP_MARKERS)
