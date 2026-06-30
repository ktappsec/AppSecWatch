"""Recognition of infrastructure cookies (load balancer / WAF / RUM telemetry).

These cookies are emitted by network appliances and monitoring agents, NOT by the
application: F5 BIG-IP persistence / ASM / APM cookies, cloud & appliance load
balancers (AWS ALB, Citrix NetScaler), WAF/CDN edges (Cloudflare, Imperva,
Akamai), and RUM agents (AppDynamics, Dynatrace). They are opaque routing /
affinity / telemetry tokens that carry no session or auth state, so flagging them
for a missing HttpOnly/Secure/SameSite flag is noise — an attacker who reads one
via JavaScript gains nothing exploitable. WatchTower drops cookie-flag findings
for them entirely (high-signal output, see AGENTS.md).

``is_infra_cookie(name)`` is the single source of truth, reused by the
deterministic header check (``audit/header_checks.py``) and the AI triage guard
(``ai/analyzer.py``).
"""
from __future__ import annotations

import re

# Each alternative is matched (case-insensitively) against the cookie NAME only.
# Anchored with ^…(and $ where an exact name is expected) to keep false matches
# on real application cookies near zero.
_INFRA_COOKIE_PATTERNS: tuple[str, ...] = (
    # --- F5 BIG-IP (LTM persistence, ASM/Advanced WAF, AVR, APM) ---
    r"^BIGipServer",                       # LTM pool persistence
    r"^TS[0-9a-f]{6,}$",                    # ASM / Advanced WAF (e.g. TS01a5e83e)
    r"^f5avr",                             # AVR analytics (e.g. f5avraaaa..._session_)
    r"^f5_cspm",                           # client-side posture module
    r"^F5_",                               # APM (F5_ST, F5_fullWT, …)
    r"^MRHSession$", r"^LastMRH_Session$",  # APM session
    # --- Cloud / appliance load balancers ---
    r"^AWSALB",                            # AWS ALB stickiness (AWSALB, AWSALBCORS)
    r"^NSC_",                              # Citrix NetScaler
    # --- WAF / CDN edge ---
    r"^__cf",                              # Cloudflare (__cflb, __cf_bm, __cfduid)
    r"^incap_ses", r"^visid_incap",        # Imperva Incapsula
    r"^ak_bmsc$", r"^bm_sz$", r"^_abck$",  # Akamai Bot Manager
    # --- RUM / telemetry agents ---
    r"^ADRUM",                             # AppDynamics
    r"^dtCookie$", r"^dtLatC$", r"^dtPC$", r"^dtSa$",  # Dynatrace
    r"^rxVisitor$", r"^rxvt$",             # Dynatrace (legacy)
)

_INFRA_COOKIE_RE = re.compile("|".join(_INFRA_COOKIE_PATTERNS), re.IGNORECASE)


def is_infra_cookie(name: str) -> bool:
    """True when ``name`` is a load-balancer / WAF / RUM cookie (no app or session
    state), so its missing HttpOnly/Secure/SameSite flags are not a finding."""
    return bool(name) and bool(_INFRA_COOKIE_RE.match(name.strip()))
