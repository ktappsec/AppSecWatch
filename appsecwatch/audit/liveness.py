"""Assessability — did a host actually return a real application surface?

The pipeline probes DNS-live hosts with httpx, but many "live" responses are not
applications: 5xx gateway timeouts, 401/403/429 blocks, and — critically — WAF
block pages that answer **HTTP 200** with a rejection body ("Request Rejected",
"Aradığınız sayfaya ulaşılamıyor"). Rating security headers on those is noise, and
suppressing every finding on them makes the host read as *clean* when it was never
assessed at all.

`classify_assessability` is the single source of truth for that distinction. It is a
pure function over the already-captured `PageSignals` (no new requests). A host that
is NOT assessable has its findings suppressed with a `coverage` verdict and is listed
in a dedicated "not assessed / blocked" section instead of counting toward posture.

The classification is deliberately conservative: a 2xx with real content, a form, or a
password input is always assessed. Only clear error/block signatures flip it.
"""
from __future__ import annotations

from appsecwatch.models import AIFindingVerdict, Finding, LiveWebServer, PageSignals

# Substrings (matched case-insensitively against title + visible body text) that
# identify a WAF / edge block page even when it answers 200. Kept tight to avoid
# flipping legitimate content; extend as new block templates are observed.
_BLOCK_MARKERS: tuple[str, ...] = (
    "request rejected",                     # F5 ASM / BIG-IP
    "aradığınız sayfaya ulaşılamıyor",     # Turkish generic block/error page
    "sorry, you have been blocked",         # Cloudflare
    "attention required",                   # Cloudflare challenge
    "access denied",                        # Akamai / generic
    "web page blocked",                     # Imperva / Palo Alto
    "the requested url was rejected",       # F5 ASM variant
    "this request was blocked",
)

# Below this many chars of visible body text (and with no form), a 401/403/429 is
# treated as a bare block/error stub rather than a served application.
_TINY_BODY_CHARS = 32

# Status codes that, with a tiny/empty body, indicate a block rather than an app.
_BLOCK_STATUSES = frozenset({401, 403, 429})


def _has_block_marker(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _BLOCK_MARKERS)


def classify_assessability(signals: PageSignals) -> tuple[bool, str | None]:
    """Return ``(assessed, reason)`` for a probed host.

    ``assessed`` is False when the response is not a real application surface:
      * no HTTP response at all (``status_code`` is None);
      * a server error (``status_code >= 500``);
      * a WAF/block signature — a block-marker phrase in the title/body at any
        status, or a 401/403/429 with an empty/tiny body and no form.

    A real app (has a password input or a form, or serves non-trivial content at a
    2xx/3xx without a block marker) is always assessed. ``reason`` is a short human
    string when not assessed, else None.
    """
    text = f"{signals.title or ''} {signals.body_snippet or ''}"

    # A block-page phrase is decisive regardless of status (covers the 200 WAF pages).
    if _has_block_marker(text):
        return False, "WAF/block page"

    status = signals.status_code
    if status is None:
        return False, "no HTTP response"
    if status >= 500:
        return False, f"server error ({status})"

    # A real form/login is an application even at an odd status → assessed.
    if signals.has_password_input or signals.form_count > 0:
        return True, None

    if status in _BLOCK_STATUSES:
        body_len = len((signals.body_snippet or "").strip())
        if body_len < _TINY_BODY_CHARS:
            return False, f"blocked/forbidden ({status})"

    return True, None


def not_assessed_hosts(live_servers: list[LiveWebServer]) -> dict[str, str]:
    """Map host → reason for every live server that was probed but not assessable."""
    return {
        s.host: (s.not_assessed_reason or "not assessed")
        for s in live_servers
        if s.host and not s.assessed
    }


def apply_coverage_suppressions(
    findings: list[Finding], live_servers: list[LiveWebServer]
) -> int:
    """Suppress every finding on a not-assessed host with a ``coverage`` verdict.

    A blocked/error response is not a real application surface, so rating its headers
    is noise — but silently dropping the findings would make the host read as *clean*.
    Instead we hide them from the report body + severity counts + posture (via the
    existing ``.suppressed`` machinery) while keeping them in findings.json, and the
    host is listed in the report's 'not assessed' section. Only findings without an
    existing verdict are touched, so a prior AI/manual verdict is never overwritten.
    """
    blocked = not_assessed_hosts(live_servers)
    if not blocked:
        return 0
    n = 0
    for f in findings:
        if f.host in blocked and f.ai_verdict is None:
            f.ai_verdict = AIFindingVerdict(
                suppressed=True,
                confidence="high",
                reason=f"host not assessed: {blocked[f.host]}",
                source="coverage",
            )
            n += 1
    return n
