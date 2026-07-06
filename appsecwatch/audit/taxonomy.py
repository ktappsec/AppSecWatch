"""Controlled finding-class taxonomy — the ONE cross-source classification.

Every ``Finding`` (deterministic or AI) is mapped to exactly one stable
``finding_class`` drawn from a fixed vocabulary, and each class rolls up into one
display ``category``. This is deliberately a *closed* set: a small, fixed
vocabulary is what gives findings a **stable cross-scan identity** (so the same
issue correlates run-to-run even when a tool's wording drifts) and a coherent
**category grouping** for the report + UI density collapse.

Reused by:
  * ``ai/analyzer`` — AI findings must emit a class from this vocabulary; their
    cross-scan identity keys on ``(host, class)`` rather than the drifting title.
  * ``report/aggregator`` + ``api/result`` — a classification pass stamps
    ``finding.finding_class`` / ``finding.category`` so both ``result.json`` and
    the report context carry them (Pydantic *properties* aren't serialized, so
    these must be real model fields set before dump).
  * ``api/finding_state`` + the analytics page — per-class lifecycle + breakdowns.

``classify()`` is TOTAL and deterministic: an unmapped finding falls back to
``misc.uncategorized`` (category ``other``), never raising.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid an import cycle at module load (models imports nothing here)
    from appsecwatch.models import Finding

# --------------------------------------------------------------------------- #
# Categories (display order + label). Labels stay ENGLISH — finding/vuln names
# are never translated (a Turkish report keeps class names English by design).
# --------------------------------------------------------------------------- #
CATEGORY_LABELS: dict[str, str] = {
    "transport": "Transport & TLS",
    "headers": "Security Headers",
    "csp": "Content Security Policy",
    "auth": "Authentication & Session",
    "injection": "Injection & Input Validation",
    "exposure": "Access Control & Exposure",
    "supply": "Supply Chain & Dependencies",
    "infra": "Infrastructure & Takeover",
    "disclosure": "Information Disclosure",
    "crypto": "Cryptography & Secrets",
    "other": "Other",
}
CATEGORY_ORDER: tuple[str, ...] = tuple(CATEGORY_LABELS)

# --------------------------------------------------------------------------- #
# The closed class vocabulary → its category.
# --------------------------------------------------------------------------- #
CATEGORY_OF: dict[str, str] = {
    # Transport & TLS
    "tls.weak-protocol": "transport",
    "tls.weak-cipher": "transport",
    "tls.cert-expired": "transport",
    "tls.cert-invalid": "transport",
    "tls.cert-weak-key": "transport",
    "tls.cert-weak-sig": "transport",
    "tls.insecure-renegotiation": "transport",
    # Security Headers
    "headers.hsts-missing": "headers",
    "headers.xfo-missing": "headers",
    "headers.xcto-missing": "headers",
    "headers.referrer-policy": "headers",
    "headers.permissions-policy": "headers",
    "headers.cookie-security": "headers",
    "headers.info-leak-header": "headers",
    # Content Security Policy
    "csp.missing": "csp",
    "csp.unsafe-inline": "csp",
    "csp.unsafe-eval": "csp",
    "csp.wildcard-source": "csp",
    "csp.missing-frame-ancestors": "csp",
    "csp.weak-directive": "csp",
    # Authentication & Session
    "auth.exposed-login": "auth",
    "auth.default-credential": "auth",
    "auth.token-exposure": "auth",
    "auth.missing-auth": "auth",
    "auth.session-fixation": "auth",
    # Injection & Input Validation
    "injection.sqli": "injection",
    "injection.xss": "injection",
    "injection.command": "injection",
    "injection.ssrf": "injection",
    "injection.xxe": "injection",
    "injection.template": "injection",
    "injection.open-redirect": "injection",
    "injection.path-traversal": "injection",
    # Access Control & Exposure
    "exposure.admin-panel": "exposure",
    "exposure.sensitive-file": "exposure",
    "exposure.directory-listing": "exposure",
    "exposure.debug-interface": "exposure",
    "exposure.api-docs": "exposure",
    # Supply Chain & Dependencies
    "supply.vulnerable-js-lib": "supply",
    "supply.sri-missing": "supply",
    "supply.untrusted-3p-script": "supply",
    "supply.outdated-dependency": "supply",
    # Infrastructure & Takeover
    "takeover.dangling-cname": "infra",
    "takeover.dangling-nxdomain": "infra",
    "infra.subdomain-takeover": "infra",
    "infra.misconfiguration": "infra",
    # Information Disclosure
    "disclosure.version-banner": "disclosure",
    "disclosure.stack-trace": "disclosure",
    "disclosure.internal-address": "disclosure",
    "disclosure.sensitive-data": "disclosure",
    # Cryptography & Secrets
    "secrets.exposed-key": "crypto",
    "crypto.weak-algorithm": "crypto",
    # Safety net
    "misc.uncategorized": "other",
}

FINDING_CLASSES: frozenset[str] = frozenset(CATEGORY_OF)

# Per-source default when nothing more specific matches (still a valid class).
_SOURCE_DEFAULT: dict[str, str] = {
    "nuclei": "misc.uncategorized",
    "takeover": "infra.subdomain-takeover",
    "sslscan": "tls.cert-invalid",
    "headers": "headers.info-leak-header",
    "csp": "csp.weak-directive",
    "js_lib": "supply.vulnerable-js-lib",
    "zap": "misc.uncategorized",
    "ai_headers": "headers.info-leak-header",
    "ai_supply_chain": "supply.untrusted-3p-script",
}

# Keyword → class, scanned in order over a lowercased "template_id + title" blob.
# Used for the free-text sources (nuclei / zap / AI fallback). First hit wins, so
# order matters (specific before generic).
_KEYWORD_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("sql-injection", "sqli", "sql injection"), "injection.sqli"),
    (("cross-site-scripting", "xss", "cross site scripting"), "injection.xss"),
    (("command-injection", "rce", "remote-code", "os command", "code-execution",
      "code execution"), "injection.command"),
    (("ssrf", "server-side request"), "injection.ssrf"),
    (("xxe", "xml-external", "xml external"), "injection.xxe"),
    (("ssti", "template-injection", "template injection"), "injection.template"),
    (("open-redirect", "open redirect"), "injection.open-redirect"),
    (("path-traversal", "directory-traversal", "lfi", "local-file",
      "path traversal", "directory traversal"), "injection.path-traversal"),
    (("default-login", "default-credential", "default password",
      "default creds"), "auth.default-credential"),
    (("login", "signin", "sign-in", "authentication-required"), "auth.exposed-login"),
    (("directory-listing", "dir-listing", "directory listing"), "exposure.directory-listing"),
    (("swagger", "openapi", "api-docs", "graphql"), "exposure.api-docs"),
    (("actuator", "debug", "stacktrace", "phpinfo", "trace.axd"), "exposure.debug-interface"),
    (("admin-panel", "admin-login", "admin-interface", "adminer",
      "phpmyadmin", "dashboard"), "exposure.admin-panel"),
    (("git-config", ".git", ".env", "backup", "config-file", "exposed-config",
      "sensitive-file", "credentials-disclosure", "exposure"), "exposure.sensitive-file"),
    (("takeover",), "infra.subdomain-takeover"),
    (("misconfig", "misconfiguration"), "infra.misconfiguration"),
    (("stack-trace", "stack trace", "error-page"), "disclosure.stack-trace"),
    (("private-ip", "internal-ip", "internal-address"), "disclosure.internal-address"),
    (("secret", "api-key", "apikey", "access-key", "private-key",
      "token-disclosure"), "secrets.exposed-key"),
    (("weak-cipher", "weak-crypto", "weak-algorithm"), "crypto.weak-algorithm"),
    (("version", "detect", "banner", "tech-detect", "fingerprint"),
     "disclosure.version-banner"),
)


def _keyword_class(blob: str, default: str) -> str:
    for needles, cls in _KEYWORD_RULES:
        if any(n in blob for n in needles):
            return cls
    return default


def _classify_headers(check_id: str) -> str:
    cid = check_id.lower()
    if cid.startswith("hsts"):
        return "headers.hsts-missing"
    if cid.startswith("xcto"):
        return "headers.xcto-missing"
    if cid.startswith("clickjacking"):
        return "headers.xfo-missing"
    if cid.startswith("referrer-policy"):
        return "headers.referrer-policy"
    if cid.startswith("permissions-policy"):
        return "headers.permissions-policy"
    if cid.startswith("cookie."):
        return "headers.cookie-security"
    # info-disclosure.* / xss-protection.legacy / cross-origin isolation / cache
    # / clear-site-data → the generic header info-leak/hardening class.
    return "headers.info-leak-header"


def _classify_csp(check_id: str) -> str:
    cid = check_id.lower()
    if cid in ("csp.missing", "csp.report-only"):
        return "csp.missing"
    if "unsafe-inline" in cid:
        return "csp.unsafe-inline"
    if "unsafe-eval" in cid:
        return "csp.unsafe-eval"
    if "wildcard" in cid or "insecure-scheme" in cid:
        return "csp.wildcard-source"
    if "frame-ancestors" in cid:
        return "csp.missing-frame-ancestors"
    return "csp.weak-directive"


def _classify_tls(f: "Finding") -> str:
    name = ((f.evidence or {}).get("check") or f.title or "").lower()
    if "renegotiation" in name:
        return "tls.insecure-renegotiation"
    if "weak cipher" in name or "ciphers" in name:
        return "tls.weak-cipher"
    if "disabled" in name and ("ssl" in name or "tls" in name):
        return "tls.weak-protocol"
    if "signature" in name:
        return "tls.cert-weak-sig"
    if "key" in name:
        return "tls.cert-weak-key"
    if "days remaining" in name or "valid" in name or "expired" in name:
        return "tls.cert-expired"
    return "tls.cert-invalid"


def classify(f: "Finding") -> tuple[str, str]:
    """Map a finding to ``(category, finding_class)``. Total + deterministic."""
    src = f.source
    ev = f.evidence or {}

    # AI findings carry an explicit class once the model emits one (analyzer sets
    # evidence['class']); honor it when it's a valid vocabulary member.
    declared = ev.get("class")
    if isinstance(declared, str) and declared in FINDING_CLASSES:
        return CATEGORY_OF[declared], declared

    if src == "headers":
        cls = _classify_headers(f.check_id or "")
    elif src == "csp":
        cls = _classify_csp(f.check_id or "")
    elif src == "sslscan":
        cls = _classify_tls(f)
    elif src == "js_lib":
        cls = "supply.vulnerable-js-lib"
    elif src == "takeover":
        cls = "infra.subdomain-takeover"
    elif src in ("nuclei", "zap"):
        blob = f"{ev.get('template_id', '')} {f.title}".lower()
        cls = _keyword_class(blob, _SOURCE_DEFAULT[src])
    elif src == "ai_supply_chain":
        blob = f"{f.check_id or ''} {f.title}".lower()
        if "sri" in blob or "subresource" in blob:
            cls = "supply.sri-missing"
        elif "outdated" in blob or "version" in blob:
            cls = "supply.outdated-dependency"
        elif "third" in blob or "3p" in blob or "untrusted" in blob:
            cls = "supply.untrusted-3p-script"
        else:
            cls = _keyword_class(blob, _SOURCE_DEFAULT[src])
    elif src == "ai_headers":
        cls = _keyword_class(f"{f.check_id or ''} {f.title}".lower(),
                             _SOURCE_DEFAULT[src])
        # keep header-ish AI findings in the headers/csp families when possible
        if cls == _SOURCE_DEFAULT[src]:
            blob = (f.check_id or f.title or "").lower()
            if "csp" in blob:
                cls = _classify_csp(blob if blob.startswith("csp") else f"csp.{blob}")
            elif "cookie" in blob:
                cls = "headers.cookie-security"
    else:
        cls = _SOURCE_DEFAULT.get(src, "misc.uncategorized")

    if cls not in FINDING_CLASSES:  # defensive — never emit an unknown class
        cls = "misc.uncategorized"
    return CATEGORY_OF[cls], cls


def classify_findings(findings: list["Finding"]) -> None:
    """Stamp ``category`` + ``finding_class`` on each finding in place. Idempotent."""
    for f in findings:
        cat, cls = classify(f)
        f.category = cat
        f.finding_class = cls


def vocabulary_hint() -> str:
    """Compact category-grouped class list, injected into AI prompts so the model
    emits a class from the fixed vocabulary."""
    by_cat: dict[str, list[str]] = {}
    for cls, cat in CATEGORY_OF.items():
        by_cat.setdefault(cat, []).append(cls)
    return "; ".join(
        f"{cat} ({', '.join(sorted(by_cat[cat]))})"
        for cat in CATEGORY_ORDER if cat in by_cat
    )
