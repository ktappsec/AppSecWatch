"""Deterministic security-header analysis (the `headers` capability).

Pure, passive evaluation over the response headers WatchTower already captured
during the httpx recon pass (`PageSignals`) — zero new requests. Two sub-steps:

  * ``headers.best-practice`` — the OWASP Secure Headers catalog (HSTS, clickjacking,
    nosniff, Referrer-Policy, Permissions-Policy, cookie flags, info-disclosure,
    deprecated X-XSS-Protection) plus situational cross-origin / cache controls.
  * ``headers.csp`` — a structured Content-Security-Policy parse with
    high-confidence weakness rules (unsafe-inline/eval, wildcards, insecure
    schemes, missing object-src/base-uri, report-only-only).

Design (see DESIGN.md / project-header-checks):
  - Mechanical + response-fact calibration ONLY. Rules read facts they can see
    unambiguously (URL scheme, content-type, set-cookie, has_password_input) to
    avoid the dumbest false-positives — e.g. HSTS is N/A on http, clickjacking is
    informational on a JSON endpoint, situational headers only fire on apparently
    sensitive pages. They never *infer business context*; that (and false-positive
    suppression) is the AI's job downstream.
  - Every finding carries a stable, host-unique ``check_id`` the AI references to
    soft-suppress it. The deterministic findings always stand on their own.

These functions return plain ``Finding`` objects; the ``HeadersStage`` fans them
out per host and the ``ai.headers`` stage may later attach suppression verdicts.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from watchtower.audit.cookies import is_infra_cookie
from watchtower.config import HeadersConfig
from watchtower.models import Finding, PageSignals, Severity

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

_SESSION_COOKIE_RE = re.compile(r"sess|auth|token|jwt|sid|login|csrf", re.IGNORECASE)
_HSTS_RECOMMENDED_MAX_AGE = 31_536_000  # 1 year (OWASP)


def _is_https(url: str) -> bool:
    return urlparse(url).scheme == "https"


def _content_type(headers: dict[str, str]) -> str:
    return (headers.get("content-type") or "").split(";")[0].strip().lower()


def _is_html(ct: str) -> bool:
    return ct in ("text/html", "application/xhtml+xml") or not ct  # blank ct → assume framable


def _is_json(ct: str) -> bool:
    return ct == "application/json" or ct.endswith("+json")


def _cookie_name(raw: str) -> str:
    return raw.split("=", 1)[0].strip()


def _has_flag(raw: str, flag: str) -> bool:
    return any(seg.strip().lower().startswith(flag) for seg in raw.split(";"))


def _apparently_sensitive(signals: PageSignals) -> bool:
    """Response-fact heuristic for 'this page handles a session' — gates the
    noisier situational checks so they don't spam every static asset."""
    if signals.has_password_input:
        return True
    return any(
        _SESSION_COOKIE_RE.search(name) and not is_infra_cookie(name)
        for name in (_cookie_name(c) for c in signals.set_cookies)
    )


# ---------------------------------------------------------------------------
# finding builder (severity overrides + disabled-check filtering)
# ---------------------------------------------------------------------------

class _Emitter:
    """Collects findings for one host, applying config overrides + disables."""

    def __init__(self, host: str, cfg: HeadersConfig) -> None:
        self.host = host
        self.cfg = cfg
        self.findings: list[Finding] = []

    def _disabled(self, check_id: str) -> bool:
        return any(check_id == d or check_id.startswith(d + ".") or check_id.startswith(d)
                   for d in self.cfg.disabled_checks)

    def add(
        self,
        *,
        source: str,
        check_id: str,
        severity: Severity,
        title: str,
        description: str,
        evidence: dict | None = None,
    ) -> None:
        if self._disabled(check_id):
            return
        sev: Severity = self.cfg.severity_overrides.get(check_id, severity)  # type: ignore[assignment]
        ev = {"check_id": check_id, **(evidence or {})}
        self.findings.append(Finding(
            source=source,  # type: ignore[arg-type]
            host=self.host,
            severity=sev,
            title=title,
            description=description,
            evidence=ev,
            check_id=check_id,
        ))


# ---------------------------------------------------------------------------
# best-practice catalog
# ---------------------------------------------------------------------------

def check_best_practice(url: str, signals: PageSignals, em: _Emitter) -> None:
    h = signals.headers
    https = _is_https(url)
    ct = _content_type(h)
    sensitive = _apparently_sensitive(signals)

    # --- HSTS (https only) -------------------------------------------------
    if https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            em.add(source="headers", check_id="hsts.missing", severity="medium",
                   title="Missing HTTP Strict-Transport-Security (HSTS)",
                   description="No Strict-Transport-Security header on an HTTPS host; "
                               "clients are not pinned to HTTPS and remain exposed to SSL-strip.",
                   evidence={"header": "strict-transport-security", "observed": "(absent)"})
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            max_age = int(m.group(1)) if m else 0
            no_sub = "includesubdomains" not in hsts.lower()
            if max_age < _HSTS_RECOMMENDED_MAX_AGE or no_sub:
                why = []
                if max_age < _HSTS_RECOMMENDED_MAX_AGE:
                    why.append(f"max-age {max_age} < {_HSTS_RECOMMENDED_MAX_AGE} (1y)")
                if no_sub:
                    why.append("no includeSubDomains")
                em.add(source="headers", check_id="hsts.weak", severity="low",
                       title="Weak HSTS policy",
                       description="HSTS is present but " + " and ".join(why) + ".",
                       evidence={"header": "strict-transport-security", "observed": hsts})

    # --- X-Content-Type-Options -------------------------------------------
    xcto = (h.get("x-content-type-options") or "").lower()
    if "nosniff" not in xcto:
        em.add(source="headers", check_id="xcto.missing", severity="low",
               title="Missing X-Content-Type-Options: nosniff",
               description="Without nosniff, browsers may MIME-sniff responses, enabling "
                           "content-type confusion attacks.",
               evidence={"header": "x-content-type-options", "observed": xcto or "(absent)"})

    # --- Clickjacking (XFO or CSP frame-ancestors) ------------------------
    xfo = h.get("x-frame-options")
    csp = h.get("content-security-policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        if _is_json(ct):
            sev: Severity = "info"
            note = " The endpoint returns JSON and is not framable, so this is informational."
        elif _is_html(ct):
            sev = "medium"
            note = ""
        else:
            sev = "low"
            note = ""
        em.add(source="headers", check_id="clickjacking.missing", severity=sev,
               title="No clickjacking protection",
               description="Neither X-Frame-Options nor CSP frame-ancestors is set; the page "
                           "may be framed for clickjacking." + note,
               evidence={"header": "x-frame-options / frame-ancestors", "observed": "(absent)",
                         "content_type": ct or "(unknown)"})

    # --- Referrer-Policy --------------------------------------------------
    rp = (h.get("referrer-policy") or "").lower()
    if not rp:
        em.add(source="headers", check_id="referrer-policy.missing", severity="low",
               title="Missing Referrer-Policy",
               description="No Referrer-Policy; the browser default may leak full URLs to "
                           "third parties on cross-origin navigation.",
               evidence={"header": "referrer-policy", "observed": "(absent)"})
    elif rp in ("unsafe-url", "no-referrer-when-downgrade"):
        em.add(source="headers", check_id="referrer-policy.weak", severity="low",
               title="Weak Referrer-Policy",
               description=f"Referrer-Policy '{rp}' can leak referrer information; prefer "
                           "'strict-origin-when-cross-origin' or stricter.",
               evidence={"header": "referrer-policy", "observed": rp})

    # --- Permissions-Policy -----------------------------------------------
    if not h.get("permissions-policy") and not h.get("feature-policy"):
        em.add(source="headers", check_id="permissions-policy.missing", severity="info",
               title="Missing Permissions-Policy",
               description="No Permissions-Policy; powerful browser features (camera, "
                           "geolocation, etc.) are not explicitly restricted.",
               evidence={"header": "permissions-policy", "observed": "(absent)"})

    # --- Deprecated X-XSS-Protection --------------------------------------
    xxp = (h.get("x-xss-protection") or "").strip()
    if xxp and not xxp.startswith("0"):
        em.add(source="headers", check_id="xss-protection.legacy", severity="low",
               title="Deprecated X-XSS-Protection enabled",
               description="X-XSS-Protection is deprecated and its filter can introduce "
                           "vulnerabilities in legacy browsers; set it to '0' or remove it.",
               evidence={"header": "x-xss-protection", "observed": xxp})

    # --- Cookie flags (per cookie) ----------------------------------------
    for raw in signals.set_cookies:
        name = _cookie_name(raw) or "(unnamed)"
        # Load-balancer / WAF / RUM cookies (F5 BIG-IP, AWS ALB, Akamai, …) carry
        # no app or session state — their flag gaps are not a finding. Drop them.
        if is_infra_cookie(name):
            continue
        session_like = bool(_SESSION_COOKIE_RE.search(name))
        if https and not _has_flag(raw, "secure"):
            em.add(source="headers", check_id=f"cookie.secure.{name}", severity="medium",
                   title=f"Cookie '{name}' missing Secure flag",
                   description="Cookie set without Secure on an HTTPS host; it may be sent over "
                               "plaintext HTTP.",
                   evidence={"cookie": name, "flag": "Secure"})
        if not _has_flag(raw, "httponly"):
            em.add(source="headers", check_id=f"cookie.httponly.{name}",
                   severity="medium" if session_like else "low",
                   title=f"Cookie '{name}' missing HttpOnly flag",
                   description="Cookie is readable from JavaScript (no HttpOnly); a session/auth "
                               "cookie this way is exposed to XSS theft."
                               if session_like else
                               "Cookie is readable from JavaScript (no HttpOnly).",
                   evidence={"cookie": name, "flag": "HttpOnly"})
        if not _has_flag(raw, "samesite"):
            em.add(source="headers", check_id=f"cookie.samesite.{name}", severity="low",
                   title=f"Cookie '{name}' missing SameSite attribute",
                   description="No SameSite attribute; the cookie may be sent on cross-site "
                               "requests, aiding CSRF.",
                   evidence={"cookie": name, "flag": "SameSite"})

    # --- Information disclosure --------------------------------------------
    server = h.get("server") or ""
    if server and re.search(r"\d", server):
        em.add(source="headers", check_id="info-disclosure.server", severity="low",
               title="Server header discloses software version",
               description=f"Server header '{server}' reveals software/version, easing "
                           "targeted exploitation.",
               evidence={"header": "server", "observed": server})
    if h.get("x-powered-by"):
        em.add(source="headers", check_id="info-disclosure.x-powered-by", severity="low",
               title="X-Powered-By discloses technology",
               description=f"X-Powered-By '{h['x-powered-by']}' reveals the backend technology.",
               evidence={"header": "x-powered-by", "observed": h["x-powered-by"]})
    for hdr in ("x-aspnet-version", "x-aspnetmvc-version"):
        if h.get(hdr):
            em.add(source="headers", check_id="info-disclosure.aspnet", severity="low",
                   title=f"{hdr} discloses framework version",
                   description=f"{hdr} '{h[hdr]}' reveals the ASP.NET version.",
                   evidence={"header": hdr, "observed": h[hdr]})

    # --- Situational: cross-origin isolation + cache (sensitive pages) -----
    if sensitive:
        for hdr, cid, label in (
            ("cross-origin-opener-policy", "coop.missing", "Cross-Origin-Opener-Policy"),
            ("cross-origin-embedder-policy", "coep.missing", "Cross-Origin-Embedder-Policy"),
            ("cross-origin-resource-policy", "corp.missing", "Cross-Origin-Resource-Policy"),
        ):
            if not h.get(hdr):
                em.add(source="headers", check_id=cid, severity="info",
                       title=f"Missing {label}",
                       description=f"{label} is not set; cross-origin isolation is incomplete for "
                                   "a sensitive page.",
                       evidence={"header": hdr, "observed": "(absent)"})
        if not h.get("x-permitted-cross-domain-policies"):
            em.add(source="headers", check_id="permitted-xdp.missing", severity="info",
                   title="Missing X-Permitted-Cross-Domain-Policies",
                   description="Adobe cross-domain policy is not restricted (none).",
                   evidence={"header": "x-permitted-cross-domain-policies", "observed": "(absent)"})
        cc = (h.get("cache-control") or "").lower()
        if not any(tok in cc for tok in ("no-store", "private", "no-cache")):
            em.add(source="headers", check_id="cache-control.sensitive", severity="low",
                   title="Sensitive response may be cacheable",
                   description="A page that appears to handle a session lacks "
                               "Cache-Control: no-store/private; sensitive content may be cached.",
                   evidence={"header": "cache-control", "observed": cc or "(absent)"})
        if not h.get("clear-site-data"):
            em.add(source="headers", check_id="clear-site-data.hint", severity="info",
                   title="Consider Clear-Site-Data on logout",
                   description="This app appears to manage sessions; logout endpoints should "
                               "return Clear-Site-Data to purge client state. (Advisory.)",
                   evidence={"header": "clear-site-data", "observed": "(absent)"})


# ---------------------------------------------------------------------------
# CSP analysis
# ---------------------------------------------------------------------------

def parse_csp(policy: str) -> dict[str, list[str]]:
    """Parse a CSP string into {directive: [sources]} (directive names lowered)."""
    out: dict[str, list[str]] = {}
    for part in policy.split(";"):
        toks = part.split()
        if not toks:
            continue
        name = toks[0].lower()
        out[name] = toks[1:]
    return out


def _script_sources(directives: dict[str, list[str]]) -> list[str]:
    """Effective script sources: script-src, falling back to default-src."""
    if "script-src" in directives:
        return directives["script-src"]
    return directives.get("default-src", [])


def check_csp(url: str, signals: PageSignals, em: _Emitter) -> None:
    h = signals.headers
    enforced = h.get("content-security-policy")
    report_only = h.get("content-security-policy-report-only")
    ct = _content_type(h)

    if not enforced:
        if report_only:
            em.add(source="csp", check_id="csp.report-only", severity="medium",
                   title="CSP is report-only (not enforced)",
                   description="Only Content-Security-Policy-Report-Only is set; the policy "
                               "reports violations but does not block anything.",
                   evidence={"directive": "(report-only)", "observed": report_only[:300]})
        else:
            sev: Severity = "medium" if _is_html(ct) and not _is_json(ct) else "info"
            em.add(source="csp", check_id="csp.missing", severity=sev,
                   title="No Content-Security-Policy",
                   description="No CSP is set; the page has no defense-in-depth against XSS / "
                               "content injection.",
                   evidence={"directive": "content-security-policy", "observed": "(absent)"})
        return

    d = parse_csp(enforced)
    scripts = _script_sources(d)
    scripts_l = [s.lower() for s in scripts]
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha")) for s in scripts_l)

    if "'unsafe-inline'" in scripts_l:
        em.add(source="csp", check_id="csp.unsafe-inline.script-src", severity="high",
               title="CSP allows 'unsafe-inline' scripts",
               description="script-src permits 'unsafe-inline', which largely defeats CSP's XSS "
                           "protection. Use nonces/hashes with 'strict-dynamic' instead."
                           + ("" if has_nonce_or_hash else " (no nonce/hash present)"),
               evidence={"directive": "script-src", "observed": " ".join(scripts) or "(default-src)"})
    if "'unsafe-eval'" in scripts_l:
        em.add(source="csp", check_id="csp.unsafe-eval", severity="medium",
               title="CSP allows 'unsafe-eval'",
               description="script-src permits 'unsafe-eval', enabling eval()-based code "
                           "execution paths.",
               evidence={"directive": "script-src", "observed": " ".join(scripts)})
    if "*" in scripts_l:
        em.add(source="csp", check_id="csp.wildcard.script-src", severity="high",
               title="CSP script-src uses wildcard '*'",
               description="A wildcard script source allows scripts from any origin, negating "
                           "the policy.",
               evidence={"directive": "script-src", "observed": " ".join(scripts)})
    if any(s in ("http:", "data:") for s in scripts_l):
        em.add(source="csp", check_id="csp.insecure-scheme.script-src", severity="medium",
               title="CSP script-src allows an insecure scheme",
               description="script-src allows http: or data: sources, which are attacker-"
                           "controllable or unencrypted.",
               evidence={"directive": "script-src", "observed": " ".join(scripts)})

    # object-src should be 'none' (or default-src 'none')
    object_src = d.get("object-src", d.get("default-src"))
    if object_src is None or [s.lower() for s in object_src] != ["'none'"]:
        em.add(source="csp", check_id="csp.object-src", severity="low",
               title="CSP object-src not locked to 'none'",
               description="object-src is not 'none'; plugin/embed vectors (Flash/Java) are not "
                           "fully disabled.",
               evidence={"directive": "object-src",
                         "observed": " ".join(object_src) if object_src else "(absent)"})

    if "base-uri" not in d:
        em.add(source="csp", check_id="csp.base-uri", severity="low",
               title="CSP missing base-uri",
               description="No base-uri directive; a <base> tag injection can re-root relative "
                           "script URLs.",
               evidence={"directive": "base-uri", "observed": "(absent)"})


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def run_header_checks(
    url: str,
    signals: PageSignals,
    *,
    do_csp: bool = True,
    do_best_practice: bool = True,
    cfg: HeadersConfig,
) -> list[Finding]:
    """Run the selected deterministic header checks for one host."""
    em = _Emitter(signals.host, cfg)
    if do_best_practice:
        check_best_practice(url, signals, em)
    if do_csp:
        check_csp(url, signals, em)
    return em.findings
