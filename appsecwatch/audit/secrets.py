"""Client-side secret exposure detection over crawler script bodies.

Deterministic + offline + precision-first. The crawler reads each script BODY in
memory during the crawl (the same bodies the retire.js-style js-lib scan uses),
runs a curated ruleset (`data/secrets.json`) targeting material that must NEVER
appear in a browser bundle — private keys, cloud provider secret keys, DB
connection strings, vendor secret API tokens — and records only a MASKED preview
plus the script url + line onto ``CrawlerArtifact.detected_secrets``. The raw
value is used solely to compute the mask + check the allow-list, then discarded;
it is never persisted (runs/<id>/ stays a shareable artifact set).

Precision over recall by design:
  * An **allow-list** is matched FIRST and hard-drops known-public tokens
    (Firebase/Maps `AIza…`, Stripe *publishable* `pk_…`, Sentry DSN, reCAPTCHA
    site key, GA/GTM ids, Algolia search key) before any rule can fire.
  * No generic high-entropy catch-all in v1 (the false-positive firehose).

Emits ``source='secret'`` Findings; per-rule severity (critical/high/medium).
`check_id = secret.<rule>.<masked-fingerprint>` gives a stable cross-scan/-host
identity from the masked preview (no hash needed): the same leaked key collapses
into one report row across hosts and drives finding_state lifecycle (rotate the
secret → preview changes → old finding auto-resolves, new one opens).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from appsecwatch.models import Finding

_DB_PATH = Path(__file__).parent / "data" / "secrets.json"

# A cred-bearing URL: scheme://user:password@host… — mask only the password so the
# host/user (useful, non-secret) survive in the preview.
_CRED_URL = re.compile(r"^([\w+.\-]+://[^/@\s]+:)([^/@\s]+)(@.+)$")


@lru_cache(maxsize=1)
def load_db() -> dict[str, Any]:
    return json.loads(_DB_PATH.read_text())


@lru_cache(maxsize=1)
def _allow_patterns() -> tuple[re.Pattern, ...]:
    return tuple(re.compile(p) for p in load_db().get("allow", []))


def _is_public(value: str) -> bool:
    """True if the matched value is a known-public token (allow-list) — dropped
    before it can become a finding."""
    return any(p.search(value) for p in _allow_patterns())


def _mask(rule: dict[str, Any], value: str) -> str:
    """Produce a shareable, non-leaking preview of a match.

    Rules whose match is a non-secret MARKER (``"mask": false`` — e.g. a
    ``-----BEGIN … KEY-----`` header) show a truncated literal. Cred-bearing URLs
    mask only the password segment. Everything else shows boundary characters
    only, never the interior.
    """
    v = value.strip()
    if rule.get("mask") is False:
        return v[:48]
    m = _CRED_URL.match(v)
    if m:
        return f"{m.group(1)}{'•' * 6}{m.group(3)[:40]}"
    n = len(v)
    if n <= 8:  # too short to reveal boundaries safely
        return "•" * n
    keep = 4
    return f"{v[:keep]}{'•' * min(n - 2 * keep, 12)}{v[-keep:]}"


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def detect_in_content(text: str, db: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Scan a script body and return already-masked secret matches:
    ``[{rule, title, severity, line, preview}, ...]`` (NO raw value, NO url — the
    caller adds the script url). Public (allow-listed) matches are dropped."""
    db = db if db is not None else load_db()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()  # (rule_id, preview) — dedup within one body
    for rule in db.get("rules", []):
        rid = rule.get("id", "")
        for pat in rule.get("patterns", []):
            for m in re.finditer(pat, text, re.IGNORECASE):
                raw = m.group(1) if m.groups() else m.group(0)
                if not raw or _is_public(raw):
                    continue
                preview = _mask(rule, raw)
                if (rid, preview) in seen:
                    continue
                seen.add((rid, preview))
                out.append({
                    "rule": rid,
                    "title": rule.get("title", f"Secret exposed ({rid})"),
                    "severity": rule.get("severity", "high"),
                    "line": _line_of(text, m.start()),
                    "preview": preview,
                })
    return out


def _fingerprint(preview: str) -> str:
    """Stable id fragment from a masked preview (alnum boundary chars only)."""
    return re.sub(r"[^0-9A-Za-z]", "", preview).lower()[:16] or "x"


def scan_secrets(artifacts) -> list[Finding]:
    """Project each artifact's ``detected_secrets`` (recorded by the crawler) into
    ``source='secret'`` Findings. Deduped by (host, rule, preview)."""
    findings: list[Finding] = []
    seen: set[tuple[str | None, str, str]] = set()
    for art in artifacts:
        host = getattr(art, "host", None)
        for s in getattr(art, "detected_secrets", None) or []:
            rid = s.get("rule") or ""
            preview = s.get("preview") or ""
            key = (host, rid, preview)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                source="secret",
                host=host,
                severity=s.get("severity", "high"),
                title=s.get("title", f"Secret exposed ({rid})"),
                description="A credential-shaped value was found in a JavaScript "
                            "bundle served to browsers. Client-side code is fully "
                            "readable, so any real secret here is compromised and "
                            "must be rotated and moved server-side.",
                evidence={
                    "rule": rid,
                    "url": s.get("url", ""),
                    "line": s.get("line"),
                    "preview": preview,
                },
                check_id=f"secret.{rid}.{_fingerprint(preview)}",
            ))
    return findings
