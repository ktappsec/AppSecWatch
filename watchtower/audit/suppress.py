"""Finding fingerprinting + manual-suppression application (engine-side).

A suppression is keyed by a stable fingerprint `source|host|key`. `key` is the
deterministic identifier for the finding's class (check_id / template_id / sslyze
check / js_lib library@version), falling back to the title. A finding matches a
suppression set if its host-specific fingerprint OR its global (`source|*|key`)
fingerprint is present. Matching marks the finding via the verdict path
(`AIFindingVerdict(suppressed=True, source='manual')`) — hidden + uncounted, never
deleted. The CLI never passes a set, so CLI scans suppress nothing.
"""
from __future__ import annotations

from watchtower.models import AIFindingVerdict, Finding


def finding_key(f: Finding) -> str:
    if f.check_id:
        return f.check_id
    ev = f.evidence or {}
    if f.source in ("nuclei", "takeover"):
        return ev.get("template_id") or f.title
    if f.source == "sslyze":
        return ev.get("check") or f.title
    if f.source == "js_lib":
        lib = ev.get("library")
        return f"{lib}@{ev.get('version', '')}" if lib else f.title
    return f.title


def finding_fingerprint(f: Finding, host: str | None = None) -> str:
    return f"{f.source}|{host if host is not None else (f.host or '')}|{finding_key(f)}"


def finding_matches(f: Finding, suppress_set: set[str]) -> bool:
    return finding_fingerprint(f) in suppress_set or finding_fingerprint(f, "*") in suppress_set


def apply_suppressions(findings: list[Finding], suppress_set: set[str],
                       reason: str = "manually suppressed") -> int:
    """Mark matching findings as suppressed. Returns the count newly suppressed.
    Skips findings already suppressed (e.g. by the AI header pass)."""
    n = 0
    for f in findings:
        if f.ai_verdict is not None and f.ai_verdict.suppressed:
            continue
        if finding_matches(f, suppress_set):
            f.ai_verdict = AIFindingVerdict(
                suppressed=True, confidence="high", reason=reason, source="manual"
            )
            n += 1
    return n
