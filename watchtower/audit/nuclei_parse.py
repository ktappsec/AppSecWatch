"""Canonical nuclei JSONL → `Finding` parser.

Both the main web-CVE scan (`nuclei_runner`) and the takeover scan (`takeovers`)
emit nuclei's `-jsonl` format and project it onto `Finding`. This is the single
place that mapping lives, so the two callers can't drift in evidence shape or
field handling — they differ only in `source` / `default_severity` /
`default_title`.
"""
from __future__ import annotations

import json
from typing import Iterable

from watchtower.models import Finding, FindingSource, Severity


def _tags(info: dict) -> list[str]:
    raw = info.get("tags")
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str) and raw:
        return raw.split(",")
    return []


def parse_nuclei_jsonl(
    lines: Iterable[str],
    *,
    source: FindingSource,
    default_severity: Severity,
    default_title: str,
) -> list[Finding]:
    """Parse nuclei `-jsonl` lines into `Finding`s, skipping blank/malformed lines."""
    findings: list[Finding] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        findings.append(
            Finding(
                source=source,
                host=obj.get("host") or obj.get("matched-at"),
                severity=info.get("severity") or default_severity,
                title=info.get("name") or obj.get("template-id") or default_title,
                description=info.get("description", "") or "",
                evidence={
                    "template_id": obj.get("template-id"),
                    "matched_at": obj.get("matched-at"),
                    "matcher_name": obj.get("matcher-name"),
                    "extracted_results": obj.get("extracted-results"),
                    "tags": _tags(info),
                },
            )
        )
    return findings
