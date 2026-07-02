"""Merge httpx-detected tech with AI-inferred tech, source-tagged + deduped.

httpx (`-tech-detect`) is deterministic; the ai.profile pass also emits an
inferred tech list. The merged `[{name, source}]` (source = httpx | ai) is
surfaced on the asset inventory + report. httpx wins on a case-insensitive name
collision.
"""
from __future__ import annotations


def merge_tech(httpx_tech, ai_tech) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for name in (httpx_tech or []):
        k = (name or "").strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append({"name": name, "source": "httpx"})
    for name in (ai_tech or []):
        k = (name or "").strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append({"name": name, "source": "ai"})
    return out
