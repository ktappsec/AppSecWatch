"""Curated, names-only surface summary derived from a CrawlerArtifact.

Single source of truth for (a) the per-asset EASM surface the server persists onto
the assets row and (b) the curated manifest fed to the AI profiler. STRUCTURE ONLY
— third-party domains, API/data endpoints, and cookie/storage KEY NAMES; never any
value or body, and query strings are dropped (they can carry tokens). runs/<id>/ is
a shareable artifact set, so this never widens its sensitivity surface.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from appsecwatch.models import CrawlerArtifact
from appsecwatch.util.domains import etld_plus_one

# Bounds so a chatty SPA can't bloat the artifact / LLM payload.
_MAX_DOMAINS = 60
_MAX_ENDPOINTS = 80
# Resource types that represent API/data calls (vs. static assets like img/css/font).
_ENDPOINT_TYPES = {"xhr", "fetch", "websocket", "eventsource"}


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def curated_surface(artifact: CrawlerArtifact) -> dict:
    """Project a CrawlerArtifact into a compact, names-only surface dict:
    {third_party_domains, script_domains, endpoints, cookie_keys, storage_keys}."""
    self_e1 = etld_plus_one(artifact.host) if artifact.host else ""

    third_party: set[str] = set()
    script_domains: set[str] = set()
    endpoints: list[str] = []
    seen_ep: set[str] = set()

    for r in artifact.resources:
        url = r.get("url") or ""
        host = _host_of(url)
        if not host:
            continue
        e1 = etld_plus_one(host)
        if e1 and e1 != self_e1:
            third_party.add(e1)
        rtype = r.get("type")
        if rtype == "script" and e1:
            script_domains.add(e1)
        if rtype in _ENDPOINT_TYPES:
            method = str(r.get("method") or "GET").upper()
            path = urlsplit(url).path or "/"          # path only — drop query (may carry tokens)
            ep = f"{method} {host}{path}"
            if ep not in seen_ep:
                seen_ep.add(ep)
                endpoints.append(ep)

    cookie_keys = sorted({c.get("name") for c in artifact.cookies if c.get("name")})
    storage_keys = sorted(
        set(artifact.local_storage_keys) | set(artifact.session_storage_keys)
    )

    return {
        "third_party_domains": sorted(third_party)[:_MAX_DOMAINS],
        "script_domains": sorted(script_domains)[:_MAX_DOMAINS],
        "endpoints": endpoints[:_MAX_ENDPOINTS],
        "cookie_keys": cookie_keys,
        "storage_keys": storage_keys,
    }
