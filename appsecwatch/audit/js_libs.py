"""Vulnerable-JS-library detection (retire.js-style) over crawler scripts.

Deterministic + offline. Two detection modes feed one vuln-range check:

  * URL match — a script's URL carries the version (the common CDN/static-asset
    pattern), matched against each library's ``uri`` regexes.
  * CONTENT match — the version is inside a bundled/minified body. The crawler
    reads each script body IN MEMORY during the crawl, runs the ``filecontent``
    signatures, and records only the detected ``{library, version}`` onto
    ``CrawlerArtifact.detected_libs`` — NEVER the body (runs/<id>/ stays a
    shareable artifact set). This catches libraries whose version isn't in the URL.

Both feed the bundled vuln DB (`data/js_libs.json`, retire.js-shaped: per library
`uri` + `filecontent` regexes with a version capture group + vuln ranges + CVEs).
Emits `source='js_lib'` Findings; `library_inventory()` returns ALL detected libs
(vulnerable or not) for the per-asset tech inventory.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from appsecwatch.models import Finding

_DB_PATH = Path(__file__).parent / "data" / "js_libs.json"


@lru_cache(maxsize=1)
def load_db() -> dict[str, Any]:
    return json.loads(_DB_PATH.read_text())


def _vt(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _cmp(a: str, b: str) -> int:
    ta, tb = _vt(a), _vt(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _affected(ver: str, vuln: dict[str, Any]) -> bool:
    if "atOrAbove" in vuln and _cmp(ver, vuln["atOrAbove"]) < 0:
        return False
    if "above" in vuln and _cmp(ver, vuln["above"]) <= 0:
        return False
    if "below" in vuln and _cmp(ver, vuln["below"]) >= 0:
        return False
    if "atOrBelow" in vuln and _cmp(ver, vuln["atOrBelow"]) > 0:
        return False
    return True


def _match(patterns: list[str], text: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m and m.groups():
            return m.group(1)
    return None


def detect_in_url(url: str, db: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """(library, version) pairs detected from a script URL."""
    db = db if db is not None else load_db()
    out: list[tuple[str, str]] = []
    for lib, spec in db.items():
        ver = _match(spec.get("uri", []), url)
        if ver:
            out.append((lib, ver))
    return out


def detect_in_content(text: str, db: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """(library, version) pairs detected from a script BODY (called in-memory by
    the crawler; the body is never persisted)."""
    db = db if db is not None else load_db()
    out: list[tuple[str, str]] = []
    for lib, spec in db.items():
        ver = _match(spec.get("filecontent", []), text)
        if ver:
            out.append((lib, ver))
    return out


def _detected_pairs(art) -> list[tuple[str, str, str]]:
    """All (library, version, url) detected for one artifact — URL matches over its
    scripts plus the crawler's in-memory content matches (`detected_libs`)."""
    db = load_db()
    pairs: list[tuple[str, str, str]] = []
    for s in getattr(art, "scripts", []) or []:
        url = (s.get("url") if isinstance(s, dict) else None) or ""
        if url:
            for lib, ver in detect_in_url(url, db):
                pairs.append((lib, ver, url))
    for d in getattr(art, "detected_libs", []) or []:
        lib = d.get("library") if isinstance(d, dict) else None
        ver = d.get("version") if isinstance(d, dict) else None
        if lib and ver:
            pairs.append((lib, ver, d.get("url", "")))
    return pairs


def scan_scripts(artifacts, db: dict[str, Any] | None = None) -> list[Finding]:
    """Return js_lib Findings for vulnerable libraries seen (URL or content)."""
    db = db if db is not None else load_db()
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for art in artifacts:
        host = getattr(art, "host", None)
        for lib, ver, url in _detected_pairs(art):
            spec = db.get(lib)
            if not spec:
                continue
            for vuln in spec.get("vulnerabilities", []):
                if not _affected(ver, vuln):
                    continue
                cves = vuln.get("cve") or []
                dedupe = (host, lib, ver, tuple(cves))
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                findings.append(Finding(
                    source="js_lib", host=host,
                    severity=vuln.get("severity", "medium"),
                    title=f"Vulnerable JS library: {lib} {ver}",
                    description=vuln.get("summary", ""),
                    evidence={"library": lib, "version": ver,
                              "cve": ", ".join(cves), "url": url},
                    check_id=f"js_lib.{lib}.{ver}",
                ))
    return findings


def library_inventory(artifacts, db: dict[str, Any] | None = None) -> dict[str, list[dict[str, str]]]:
    """Per-host inventory of ALL detected JS libraries (vulnerable or not), for the
    asset tech list. `{host: [{"name": "jquery", "version": "3.6.0"}, ...]}`."""
    inv: dict[str, list[dict[str, str]]] = {}
    for art in artifacts:
        host = getattr(art, "host", None)
        if not host:
            continue
        seen: set[tuple[str, str]] = set()
        libs: list[dict[str, str]] = []
        for lib, ver, _url in _detected_pairs(art):
            if (lib, ver) in seen:
                continue
            seen.add((lib, ver))
            libs.append({"name": lib, "version": ver})
        if libs:
            inv[host] = libs
    return inv
