"""Vulnerable-JS-library detection (retire.js-style) over crawler scripts.

Deterministic + offline: match each captured script URL against a bundled vuln DB
(`data/js_libs.json`: library URI regexes with a version capture group + known-
vuln version ranges + CVEs). No extra requests — uses the scripts the crawler
already saw. Emits `source='js_lib'` Findings. Catches the version-in-URL case
(the common CDN/static-asset pattern); content/hash detection is a later add.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from watchtower.models import Finding

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


def _extract_version(url: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        m = re.search(pat, url, re.IGNORECASE)
        if m and m.groups():
            return m.group(1)
    return None


def scan_scripts(artifacts, db: dict[str, Any] | None = None) -> list[Finding]:
    """Return js_lib Findings for vulnerable libraries seen in the scripts."""
    db = db if db is not None else load_db()
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for art in artifacts:
        host = getattr(art, "host", None)
        for s in getattr(art, "scripts", []) or []:
            url = (s.get("url") if isinstance(s, dict) else None) or ""
            if not url:
                continue
            for lib, spec in db.items():
                ver = _extract_version(url, spec.get("uri", []))
                if not ver:
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
