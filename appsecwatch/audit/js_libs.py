"""Vulnerable-JS-library detection over crawler scripts, on retire.js signatures.

Deterministic + offline. Two detection modes feed one vuln-range check:

  * URL match — a script's URL carries the version (the common CDN/static-asset
    pattern), matched against each library's ``uri``/``filename`` regexes.
  * CONTENT match — the version is inside a bundled/minified body. The crawler
    reads each script body IN MEMORY during the crawl, runs the ``filecontent``
    signatures, and records only the detected ``{library, version}`` onto
    ``CrawlerArtifact.detected_libs`` — NEVER the body (runs/<id>/ stays a
    shareable artifact set). This catches libraries whose version isn't in the URL.

Signatures are the **retire.js repository** (Apache-2.0), vendored as the bundled
seed at `data/js_libs.json` and refreshable into the signature store — see
`audit/signatures.py` and `data/js_libs.SOURCE.md`. `load_db()` is the ONE entry
point: it resolves store-over-bundled, normalizes upstream shape into the internal
one, and compiles the patterns (they run over every script body, so compiling once
per process matters).

Upstream regexes are JS-flavored. The handful Python's `re` cannot compile (e.g.
lodash's variable-width look-behind) are skipped **per pattern**, never per
library — dropping a whole library over one bad regex would silently lose
detections. Content patterns are anchored by upstream to a library's own banner
comment or minified structure, which is what keeps a *requirement* string like
bootstrap's `"requires at least jQuery v1.9.1"` from reading as a version
declaration.

Emits `source='js_lib'` Findings; `library_inventory()` returns ALL detected libs
(vulnerable or not) for the per-asset tech inventory.
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from typing import Any

from appsecwatch.models import Finding

# A pure/offline helper with no run context (the RunLogger is run-scoped and
# passed in elsewhere), so signature-load diagnostics go to stdlib logging.
log = logging.getLogger(__name__)

#: retire.js writes version capture groups as a placeholder; this is the exact
#: expansion upstream uses (`node/lib/retire.js::replaceVersion`).
_VERSION_PLACEHOLDER = "§§version§§"
_VERSION_RE = r"[0-9][0-9.a-z_\\-]+"


def _expand(pattern: str) -> str:
    """Expand upstream's version placeholder inside one pattern.

    Done on the PARSED string rather than the raw file text: upstream ships the
    placeholder as literal UTF-8 (`§§version§§`), but any pack round-tripped
    through an ASCII-escaping serializer carries `\\u00a7...` instead, and a
    text-level replace would silently leave the placeholder in — yielding regexes
    that compile fine and match nothing.
    """
    return pattern.replace(_VERSION_PLACEHOLDER, _VERSION_RE)


def _compile_all(patterns: list[str], lib: str, kind: str) -> list[re.Pattern[str]]:
    """Compile what we can; skip (don't drop the library over) JS-only syntax."""
    out: list[re.Pattern[str]] = []
    for pat in patterns:
        if not isinstance(pat, str):
            continue
        try:
            out.append(re.compile(_expand(pat), re.IGNORECASE))
        except re.error as e:
            log.debug(f"js_libs: skipping uncompilable {kind} pattern for {lib}: {e}")
    return out


def _normalize_vuln(v: dict[str, Any]) -> dict[str, Any]:
    ident = v.get("identifiers") or {}
    cve = ident.get("CVE") or ident.get("cve") or []
    if isinstance(cve, str):
        cve = [cve]
    entry: dict[str, Any] = {
        "severity": (v.get("severity") or "medium").lower(),
        "cve": list(cve),
        "summary": ident.get("summary") or v.get("summary") or "",
    }
    for k in ("below", "atOrAbove", "above", "atOrBelow"):
        if k in v:
            entry[k] = v[k]
    return entry


def normalize_db(text: str) -> dict[str, Any]:
    """Upstream (or already-internal) signature text → the internal shape.

    Internal shape per library::

        {"uri": [...], "filecontent": [...],          # source regexes (introspection)
         "_uri": [compiled], "_filecontent": [compiled],
         "vulnerabilities": [{severity, cve[], summary, below?, atOrAbove?, ...}]}
    """
    raw = json.loads(text)
    db: dict[str, Any] = {}
    for lib, spec in raw.items():
        if lib.startswith("$") or not isinstance(spec, dict):
            continue
        ex = spec.get("extractors")
        if isinstance(ex, dict):
            # Upstream: `filename` matches the basename, `uri` the full URL. We
            # search both against the whole URL — a basename regex is still a
            # valid substring match there.
            uri = [*(ex.get("uri") or []), *(ex.get("filename") or [])]
            fc = list(ex.get("filecontent") or [])
            vulns = [_normalize_vuln(v) for v in (spec.get("vulnerabilities") or [])]
        else:  # already internal shape (hand-written pack / tests)
            uri = list(spec.get("uri") or [])
            fc = list(spec.get("filecontent") or [])
            vulns = list(spec.get("vulnerabilities") or [])
        if not uri and not fc:
            continue  # hash-only libraries: nothing we can match on yet
        db[lib] = {
            "uri": uri, "filecontent": fc, "vulnerabilities": vulns,
            "_uri": _compile_all(uri, lib, "uri"),
            "_filecontent": _compile_all(fc, lib, "filecontent"),
        }
    return db


@lru_cache(maxsize=1)
def load_db() -> dict[str, Any]:
    """The active signature pack (store copy if updated, else the bundled seed)."""
    from appsecwatch.audit import signatures

    path = signatures.active_path(signatures.JS_LIBS)
    try:
        db = normalize_db(path.read_text())
    except Exception as e:  # noqa: BLE001 — a bad store copy must not kill the scan
        log.warning(f"js_libs: failed to load {path} ({e}); falling back to bundled")
        db = normalize_db(signatures.bundled_path(signatures.JS_LIBS).read_text())
    return db


def reload_db() -> None:
    """Drop the cached pack so a freshly-installed update takes effect in-process."""
    load_db.cache_clear()


_VERSION_SPLIT = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


_MIN_SUFFIX = re.compile(r"[.-]min$", re.IGNORECASE)

#: A plausible version: dotted digits, optionally a bounded pre-release tail
#: ('-rc.1', '-aem', '-canary.13', 'b1'). Upstream's `uri` patterns often capture
#: a whole PATH SEGMENT, which on some stacks is not a version at all — a real
#: JSF/RichFaces asset in our estate yielded `3_3_3.Finaljavascript`. Upstream
#: scans local files where that can't happen; we match against arbitrary URLs.
_PLAUSIBLE_VERSION = re.compile(
    r"^\d+(?:\.\d+)*(?:[-._+][a-z0-9][a-z0-9.\-_+]{0,15}|[a-z][a-z0-9]{0,3})?$",
    re.IGNORECASE,
)


def _clean_version(v: str) -> str:
    """Tidy a captured version; '' if it is not plausibly a version.

    Upstream's version placeholder (`[0-9][0-9.a-z_\\-]+`) is greedy and its
    char class includes '.', 'm', 'i', 'n' — so `jquery-3.3.7.min.js` backtracks
    to a capture of `3.3.7.min`. retire.js strips that same suffix after
    extracting (`node/lib/retire.js:30`); mirror it or every `.min.js` asset
    reports an unmatchable version.
    """
    v = (v or "").strip()
    v = _MIN_SUFFIX.sub("", v)
    v = v.rstrip(".-_")
    if not v or not _PLAUSIBLE_VERSION.match(v):
        return ""
    return v


def _vt(v: str) -> tuple[tuple[int, ...], str]:
    """(release tuple, pre-release suffix). '1.0.0-rc.1' -> ((1,0,0), '-rc.1').

    Upstream bounds carry pre-release suffixes in several shapes ('1.0.0-rc.1',
    '1.9.0b1', '1.0.0.beta.3'), so the split is 'leading dotted digits, then the
    rest' rather than a semver-only '-' split.
    """
    m = _VERSION_SPLIT.match((v or "").strip())
    if not m:
        return (tuple(int(x) for x in re.findall(r"\d+", v or "")), "")
    return tuple(int(x) for x in m.group(1).split(".")), m.group(2)


def _cmp(a: str, b: str) -> int:
    ta, sa = _vt(a)
    tb, sb = _vt(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    if ta != tb:
        return 1 if ta > tb else -1
    # Equal release parts: a pre-release sorts BELOW its release (semver), so
    # '1.0.0-rc.1' < '1.0.0'. Without this, `below: 1.0.0-rc.1` would flag the
    # released 1.0.0 as affected.
    if sa == sb:
        return 0
    if not sa:
        return 1
    if not sb:
        return -1
    return (sa > sb) - (sa < sb)


def _affected(ver: str, vuln: dict[str, Any]) -> bool:
    # Upstream can pin specific known-unaffected builds (e.g. vendor backports
    # like '1.12.4-aem'); absent from the flat repository today, present in the
    # master format, so honour it rather than depend on which file was fetched.
    if ver in (vuln.get("excludes") or ()):
        return False
    if "atOrAbove" in vuln and _cmp(ver, vuln["atOrAbove"]) < 0:
        return False
    if "above" in vuln and _cmp(ver, vuln["above"]) <= 0:
        return False
    if "below" in vuln and _cmp(ver, vuln["below"]) >= 0:
        return False
    if "atOrBelow" in vuln and _cmp(ver, vuln["atOrBelow"]) > 0:
        return False
    return True


def _compiled(spec: dict[str, Any], key: str) -> list[re.Pattern[str]]:
    """Compiled patterns for `key`, compiling on the fly for a db dict handed in
    by a caller/test that never went through `normalize_db`."""
    pre = spec.get(f"_{key}")
    if pre is not None:
        return pre
    return _compile_all(spec.get(key) or [], "?", key)


def _match(patterns: list[re.Pattern[str]], text: str) -> str | None:
    for pat in patterns:
        m = pat.search(text)
        if m and m.groups():
            ver = _clean_version(m.group(1))
            if ver:
                return ver
    return None


def detect_in_url(url: str, db: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """(library, version) pairs detected from a script URL."""
    db = db if db is not None else load_db()
    out: list[tuple[str, str]] = []
    for lib, spec in db.items():
        ver = _match(_compiled(spec, "uri"), url)
        if ver:
            out.append((lib, ver))
    return out


def detect_in_content(text: str, db: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """(library, version) pairs detected from a script BODY (called in-memory by
    the crawler; the body is never persisted)."""
    db = db if db is not None else load_db()
    out: list[tuple[str, str]] = []
    for lib, spec in db.items():
        ver = _match(_compiled(spec, "filecontent"), text)
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


#: Severity ordering for collapsing a library's many vuln entries to one finding.
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def scan_scripts(artifacts, db: dict[str, Any] | None = None) -> list[Finding]:
    """Return js_lib Findings for vulnerable libraries seen (URL or content).

    ONE finding per (host, library, version) — every affected vuln entry for that
    version is folded into a single row (severity = the worst of them, every CVE
    listed). A badly-outdated library can carry 20+ upstream CVE entries; emitting
    one finding each inflated the severity histogram / posture / finding_state with
    rows that are the same real problem (the report already collapsed them by
    `group_key`, so it could only ever show one arbitrary CVE + severity anyway).
    """
    db = db if db is not None else load_db()
    # (host, lib, ver) -> aggregation state, in first-seen order.
    groups: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    for art in artifacts:
        host = getattr(art, "host", None)
        for lib, ver, url in _detected_pairs(art):
            spec = db.get(lib)
            if not spec:
                continue
            key = (host, lib, ver)
            for vuln in spec.get("vulnerabilities", []):
                if not _affected(ver, vuln):
                    continue
                g = groups.get(key)
                if g is None:
                    g = groups[key] = {"url": url, "sev": "info",
                                       "cves": [], "summaries": []}
                    order.append(key)
                if _SEV_RANK.get(vuln.get("severity", "medium"), 2) > _SEV_RANK.get(g["sev"], 0):
                    g["sev"] = vuln.get("severity", "medium")
                for c in (vuln.get("cve") or []):
                    if c and c not in g["cves"]:
                        g["cves"].append(c)
                s = (vuln.get("summary") or "").strip()
                if s and s not in g["summaries"]:
                    g["summaries"].append(s)

    findings: list[Finding] = []
    for key in order:
        host, lib, ver = key
        g = groups[key]
        cves = g["cves"]
        findings.append(Finding(
            source="js_lib", host=host,
            severity=g["sev"] if g["sev"] != "info" else "medium",
            title=f"Vulnerable JS library: {lib} {ver}",
            description="; ".join(g["summaries"]),
            evidence={"library": lib, "version": ver,
                      "cve": ", ".join(cves), "cve_count": len(cves), "url": g["url"]},
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
