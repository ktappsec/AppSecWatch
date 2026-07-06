"""All-in-one search over assets + findings (SQLite FTS5, LIKE fallback).

One index, one `search()` entry point powering both the Assets search box and the
global command palette. Assets are indexed by fqdn / group / tech / contacted
domains / endpoints / profile summary; findings by title / description / host /
category / source. Kept in sync at scan end (`reindex_asset` / `index_findings`).

FTS5 is optional (a stripped SQLite build lacks it): when `db.fts_enabled` is
False every method degrades to a `LIKE` scan so search never breaks.
"""
from __future__ import annotations

import json
import re
from typing import Any

from appsecwatch.api.db import Database
from appsecwatch.audit.suppress import finding_fingerprint
from appsecwatch.models import Finding

_TOKEN_RE = re.compile(r"[\w.\-]+", re.UNICODE)


def _fts_query(q: str) -> str | None:
    """Turn a free-text query into a safe FTS5 MATCH expression (prefix-AND)."""
    toks = _TOKEN_RE.findall(q.lower())
    if not toks:
        return None
    return " ".join(f'"{t}"*' for t in toks)


def _coerce(value: Any, default: Any) -> Any:
    """Accept either a JSON string (a raw DB row) or an already-parsed list/dict
    (an ``AssetManager`` row from ``get()``/``list()``). Both feed FTS field
    extraction — reindex from a scan passes parsed rows, tests pass strings."""
    if value is None or value == "":
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _names(tech: Any) -> str:
    items = _coerce(tech, [])
    if not isinstance(items, list):
        return ""
    out = []
    for it in items:
        if isinstance(it, dict) and it.get("name"):
            out.append(str(it["name"]))
        elif isinstance(it, str):
            out.append(it)
    return " ".join(out)


def _asset_fts_fields(row: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    surface = _coerce(row.get("surface"), {})
    if not isinstance(surface, dict):
        surface = {}
    profile = _coerce(row.get("profile"), {})
    if not isinstance(profile, dict):
        profile = {}
    domains = " ".join((surface.get("third_party_domains") or [])
                       + (surface.get("script_domains") or []))
    endpoints = " ".join(surface.get("endpoints") or [])
    profile_summary = " ".join(
        str(x) for x in (
            [profile.get("app_type"), profile.get("reasoning")]
            + list(profile.get("detected_tech") or [])
        ) if x
    )
    return (row.get("fqdn") or "", row.get("group") or "", _names(row.get("tech")),
            domains, endpoints, profile_summary)


class FTSIndex:
    def __init__(self, db: Database) -> None:
        self.db = db

    @property
    def enabled(self) -> bool:
        return self.db.fts_enabled

    # ---- indexing ---------------------------------------------------------- #

    def reindex_asset(self, row: dict[str, Any]) -> None:
        if not self.enabled:
            return
        fqdn = row.get("fqdn")
        if not fqdn:
            return
        try:
            self.db.execute("DELETE FROM assets_fts WHERE fqdn=?", (fqdn,))
            self.db.execute(
                'INSERT INTO assets_fts (fqdn, "group", tech, domains, endpoints, '
                "profile_summary) VALUES (?, ?, ?, ?, ?, ?)",
                _asset_fts_fields(row),
            )
        except Exception:  # best-effort — indexing must never break a scan
            pass

    def index_findings(self, scan_id: str, findings: list[Finding],
                       hosts: set[str] | None = None) -> None:
        """Replace the indexed findings for the scanned hosts with this scan's set
        (keeps search reflecting the latest scan per host)."""
        if not self.enabled:
            return
        hosts = hosts if hosts is not None else {f.host for f in findings if f.host}
        try:
            for h in hosts:
                self.db.execute("DELETE FROM findings_fts WHERE host=?", (h,))
            for f in findings:
                self.db.execute(
                    "INSERT INTO findings_fts (title, description, host, category, "
                    "source, fingerprint, scan_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (f.title, f.description or "", f.host or "", f.category or "",
                     f.source, finding_fingerprint(f), scan_id),
                )
        except Exception:
            pass

    def remove_asset(self, fqdn: str) -> None:
        """Drop an asset from the FTS index (on delete). Best-effort."""
        if not self.enabled or not fqdn:
            return
        try:
            self.db.execute("DELETE FROM assets_fts WHERE fqdn=?", (fqdn,))
        except Exception:
            pass

    def rebuild_assets(self, rows: list[dict[str, Any]]) -> None:
        """Full rebuild of the asset index from `rows` — the coarse path for bulk
        ops (delete/regroup) where the affected set isn't cheaply enumerable."""
        if not self.enabled:
            return
        try:
            self.db.execute("DELETE FROM assets_fts")
            for row in rows:
                if row.get("fqdn"):
                    self.db.execute(
                        'INSERT INTO assets_fts (fqdn, "group", tech, domains, '
                        "endpoints, profile_summary) VALUES (?, ?, ?, ?, ?, ?)",
                        _asset_fts_fields(row),
                    )
        except Exception:
            pass

    # ---- querying ---------------------------------------------------------- #

    def search(self, q: str, *, kinds: tuple[str, ...] = ("assets", "findings"),
               limit: int = 20) -> dict[str, list[dict[str, Any]]]:
        q = (q or "").strip()
        if not q:
            return {"assets": [], "findings": []}
        if self.enabled:
            match = _fts_query(q)
            if match is None:
                return {"assets": [], "findings": []}
            return self._search_fts(match, kinds, limit)
        return self._search_like(q, kinds, limit)

    def _search_fts(self, match: str, kinds: tuple[str, ...],
                    limit: int) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {"assets": [], "findings": []}
        if "assets" in kinds:
            out["assets"] = self.db.query(
                'SELECT fqdn, "group" FROM assets_fts WHERE assets_fts MATCH ? '
                "ORDER BY rank LIMIT ?", (match, limit)
            )
        if "findings" in kinds:
            out["findings"] = self.db.query(
                "SELECT title, host, category, source, fingerprint, scan_id "
                "FROM findings_fts WHERE findings_fts MATCH ? ORDER BY rank LIMIT ?",
                (match, limit),
            )
        return out

    def _search_like(self, q: str, kinds: tuple[str, ...],
                     limit: int) -> dict[str, list[dict[str, Any]]]:
        like = f"%{q.lower()}%"
        out: dict[str, list[dict[str, Any]]] = {"assets": [], "findings": []}
        if "assets" in kinds:
            out["assets"] = self.db.query(
                'SELECT fqdn, "group" FROM assets WHERE lower(fqdn) LIKE ? '
                "OR lower(COALESCE(tech,'')) LIKE ? OR lower(COALESCE(surface,'')) LIKE ? "
                "OR lower(COALESCE(profile,'')) LIKE ? LIMIT ?",
                (like, like, like, like, limit),
            )
        if "findings" in kinds:
            out["findings"] = self.db.query(
                "SELECT title, host, category, finding_class, source, fingerprint, "
                "last_seen_scan AS scan_id FROM finding_state "
                "WHERE lower(COALESCE(title,'')) LIKE ? OR lower(COALESCE(host,'')) LIKE ? "
                "LIMIT ?",
                (like, like, limit),
            )
        return out
