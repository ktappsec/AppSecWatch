"""Assets inventory over the SQLite `assets` table (server-side).

CSV import (`domain,group`), CRUD, grouped listing, scan-target resolution, and
the recon→assets sync. Merge rules: imported assets' group/notes are never
clobbered by recon; discovered subdomains inherit their root's group.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from appsecwatch.api.db import Database

if TYPE_CHECKING:
    from appsecwatch.api.search import FTSIndex

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(domain: str) -> str:
    return (domain or "").strip().lower().rstrip(".")


def _valid(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


def _clamp_priority(value: Any) -> int | None:
    """Coerce a manual priority to an int in 1..10, or None if unset/invalid."""
    if value is None or value == "":
        return None
    try:
        return max(1, min(10, int(value)))
    except (TypeError, ValueError):
        return None


def _root_of(fqdn: str, scanned_roots: list[str]) -> str | None:
    """The longest scanned root that fqdn sits under (or equals)."""
    best = None
    for r in scanned_roots:
        if fqdn == r or fqdn.endswith("." + r):
            if best is None or len(r) > len(best):
                best = r
    return best


class AssetManager:
    def __init__(self, db: Database) -> None:
        self.db = db
        # Optional FTS index kept in sync on every write (set by the app factory).
        # When None (CLI/tests) or FTS unavailable, the hooks below are no-ops.
        self.search: "FTSIndex | None" = None

    # ----- FTS sync (best-effort; never break a CRUD op) ------------------ #
    def _fts_reindex(self, fqdn: str) -> None:
        if self.search is None:
            return
        row = self.get(fqdn)
        if row:
            self.search.reindex_asset(row)

    def _fts_remove(self, fqdn: str) -> None:
        if self.search is not None:
            self.search.remove_asset(_norm(fqdn))

    def _fts_rebuild(self) -> None:
        if self.search is not None:
            self.search.rebuild_assets(self.list())

    # ----- read ----------------------------------------------------------- #
    def _row(self, r: dict[str, Any]) -> dict[str, Any]:
        out = dict(r)
        out["group"] = out.pop("group", None)
        out["a_records"] = json.loads(out["a_records"]) if out.get("a_records") else []
        out["cname_chain"] = json.loads(out["cname_chain"]) if out.get("cname_chain") else []
        out["tech"] = json.loads(out["tech"]) if out.get("tech") else []
        out["profile"] = json.loads(out["profile"]) if out.get("profile") else None
        out["finding_counts"] = json.loads(out["finding_counts"]) if out.get("finding_counts") else {}
        out["surface"] = json.loads(out["surface"]) if out.get("surface") else None
        return out

    def list(self, *, group: str | None = None, status: str | None = None,
             source: str | None = None, q: str | None = None,
             new_since_scan: str | None = None,
             sort: str | None = None, summary: bool = False) -> list[dict[str, Any]]:
        # `summary` projects only the columns the dashboard consumes, dropping the
        # heavy per-asset JSON (tech/profile/surface) — the rest of `Asset` fills
        # from defaults. WHERE/ORDER can still reference unselected columns.
        cols = '"group", fqdn, source, status, priority, finding_counts' if summary else "*"
        sql = f"SELECT {cols} FROM assets"
        where, p = [], []
        if group is not None:
            where.append('"group" = ?'); p.append(group)
        if status:
            where.append("status = ?"); p.append(status)
        if source:
            where.append("source = ?"); p.append(source)
        if new_since_scan:
            where.append("first_seen_scan = ?"); p.append(new_since_scan)
        if q:
            # All-in-one asset search: fqdn + tech + surface (contacted domains/
            # endpoints) + profile summary (JSON columns, substring match).
            like = f"%{q.strip().lower()}%"
            where.append("(lower(fqdn) LIKE ? OR lower(COALESCE(tech,'')) LIKE ? "
                         "OR lower(COALESCE(surface,'')) LIKE ? "
                         "OR lower(COALESCE(profile,'')) LIKE ?)")
            p.extend([like, like, like, like])
        if where:
            sql += " WHERE " + " AND ".join(where)
        if sort == "priority":
            sql += ' ORDER BY priority IS NULL, priority DESC, fqdn'
        else:
            sql += ' ORDER BY "group" IS NULL, "group", fqdn'
        return [self._row(r) for r in self.db.query(sql, tuple(p))]

    def groups(self) -> list[dict[str, Any]]:
        rows = self.db.query(
            'SELECT "group" AS g, COUNT(*) AS n, MAX(last_scan_id) AS last '
            'FROM assets GROUP BY "group" ORDER BY "group" IS NULL, "group"'
        )
        return [{"group": r["g"], "count": r["n"], "last_scan_id": r["last"]} for r in rows]

    def get(self, fqdn: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM assets WHERE fqdn = ?", (_norm(fqdn),))
        return self._row(rows[0]) if rows else None

    # ----- write (UI CRUD + CSV) ----------------------------------------- #
    def upsert_imported(
        self, fqdn: str, group: str | None, notes: str | None = None,
        priority: int | None = None,
    ) -> bool:
        """Add/update an imported asset (a root). Returns True if newly added.
        `priority` (1..10) is operator-set business criticality; COALESCE on
        update so re-import never wipes an existing value."""
        d = _norm(fqdn)
        if not _valid(d):
            raise ValueError(f"invalid domain: {fqdn!r}")
        pr = _clamp_priority(priority)
        existing = self.get(d)
        now = _now()
        if existing:
            self.db.execute(
                'UPDATE assets SET "group"=?, notes=COALESCE(?, notes), '
                "priority=COALESCE(?, priority), "
                "source='imported', root=COALESCE(root, ?), last_seen=? WHERE fqdn=?",
                (group, notes, pr, d, now, d),
            )
            self._fts_reindex(d)
            return False
        self.db.execute(
            'INSERT INTO assets (fqdn, "group", source, root, notes, priority, '
            "first_seen, last_seen) VALUES (?, ?, 'imported', ?, ?, ?, ?, ?)",
            (d, group, d, notes, pr, now, now),
        )
        self._fts_reindex(d)
        return True

    def update(self, fqdn: str, fields: dict[str, Any]) -> bool:
        """Partial edit of an existing asset (group/notes/priority only); does NOT
        change `source`. Returns True if a row was updated."""
        d = _norm(fqdn)
        sets, p = [], []
        for k in ("group", "notes", "priority"):
            if k not in fields:
                continue
            v = _clamp_priority(fields[k]) if k == "priority" else fields[k]
            sets.append(f'"group"=?' if k == "group" else f"{k}=?")
            p.append(v)
        if not sets:
            return self.get(d) is not None
        sets.append("last_seen=?")
        p.append(_now())
        p.append(d)
        changed = self.db.execute(f"UPDATE assets SET {', '.join(sets)} WHERE fqdn=?", tuple(p)) > 0
        self._fts_reindex(d)
        return changed

    def delete(self, fqdn: str) -> bool:
        d = _norm(fqdn)
        removed = self.db.execute("DELETE FROM assets WHERE fqdn = ?", (d,)) > 0
        if removed:
            self._fts_remove(d)
        return removed

    def import_csv(self, text: str) -> dict[str, int]:
        """Upsert rows from a `domain,group[,priority]` CSV. Header optional."""
        added = updated = skipped = 0
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row:
                continue
            domain = _norm(row[0])
            if not domain or domain in ("domain", "fqdn") or not _valid(domain):
                skipped += 1
                continue
            group = (row[1].strip() if len(row) > 1 else "") or None
            priority = _clamp_priority(row[2].strip()) if len(row) > 2 else None
            if self.upsert_imported(domain, group, priority=priority):
                added += 1
            else:
                updated += 1
        return {"added": added, "updated": updated, "skipped": skipped}

    # ----- scan-target resolution ---------------------------------------- #
    def resolve_roots(self, *, group: str | None = None,
                      assets: list[str] | None = None, all_assets: bool = False) -> list[str]:
        if group is not None:
            rows = self.db.query(
                'SELECT fqdn FROM assets WHERE "group"=? AND source=\'imported\'', (group,)
            )
            if not rows:  # group with no imported roots → fall back to its assets
                rows = self.db.query('SELECT fqdn FROM assets WHERE "group"=?', (group,))
            return [r["fqdn"] for r in rows]
        if assets:
            return [_norm(a) for a in assets]
        if all_assets:
            rows = self.db.query("SELECT fqdn FROM assets WHERE source='imported'")
            return [r["fqdn"] for r in rows]
        return []

    # ----- recon → assets sync (post-scan) ------------------------------- #
    def sync_discovered(self, triaged: list, scanned_roots: list[str],
                        scan_id: str, group: str | None = None,
                        tech_by_host: dict[str, list[dict]] | None = None,
                        profile_by_host: dict[str, dict] | None = None,
                        finding_counts_by_host: dict[str, dict] | None = None,
                        surface_by_host: dict[str, dict] | None = None) -> tuple[int, list[str]]:
        """Upsert every triaged FQDN. Discovered inherit their root's imported
        group (else the scan's group); imported assets keep their group/notes.
        tech/profile/finding_counts/surface (by host) are written onto matching assets.

        Returns ``(upserted_count, newly_discovered_fqdns)`` — a fqdn is NEW when it
        was not already in the inventory before this scan (drives the new-domain
        alert). New assets get ``first_seen_scan`` set to this scan's id."""
        roots = [_norm(r) for r in (scanned_roots or [])]
        # Precompute each root's imported group for inheritance.
        root_group: dict[str, str | None] = {}
        for r in roots:
            a = self.get(r)
            root_group[r] = a.get("group") if a and a.get("source") == "imported" else None
        now, n = _now(), 0
        new_fqdns: list[str] = []
        for t in triaged:
            fqdn = _norm(getattr(t, "fqdn", ""))
            if not fqdn:
                continue
            is_new = self.get(fqdn) is None      # never seen before this scan
            if is_new:
                new_fqdns.append(fqdn)
            root = _root_of(fqdn, roots)
            inherited = (root_group.get(root) if root else None) or group
            a_records = json.dumps(list(getattr(t, "a_records", []) or []))
            cname_chain = json.dumps(list(getattr(t, "cname_chain", []) or []))
            self.db.execute(
                'INSERT INTO assets (fqdn, "group", source, root, status, a_records, '
                "cname_chain, asn, as_org, first_seen, last_seen, last_scan_id, first_seen_scan) "
                "VALUES (?, ?, 'discovered', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(fqdn) DO UPDATE SET "
                "  status=excluded.status, a_records=excluded.a_records, "
                "  cname_chain=excluded.cname_chain, "
                "  asn=excluded.asn, as_org=excluded.as_org, "
                "  last_seen=excluded.last_seen, last_scan_id=excluded.last_scan_id, "
                "  root=COALESCE(assets.root, excluded.root), "
                '  "group"=CASE WHEN assets.source=\'imported\' THEN assets."group" '
                '             ELSE COALESCE(excluded."group", assets."group") END',
                (fqdn, inherited, root, getattr(t, "status", None), a_records,
                 cname_chain, getattr(t, "asn", None), getattr(t, "as_org", None),
                 now, now, scan_id, scan_id),
            )
            n += 1
        # Tech (httpx + AI merged) — only for hosts we have it for; don't clobber
        # an existing list with an empty one.
        for host, tech in (tech_by_host or {}).items():
            if tech:
                self.db.execute("UPDATE assets SET tech=? WHERE fqdn=?",
                                (json.dumps(tech), _norm(host)))
        for host, prof in (profile_by_host or {}).items():
            if prof:
                self.db.execute("UPDATE assets SET profile=? WHERE fqdn=?",
                                (json.dumps(prof), _norm(host)))
        for host, fc in (finding_counts_by_host or {}).items():
            self.db.execute("UPDATE assets SET finding_counts=? WHERE fqdn=?",
                            (json.dumps(fc), _norm(host)))
        # Curated EASM surface (names only) — overwrite from the last scan; a host
        # the crawler didn't reach simply isn't in the map (keeps its prior surface).
        for host, surf in (surface_by_host or {}).items():
            if surf:
                self.db.execute("UPDATE assets SET surface=? WHERE fqdn=?",
                                (json.dumps(surf), _norm(host)))
        return n, new_fqdns

    # ----- bulk ops ------------------------------------------------------- #
    def _bulk_where(self, fqdns: list[str] | None, filt: dict | None) -> tuple[str, list]:
        if fqdns:
            ph = ",".join("?" * len(fqdns))
            return f"fqdn IN ({ph})", [_norm(f) for f in fqdns]
        filt = filt or {}
        where, p = [], []
        if filt.get("group") is not None:
            where.append('"group" = ?'); p.append(filt["group"])
        if filt.get("status"):
            where.append("status = ?"); p.append(filt["status"])
        if filt.get("source"):
            where.append("source = ?"); p.append(filt["source"])
        # Empty selection matches NOTHING (never delete/update the whole table).
        return (" AND ".join(where) if where else "1=0"), p

    def bulk_delete(self, *, fqdns: list[str] | None = None, filter: dict | None = None) -> int:
        clause, p = self._bulk_where(fqdns, filter)
        n = self.db.execute(f"DELETE FROM assets WHERE {clause}", tuple(p))
        if n:
            self._fts_rebuild()
        return n

    def bulk_set_group(self, *, group: str | None, fqdns: list[str] | None = None,
                       filter: dict | None = None) -> int:
        clause, p = self._bulk_where(fqdns, filter)
        n = self.db.execute(f'UPDATE assets SET "group" = ? WHERE {clause}', tuple([group, *p]))
        if n:
            self._fts_rebuild()
        return n
