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
from typing import Any

from watchtower.api.db import Database

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(domain: str) -> str:
    return (domain or "").strip().lower().rstrip(".")


def _valid(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


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

    # ----- read ----------------------------------------------------------- #
    def _row(self, r: dict[str, Any]) -> dict[str, Any]:
        out = dict(r)
        out["group"] = out.pop("group", None)
        out["a_records"] = json.loads(out["a_records"]) if out.get("a_records") else []
        out["cname_chain"] = json.loads(out["cname_chain"]) if out.get("cname_chain") else []
        out["tech"] = json.loads(out["tech"]) if out.get("tech") else []
        out["profile"] = json.loads(out["profile"]) if out.get("profile") else None
        out["finding_counts"] = json.loads(out["finding_counts"]) if out.get("finding_counts") else {}
        return out

    def list(self, *, group: str | None = None, bucket: str | None = None,
             source: str | None = None, q: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM assets"
        where, p = [], []
        if group is not None:
            where.append('"group" = ?'); p.append(group)
        if bucket:
            where.append("bucket = ?"); p.append(bucket)
        if source:
            where.append("source = ?"); p.append(source)
        if q:
            where.append("fqdn LIKE ?"); p.append(f"%{q.strip().lower()}%")
        if where:
            sql += " WHERE " + " AND ".join(where)
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
    def upsert_imported(self, fqdn: str, group: str | None, notes: str | None = None) -> bool:
        """Add/update an imported asset (a root). Returns True if newly added."""
        d = _norm(fqdn)
        if not _valid(d):
            raise ValueError(f"invalid domain: {fqdn!r}")
        existing = self.get(d)
        now = _now()
        if existing:
            self.db.execute(
                'UPDATE assets SET "group"=?, notes=COALESCE(?, notes), '
                "source='imported', root=COALESCE(root, ?), last_seen=? WHERE fqdn=?",
                (group, notes, d, now, d),
            )
            return False
        self.db.execute(
            'INSERT INTO assets (fqdn, "group", source, root, notes, first_seen, last_seen) '
            "VALUES (?, ?, 'imported', ?, ?, ?, ?)",
            (d, group, d, notes, now, now),
        )
        return True

    def delete(self, fqdn: str) -> bool:
        return self.db.execute("DELETE FROM assets WHERE fqdn = ?", (_norm(fqdn),)) > 0

    def import_csv(self, text: str) -> dict[str, int]:
        """Upsert rows from a `domain,group` CSV. Header optional."""
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
            if self.upsert_imported(domain, group):
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
                        finding_counts_by_host: dict[str, dict] | None = None) -> int:
        """Upsert every triaged FQDN. Discovered inherit their root's imported
        group (else the scan's group); imported assets keep their group/notes.
        tech/profile/finding_counts (by host) are written onto matching assets."""
        roots = [_norm(r) for r in (scanned_roots or [])]
        # Precompute each root's imported group for inheritance.
        root_group: dict[str, str | None] = {}
        for r in roots:
            a = self.get(r)
            root_group[r] = a.get("group") if a and a.get("source") == "imported" else None
        now, n = _now(), 0
        for t in triaged:
            fqdn = _norm(getattr(t, "fqdn", ""))
            if not fqdn:
                continue
            root = _root_of(fqdn, roots)
            inherited = (root_group.get(root) if root else None) or group
            a_records = json.dumps(list(getattr(t, "a_records", []) or []))
            cname_chain = json.dumps(list(getattr(t, "cname_chain", []) or []))
            self.db.execute(
                'INSERT INTO assets (fqdn, "group", source, root, bucket, a_records, '
                "cname_chain, asn, as_org, first_seen, last_seen, last_scan_id) "
                "VALUES (?, ?, 'discovered', ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(fqdn) DO UPDATE SET "
                "  bucket=excluded.bucket, a_records=excluded.a_records, "
                "  cname_chain=excluded.cname_chain, "
                "  asn=excluded.asn, as_org=excluded.as_org, "
                "  last_seen=excluded.last_seen, last_scan_id=excluded.last_scan_id, "
                "  root=COALESCE(assets.root, excluded.root), "
                '  "group"=CASE WHEN assets.source=\'imported\' THEN assets."group" '
                '             ELSE COALESCE(excluded."group", assets."group") END',
                (fqdn, inherited, root, getattr(t, "bucket", None), a_records,
                 cname_chain, getattr(t, "asn", None), getattr(t, "as_org", None),
                 now, now, scan_id),
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
        return n

    # ----- re-evaluate buckets on sanctioned-range change ----------------- #
    def reevaluate(self, *, mmdb_path: str, sanctioned_cidrs: list[str],
                   sanctioned_asns: list[int], roots: list[str] | None = None) -> dict[str, int]:
        """Recompute every asset's bucket OFFLINE from its stored a_records +
        cname_chain against the NEW sanctioned ranges (per-IP ASN via the MMDB).
        Reuses the engine triage. Only bucket/asn/as_org change; group/notes kept.
        `roots` (for the CNAME-leaves-scope rule) defaults to the inventory's own
        roots (imported fqdns + each asset's root)."""
        from watchtower.recon.triage import triage_records
        from watchtower.util.ipinfo import IPInfoLookup

        assets = self.list()
        if roots is None:
            roots = sorted(
                {a["root"] for a in assets if a.get("root")}
                | {a["fqdn"] for a in assets if a.get("source") == "imported"}
            )
        ipinfo = IPInfoLookup(mmdb_path, sanctioned_cidrs, sanctioned_asns)
        total = changed = 0
        try:
            for a in assets:
                total += 1
                rec = {"host": a["fqdn"], "a": a["a_records"], "cname": a["cname_chain"]}
                t = triage_records([rec], list(roots), ipinfo)[0]
                if t.bucket != a.get("bucket"):
                    self.db.execute(
                        "UPDATE assets SET bucket=?, asn=?, as_org=? WHERE fqdn=?",
                        (t.bucket, t.asn, t.as_org, a["fqdn"]),
                    )
                    changed += 1
        finally:
            try:
                ipinfo.close()
            except Exception:  # noqa: BLE001
                pass
        return {"total": total, "changed": changed}

    # ----- bulk ops ------------------------------------------------------- #
    def _bulk_where(self, fqdns: list[str] | None, filt: dict | None) -> tuple[str, list]:
        if fqdns:
            ph = ",".join("?" * len(fqdns))
            return f"fqdn IN ({ph})", [_norm(f) for f in fqdns]
        filt = filt or {}
        where, p = [], []
        if filt.get("group") is not None:
            where.append('"group" = ?'); p.append(filt["group"])
        if filt.get("bucket"):
            where.append("bucket = ?"); p.append(filt["bucket"])
        if filt.get("source"):
            where.append("source = ?"); p.append(filt["source"])
        # Empty selection matches NOTHING (never delete/update the whole table).
        return (" AND ".join(where) if where else "1=0"), p

    def bulk_delete(self, *, fqdns: list[str] | None = None, filter: dict | None = None) -> int:
        clause, p = self._bulk_where(fqdns, filter)
        return self.db.execute(f"DELETE FROM assets WHERE {clause}", tuple(p))

    def bulk_set_group(self, *, group: str | None, fqdns: list[str] | None = None,
                       filter: dict | None = None) -> int:
        clause, p = self._bulk_where(fqdns, filter)
        return self.db.execute(f'UPDATE assets SET "group" = ? WHERE {clause}', tuple([group, *p]))
