"""Unified cross-scan finding state (server-side, SQLite `finding_state` table).

ONE row per finding fingerprint (`source|host|group_key`, host '*' = global),
carrying its lifecycle (first/last-seen scan, open|resolved|suppressed|accepted,
consecutive-absent counter) and freeform workflow `tags`. This is the single
source of truth for: manual suppression (a status), the incremental new/recurring/
resolved diff, and the analytics finding-lifecycle. Supersedes the legacy
`suppressions` table (backfilled once at DB init; retained for rollback).

Resolve rule: a finding flips to `resolved` after being absent for 2 CONSECUTIVE
scans that actually RAN its producing source (see `audit/lifecycle.source_ran`).
Manual `suppressed`/`accepted` rows are sticky — absence never auto-resolves them.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from appsecwatch.audit.lifecycle import source_ran
from appsecwatch.audit.suppress import finding_fingerprint
from appsecwatch.api.db import Database
from appsecwatch.models import Finding

# SQLite host-variable ceiling is 999; chunk IN() lists well under it.
_CHUNK = 400


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FindingStateManager:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- suppression-compatible surface (SuppressionManager delegates here) ---

    def suppressed_fingerprints(self) -> set[str]:
        """The set injected into run_scan (status='suppressed'). Same fingerprint
        format the engine's SuppressionStage matches on."""
        return {
            r["fingerprint"]
            for r in self.db.query(
                "SELECT fingerprint FROM finding_state WHERE status='suppressed'"
            )
        }

    def list_suppressed(self) -> list[dict[str, Any]]:
        return self.db.query(
            'SELECT fingerprint, source, host, group_key AS key, scope, reason, '
            'tags, status, created_at FROM finding_state '
            "WHERE status='suppressed' ORDER BY created_at DESC"
        )

    def add_suppression(self, *, source: str, host: str | None, key: str,
                        scope: str = "host", reason: str = "") -> dict[str, Any]:
        if scope == "global":
            host = "*"
        host = host or "*"
        fp = f"{source}|{host}|{key}"
        now = _now()
        self.db.execute(
            'INSERT INTO finding_state (fingerprint, source, host, group_key, '
            'status, scope, reason, tags, created_at, updated_at) '
            "VALUES (?, ?, ?, ?, 'suppressed', ?, ?, '[]', ?, ?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET status='suppressed', "
            "reason=excluded.reason, scope=excluded.scope, updated_at=excluded.updated_at",
            (fp, source, host, key, scope, reason, now, now),
        )
        return self.db.query(
            'SELECT fingerprint, source, host, group_key AS key, scope, reason, '
            "status, created_at FROM finding_state WHERE fingerprint=?", (fp,)
        )[0]

    def unsuppress(self, fingerprint: str) -> bool:
        """Un-suppress: a manual-only row (never observed by a scan) is deleted;
        an observed row returns to 'open' so its lifecycle continues."""
        rows = self.db.query(
            "SELECT first_seen_scan, last_seen_scan FROM finding_state "
            "WHERE fingerprint=? AND status='suppressed'", (fingerprint,)
        )
        if not rows:
            return False
        r = rows[0]
        if not r["first_seen_scan"] and not r["last_seen_scan"]:
            return self.db.execute(
                "DELETE FROM finding_state WHERE fingerprint=?", (fingerprint,)
            ) > 0
        return self.db.execute(
            "UPDATE finding_state SET status='open', updated_at=? WHERE fingerprint=?",
            (_now(), fingerprint),
        ) > 0

    # ---- lifecycle diff scoping -------------------------------------------- #

    def open_fingerprints(self, *, group: str | None = None,
                          roots: list[str] | None = None,
                          hosts: set[str] | None = None) -> set[str]:
        """Currently-open fingerprints (prior_open for the incremental diff),
        scoped by asset group, by the scan's roots (host == root or *.root), and/or
        an explicit host set — so the report note reflects the scanned estate."""
        q = "SELECT fingerprint, host FROM finding_state WHERE status='open' AND host!='*'"
        params: list[Any] = []
        if group:
            q += ' AND "group"=?'
            params.append(group)
        rows = self.db.query(q, tuple(params))
        norm_roots = [r.strip().lower().rstrip(".") for r in (roots or []) if r]

        def _match(host: str) -> bool:
            if hosts is not None and host not in hosts:
                return False
            if norm_roots:
                h = (host or "").lower()
                return any(h == r or h.endswith("." + r) for r in norm_roots)
            return True

        return {r["fingerprint"] for r in rows if _match(r["host"])}

    # ---- the resolve engine (called at scan end) --------------------------- #

    def sync(self, current: list[Finding], *, scanned_hosts: set[str],
             coverage: dict | None, group: str | None, scan_id: str) -> dict[str, int]:
        """Update finding_state for one completed scan and return diff counts.

        `current` is ALL findings the scan detected (incl. suppressed — a suppressed
        finding is still *present*). `scanned_hosts` bounds which stored findings may
        be resolved (a host not scanned this run is never marked absent)."""
        now = _now()
        present: dict[str, Finding] = {finding_fingerprint(f): f for f in current}

        prior = self._prior_for_hosts(scanned_hosts)
        prior_status = {fp: st for fp, st, _ in prior}
        prior_absent = {  # open + host-scoped + absent this scan
            fp: absent for fp, st, absent in prior
            if st == "open" and fp not in present
        }

        new = sum(1 for fp in present if fp not in prior_status)
        recurring = sum(
            1 for fp in present if prior_status.get(fp) in ("open", "suppressed", "accepted")
        )
        reopened = sum(1 for fp in present if prior_status.get(fp) == "resolved")

        for fp, f in present.items():
            self._upsert_present(fp, f, group=group, scan_id=scan_id, now=now)

        resolved = 0
        for fp, absent in prior_absent.items():
            if not source_ran(fp.split("|", 1)[0], coverage):
                continue  # source didn't run → absence is not meaningful
            became = self._mark_absent(fp, absent, now)
            resolved += 1 if became else 0

        return {"new": new, "recurring": recurring, "resolved": resolved, "reopened": reopened}

    def _prior_for_hosts(self, hosts: set[str]) -> list[tuple[str, str, int]]:
        """(fingerprint, status, consecutive_absent) for stored rows on these
        hosts. Chunked IN() to stay under the SQLite variable ceiling."""
        out: list[tuple[str, str, int]] = []
        host_list = [h for h in hosts if h]
        for i in range(0, len(host_list), _CHUNK):
            chunk = host_list[i:i + _CHUNK]
            ph = ",".join("?" for _ in chunk)
            rows = self.db.query(
                f"SELECT fingerprint, status, consecutive_absent FROM finding_state "
                f"WHERE host IN ({ph})", tuple(chunk)
            )
            out.extend((r["fingerprint"], r["status"], r["consecutive_absent"] or 0) for r in rows)
        return out

    def _upsert_present(self, fp: str, f: Finding, *, group: str | None,
                        scan_id: str, now: str) -> None:
        parts = fp.split("|", 2)
        source, host = parts[0], (parts[1] if len(parts) > 1 else "")
        self.db.execute(
            'INSERT INTO finding_state (fingerprint, source, host, group_key, '
            'finding_class, category, severity, title, status, tags, "group", '
            'first_seen_scan, last_seen_scan, consecutive_absent, created_at, updated_at) '
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', '[]', ?, ?, ?, 0, ?, ?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET "
            "  severity=excluded.severity, title=excluded.title, "
            "  finding_class=excluded.finding_class, category=excluded.category, "
            '  "group"=COALESCE(excluded."group", finding_state."group"), '
            "  last_seen_scan=excluded.last_seen_scan, consecutive_absent=0, "
            "  status=CASE WHEN finding_state.status='resolved' THEN 'open' "
            "              ELSE finding_state.status END, "
            "  updated_at=excluded.updated_at",
            (fp, source, host, f.group_key, f.finding_class, f.category,
             f.severity, f.title, group, scan_id, scan_id, now, now),
        )

    def _mark_absent(self, fp: str, absent: int, now: str) -> bool:
        """Increment the absent counter; flip to resolved at 2. Returns True when
        it just became resolved."""
        became_resolved = (absent + 1) >= 2
        self.db.execute(
            "UPDATE finding_state SET consecutive_absent=consecutive_absent+1, "
            "status=CASE WHEN consecutive_absent+1 >= 2 THEN 'resolved' ELSE status END, "
            "updated_at=? WHERE fingerprint=? AND status='open'",
            (now, fp),
        )
        return became_resolved

    # ---- tags / status / listing (API-facing, later phases) ---------------- #

    def get(self, fingerprint: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM finding_state WHERE fingerprint=?", (fingerprint,))
        return rows[0] if rows else None

    def set_tags(self, fingerprint: str, tags: list[str]) -> bool:
        clean = sorted({t.strip() for t in tags if t and t.strip()})
        return self.db.execute(
            "UPDATE finding_state SET tags=?, updated_at=? WHERE fingerprint=?",
            (json.dumps(clean), _now(), fingerprint),
        ) > 0

    def set_status(self, fingerprint: str, status: str) -> bool:
        if status not in ("open", "resolved", "suppressed", "accepted"):
            raise ValueError(f"invalid status: {status}")
        return self.db.execute(
            "UPDATE finding_state SET status=?, updated_at=? WHERE fingerprint=?",
            (status, _now(), fingerprint),
        ) > 0

    def list(self, *, status: str | None = None, group: str | None = None,
             finding_class: str | None = None, host: str | None = None,
             sort: str = "last_seen_scan", limit: int = 500) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            where.append("status=?"); params.append(status)
        if group:
            where.append('"group"=?'); params.append(group)
        if finding_class:
            where.append("finding_class=?"); params.append(finding_class)
        if host:
            where.append("host=?"); params.append(host)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        order = sort if sort in (
            "last_seen_scan", "first_seen_scan", "consecutive_absent", "severity"
        ) else "last_seen_scan"
        rows = self.db.query(
            f"SELECT * FROM finding_state{clause} ORDER BY {order} DESC LIMIT ?",
            tuple(params) + (limit,),
        )
        for r in rows:
            r["tags"] = json.loads(r.get("tags") or "[]")
        return rows

    def analytics(self, *, group: str | None = None) -> dict[str, Any]:
        """Posture-over-time analytics core: status/category/severity breakdowns of
        the CURRENT finding state, the most widespread issues, the oldest still-open
        findings, and per-asset-priority open counts. Trends come from ScanHistory."""
        where, params = "", []
        if group:
            where, params = ' WHERE "group"=?', [group]
        rows = self.db.query(
            "SELECT status, category, severity, host, group_key, finding_class, title, "
            f"first_seen_scan FROM finding_state{where}", tuple(params)
        )
        by_status: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        widespread: dict[str, dict] = {}
        open_rows: list[dict] = []
        for r in rows:
            st = r["status"] or "open"
            by_status[st] = by_status.get(st, 0) + 1
            if st != "open":
                continue
            cat = r["category"] or "other"
            by_category[cat] = by_category.get(cat, 0) + 1
            sev = r["severity"] or "info"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            open_rows.append(r)
            gk = r["finding_class"] or r["group_key"] or r["title"] or "?"
            w = widespread.setdefault(gk, {"key": gk, "title": r["title"],
                                           "category": r["category"], "hosts": set()})
            if r["host"]:
                w["hosts"].add(r["host"])
        longest = sorted((r for r in open_rows if r["first_seen_scan"]),
                         key=lambda r: r["first_seen_scan"])[:10]
        widespread_list = sorted(widespread.values(), key=lambda w: -len(w["hosts"]))[:10]
        # Per-asset-priority open-finding counts (join assets on host).
        prio = self.db.query(
            "SELECT COALESCE(a.priority, 0) AS priority, COUNT(*) AS n "
            "FROM finding_state fs LEFT JOIN assets a ON a.fqdn = fs.host "
            f"WHERE fs.status='open'{(' AND fs.' + where[7:]) if where else ''} "
            "GROUP BY COALESCE(a.priority, 0) ORDER BY priority DESC",
            tuple(params),
        )
        return {
            "by_status": by_status,
            "by_category": by_category,
            "by_severity": by_severity,
            "open_total": by_status.get("open", 0),
            "resolved_total": by_status.get("resolved", 0),
            "suppressed_total": by_status.get("suppressed", 0),
            "widespread": [
                {"key": w["key"], "title": w["title"], "category": w["category"],
                 "host_count": len(w["hosts"])} for w in widespread_list
            ],
            "longest_open": [
                {"title": r["title"], "host": r["host"], "category": r["category"],
                 "severity": r["severity"], "first_seen_scan": r["first_seen_scan"]}
                for r in longest
            ],
            "by_priority": [{"priority": p["priority"], "open": p["n"]} for p in prio],
        }
