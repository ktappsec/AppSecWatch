"""SQLite foundation for the Web API (server-only).

The scan engine and the CLI stay DB-free; the **server** owns all DB writes (from
the shared ScanState/run artifacts after a scan, and from UI CRUD). `runs/<id>/`
stays the authoritative artifact store — this DB is the cross-run *relational*
layer. Phase 1 ships the `assets` table; later phases append their own CREATE
statements to `_SCHEMA` (all idempotent). See the SQLite roadmap.

Access pattern: one connection (`check_same_thread=False`, WAL) guarded by a lock;
methods are synchronous and meant to be called off the event loop via
`asyncio.to_thread(...)` from the async routes.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ENV_DB_PATH = "APPSECWATCH_DB_PATH"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# Each phase appends its statements here; all must be idempotent (IF NOT EXISTS).
_SCHEMA: list[str] = [
    # --- P1: assets inventory ---------------------------------------------- #
    """
    CREATE TABLE IF NOT EXISTS assets (
        fqdn         TEXT PRIMARY KEY,
        "group"      TEXT,                                 -- iştirak
        source       TEXT NOT NULL DEFAULT 'discovered',   -- imported | discovered
        root         TEXT,                                 -- owning root domain
        status       TEXT,                                 -- live | dead
        a_records    TEXT,                                 -- JSON list[str]
        cname_chain  TEXT,                                 -- JSON list[str] (for re-eval)
        asn          INTEGER,
        as_org       TEXT,
        tech         TEXT,                                 -- JSON list[{name,source}] (P3)
        profile      TEXT,                                 -- JSON AppProfile (ai.profile)
        finding_counts TEXT,                               -- JSON {sev: n} from last scan
        surface      TEXT,                                 -- JSON curated surface (EASM): domains/endpoints/keys
        priority     INTEGER,                              -- manual business criticality 1..10 (10 highest)
        notes        TEXT,
        first_seen   TEXT,
        last_seen    TEXT,
        last_scan_id TEXT
    )
    """,
    'CREATE INDEX IF NOT EXISTS idx_assets_group ON assets("group")',
    "CREATE INDEX IF NOT EXISTS idx_assets_root ON assets(root)",
    # --- P2: scans history index + schedules ------------------------------- #
    """
    CREATE TABLE IF NOT EXISTS scans (
        id            TEXT PRIMARY KEY,
        state         TEXT,
        roots         TEXT,                                 -- JSON list
        "group"       TEXT,
        "only"        TEXT,                                 -- JSON list
        skip          TEXT,                                 -- JSON list
        throttle      TEXT,
        submitted_at  TEXT,
        started_at    TEXT,
        finished_at   TEXT,
        finding_count INTEGER DEFAULT 0,
        sev_critical  INTEGER DEFAULT 0,                    -- per-severity breakdown (for trends)
        sev_high      INTEGER DEFAULT 0,
        sev_medium    INTEGER DEFAULT 0,
        sev_low       INTEGER DEFAULT 0,
        sev_info      INTEGER DEFAULT 0,
        risk_score    INTEGER,                              -- derived 0..100 (see aggregator.risk_score)
        source        TEXT DEFAULT 'manual',               -- manual | schedule
        schedule_id   TEXT
    )
    """,
    'CREATE INDEX IF NOT EXISTS idx_scans_group ON scans("group")',
    "CREATE INDEX IF NOT EXISTS idx_scans_finished ON scans(finished_at)",
    """
    CREATE TABLE IF NOT EXISTS schedules (
        id           TEXT PRIMARY KEY,
        name         TEXT,
        target       TEXT,                                  -- JSON {roots|group|assets|all_assets}
        "only"       TEXT,
        skip         TEXT,
        throttle     TEXT,
        compress     INTEGER DEFAULT 1,
        cadence      TEXT,                                  -- hourly | daily | weekly
        at_time      TEXT,                                  -- "HH:MM" (UTC)
        weekday      INTEGER,                               -- 0=Mon..6=Sun (weekly)
        enabled      INTEGER DEFAULT 1,
        next_run_at  TEXT,
        last_run_at  TEXT,
        last_job_id  TEXT,
        created_at   TEXT
    )
    """,
    # --- P3: manual finding suppressions ---------------------------------- #
    """
    CREATE TABLE IF NOT EXISTS suppressions (
        fingerprint TEXT PRIMARY KEY,                       -- source|host|key
        source      TEXT,
        host        TEXT,                                   -- '*' = global
        key         TEXT,
        scope       TEXT DEFAULT 'host',                    -- host | global
        reason      TEXT,
        created_at  TEXT
    )
    """,
    # --- P4: nuclei catalog + custom templates ---------------------------- #
    """
    CREATE TABLE IF NOT EXISTS nuclei_templates (
        id       TEXT PRIMARY KEY,
        name     TEXT,
        severity TEXT,
        tags     TEXT,                                      -- JSON list
        category TEXT,
        path     TEXT,
        source   TEXT DEFAULT 'bundled'                     -- bundled | custom
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_nuclei_category ON nuclei_templates(category)",
    "CREATE INDEX IF NOT EXISTS idx_nuclei_severity ON nuclei_templates(severity)",
    """
    CREATE TABLE IF NOT EXISTS custom_templates (
        id         TEXT PRIMARY KEY,
        name       TEXT,
        yaml       TEXT,
        enabled    INTEGER DEFAULT 1,
        valid      INTEGER DEFAULT 0,
        error      TEXT,
        created_at TEXT,
        updated_at TEXT
    )
    """,
    # --- scan option templates (reusable presets; no target) -------------- #
    """
    CREATE TABLE IF NOT EXISTS scan_templates (
        id         TEXT PRIMARY KEY,
        name       TEXT,
        "only"     TEXT,                                   -- JSON list
        skip       TEXT,                                   -- JSON list
        throttle   TEXT,
        compress   INTEGER DEFAULT 1,
        created_at TEXT
    )
    """,
    # --- cross-scan finding state (UNIFIED identity + lifecycle + tags) ---- #
    # Keyed on the suppression fingerprint `source|host|group_key` (host '*' =
    # global). Suppression is now just one `status`; freeform `tags` carry
    # workflow ("sent-to-dev" etc.). `consecutive_absent` drives the 2-scan
    # resolve rule (only incremented when the producing source actually ran).
    # Supersedes `suppressions` (retained for rollback; backfilled in _init_schema).
    """
    CREATE TABLE IF NOT EXISTS finding_state (
        fingerprint        TEXT PRIMARY KEY,               -- source|host|group_key
        source             TEXT,
        host               TEXT,                           -- '*' = global
        group_key          TEXT,
        finding_class      TEXT,                           -- controlled taxonomy
        category           TEXT,
        severity           TEXT,                           -- last-seen severity
        title              TEXT,                           -- last-seen human title
        status             TEXT DEFAULT 'open',            -- open|resolved|suppressed|accepted
        tags               TEXT DEFAULT '[]',              -- JSON list[str] (freeform)
        reason             TEXT DEFAULT '',                -- suppression/accept note
        scope              TEXT DEFAULT 'host',            -- host | global
        consecutive_absent INTEGER DEFAULT 0,
        first_seen_scan    TEXT,
        last_seen_scan     TEXT,
        "group"            TEXT,                           -- owning asset group (analytics)
        created_at         TEXT,
        updated_at         TEXT
    )
    """,
    'CREATE INDEX IF NOT EXISTS idx_fstate_status ON finding_state(status)',
    "CREATE INDEX IF NOT EXISTS idx_fstate_group_key ON finding_state(group_key)",
    'CREATE INDEX IF NOT EXISTS idx_fstate_group ON finding_state("group")',
    "CREATE INDEX IF NOT EXISTS idx_fstate_class ON finding_state(finding_class)",
    # --- in-app notifications (pluggable notifier: in-app channel sink) ---- #
    """
    CREATE TABLE IF NOT EXISTS notifications (
        id         TEXT PRIMARY KEY,
        type       TEXT,                                   -- e.g. asset.new
        title      TEXT,
        body       TEXT,
        payload    TEXT,                                   -- JSON
        "group"    TEXT,
        scan_id    TEXT,
        read       INTEGER DEFAULT 0,
        created_at TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read)",
    "CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at)",
]

# FTS5 virtual tables — created SEPARATELY + GUARDED (a stripped SQLite build may
# lack the fts5 module; putting these in the unguarded _SCHEMA loop would raise).
_FTS_SCHEMA: list[str] = [
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS assets_fts USING fts5(
        fqdn, "group", tech, domains, endpoints, profile_summary
    )
    """,
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
        title, description, host, category, source,
        fingerprint UNINDEXED, scan_id UNINDEXED
    )
    """,
]


# (table, column, type) added to existing DBs. New columns must also appear in the
# CREATE above so fresh DBs get them directly.
_MIGRATIONS: list[tuple[str, str, str]] = [
    ("assets", "cname_chain", "TEXT"),
    ("assets", "profile", "TEXT"),
    ("assets", "finding_counts", "TEXT"),
    ("assets", "status", "TEXT"),          # buckets → liveness; backfilled in _init_schema
    ("assets", "surface", "TEXT"),         # curated EASM surface from the last scan
    ("assets", "priority", "INTEGER"),     # manual business criticality 1..10
    ("assets", "first_seen_scan", "TEXT"), # scan id that first discovered the asset (new-domain alert)
    ("scans", "sev_critical", "INTEGER DEFAULT 0"),   # per-severity trend columns
    ("scans", "sev_high", "INTEGER DEFAULT 0"),
    ("scans", "sev_medium", "INTEGER DEFAULT 0"),
    ("scans", "sev_low", "INTEGER DEFAULT 0"),
    ("scans", "sev_info", "INTEGER DEFAULT 0"),
    ("scans", "risk_score", "INTEGER"),               # derived 0..100
]


def default_db_path(output_root: str | Path) -> Path:
    env = os.environ.get(ENV_DB_PATH)
    return Path(env) if env else Path(output_root) / "appsecwatch.db"


class Database:
    """Thin synchronous SQLite wrapper (one locked connection, WAL)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # Set by _init_schema: True when the fts5 module is available (search uses
        # LIKE fallback when False so the box never breaks).
        self.fts_enabled: bool = False
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            for stmt in _SCHEMA:
                self._conn.execute(stmt)
            # FTS5 is optional — a stripped SQLite build lacks it. Create guarded
            # and record availability; search falls back to LIKE when unavailable.
            try:
                for stmt in _FTS_SCHEMA:
                    self._conn.execute(stmt)
                self.fts_enabled = True
            except sqlite3.OperationalError:
                self.fts_enabled = False
            # Idempotent column migrations for DBs created before a column existed
            # (fresh DBs already have it via the CREATE above).
            for table, col, ddl in _MIGRATIONS:
                try:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
                except sqlite3.OperationalError:
                    pass  # column already present
            # One-time backfill of the new liveness `status` from the legacy
            # `bucket` (dead→dead; in_scope/shadow_it→live). Guarded: a fresh DB
            # has no `bucket` column → OperationalError → skipped.
            try:
                self._conn.execute(
                    "UPDATE assets SET status = CASE WHEN bucket='dead' THEN 'dead' "
                    "ELSE 'live' END WHERE status IS NULL AND bucket IS NOT NULL"
                )
            except sqlite3.OperationalError:
                pass
            # One-time migration of legacy manual suppressions into the unified
            # finding_state table (status='suppressed'). INSERT OR IGNORE so an
            # already-migrated / re-opened fingerprint is never resurrected, and
            # the legacy `suppressions` table is retained for rollback.
            try:
                now = _now_iso()
                self._conn.execute(
                    "INSERT OR IGNORE INTO finding_state "
                    "(fingerprint, source, host, group_key, status, scope, reason, "
                    " tags, created_at, updated_at) "
                    "SELECT fingerprint, source, host, key, 'suppressed', "
                    "       COALESCE(scope,'host'), COALESCE(reason,''), '[]', "
                    "       COALESCE(created_at, ?), COALESCE(created_at, ?) "
                    "FROM suppressions",
                    (now, now),
                )
            except sqlite3.OperationalError:
                pass
            self._conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]

    def execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
