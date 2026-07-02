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
from pathlib import Path
from typing import Any

ENV_DB_PATH = "APPSECWATCH_DB_PATH"

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
]


# (table, column, type) added to existing DBs. New columns must also appear in the
# CREATE above so fresh DBs get them directly.
_MIGRATIONS: list[tuple[str, str, str]] = [
    ("assets", "cname_chain", "TEXT"),
    ("assets", "profile", "TEXT"),
    ("assets", "finding_counts", "TEXT"),
    ("assets", "status", "TEXT"),          # buckets → liveness; backfilled in _init_schema
    ("assets", "surface", "TEXT"),         # curated EASM surface from the last scan
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
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            for stmt in _SCHEMA:
                self._conn.execute(stmt)
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
