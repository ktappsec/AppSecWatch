"""Nuclei template catalog (SQLite `nuclei_templates` table).

Walks a nuclei-templates directory, parses each YAML's `id` + `info{name,
severity,tags}` and derives a category from its path, and caches the rows for a
searchable/tickable picker. Re-indexed on demand (POST /nuclei/reindex) and after
the image runs `nuclei -update-templates`. Custom templates are merged in with
source='custom'.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from appsecwatch.api.db import Database

_TOP_DIRS = {"http", "dns", "tcp", "ssl", "javascript", "headless", "file",
             "network", "workflows", "code", "cloud"}


def default_templates_dir() -> Path | None:
    """Best-effort nuclei-templates location (env override, then common paths)."""
    env = os.environ.get("NUCLEI_TEMPLATES_DIR")
    if env:
        return Path(env)
    for c in (Path.home() / "nuclei-templates",
              Path.home() / ".config" / "nuclei-templates"):
        if c.is_dir():
            return c
    return None


def _category(root: Path, path: Path) -> str:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    parts = parts[:-1]  # drop filename
    if not parts:
        return "misc"
    if parts[0] in _TOP_DIRS and len(parts) > 1:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _parse(path: Path) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text())
    except Exception:  # noqa: BLE001 — skip unparseable templates
        return None
    if not isinstance(data, dict) or not data.get("id"):
        return None
    info = data.get("info") or {}
    tags = info.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    return {
        "id": str(data["id"]),
        "name": info.get("name"),
        "severity": (info.get("severity") or "").lower() or None,
        "tags": tags or [],
    }


class NucleiCatalog:
    def __init__(self, db: Database) -> None:
        self.db = db

    def index(self, root: str | Path, *, source: str = "bundled") -> int:
        """Walk `root`, upserting parsed templates. Returns the count indexed."""
        root = Path(root)
        if not root.is_dir():
            return 0
        import json
        n = 0
        for path in root.rglob("*"):
            if path.suffix.lower() not in (".yaml", ".yml") or not path.is_file():
                continue
            meta = _parse(path)
            if meta is None:
                continue
            self.db.execute(
                "INSERT INTO nuclei_templates (id, name, severity, tags, category, path, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name, severity=excluded.severity, "
                "tags=excluded.tags, category=excluded.category, path=excluded.path, source=excluded.source",
                (meta["id"], meta["name"], meta["severity"], json.dumps(meta["tags"]),
                 _category(root, path), str(path), source),
            )
            n += 1
        return n

    def upsert_custom(self, *, id: str, name: str | None, severity: str | None,
                      tags: list[str], path: str) -> None:
        import json
        self.db.execute(
            "INSERT INTO nuclei_templates (id, name, severity, tags, category, path, source) "
            "VALUES (?, ?, ?, ?, 'custom', ?, 'custom') "
            "ON CONFLICT(id) DO UPDATE SET name=excluded.name, severity=excluded.severity, "
            "tags=excluded.tags, path=excluded.path, source='custom'",
            (id, name, severity, json.dumps(tags or []), path),
        )

    def search(self, *, q: str | None = None, category: str | None = None,
               tag: str | None = None, severity: str | None = None,
               source: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        import json
        sql = "SELECT * FROM nuclei_templates"
        where, p = [], []
        if q:
            where.append("(id LIKE ? OR name LIKE ?)")
            p += [f"%{q}%", f"%{q}%"]
        if category:
            where.append("category = ?"); p.append(category)
        if severity:
            where.append("severity = ?"); p.append(severity)
        if source:
            where.append("source = ?"); p.append(source)
        if tag:
            where.append("tags LIKE ?"); p.append(f'%"{tag}"%')
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY category, id LIMIT ?"
        p.append(limit)
        out = []
        for r in self.db.query(sql, tuple(p)):
            r = dict(r)
            r["tags"] = json.loads(r["tags"]) if r.get("tags") else []
            out.append(r)
        return out

    def categories(self) -> list[dict[str, Any]]:
        return self.db.query(
            "SELECT category, COUNT(*) AS count FROM nuclei_templates "
            "GROUP BY category ORDER BY category"
        )
