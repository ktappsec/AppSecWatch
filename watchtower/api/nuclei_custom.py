"""Custom nuclei templates (SQLite `custom_templates`) + the AI generator.

The DB is the source of truth (UI editor). On save we `nuclei -validate` (graceful
basic check if the binary is absent) and mirror valid templates into the catalog
(source='custom'). Before a scan the enabled+valid templates are materialized to a
directory passed to nuclei via -t. The generator drafts a template from a natural-
language description via the LLM, then validates it.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from watchtower.api.db import Database

_FENCE = re.compile(r"```(?:ya?ml)?\s*(.*?)```", re.DOTALL)

_GEN_SYSTEM = (
    "You are an expert author of Nuclei security templates. Given a description of "
    "a check, output ONE valid Nuclei YAML template and NOTHING else (no prose). It "
    "MUST have a unique 'id', an 'info' block (name, author, severity, tags, "
    "description) and an appropriate matcher. Prefer http requests. NEVER use the "
    "'code' protocol. Keep it self-contained and safe (no destructive payloads)."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_yaml(text: str) -> str:
    m = _FENCE.search(text or "")
    return (m.group(1) if m else (text or "")).strip()


def _parse_meta(yaml_text: str) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(yaml_text)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict) or not data.get("id"):
        return None
    info = data.get("info") or {}
    tags = info.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    return {"id": str(data["id"]), "name": info.get("name"),
            "severity": (info.get("severity") or "").lower() or None, "tags": tags or []}


_VALIDATION_SIGNALS = (
    "invalid template", "validation", "syntax error", "could not parse",
    "unmarshal", "cannot unmarshal", "field id", "no templates",
)


def validate_template(yaml_text: str) -> tuple[bool, str]:
    """Validate a template. The structural check (YAML + id + info) is definitive;
    `nuclei -validate` is best-effort on top and only marks a structurally-valid
    template invalid when its output clearly signals a *validation* error — never
    on server-context noise (metrics/interactsh/update-check)."""
    meta = _parse_meta(yaml_text)
    if meta is None:
        return False, "not a valid nuclei template (missing id/info or bad YAML)"
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=True) as tf:
        tf.write(yaml_text)
        tf.flush()
        try:
            # -duc: skip the update check. stdin=DEVNULL: nuclei reads targets from
            # stdin and would otherwise block.
            r = subprocess.run(
                ["nuclei", "-validate", "-duc", "-no-interactsh", "-t", tf.name],
                capture_output=True, stdin=subprocess.DEVNULL, timeout=20,
            )
        except FileNotFoundError:
            return True, ""  # nuclei absent → trust structural check
        except Exception:  # noqa: BLE001 — timeout/other → trust structural check
            return True, ""
        if r.returncode == 0:
            return True, ""
        out = (r.stderr + r.stdout).decode("utf-8", "replace").lower()
        if any(sig in out for sig in _VALIDATION_SIGNALS):
            return False, r.stderr.decode("utf-8", "replace")[-400:] or "validation failed"
        return True, ""  # non-zero but only startup noise → trust structural check


class CustomTemplateManager:
    def __init__(self, db: Database, catalog=None) -> None:
        self.db = db
        self.catalog = catalog  # NucleiCatalog | None — mirror valid templates in

    def list(self) -> list[dict[str, Any]]:
        return self.db.query("SELECT * FROM custom_templates ORDER BY created_at DESC")

    def get(self, tid: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM custom_templates WHERE id=?", (tid,))
        return rows[0] if rows else None

    def _sync_catalog(self, row: dict[str, Any]) -> None:
        if self.catalog is None or not row.get("valid"):
            return
        meta = _parse_meta(row["yaml"]) or {}
        if meta.get("id"):
            self.catalog.upsert_custom(
                id=meta["id"], name=meta.get("name") or row.get("name"),
                severity=meta.get("severity"), tags=meta.get("tags", []),
                path=f"custom:{row['id']}",
            )

    def create(self, *, name: str | None, yaml_text: str, enabled: bool = True) -> dict[str, Any]:
        tid = uuid.uuid4().hex[:12]
        ok, err = validate_template(yaml_text)
        now = _now()
        self.db.execute(
            "INSERT INTO custom_templates (id, name, yaml, enabled, valid, error, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (tid, name, yaml_text, 1 if enabled else 0, 1 if ok else 0, err, now, now),
        )
        row = self.get(tid)
        self._sync_catalog(row)
        return row

    def update(self, tid: str, *, name: str | None = None, yaml_text: str | None = None,
               enabled: bool | None = None) -> dict[str, Any] | None:
        cur = self.get(tid)
        if cur is None:
            return None
        new_yaml = yaml_text if yaml_text is not None else cur["yaml"]
        ok, err = validate_template(new_yaml)
        self.db.execute(
            "UPDATE custom_templates SET name=?, yaml=?, enabled=?, valid=?, error=?, updated_at=? WHERE id=?",
            (name if name is not None else cur["name"], new_yaml,
             1 if (cur["enabled"] if enabled is None else enabled) else 0,
             1 if ok else 0, err, _now(), tid),
        )
        row = self.get(tid)
        self._sync_catalog(row)
        return row

    def delete(self, tid: str) -> bool:
        return self.db.execute("DELETE FROM custom_templates WHERE id=?", (tid,)) > 0

    def materialize_enabled(self, dest: str | Path) -> str | None:
        """Write enabled+valid templates to `dest`; return the dir (or None if empty)."""
        rows = self.db.query("SELECT * FROM custom_templates WHERE enabled=1 AND valid=1")
        if not rows:
            return None
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        for r in rows:
            (dest / f"{r['id']}.yaml").write_text(r["yaml"])
        return str(dest)

    async def generate(self, description: str, llm_cfg) -> dict[str, Any]:
        """Draft a template from a description via the LLM, then validate it."""
        from watchtower.ai.client import LLMClient

        client = LLMClient(llm_cfg)
        user = f"Write a Nuclei template for: {description}"
        try:
            raw = await client.chat(_GEN_SYSTEM, user)
        except Exception as e:  # noqa: BLE001 — LLM error degrades gracefully
            return {"yaml": "", "valid": False, "error": f"LLM error: {e}"}
        finally:
            close = getattr(client, "aclose", None) or getattr(client, "close", None)
            if close:
                try:
                    res = close()
                    if hasattr(res, "__await__"):
                        await res
                except Exception:  # noqa: BLE001
                    pass
        yaml_text = _extract_yaml(raw)
        ok, err = validate_template(yaml_text)
        return {"yaml": yaml_text, "valid": ok, "error": err}
