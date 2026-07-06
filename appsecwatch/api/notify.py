"""Pluggable notification subsystem (server-side).

A small channel abstraction so notifications (new-domain discovery today; more
later) fan out to multiple sinks. Ships two channels — in-app (writes the
`notifications` table, always on) and webhook (Slack / Teams / generic JSON,
opt-in) — and leaves a documented seam for an email channel (schema + stub, no
SMTP in v1). `Notifier.dispatch` is best-effort: a channel failure is logged and
never propagates.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

import httpx

from appsecwatch.api.db import Database

log = logging.getLogger("appsecwatch.api")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    type: str                                   # e.g. "asset.new"
    title: str
    body: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    group: str | None = None
    scan_id: str | None = None


class Channel(Protocol):
    name: str

    async def send(self, event: Event) -> None: ...


class InAppChannel:
    """Persists notifications into the `notifications` table (read by the UI)."""
    name = "in_app"

    def __init__(self, db: Database) -> None:
        self.db = db

    async def send(self, event: Event) -> None:
        await asyncio.to_thread(self._write, event)

    def _write(self, event: Event) -> None:
        self.db.execute(
            'INSERT INTO notifications (id, type, title, body, payload, "group", '
            "scan_id, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (secrets.token_hex(8), event.type, event.title, event.body,
             json.dumps(event.payload), event.group, event.scan_id, _now()),
        )


class WebhookChannel:
    """Posts to a Slack / Teams / generic incoming webhook."""
    name = "webhook"

    def __init__(self, url: str, fmt: str = "generic", timeout: int = 10) -> None:
        self.url = url
        self.fmt = fmt
        self.timeout = timeout

    async def send(self, event: Event) -> None:
        body = self._format(event)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            await client.post(self.url, json=body)

    def _format(self, event: Event) -> dict[str, Any]:
        if self.fmt == "slack":
            return {"text": f"*{event.title}*\n{event.body}"}
        if self.fmt == "teams":
            return {"text": f"{event.title}\n\n{event.body}"}
        return {
            "type": event.type, "title": event.title, "body": event.body,
            "payload": event.payload, "group": event.group, "scan_id": event.scan_id,
        }


class EmailChannel:
    """Future SMTP channel — schema/stub only (no send in v1)."""
    name = "email"

    async def send(self, event: Event) -> None:  # pragma: no cover - not implemented
        log.info("email channel not implemented (event=%s)", event.type)


class Notifier:
    def __init__(self, channels: list[Channel]) -> None:
        self.channels = channels

    async def dispatch(self, event: Event) -> None:
        for ch in self.channels:
            try:
                await ch.send(event)
            except Exception as e:  # noqa: BLE001 — never let a channel break a scan
                log.warning("notifier channel %s failed: %r", ch.name, e)

    @classmethod
    def from_config(cls, db: Database, notifier_cfg: Any) -> "Notifier":
        """Build from a NotifierConfig: in-app always on; webhook when a URL is set;
        email when enabled (stub)."""
        channels: list[Channel] = [InAppChannel(db)]
        url = getattr(notifier_cfg, "webhook_url", "") if notifier_cfg else ""
        if url:
            channels.append(WebhookChannel(
                url, getattr(notifier_cfg, "webhook_format", "generic"),
                getattr(notifier_cfg, "timeout_seconds", 10),
            ))
        if notifier_cfg and getattr(notifier_cfg, "email_enabled", False):
            channels.append(EmailChannel())
        return cls(channels)


# --------------------------------------------------------------------------- #
# In-app notification store (read side, for the API)
# --------------------------------------------------------------------------- #
def list_notifications(db: Database, *, unread_only: bool = False,
                       limit: int = 50) -> list[dict[str, Any]]:
    q = "SELECT * FROM notifications"
    if unread_only:
        q += " WHERE read=0"
    q += " ORDER BY created_at DESC LIMIT ?"
    rows = db.query(q, (limit,))
    for r in rows:
        try:
            r["payload"] = json.loads(r.get("payload") or "{}")
        except (json.JSONDecodeError, TypeError):
            r["payload"] = {}
    return rows


def unread_count(db: Database) -> int:
    rows = db.query("SELECT COUNT(*) AS n FROM notifications WHERE read=0")
    return rows[0]["n"] if rows else 0


def mark_read(db: Database, notif_id: str | None = None) -> int:
    if notif_id:
        return db.execute("UPDATE notifications SET read=1 WHERE id=?", (notif_id,))
    return db.execute("UPDATE notifications SET read=1 WHERE read=0")
