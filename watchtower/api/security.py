"""HMAC-signed, SSRF-guarded webhooks.

A leaked key could turn the callback into a request forger (POST to an internal
host), so webhook hosts must be explicitly allowlisted, sent with a short
timeout, no redirects, and a single attempt. (There is no scan-target allowlist:
the per-request `roots` is the only scope — see config.py.)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from urllib.parse import urlparse

from watchtower.api.config import ServerConfig

log = logging.getLogger("watchtower.api")


def sign_webhook(body: bytes, secret: str) -> str:
    """`sha256=<hex>` HMAC-SHA256 of the raw body (matches the X-WatchTower-Signature)."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def callback_host_allowed(callback_url: str, allowlist: list[str]) -> bool:
    host = urlparse(callback_url).hostname or ""
    return host in allowlist


async def send_webhook(
    server: ServerConfig,
    callback_url: str,
    event: str,
    payload: dict,
) -> None:
    """Fire a single, signed, SSRF-guarded POST. Failures are logged, not retried.

    Guards: host must be allowlisted; short timeout; redirects NOT followed
    (a redirect could bounce the request to an internal host)."""
    if not callback_host_allowed(callback_url, server.webhook.callback_host_allowlist):
        log.warning("webhook host not allowlisted, skipping: %s", callback_url)
        return

    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "X-WatchTower-Event": event,
    }
    if server.webhook_secret:
        headers["X-WatchTower-Signature"] = sign_webhook(body, server.webhook_secret)

    import httpx

    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=server.webhook.timeout_seconds
        ) as client:
            resp = await client.post(callback_url, content=body, headers=headers)
        log.info(
            "webhook delivered: event=%s url=%s status=%s",
            event, callback_url, resp.status_code,
        )
    except Exception as e:  # noqa: BLE001 — fire-and-forget, never crash the run
        log.warning("webhook_failed: event=%s url=%s err=%r", event, callback_url, e)
