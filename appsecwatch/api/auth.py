"""API-key authentication (WEB_API_PLAN §1, decision 5).

Static keys via `Authorization: Bearer <key>` (also `X-API-Key`), compared in
constant time. Multiple keys allow per-caller revocation. 401 on missing/invalid.

If no keys are configured the server runs **open** (auth disabled) — convenient
for local UI development. `create_app` logs a loud warning in that case; a real
deployment sets `APPSECWATCH_API_KEYS`.
"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request, status

from appsecwatch.api.models import error_response


def _extract_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token.strip()
    if x_api_key:
        return x_api_key.strip()
    return None


def _matches(presented: str, configured: list[str]) -> bool:
    # Constant-time compare against every configured key (no early-out by length).
    ok = False
    for key in configured:
        if hmac.compare_digest(presented, key):
            ok = True
    return ok


async def require_api_key(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """FastAPI dependency: 401 unless a valid key is presented (or auth disabled).

    Also accepts the key via an `?api_key=` query param. Headers can't be set on
    `<iframe src>` / `<a href>`, so this lets a browser view/download the HTML
    report and logs directly. (The key may then appear in access logs — fine for
    a self-hosted internal tool; prefer the header for programmatic callers.)
    """
    server = request.app.state.config
    if not server.auth_enabled:
        return
    presented = _extract_key(authorization, x_api_key) or request.query_params.get("api_key")
    if not presented or not _matches(presented, server.api_keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response("unauthorized", "missing or invalid API key"),
            headers={"WWW-Authenticate": "Bearer"},
        )
