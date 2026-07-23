"""Authentication: API keys (WEB_API_PLAN §1, decision 5) + an HTTP Basic front door.

**Two layers, deliberately different in reach.**

`require_api_key` is a per-route dependency, so it only guards routes that declare
it — i.e. `/api/*`. The built UI is mounted as plain static files with no
dependency at all, so on its own the API key leaves the whole SPA shell readable
by anyone who can reach the port.

`BasicAuthMiddleware` closes that: it runs on the PARENT app, ahead of both the
static mount and the `/api` sub-app, so nothing is served anonymously. It is the
browser-facing gate — the native credential prompt — and it is what makes putting
this server behind a public tunnel safe.

Either credential is sufficient. A request carrying a valid API key skips the
Basic challenge (so scripts, `curl`, and the `?api_key=` report links keep working
unchanged), and a request that clears Basic satisfies `require_api_key` too (so a
human who logged in at the front door does not ALSO have to paste a 64-char key
into Settings). Both are the same principal — someone authorised to drive scans —
so neither grants more than the other.

If neither is configured the server runs **open** — convenient for local UI
development, and loudly warned about at startup.
"""
from __future__ import annotations

import base64
import binascii
import hmac

from fastapi import Header, HTTPException, Request, status
from starlette.responses import JSONResponse

from appsecwatch.api.models import error_response

#: Never challenged. `deploy.sh` and container/orchestrator probes poll this, and a
#: health check that needs credentials is a health check that reports the wrong
#: thing when the credentials are what broke. It exposes only status + version.
_UNPROTECTED_PATHS = frozenset({"/healthz", "/api/healthz"})


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


def has_valid_api_key(request: Request, server) -> bool:
    """Whether this request carries a valid API key, read straight off the raw
    request. Shared by the dependency and the middleware (which runs before any
    route resolution and so cannot use FastAPI's Header injection)."""
    if not server.api_keys:
        return False
    presented = _extract_key(
        request.headers.get("authorization"), request.headers.get("x-api-key")
    ) or request.query_params.get("api_key")
    return bool(presented and _matches(presented, server.api_keys))


def check_basic_credentials(authorization: str | None, server) -> bool:
    """Validate an `Authorization: Basic <b64>` header against the configured pair.

    Both halves are compared in constant time, and BOTH are always compared even
    once one has failed — an early return on a bad username would leak, by timing,
    whether a guessed username exists.
    """
    if not authorization:
        return False
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "basic" or not token:
        return False
    try:
        decoded = base64.b64decode(token.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    user, sep, password = decoded.partition(":")
    if not sep:
        return False
    user_ok = hmac.compare_digest(user, server.basic_auth_user or "")
    pass_ok = hmac.compare_digest(password, server.basic_auth_password or "")
    return user_ok and pass_ok


class BasicAuthMiddleware:
    """Challenge every request that isn't already authenticated by an API key.

    Installed on the PARENT app so it covers the static UI mount as well as
    `/api` — that reach is the entire point (see the module docstring).

    On success it stamps `basic_authed` into the ASGI scope's `state`, which
    `require_api_key` reads back via `request.state`, so clearing the front door
    is enough to use the app. The scope (and so that stamp) is carried across the
    `/api` mount boundary — `tests/test_basic_auth.py` pins this.

    **Pure ASGI, deliberately not `BaseHTTPMiddleware`.** The latter wraps every
    response in an anyio task group and buffers it, which costs a scheduling hop
    on each request (this runs on EVERY request, including every static asset)
    and interferes with the file responses the report/artifact routes return.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        app = scope.get("app")
        server = getattr(getattr(app, "state", None), "config", None)
        if server is None or not server.basic_auth_enabled:
            return await self.app(scope, receive, send)
        if scope.get("path") in _UNPROTECTED_PATHS:
            return await self.app(scope, receive, send)

        request = Request(scope, receive)
        # An API key is an equally valid credential — don't challenge a script.
        if has_valid_api_key(request, server) or check_basic_credentials(
            request.headers.get("authorization"), server
        ):
            scope.setdefault("state", {})["basic_authed"] = True
            return await self.app(scope, receive, send)

        # The realm is what the browser shows in its prompt and what it keys
        # cached credentials on, so it must stay stable across releases.
        response = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=error_response("unauthorized", "authentication required"),
            headers={"WWW-Authenticate": 'Basic realm="AppSecWatch", charset="UTF-8"'},
        )
        await response(scope, receive, send)


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

    A request already cleared by `BasicAuthMiddleware` passes without a key: the
    browser authenticated the same human at the front door, so demanding a second
    credential would only push people into pasting the API key somewhere.
    """
    server = request.app.state.config
    if getattr(request.state, "basic_authed", False):
        return
    if not server.auth_enabled:
        return
    presented = _extract_key(authorization, x_api_key) or request.query_params.get("api_key")
    if not presented or not _matches(presented, server.api_keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response("unauthorized", "missing or invalid API key"),
            headers={"WWW-Authenticate": "Bearer"},
        )
