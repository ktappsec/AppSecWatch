"""AppSecWatch Web API — a thin async HTTP layer over the scan engine.

Exposes AppSecWatch as an authenticated service (`appsecwatch serve`). It reuses the
existing async runner (`run_scan`) and Pydantic models; it does **not** change
the scan engine. See WEB_API_PLAN.md for the locked design.
"""
from __future__ import annotations

__all__ = ["create_app"]


def create_app(*args, **kwargs):
    # Lazy re-export so `import appsecwatch.api` stays cheap (FastAPI import deferred).
    from appsecwatch.api.server import create_app as _create_app

    return _create_app(*args, **kwargs)
