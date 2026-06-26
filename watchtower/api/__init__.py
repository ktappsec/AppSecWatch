"""WatchTower Web API — a thin async HTTP layer over the scan engine.

Exposes WatchTower as an authenticated service (`watchtower serve`). It reuses the
existing async runner (`run_scan`) and Pydantic models; it does **not** change
the scan engine. See WEB_API_PLAN.md for the locked design.
"""
from __future__ import annotations

__all__ = ["create_app"]


def create_app(*args, **kwargs):
    # Lazy re-export so `import watchtower.api` stays cheap (FastAPI import deferred).
    from watchtower.api.server import create_app as _create_app

    return _create_app(*args, **kwargs)
