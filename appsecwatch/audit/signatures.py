"""Updatable signature packs (the js-lib vuln DB today; more can join).

Mirrors how nuclei-templates are handled: a copy is **seeded into the image at
build time**, the live copy is located at runtime via an env override with
fallbacks, and it is refreshed by an **explicit** action — never silently on a
scan. The differences from nuclei are deliberate:

  * nuclei ships its own updater (`nuclei -update-templates`); retire.js does
    not, so `update_js_libs` is the fetcher (one httpx GET — already a dep).
  * nuclei-templates live inside the image and are re-fetched on rebuild. The
    signature store defaults under ``output_root`` instead, which on the standard
    deployment is the persisted ``appsecwatch-data`` volume — so an update
    survives a docker rebuild, same precedent as the config store and the DB.

Resolution order for the live pack (first hit wins):

  1. ``<store_dir()>/<name>.json`` — a fetched update, if one has been applied
  2. the bundled seed under ``audit/data/`` — always present

so a fetch is strictly additive: an air-gapped deployment that never calls
`update_*` keeps scanning on the vendored copy.

A fetched pack replaces the store copy **atomically** and only after it parses
and passes a shape check, so a captive portal's HTML error page or a truncated
body can never clobber a working DB. The previous copy is kept as ``.bak``.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).parent / "data"

# Env override for the writable signature store (the server points this at
# <output_root>/.signatures so updates land on the persisted volume).
ENV_SIGNATURE_DIR = "APPSECWATCH_SIGNATURES_DIR"

JS_LIBS = "js_libs"

#: Upstream retire.js signature repository (flat format: per-library
#: `extractors` + `vulnerabilities` with top-level `below`/`atOrAbove` ranges).
JS_LIBS_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master"
    "/repository/jsrepository.json"
)


#: Set by the server to `<output_root>/.signatures`. Module state rather than an
#: `os.environ.setdefault`, which would let the FIRST app factory in a process pin
#: the directory for every later one (two `create_app`s with different
#: output_roots silently shared a store — caught in tests).
_default_store_dir: Path | None = None


def set_default_store_dir(path: str | Path | None) -> None:
    """Set the fallback store dir (the env override still wins). Clears the
    loader cache so a later `load_db()` re-resolves against the new location."""
    global _default_store_dir
    _default_store_dir = Path(path) if path else None
    from appsecwatch.audit.js_libs import reload_db
    reload_db()


def store_dir() -> Path:
    """Writable signature store: operator env override, then the server-configured
    default (`<output_root>/.signatures`), then a per-user path for CLI use."""
    env = os.environ.get(ENV_SIGNATURE_DIR)
    if env:
        return Path(env)
    if _default_store_dir is not None:
        return _default_store_dir
    return Path.home() / ".appsecwatch" / "signatures"


def bundled_path(name: str = JS_LIBS) -> Path:
    return _DATA_DIR / f"{name}.json"


def store_path(name: str = JS_LIBS) -> Path:
    return store_dir() / f"{name}.json"


def meta_path(name: str = JS_LIBS) -> Path:
    return store_dir() / f"{name}.meta.json"


def active_path(name: str = JS_LIBS) -> Path:
    """The pack that will actually be loaded: store copy if present, else bundled."""
    p = store_path(name)
    if p.is_file():
        return p
    return bundled_path(name)


def is_updated(name: str = JS_LIBS) -> bool:
    return store_path(name).is_file()


@dataclass
class SignatureMeta:
    """Provenance sidecar for a fetched pack (never written for the bundled seed)."""
    name: str
    source_url: str
    fetched_at: str
    entry_count: int
    vuln_count: int
    etag: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def read_meta(name: str = JS_LIBS) -> dict[str, Any] | None:
    p = meta_path(name)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:  # noqa: BLE001 — a corrupt sidecar is not fatal
        return None


def _counts(raw: dict[str, Any]) -> tuple[int, int]:
    libs = [v for k, v in raw.items() if not k.startswith("$") and isinstance(v, dict)]
    return len(libs), sum(len(v.get("vulnerabilities") or []) for v in libs)


def validate_js_libs(text: str) -> tuple[dict[str, Any], int, int]:
    """Parse + shape-check a candidate js-lib pack.

    Raises ValueError on anything that is not plausibly the retire.js repository,
    so a redirect/error page never replaces a working DB.
    """
    try:
        raw = json.loads(text)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"not valid JSON ({e})") from e
    if not isinstance(raw, dict) or not raw:
        raise ValueError("expected a non-empty JSON object")
    entries, vulns = _counts(raw)
    if entries < 10:
        raise ValueError(f"only {entries} libraries — implausibly small, refusing")
    if vulns < 10:
        raise ValueError(f"only {vulns} vulnerability entries — refusing")
    # At least one library must carry usable extractors, else nothing would match.
    usable = any(
        (v.get("extractors") or {}).get("uri")
        or (v.get("extractors") or {}).get("filecontent")
        or v.get("uri") or v.get("filecontent")
        for k, v in raw.items() if not k.startswith("$") and isinstance(v, dict)
    )
    if not usable:
        raise ValueError("no library carries uri/filecontent extractors")
    return raw, entries, vulns


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        if path.is_file():
            shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def apply_js_libs(text: str, *, source_url: str, etag: str | None = None) -> SignatureMeta:
    """Validate + install a js-lib pack into the store. Returns its provenance."""
    _raw, entries, vulns = validate_js_libs(text)
    _atomic_write(store_path(JS_LIBS), text)
    meta = SignatureMeta(
        name=JS_LIBS, source_url=source_url,
        fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        entry_count=entries, vuln_count=vulns, etag=etag,
    )
    _atomic_write(meta_path(JS_LIBS), json.dumps(meta.as_dict(), indent=2))
    # The loader caches; a fresh pack must take effect without a restart.
    from appsecwatch.audit.js_libs import reload_db
    reload_db()
    return meta


async def update_js_libs(url: str | None = None, *, timeout: float = 60.0) -> SignatureMeta:
    """Fetch the upstream retire.js repository and install it. Raises on failure."""
    import httpx

    src = url or JS_LIBS_URL
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(src)
        resp.raise_for_status()
        text = resp.text
        etag = resp.headers.get("etag")
    return apply_js_libs(text, source_url=src, etag=etag)


def status(name: str = JS_LIBS) -> dict[str, Any]:
    """Freshness/provenance summary for the UI + `/capabilities`."""
    path = active_path(name)
    meta = read_meta(name)
    try:
        raw = json.loads(path.read_text())
        entries, vulns = _counts(raw)
    except Exception:  # noqa: BLE001
        entries = vulns = 0
    return {
        "name": name,
        "origin": "store" if is_updated(name) else "bundled",
        "path": str(path),
        "store_dir": str(store_dir()),
        "entry_count": entries,
        "vuln_count": vulns,
        "fetched_at": (meta or {}).get("fetched_at"),
        "source_url": (meta or {}).get("source_url") or JS_LIBS_URL,
    }
