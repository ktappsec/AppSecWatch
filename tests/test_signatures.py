"""Updatable signature packs: resolution, validation, atomic install, reload.

No network — `update_js_libs` is exercised via `apply_js_libs` (its install half)
so the suite stays offline like every other tool-facing test.
"""
from __future__ import annotations

import json

import pytest

from appsecwatch.audit import signatures as sig
from appsecwatch.audit.js_libs import detect_in_content, load_db, reload_db


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    """Point the store at a tmp dir and keep the loader cache from leaking."""
    monkeypatch.setenv(sig.ENV_SIGNATURE_DIR, str(tmp_path / "sigs"))
    reload_db()
    yield tmp_path / "sigs"
    reload_db()


def _pack(libs: int = 12, vulns: int = 2) -> str:
    """A minimally-plausible upstream-shaped pack."""
    return json.dumps({
        f"lib{i}": {
            "extractors": {"filecontent": [rf"lib{i} v(§§version§§)"]},
            "vulnerabilities": [
                {"below": "9.9.9", "severity": "medium",
                 "identifiers": {"CVE": [f"CVE-2020-{i}{j}"], "summary": "x"}}
                for j in range(vulns)
            ],
        } for i in range(libs)
    })


# --------------------------------------------------------------------------- #
# Resolution: bundled is the floor, a fetched pack takes precedence
# --------------------------------------------------------------------------- #
def test_falls_back_to_bundled_when_store_empty(store):
    assert sig.is_updated() is False
    assert sig.active_path() == sig.bundled_path()
    assert sig.status()["origin"] == "bundled"
    assert sig.status()["fetched_at"] is None


def test_store_copy_wins_over_bundled(store):
    sig.apply_js_libs(_pack(), source_url="https://example.test/p.json")
    assert sig.is_updated() is True
    assert sig.active_path() == sig.store_path()
    st = sig.status()
    assert st["origin"] == "store" and st["entry_count"] == 12
    assert st["fetched_at"] and st["source_url"] == "https://example.test/p.json"


def test_bundled_seed_is_never_modified_by_an_update(store):
    before = sig.bundled_path().read_bytes()
    sig.apply_js_libs(_pack(), source_url="https://example.test/p.json")
    assert sig.bundled_path().read_bytes() == before


# --------------------------------------------------------------------------- #
# Validation: a bad payload must never replace a working pack
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("payload,reason", [
    ("<html>503 Service Unavailable</html>", "captive portal / error page"),
    ("", "empty body"),
    ("{}", "empty object"),
    (json.dumps({"jquery": {"extractors": {}}}), "no usable extractors"),
    (_pack(libs=3), "implausibly few libraries (truncated download)"),
])
def test_validate_rejects(payload, reason):
    with pytest.raises(ValueError):
        sig.validate_js_libs(payload)


def test_rejected_update_leaves_previous_pack_in_place(store):
    sig.apply_js_libs(_pack(libs=20), source_url="https://example.test/good.json")
    good = sig.store_path().read_text()
    with pytest.raises(ValueError):
        sig.apply_js_libs("<html>nope</html>", source_url="https://example.test/bad")
    assert sig.store_path().read_text() == good
    assert sig.status()["entry_count"] == 20


def test_previous_pack_kept_as_backup(store):
    sig.apply_js_libs(_pack(libs=20), source_url="https://example.test/1.json")
    sig.apply_js_libs(_pack(libs=30), source_url="https://example.test/2.json")
    bak = sig.store_path().with_suffix(".json.bak")
    assert bak.is_file()
    assert len(json.loads(bak.read_text())) == 20      # the superseded copy
    assert sig.status()["entry_count"] == 30


# --------------------------------------------------------------------------- #
# The loader must pick up an installed pack without a restart
# --------------------------------------------------------------------------- #
def test_update_takes_effect_in_process(store):
    assert "lib0" not in load_db()                      # bundled seed has no lib0
    sig.apply_js_libs(_pack(), source_url="https://example.test/p.json")
    db = load_db()
    assert "lib0" in db
    assert ("lib0", "1.2.3") in detect_in_content("lib0 v1.2.3", db)


def test_corrupt_store_pack_degrades_to_bundled(store):
    sig.apply_js_libs(_pack(), source_url="https://example.test/p.json")
    sig.store_path().write_text("{ this is not json")
    reload_db()
    db = load_db()
    assert "jquery" in db          # fell back to the bundled seed rather than dying
    assert "lib0" not in db
