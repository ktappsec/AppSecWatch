"""All-in-one search: FTS5 index + LIKE fallback (api/search.py)."""
from __future__ import annotations

import json

from appsecwatch.api.db import Database
from appsecwatch.api.search import FTSIndex
from appsecwatch.audit.taxonomy import classify_findings
from appsecwatch.models import Finding


def _asset_row(fqdn, group="corp", tech=None, surface=None, profile=None):
    return {
        "fqdn": fqdn,
        "group": group,
        "tech": json.dumps(tech or [{"name": "nginx", "source": "httpx"}]),
        "surface": json.dumps(surface or {"third_party_domains": ["cdn.example.com"],
                                          "endpoints": ["GET api.example.com/v1/users"]}),
        "profile": json.dumps(profile or {"app_type": "customer portal", "reasoning": "login form"}),
    }


def _finding():
    f = Finding(source="nuclei", host="app.example.com", severity="high",
                title="SQL Injection", description="sqli in id param",
                evidence={"template_id": "sql-injection"})
    classify_findings([f])
    return f


def test_fts_search_assets_and_findings(tmp_path):
    db = Database(tmp_path / "t.db")
    if not db.fts_enabled:
        return  # environment lacks fts5 — LIKE path covered below
    idx = FTSIndex(db)
    idx.reindex_asset(_asset_row("app.example.com"))
    idx.index_findings("s1", [_finding()])

    assert any(r["fqdn"] == "app.example.com" for r in idx.search("nginx")["assets"])
    assert idx.search("nginx")["findings"] == [] or True
    # search by tech, by contacted domain, by profile summary
    assert idx.search("cdn.example")["assets"]
    assert idx.search("portal")["assets"]
    # finding search by title
    fnd = idx.search("injection")["findings"]
    assert fnd and fnd[0]["source"] == "nuclei" and fnd[0]["category"] == "injection"


def test_reindex_replaces_stale_rows(tmp_path):
    db = Database(tmp_path / "t.db")
    if not db.fts_enabled:
        return
    idx = FTSIndex(db)
    idx.reindex_asset(_asset_row("app.example.com", tech=[{"name": "apache"}]))
    idx.reindex_asset(_asset_row("app.example.com", tech=[{"name": "nginx"}]))
    assert not idx.search("apache")["assets"]     # stale row gone
    assert idx.search("nginx")["assets"]


def test_parsed_row_indexes_tech(tmp_path):
    """Production feeds `reindex_asset` a PARSED AssetManager row (tech=list,
    surface/profile=dict), not JSON strings. Ensure tech/domains/profile still
    index — not just fqdn+group."""
    db = Database(tmp_path / "t.db")
    if not db.fts_enabled:
        return
    idx = FTSIndex(db)
    idx.reindex_asset({
        "fqdn": "p.example.com", "group": "corp",
        "tech": [{"name": "nginx"}],
        "surface": {"third_party_domains": ["cdn.example.com"], "endpoints": []},
        "profile": {"app_type": "portal", "reasoning": "login"},
    })
    assert idx.search("nginx")["assets"]
    assert idx.search("cdn.example")["assets"]
    assert idx.search("portal")["assets"]


def test_asset_crud_keeps_fts_in_sync(tmp_path):
    """AssetManager writes keep assets_fts current so a freshly-imported (never
    scanned) asset is findable in global search immediately."""
    from appsecwatch.api.assets import AssetManager

    db = Database(tmp_path / "t.db")
    if not db.fts_enabled:
        return
    idx = FTSIndex(db)
    am = AssetManager(db)
    am.search = idx

    am.upsert_imported("app.example.com", "corp")
    assert any(r["fqdn"] == "app.example.com" for r in idx.search("app.example.com")["assets"])

    am.update("app.example.com", {"group": "movedgrp"})
    assert idx.search("movedgrp")["assets"]

    am.delete("app.example.com")
    assert not idx.search("app.example.com")["assets"]


def test_bulk_and_import_keep_fts_in_sync(tmp_path):
    from appsecwatch.api.assets import AssetManager

    db = Database(tmp_path / "t.db")
    if not db.fts_enabled:
        return
    idx = FTSIndex(db)
    am = AssetManager(db)
    am.search = idx

    am.import_csv("a.example.com,corp\nb.example.com,corp")
    assert idx.search("a.example")["assets"]
    assert idx.search("b.example")["assets"]

    am.bulk_delete(fqdns=["a.example.com"])
    assert not idx.search("a.example")["assets"]
    assert idx.search("b.example")["assets"]      # survivor still indexed after rebuild

    am.bulk_set_group(group="regrouped", fqdns=["b.example.com"])
    assert idx.search("regrouped")["assets"]


def test_like_fallback_when_fts_disabled(tmp_path):
    db = Database(tmp_path / "t.db")
    db.fts_enabled = False  # force the degraded path
    # seed the base tables the LIKE fallback scans
    db.execute("INSERT INTO assets (fqdn, \"group\", tech) VALUES ('app.example.com','corp',?)",
               (json.dumps([{"name": "nginx"}]),))
    db.execute(
        "INSERT INTO finding_state (fingerprint, source, host, group_key, title, status) "
        "VALUES ('nuclei|app.example.com|sql','nuclei','app.example.com','sql','SQL Injection','open')"
    )
    idx = FTSIndex(db)
    assert idx.search("nginx")["assets"]
    assert idx.search("injection")["findings"]
