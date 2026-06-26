"""AssetManager — CSV import, CRUD, resolution, and the recon→assets sync."""
from __future__ import annotations

import pytest

from watchtower.api.assets import AssetManager
from watchtower.api.db import Database
from watchtower.models import TriagedAsset


def _am(tmp_path) -> AssetManager:
    return AssetManager(Database(tmp_path / "t.db"))


def _ta(fqdn, ips=("1.2.3.4",), status="live", asn=64500):
    return TriagedAsset(fqdn=fqdn, a_records=list(ips), cname_chain=[],
                        asn=asn, as_org="Org", status=status, reason="t")


# --- CSV import / CRUD ------------------------------------------------------
def test_import_csv_upsert_and_skip(tmp_path):
    am = _am(tmp_path)
    res = am.import_csv("domain,group\nkuveytturk.com.tr,Bank\nINVALID\napp.example.com,Sub\n")
    assert res == {"added": 2, "updated": 0, "skipped": 2}  # header + INVALID skipped
    # re-import updates, doesn't duplicate
    res2 = am.import_csv("kuveytturk.com.tr,Bank\napp.example.com,Sub2\n")
    assert res2["added"] == 0 and res2["updated"] == 2
    assert am.get("app.example.com")["group"] == "Sub2"


def test_upsert_invalid_domain_raises(tmp_path):
    am = _am(tmp_path)
    with pytest.raises(ValueError):
        am.upsert_imported("nodot", "G")


def test_list_filters_and_groups(tmp_path):
    am = _am(tmp_path)
    am.upsert_imported("a.com", "G1")
    am.upsert_imported("b.com", "G2")
    assert {a["fqdn"] for a in am.list()} == {"a.com", "b.com"}
    assert [a["fqdn"] for a in am.list(group="G1")] == ["a.com"]
    assert {g["group"]: g["count"] for g in am.groups()} == {"G1": 1, "G2": 1}
    assert am.delete("a.com") is True and am.get("a.com") is None


# --- scan-target resolution -------------------------------------------------
def test_resolve_roots(tmp_path):
    am = _am(tmp_path)
    am.upsert_imported("a.com", "Bank")
    am.upsert_imported("b.com", "Bank")
    am.upsert_imported("c.com", "Other")
    assert set(am.resolve_roots(group="Bank")) == {"a.com", "b.com"}
    assert set(am.resolve_roots(all_assets=True)) == {"a.com", "b.com", "c.com"}
    assert am.resolve_roots(assets=["x.com"]) == ["x.com"]
    assert am.resolve_roots(group="Nope") == []


# --- recon → assets sync ----------------------------------------------------
def test_sync_inherits_group_and_keeps_imported(tmp_path):
    am = _am(tmp_path)
    am.upsert_imported("kuveytturk.com.tr", "Bank")
    am.upsert_imported("special.kuveytturk.com.tr", "Special")  # imported subdomain
    triaged = [
        _ta("kuveytturk.com.tr"),                                  # the root (imported)
        _ta("app.kuveytturk.com.tr"),                              # discovered → inherit Bank
        _ta("special.kuveytturk.com.tr"),                          # imported → keep Special
        _ta("ext.zendesk.com"),                                    # off-root → no group
    ]
    n = am.sync_discovered(triaged, ["kuveytturk.com.tr"], "S1", group=None)
    assert n == 4
    root = am.get("kuveytturk.com.tr")
    assert root["source"] == "imported" and root["group"] == "Bank"
    assert root["status"] == "live" and root["last_scan_id"] == "S1"
    disc = am.get("app.kuveytturk.com.tr")
    assert disc["source"] == "discovered" and disc["group"] == "Bank"
    assert disc["root"] == "kuveytturk.com.tr" and disc["a_records"] == ["1.2.3.4"]
    assert am.get("special.kuveytturk.com.tr")["group"] == "Special"  # not clobbered
    off = am.get("ext.zendesk.com")
    assert off["group"] is None and off["status"] == "live"


def test_sync_preserves_first_seen(tmp_path):
    am = _am(tmp_path)
    am.sync_discovered([_ta("a.com")], ["a.com"], "S1")
    first = am.get("a.com")["first_seen"]
    am.sync_discovered([_ta("a.com")], ["a.com"], "S2")
    a = am.get("a.com")
    assert a["first_seen"] == first and a["last_scan_id"] == "S2"


def test_sync_explicit_group_fallback(tmp_path):
    # No imported root → discovered inherit the scan's explicit group.
    am = _am(tmp_path)
    am.sync_discovered([_ta("app.acme.com")], ["acme.com"], "S1", group="AcmeGroup")
    assert am.get("app.acme.com")["group"] == "AcmeGroup"


def test_sync_writes_merged_tech(tmp_path):
    am = _am(tmp_path)
    am.sync_discovered([_ta("a.com")], ["a.com"], "S1",
                       tech_by_host={"a.com": [{"name": "nginx", "source": "httpx"},
                                               {"name": "React", "source": "ai"}]})
    assert am.get("a.com")["tech"] == [{"name": "nginx", "source": "httpx"},
                                       {"name": "React", "source": "ai"}]


def test_sync_writes_profile_and_finding_counts(tmp_path):
    am = _am(tmp_path)
    am.sync_discovered(
        [_ta("a.com")], ["a.com"], "S1",
        profile_by_host={"a.com": {"app_type": "portal", "audience": "public"}},
        finding_counts_by_host={"a.com": {"high": 2, "medium": 1}},
    )
    a = am.get("a.com")
    assert a["profile"]["app_type"] == "portal"
    assert a["finding_counts"] == {"high": 2, "medium": 1}


def test_sync_stores_cname_chain(tmp_path):
    am = _am(tmp_path)
    t = TriagedAsset(fqdn="www.a.com", a_records=[], cname_chain=["a.cdn.net"],
                     asn=None, as_org=None, status="dead", reason="dangling cdn")
    am.sync_discovered([t], ["a.com"], "S1")
    assert am.get("www.a.com")["cname_chain"] == ["a.cdn.net"]


# --- bulk ops --------------------------------------------------------------
def test_bulk_set_group_and_delete(tmp_path):
    am = _am(tmp_path)
    for d in ("a.com", "b.com", "c.com"):
        am.upsert_imported(d, "G1" if d != "c.com" else "G2")
    assert am.bulk_set_group(group="GX", fqdns=["a.com", "b.com"]) == 2
    assert am.get("a.com")["group"] == "GX" and am.get("b.com")["group"] == "GX"
    assert am.bulk_delete(filter={"group": "GX"}) == 2
    assert am.get("a.com") is None and am.get("c.com") is not None
    # safety: empty selection touches nothing
    assert am.bulk_delete(fqdns=[], filter={}) == 0
    assert am.get("c.com") is not None
