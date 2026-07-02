"""Tests for appsecwatch.recon.triage.triage_records.

Liveness classification only: `dead` (no A records) vs `live` (resolves). Scope
is the configured roots; there is NO IP/ASN ownership gate. ASN/org are display
enrichment taken from the first A record.
"""
from __future__ import annotations

from appsecwatch.recon.triage import triage_records


def _rec(host: str, a=None, cname=None) -> dict:
    return {"host": host, "a": list(a or []), "cname": list(cname or [])}


# ---------------------- dead ----------------------

def test_dead_when_no_a_records(make_ipinfo):
    ip = make_ipinfo()
    assets = triage_records([_rec("missing.example.com", a=[])], ip)
    assert len(assets) == 1
    a = assets[0]
    assert a.status == "dead"
    assert a.a_records == []
    assert "no a records" in a.reason.lower()


def test_dead_when_a_field_absent_entirely(make_ipinfo):
    ip = make_ipinfo()
    assert triage_records([{"host": "x.example.com"}], ip)[0].status == "dead"


def test_ipv6_records_are_ignored(make_ipinfo):
    # IPv4 only — an AAAA-only record has no usable A → dead.
    ip = make_ipinfo()
    assert triage_records([_rec("v6.example.com", a=["2001:db8::1"])], ip)[0].status == "dead"


# ---------------------- live (regardless of hosting) ----------------------

def test_live_when_it_resolves(make_ipinfo):
    ip = make_ipinfo()
    assets = triage_records([_rec("api.example.com", a=["203.0.113.5"])], ip)
    assert assets[0].status == "live"
    assert "resolves" in assets[0].reason.lower()


def test_live_regardless_of_hosting(make_ipinfo):
    # No sanctioned-range gate — an off-prem IP is still live + in play.
    ip = make_ipinfo(asn_map={"203.0.113.5": (64511, "Outside Corp")})
    assets = triage_records([_rec("api.example.com", a=["203.0.113.5"])], ip)
    assert assets[0].status == "live"
    assert assets[0].asn == 64511 and assets[0].as_org == "Outside Corp"


def test_live_keeps_third_party_cname(make_ipinfo):
    # A SaaS-hosted subdomain is live; the third-party CNAME is preserved (the
    # takeovers stage uses it), not a reason to skip scanning.
    ip = make_ipinfo()
    rec = _rec("support.example.com", a=["10.1.2.3"], cname=["example.zendesk.com"])
    a = triage_records([rec], ip)[0]
    assert a.status == "live"
    assert a.cname_chain == ["example.zendesk.com"]


def test_cname_chain_lowercased_and_stripped(make_ipinfo):
    ip = make_ipinfo()
    rec = _rec("x.example.com", a=["10.0.0.1"], cname=["Edge.Example.COM."])
    assert triage_records([rec], ip)[0].cname_chain == ["edge.example.com"]


# ---------------------- bulk / metadata ----------------------

def test_triage_records_preserves_order_and_count(make_ipinfo):
    ip = make_ipinfo(asn_map={"1.1.1.1": (64511, "Cloudflare")})
    recs = [
        _rec("dead.example.com", a=[]),
        _rec("ours.example.com", a=["10.0.0.1"]),
        _rec("third.example.com", a=["1.1.1.1"]),
    ]
    assets = triage_records(recs, ip)
    assert [a.status for a in assets] == ["dead", "live", "live"]
    assert [a.fqdn for a in assets] == [
        "dead.example.com", "ours.example.com", "third.example.com",
    ]


def test_asn_metadata_populated_from_primary_a(make_ipinfo):
    ip = make_ipinfo(asn_map={"10.0.0.1": (64500, "Our ASN")})
    assets = triage_records([_rec("a.example.com", a=["10.0.0.1"])], ip)
    assert assets[0].asn == 64500
    assert assets[0].as_org == "Our ASN"
