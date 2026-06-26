"""Tests for watchtower.recon.triage.triage_records.

Covers the four-rule classification (DESIGN.md §2.1.1):
    1. NXDOMAIN / no A record       → dead
    2. Any A IP outside sanctioned  → shadow_it
    3. Any CNAME hop not under root → shadow_it
    4. Otherwise                    → in_scope
"""
from __future__ import annotations

from watchtower.recon.triage import triage_records


ROOTS = ["example.com"]


def _rec(host: str, a=None, cname=None, status="NOERROR") -> dict:
    return {
        "host": host,
        "a": list(a or []),
        "cname": list(cname or []),
        "status_code": status,
    }


# ---------------------- Rule 1: dead ----------------------

def test_dead_when_no_a_records(make_ipinfo):
    ip = make_ipinfo()
    assets = triage_records([_rec("missing.example.com", a=[], status="NXDOMAIN")], ROOTS, ip)
    assert len(assets) == 1
    a = assets[0]
    assert a.bucket == "dead"
    assert a.a_records == []
    assert "no a records" in a.reason.lower()


def test_dead_when_a_field_absent_entirely(make_ipinfo):
    ip = make_ipinfo()
    assets = triage_records([{"host": "x.example.com"}], ROOTS, ip)
    assert assets[0].bucket == "dead"


# ---------------------- Rule 2: shadow_it via IP ----------------------

def test_shadow_when_ip_outside_sanctioned(make_ipinfo):
    ip = make_ipinfo(
        sanctioned_cidrs=["10.0.0.0/8"],
        asn_map={"203.0.113.5": (64511, "Outside Corp")},
    )
    assets = triage_records([_rec("api.example.com", a=["203.0.113.5"])], ROOTS, ip)
    assert assets[0].bucket == "shadow_it"
    assert "203.0.113.5" in assets[0].reason


def test_inscope_when_ip_inside_cidr(make_ipinfo):
    ip = make_ipinfo(sanctioned_cidrs=["10.0.0.0/8"])
    assets = triage_records([_rec("api.example.com", a=["10.1.2.3"])], ROOTS, ip)
    assert assets[0].bucket == "in_scope"


def test_inscope_via_sanctioned_asn_even_if_cidr_misses(make_ipinfo):
    ip = make_ipinfo(
        sanctioned_cidrs=["10.0.0.0/8"],         # 1.2.3.4 not in here
        sanctioned_asns=[64500],
        asn_map={"1.2.3.4": (64500, "Our ASN")},
    )
    assets = triage_records([_rec("a.example.com", a=["1.2.3.4"])], ROOTS, ip)
    assert assets[0].bucket == "in_scope"
    assert assets[0].asn == 64500


def test_strictest_wins_with_mixed_a_records(make_ipinfo):
    """If any A record is outside sanctioned, the asset is Shadow IT — DESIGN.md §2.1."""
    ip = make_ipinfo(
        sanctioned_cidrs=["10.0.0.0/8"],
        asn_map={"203.0.113.5": (64511, "Outside Corp")},
    )
    rec = _rec("multi.example.com", a=["10.1.2.3", "203.0.113.5"])
    assets = triage_records([rec], ROOTS, ip)
    assert assets[0].bucket == "shadow_it"


def test_ipv6_records_are_ignored(make_ipinfo):
    """IPv4 only — AAAA records mixed into the `a` array are filtered (DESIGN.md §2.1)."""
    ip = make_ipinfo()
    rec = _rec("v6.example.com", a=["2001:db8::1"])     # would be filtered by is_ipv4
    assets = triage_records([rec], ROOTS, ip)
    assert assets[0].bucket == "dead"


# ---------------------- Rule 3: shadow_it via CNAME ----------------------

def test_shadow_when_cname_targets_non_root_zone(make_ipinfo):
    ip = make_ipinfo(sanctioned_cidrs=["10.0.0.0/8"])
    rec = _rec(
        "support.example.com",
        a=["10.1.2.3"],
        cname=["example.zendesk.com"],
    )
    assets = triage_records([rec], ROOTS, ip)
    assert assets[0].bucket == "shadow_it"
    assert "non-root zone" in assets[0].reason
    assert "zendesk.com" in assets[0].reason


def test_inscope_when_cname_stays_within_roots(make_ipinfo):
    ip = make_ipinfo(sanctioned_cidrs=["10.0.0.0/8"])
    rec = _rec(
        "www.example.com",
        a=["10.1.2.3"],
        cname=["edge.example.com"],
    )
    assets = triage_records([rec], ROOTS, ip)
    assert assets[0].bucket == "in_scope"


def test_inscope_with_multiple_roots(make_ipinfo):
    ip = make_ipinfo(sanctioned_cidrs=["10.0.0.0/8"])
    rec = _rec(
        "foo.alt-corp.io",
        a=["10.1.2.3"],
        cname=["edge.alt-corp.io"],
    )
    assets = triage_records([rec], ["example.com", "alt-corp.io"], ip)
    assert assets[0].bucket == "in_scope"


# ---------------------- Rule 4: in_scope ----------------------

def test_inscope_no_cname_chain(make_ipinfo):
    ip = make_ipinfo(sanctioned_cidrs=["10.0.0.0/8"])
    rec = _rec("svc.example.com", a=["10.0.0.7"])
    assets = triage_records([rec], ROOTS, ip)
    assert assets[0].bucket == "in_scope"
    assert assets[0].cname_chain == []


# ---------------------- Bulk / metadata ----------------------

def test_triage_records_preserves_order_and_count(make_ipinfo):
    ip = make_ipinfo(sanctioned_cidrs=["10.0.0.0/8"],
                    asn_map={"1.1.1.1": (64511, "Cloudflare")})
    recs = [
        _rec("dead.example.com", a=[]),
        _rec("ours.example.com", a=["10.0.0.1"]),
        _rec("third.example.com", a=["1.1.1.1"]),
    ]
    assets = triage_records(recs, ROOTS, ip)
    assert [a.bucket for a in assets] == ["dead", "in_scope", "shadow_it"]
    assert [a.fqdn for a in assets] == [
        "dead.example.com", "ours.example.com", "third.example.com",
    ]


def test_asn_metadata_populated_from_primary_a(make_ipinfo):
    ip = make_ipinfo(
        sanctioned_cidrs=["10.0.0.0/8"],
        asn_map={"10.0.0.1": (64500, "Our ASN")},
    )
    assets = triage_records([_rec("a.example.com", a=["10.0.0.1"])], ROOTS, ip)
    assert assets[0].asn == 64500
    assert assets[0].as_org == "Our ASN"
