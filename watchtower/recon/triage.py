"""The triage router.

For each resolved subdomain, classifies it into exactly one of:
    in_scope    — all A records inside sanctioned CIDRs or sanctioned ASNs,
                  AND no CNAME in chain points to a non-root eTLD+1.
    shadow_it   — resolves to some IP, but classification rules below trip it.
    dead        — NXDOMAIN / no A record.

Locked rules (DESIGN.md §2.1.1):
  1. NXDOMAIN / no A record → dead.
  2. Any A record IP not in sanctioned_cidrs AND its ASN not in sanctioned_asns → shadow_it.
  3. Any CNAME chain entry whose eTLD+1 is not among configured roots → shadow_it.
  4. Otherwise → in_scope.

IPv4 only. AAAA records are ignored entirely.
"""
from __future__ import annotations

from typing import Any

from watchtower.models import TriagedAsset
from watchtower.util.domains import etld_plus_one, under_any_root
from watchtower.util.ipinfo import IPInfoLookup


def triage_records(
    records: list[dict[str, Any]],
    roots: list[str],
    ipinfo: IPInfoLookup,
) -> list[TriagedAsset]:
    out: list[TriagedAsset] = []
    for rec in records:
        out.append(_triage_one(rec, roots, ipinfo))
    return out


def _triage_one(rec: dict[str, Any], roots: list[str], ipinfo: IPInfoLookup) -> TriagedAsset:
    fqdn: str = (rec.get("host") or "").lower().rstrip(".")
    a_records: list[str] = [a for a in (rec.get("a") or []) if ipinfo.is_ipv4(a)]
    cname_chain: list[str] = [c.lower().rstrip(".") for c in (rec.get("cname") or [])]

    # Rule 1: dead
    if not a_records:
        return TriagedAsset(
            fqdn=fqdn,
            a_records=[],
            cname_chain=cname_chain,
            asn=None,
            as_org=None,
            bucket="dead",
            reason="No A records (NXDOMAIN or empty A-set)",
        )

    # Pick a representative ASN from the first A record (consistent display).
    primary = ipinfo.asn_info(a_records[0])

    # Rule 2: any IP outside both sanctioned_cidrs AND sanctioned_asns → shadow_it.
    for ip in a_records:
        info = ipinfo.asn_info(ip)
        in_cidr = ipinfo.in_sanctioned_cidr(ip)
        in_asn = ipinfo.asn_is_sanctioned(info.asn)
        if not in_cidr and not in_asn:
            return TriagedAsset(
                fqdn=fqdn,
                a_records=a_records,
                cname_chain=cname_chain,
                asn=info.asn,
                as_org=info.organization,
                bucket="shadow_it",
                reason=(
                    f"IP {ip} not in sanctioned CIDRs and "
                    f"ASN {info.asn or '?'} ({info.organization or '?'}) not sanctioned"
                ),
            )

    # Rule 3: any CNAME chain entry pointing outside configured roots → shadow_it.
    for hop in cname_chain:
        if not under_any_root(hop, roots):
            return TriagedAsset(
                fqdn=fqdn,
                a_records=a_records,
                cname_chain=cname_chain,
                asn=primary.asn,
                as_org=primary.organization,
                bucket="shadow_it",
                reason=f"CNAME chain points to non-root zone: {hop} (eTLD+1={etld_plus_one(hop)})",
            )

    # Rule 4: in_scope
    return TriagedAsset(
        fqdn=fqdn,
        a_records=a_records,
        cname_chain=cname_chain,
        asn=primary.asn,
        as_org=primary.organization,
        bucket="in_scope",
        reason="All A records sanctioned and no third-party CNAME hop",
    )
