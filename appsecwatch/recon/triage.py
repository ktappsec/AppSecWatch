"""The triage router.

Classifies each resolved subdomain by LIVENESS into exactly one of:
    live  — resolves (>= 1 A record). Gets the full active scan.
    dead  — NXDOMAIN / no A record. Inventory-only; if it carries a dangling
            CNAME, the takeovers stage fingerprints it offline.

Scope is the configured roots: every live host under them is in play, regardless
of where it's hosted (there is no IP/ASN ownership gate). ASN/org are display-only
enrichment, filled best-effort from the optional MMDB. IPv4 only; AAAA ignored.
"""
from __future__ import annotations

from typing import Any

from appsecwatch.models import TriagedAsset
from appsecwatch.util.ipinfo import IPInfoLookup


def triage_records(
    records: list[dict[str, Any]],
    ipinfo: IPInfoLookup,
) -> list[TriagedAsset]:
    return [_triage_one(rec, ipinfo) for rec in records]


def _triage_one(rec: dict[str, Any], ipinfo: IPInfoLookup) -> TriagedAsset:
    fqdn: str = (rec.get("host") or "").lower().rstrip(".")
    a_records: list[str] = [a for a in (rec.get("a") or []) if ipinfo.is_ipv4(a)]
    cname_chain: list[str] = [c.lower().rstrip(".") for c in (rec.get("cname") or [])]

    if not a_records:
        return TriagedAsset(
            fqdn=fqdn,
            a_records=[],
            cname_chain=cname_chain,
            asn=None,
            as_org=None,
            status="dead",
            reason="No A records (NXDOMAIN or empty A-set)",
        )

    # Resolves → live. ASN/org are pure display enrichment from the first A record.
    info = ipinfo.asn_info(a_records[0])
    return TriagedAsset(
        fqdn=fqdn,
        a_records=a_records,
        cname_chain=cname_chain,
        asn=info.asn,
        as_org=info.organization,
        status="live",
        reason="Resolves",
    )
