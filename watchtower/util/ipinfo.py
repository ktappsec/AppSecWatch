from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

import maxminddb


@dataclass(frozen=True)
class ASNInfo:
    asn: int | None
    organization: str | None


class IPInfoLookup:
    """MMDB ASN/org lookup, IPv4 only.

    The MMDB is OPTIONAL display enrichment — it no longer gates scanning. With
    no path configured (or an unreadable one), `asn_info` returns empty info
    instead of raising, so a scan never fails for lack of a GeoLite2 file.
    """

    def __init__(self, mmdb_path: str | Path | None = None) -> None:
        self._reader = None
        if mmdb_path:
            path = Path(mmdb_path)
            if path.is_file():
                self._reader = maxminddb.open_database(str(path))

    def is_ipv4(self, ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def asn_info(self, ip: str) -> ASNInfo:
        if self._reader is None:
            return ASNInfo(asn=None, organization=None)
        try:
            data = self._reader.get(ip) or {}
        except Exception:
            data = {}
        asn = data.get("autonomous_system_number")
        org = data.get("autonomous_system_organization")
        return ASNInfo(asn=int(asn) if asn is not None else None, organization=org)

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
