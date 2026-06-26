from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import maxminddb


@dataclass(frozen=True)
class ASNInfo:
    asn: int | None
    organization: str | None


class MMDBNotFoundError(RuntimeError):
    pass


class IPInfoLookup:
    """Combined sanctioned-CIDR membership + MMDB ASN lookup, IPv4 only."""

    def __init__(self, mmdb_path: str | Path, sanctioned_cidrs: list[str], sanctioned_asns: list[int]) -> None:
        path = Path(mmdb_path)
        if not path.is_file():
            raise MMDBNotFoundError(
                f"GeoLite2-ASN MMDB not found at {path}. "
                f"Bind-mount it into the container at /data/mmdb/GeoLite2-ASN.mmdb."
            )
        self._reader = maxminddb.open_database(str(path))
        self._sanctioned_nets = [ipaddress.IPv4Network(c, strict=False) for c in sanctioned_cidrs]
        self._sanctioned_asns = set(sanctioned_asns)

    def is_ipv4(self, ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def in_sanctioned_cidr(self, ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return False
        return any(addr in net for net in self._sanctioned_nets)

    def asn_info(self, ip: str) -> ASNInfo:
        try:
            data = self._reader.get(ip) or {}
        except Exception:
            data = {}
        asn = data.get("autonomous_system_number")
        org = data.get("autonomous_system_organization")
        return ASNInfo(asn=int(asn) if asn is not None else None, organization=org)

    def asn_is_sanctioned(self, asn: Optional[int]) -> bool:
        return asn is not None and asn in self._sanctioned_asns

    def close(self) -> None:
        self._reader.close()
