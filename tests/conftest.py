"""Test fixtures. We avoid loading the real MMDB by stubbing IPInfoLookup."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

import pytest


@dataclass(frozen=True)
class _ASN:
    asn: int | None
    organization: str | None


class StubIPInfo:
    """In-memory replacement for IPInfoLookup. Configure via constructor."""

    def __init__(
        self,
        sanctioned_cidrs: Iterable[str] = (),
        sanctioned_asns: Iterable[int] = (),
        asn_map: dict[str, tuple[int, str]] | None = None,
    ) -> None:
        self._nets = [ipaddress.IPv4Network(c, strict=False) for c in sanctioned_cidrs]
        self._sanctioned_asns = set(sanctioned_asns)
        self._asn_map = asn_map or {}

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
        return any(addr in net for net in self._nets)

    def asn_info(self, ip: str) -> _ASN:
        if ip in self._asn_map:
            n, o = self._asn_map[ip]
            return _ASN(asn=n, organization=o)
        return _ASN(asn=None, organization=None)

    def asn_is_sanctioned(self, asn: int | None) -> bool:
        return asn is not None and asn in self._sanctioned_asns

    def close(self) -> None:
        pass


@pytest.fixture
def make_ipinfo():
    return StubIPInfo
