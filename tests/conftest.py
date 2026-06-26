"""Test fixtures. We avoid loading the real MMDB by stubbing IPInfoLookup."""
from __future__ import annotations

import ipaddress

import pytest


class _ASN:
    def __init__(self, asn: int | None, organization: str | None) -> None:
        self.asn = asn
        self.organization = organization


class StubIPInfo:
    """In-memory replacement for IPInfoLookup (ASN lookup only — the sanctioned
    machinery is gone). `**_legacy` swallows any old sanctioned_* kwargs."""

    def __init__(self, asn_map: dict[str, tuple[int, str]] | None = None, **_legacy) -> None:
        self._asn_map = asn_map or {}

    def is_ipv4(self, ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def asn_info(self, ip: str) -> _ASN:
        if ip in self._asn_map:
            n, o = self._asn_map[ip]
            return _ASN(asn=n, organization=o)
        return _ASN(asn=None, organization=None)

    def close(self) -> None:
        pass


@pytest.fixture
def make_ipinfo():
    return StubIPInfo
