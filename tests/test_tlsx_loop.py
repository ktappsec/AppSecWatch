"""Tests for the tlsx re-feed loop (DESIGN.md §2.1):
    - Seen-set dedup across iterations
    - Hard cap at MAX_ITERATIONS
    - Only SANs under configured roots get re-fed
    - Wildcards recorded but never iterated
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from watchtower.logging import RunLogger
from watchtower.models import TriagedAsset
from watchtower.recon.tls_san import MAX_ITERATIONS, _parse_cert, tlsx_refeed_loop


@pytest.fixture
def log(tmp_path: Path) -> RunLogger:
    return RunLogger(tmp_path, mode="quiet", verbose=False)


def _asset(fqdn: str, ips: list[str]) -> TriagedAsset:
    return TriagedAsset(
        fqdn=fqdn, a_records=ips, cname_chain=[],
        asn=64500, as_org="Our",
        bucket="in_scope", reason="test fixture",
    )


def _stub_tlsx(san_map: dict[str, list[str]]):
    """Return an async stub that mimics `_tlsx_grab` — ({ip: sans}, [certs])."""
    async def fake(ips, raw_out, cfg, log, timeout=600.0):  # noqa: ARG001
        Path(raw_out).parent.mkdir(parents=True, exist_ok=True)
        Path(raw_out).write_text("")
        return {ip: list(san_map.get(ip, [])) for ip in ips}, []
    return fake


def _resolve_factory(triaged_map: dict[str, TriagedAsset]):
    async def resolve_and_triage(names, iteration):  # noqa: ARG001
        return [triaged_map[n] for n in names if n in triaged_map]
    return resolve_and_triage


@pytest.mark.asyncio
async def test_loop_discovers_new_in_root_sans(log, tmp_path):
    initial = [_asset("a.example.com", ["10.0.0.1"])]
    sans = {"10.0.0.1": ["b.example.com", "external.zendesk.com"]}
    resolved = {"b.example.com": _asset("b.example.com", ["10.0.0.2"])}

    with patch("watchtower.recon.tls_san._tlsx_grab", side_effect=_stub_tlsx(sans)):
        final, wildcards, _ = await tlsx_refeed_loop(
            initial_assets=initial,
            roots=["example.com"],
            cfg=type("C", (), {"extra_flags": []})(),
            out_dir=tmp_path,
            log=log,
            resolve_and_triage=_resolve_factory(resolved),
        )

    fqdns = {a.fqdn for a in final}
    assert "a.example.com" in fqdns and "b.example.com" in fqdns
    assert "external.zendesk.com" not in fqdns       # filtered: not under roots
    assert wildcards == []


@pytest.mark.asyncio
async def test_loop_records_wildcards_but_does_not_iterate(log, tmp_path):
    initial = [_asset("a.example.com", ["10.0.0.1"])]
    sans = {"10.0.0.1": ["*.example.com", "*.other.com"]}

    with patch("watchtower.recon.tls_san._tlsx_grab", side_effect=_stub_tlsx(sans)):
        final, wildcards, _ = await tlsx_refeed_loop(
            initial_assets=initial, roots=["example.com"],
            cfg=type("C", (), {"extra_flags": []})(), out_dir=tmp_path, log=log,
            resolve_and_triage=_resolve_factory({}),
        )

    assert wildcards == ["*.example.com", "*.other.com"]
    assert len(final) == 1


@pytest.mark.asyncio
async def test_loop_dedups_across_iterations(log, tmp_path):
    """Seen-set must prevent re-feeding the same FQDN even if it shows up again."""
    initial = [_asset("a.example.com", ["10.0.0.1"])]
    # First iter discovers b. Second iter (on b's IP) re-discovers a — should be filtered.
    sans = {
        "10.0.0.1": ["b.example.com"],
        "10.0.0.2": ["a.example.com", "c.example.com"],
    }
    resolved = {
        "b.example.com": _asset("b.example.com", ["10.0.0.2"]),
        "c.example.com": _asset("c.example.com", ["10.0.0.3"]),
    }

    call_log: list[list[str]] = []

    async def tracking_resolve(names, iteration):  # noqa: ARG001
        call_log.append(sorted(names))
        return [resolved[n] for n in names if n in resolved]

    with patch("watchtower.recon.tls_san._tlsx_grab", side_effect=_stub_tlsx(sans)):
        final, _, _ = await tlsx_refeed_loop(
            initial_assets=initial, roots=["example.com"],
            cfg=type("C", (), {"extra_flags": []})(), out_dir=tmp_path, log=log,
            resolve_and_triage=tracking_resolve,
        )

    # Iteration 1: discovers b. Iteration 2: discovers c only (a deduped). Iteration 3: nothing → stops.
    assert call_log[0] == ["b.example.com"]
    assert call_log[1] == ["c.example.com"]
    fqdns = {a.fqdn for a in final}
    assert fqdns == {"a.example.com", "b.example.com", "c.example.com"}


@pytest.mark.asyncio
async def test_loop_respects_max_iterations(log, tmp_path):
    """Even with an infinite SAN chain, the loop must stop at MAX_ITERATIONS."""
    counter = {"n": 0}

    def chain_at(ip: str) -> list[str]:
        counter["n"] += 1
        return [f"sub{counter['n']}.example.com"]

    async def infinite_tlsx(ips, raw_out, cfg, log, timeout=600.0):  # noqa: ARG001
        Path(raw_out).write_text("")
        return {ip: chain_at(ip) for ip in ips}, []

    iter_count = {"n": 0}

    async def infinite_resolve(names, iteration):  # noqa: ARG001
        iter_count["n"] += 1
        return [_asset(n, [f"10.0.0.{iter_count['n'] + 10}"]) for n in names]

    initial = [_asset("a.example.com", ["10.0.0.1"])]
    with patch("watchtower.recon.tls_san._tlsx_grab", side_effect=infinite_tlsx):
        await tlsx_refeed_loop(
            initial_assets=initial, roots=["example.com"],
            cfg=type("C", (), {"extra_flags": []})(), out_dir=tmp_path, log=log,
            resolve_and_triage=infinite_resolve,
        )

    # The loop must invoke `resolve_and_triage` no more than MAX_ITERATIONS times.
    assert iter_count["n"] <= MAX_ITERATIONS


@pytest.mark.asyncio
async def test_loop_stops_early_when_no_new_sans(log, tmp_path):
    """Loop should terminate as soon as an iteration yields zero new names."""
    initial = [_asset("a.example.com", ["10.0.0.1"])]
    sans = {"10.0.0.1": []}    # no SANs at all

    calls = {"n": 0}
    async def resolve(names, iteration):  # noqa: ARG001
        calls["n"] += 1
        return []

    with patch("watchtower.recon.tls_san._tlsx_grab", side_effect=_stub_tlsx(sans)):
        final, _, _ = await tlsx_refeed_loop(
            initial_assets=initial, roots=["example.com"],
            cfg=type("C", (), {"extra_flags": []})(), out_dir=tmp_path, log=log,
            resolve_and_triage=resolve,
        )

    assert calls["n"] == 0       # never called: empty first iteration ends the loop
    assert len(final) == 1


@pytest.mark.asyncio
async def test_loop_empty_initial_assets(log, tmp_path):
    """No initial IPs → loop should be a no-op."""
    final, wildcards, certs = await tlsx_refeed_loop(
        initial_assets=[], roots=["example.com"],
        cfg=type("C", (), {"extra_flags": []})(), out_dir=tmp_path, log=log,
        resolve_and_triage=_resolve_factory({}),
    )
    assert final == []
    assert wildcards == []
    assert certs == []


# --------------------------------------------------------------------------- #
# CertInfo capture (tlsx dossier from the same connection)
# --------------------------------------------------------------------------- #
def _cert_stub(by_ip_certs):
    """Stub _tlsx_grab returning ({ip: sans}, [CertInfo]) from raw dossiers."""
    async def fake(ips, raw_out, cfg, log, timeout=600.0):  # noqa: ARG001
        Path(raw_out).write_text("")
        certs = [_parse_cert(by_ip_certs[ip]) for ip in ips if ip in by_ip_certs]
        sans = {ip: list(by_ip_certs[ip].get("subject_an", [])) for ip in ips if ip in by_ip_certs}
        return sans, certs
    return fake


@pytest.mark.asyncio
async def test_loop_captures_cert_inventory(log, tmp_path):
    raw = {"10.0.0.1": {
        "ip": "10.0.0.1", "subject_cn": "a.example.com",
        "subject_an": ["a.example.com"], "issuer_cn": "Let's Encrypt",
        "subject_dn": "CN=a.example.com", "issuer_dn": "CN=Let's Encrypt",
        "not_after": "2099-01-01T00:00:00Z", "wildcard_certificate": False,
        "fingerprint_hash": {"sha256": "abc"}, "serial": "01",
    }}
    initial = [_asset("a.example.com", ["10.0.0.1"])]
    with patch("watchtower.recon.tls_san._tlsx_grab", side_effect=_cert_stub(raw)):
        _, _, certs = await tlsx_refeed_loop(
            initial_assets=initial, roots=["example.com"],
            cfg=type("C", (), {"extra_flags": []})(), out_dir=tmp_path, log=log,
            resolve_and_triage=_resolve_factory({}),
        )
    assert len(certs) == 1
    c = certs[0]
    assert c.ip == "10.0.0.1" and c.subject_cn == "a.example.com"
    assert c.issuer == "Let's Encrypt" and c.sha256 == "abc"
    assert c.self_signed is False and c.expired is False


def test_parse_cert_derivations():
    # self-signed: subject_dn == issuer_dn
    ss = _parse_cert({"ip": "1.1.1.1", "subject_dn": "CN=x", "issuer_dn": "CN=x",
                      "not_after": "2099-01-01T00:00:00Z", "wildcard_certificate": True})
    assert ss.self_signed is True and ss.wildcard is True and ss.expired is False
    # expired: not_after in the past → days_remaining < 0
    ex = _parse_cert({"ip": "2.2.2.2", "subject_dn": "CN=x", "issuer_dn": "CN=CA",
                      "not_after": "2000-01-01T00:00:00Z"})
    assert ex.expired is True and ex.self_signed is False and ex.days_remaining < 0
    # missing not_after → no expiry signal, not flagged expired
    none = _parse_cert({"ip": "3.3.3.3"})
    assert none.days_remaining is None and none.expired is False
