"""Deterministic dangling-CNAME takeover detection (audit/takeover_fingerprints)."""
from __future__ import annotations

from appsecwatch.audit.takeover_fingerprints import scan_cname_takeovers
from appsecwatch.models import TriagedAsset


def _dead(fqdn: str, cname_chain: list[str]) -> TriagedAsset:
    return TriagedAsset(fqdn=fqdn, a_records=[], cname_chain=cname_chain,
                        status="dead", reason="no A records")


def test_dangling_cname_to_claimable_provider_is_high():
    assets = [_dead("blog.acme.com", ["acme-blog.herokudns.com"])]
    findings = scan_cname_takeovers(assets)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "takeover" and f.severity == "high"
    assert f.host == "blog.acme.com"
    assert f.evidence["service"] == "Heroku"
    assert f.check_id == "takeover.heroku"


def test_nxdomain_class_azure_is_high():
    findings = scan_cname_takeovers([_dead("x.acme.com", ["app.azurewebsites.net"])])
    assert findings and findings[0].severity == "high"
    assert findings[0].evidence["nxdomain_claimable"] is True


def test_edge_case_provider_is_medium_review():
    # Fastly is vulnerable:false in the DB → medium "review", not high.
    findings = scan_cname_takeovers([_dead("cdn.acme.com", ["acme.global.fastly.net"])])
    assert findings and findings[0].severity == "medium"
    assert findings[0].evidence["service"] == "Fastly"


def test_no_cname_no_finding():
    assert scan_cname_takeovers([_dead("gone.acme.com", [])]) == []


def test_unknown_provider_no_finding():
    assert scan_cname_takeovers([_dead("x.acme.com", ["internal.acme-corp.net"])]) == []


def test_dot_boundary_prevents_suffix_spoof():
    # A host crafted to *contain* github.io must not match the github.io suffix.
    assets = [_dead("x.acme.com", ["evil-github.io.attacker.com"])]
    assert scan_cname_takeovers(assets) == []


def test_dedupe_per_host_and_service():
    assets = [_dead("x.acme.com", ["a.s3.amazonaws.com", "b.s3.amazonaws.com"])]
    findings = scan_cname_takeovers(assets)
    assert len(findings) == 1            # one AWS/S3 finding for the host, not two
    assert findings[0].evidence["service"] == "AWS/S3"
