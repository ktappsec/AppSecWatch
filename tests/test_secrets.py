"""Client-side secret exposure detection: precision, masking, findings, taxonomy."""
from __future__ import annotations

from appsecwatch.audit.secrets import (
    _mask,
    detect_in_content,
    load_db,
    scan_secrets,
)
from appsecwatch.audit.taxonomy import classify
from appsecwatch.models import CrawlerArtifact, Finding


# A fabricated key that matches the AWS access-key-id shape but is not a real key.
FAKE_AWS_ID = "AKIAIOSFODNN7EXAMPLE"
FAKE_STRIPE = "sk_live_" + "a" * 24
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
CONN = "postgres://admin:s3cr3tp4ss@db.internal:5432/prod"


def test_db_loads_and_has_rules_and_allow():
    db = load_db()
    assert db.get("rules")
    assert db.get("allow")


def test_detects_aws_access_key_id():
    hits = detect_in_content(f'var k = "{FAKE_AWS_ID}";')
    rules = {h["rule"] for h in hits}
    assert "aws-access-key-id" in rules


def test_detects_private_key_marker_unmasked():
    hits = detect_in_content(PRIVATE_KEY)
    pk = [h for h in hits if h["rule"] == "private-key"]
    assert pk
    # Marker rule (mask:false) → the literal (non-secret) marker is shown.
    assert "BEGIN RSA PRIVATE KEY" in pk[0]["preview"]


def test_detects_stripe_secret_key():
    hits = detect_in_content(f'const s="{FAKE_STRIPE}"')
    assert any(h["rule"] == "stripe-secret-key" for h in hits)


def test_detects_db_connection_string_and_masks_password():
    hits = detect_in_content(f'DB = "{CONN}"')
    conn = [h for h in hits if h["rule"] == "db-connection-string"]
    assert conn
    # Password must NOT appear; host/user survive for actionability.
    assert "s3cr3tp4ss" not in conn[0]["preview"]
    assert "db.internal" in conn[0]["preview"]


def test_allow_list_drops_public_tokens():
    # Firebase/Maps API key, Stripe publishable key, GA id — all public by design.
    assert detect_in_content('key:"AIzaSyA1234567890abcdefghijklmnopqrstuvw"') == []
    assert detect_in_content('pk:"pk_live_' + "a" * 24 + '"') == []
    assert detect_in_content('gtag("config","G-ABCDEF1234")') == []


def test_mask_never_reveals_interior_of_a_secret():
    db = load_db()
    rule = next(r for r in db["rules"] if r["id"] == "aws-access-key-id")
    masked = _mask(rule, FAKE_AWS_ID)
    assert FAKE_AWS_ID not in masked
    assert masked.startswith(FAKE_AWS_ID[:4])
    assert masked.endswith(FAKE_AWS_ID[-4:])
    assert "•" in masked


def test_scan_secrets_builds_findings_with_stable_identity():
    art = CrawlerArtifact(host="h1.example.com", url="https://h1.example.com")
    art.detected_secrets = [
        {"rule": "aws-access-key-id", "title": "AWS access key ID exposed in JS",
         "severity": "high", "line": 3, "preview": "AKIA••••••••MPLE",
         "url": "https://h1.example.com/app.js"},
    ]
    findings = scan_secrets([art])
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "secret"
    assert f.severity == "high"
    assert f.check_id and f.check_id.startswith("secret.aws-access-key-id.")
    assert f.evidence["preview"] == "AKIA••••••••MPLE"


def test_scan_secrets_dedupes_same_secret_across_scripts():
    art = CrawlerArtifact(host="h1", url="u")
    hit = {"rule": "stripe-secret-key", "title": "t", "severity": "high",
           "line": 1, "preview": "sk_l••••••••aaaa"}
    art.detected_secrets = [
        {**hit, "url": "u/a.js"},
        {**hit, "url": "u/b.js"},
    ]
    assert len(scan_secrets([art])) == 1


def test_same_secret_collapses_across_hosts_via_group_key():
    a1 = CrawlerArtifact(host="a", url="u")
    a2 = CrawlerArtifact(host="b", url="u")
    hit = {"rule": "aws-access-key-id", "title": "t", "severity": "high",
           "line": 1, "preview": "AKIA••••••••MPLE", "url": "u/x.js"}
    a1.detected_secrets = [hit]
    a2.detected_secrets = [dict(hit)]
    findings = scan_secrets([a1, a2])
    assert len(findings) == 2
    assert findings[0].group_key == findings[1].group_key


def test_taxonomy_classifies_secret_as_crypto():
    f = Finding(source="secret", severity="high", title="t",
                check_id="secret.aws-access-key-id.akiampl")
    category, cls = classify(f)
    assert cls == "secrets.exposed-key"
    assert category == "crypto"


def test_high_severity_secret_is_above_ai_suppression_ceiling():
    # Guards the design property: a `high`+ secret is never offered to the AI
    # suppressor (default max_severity ceiling = medium), so it stays visible.
    from appsecwatch.config import AIConfig
    ceiling = AIConfig().suppression.max_severity
    assert ceiling == "medium"
