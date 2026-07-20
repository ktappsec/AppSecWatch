"""sslscan XML → TLS scorecard parsing (audit/sslscan_runner)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from appsecwatch.audit.sslscan_runner import (
    _checks_to_findings,
    _evaluate_checklist,
    _first_ssltest,
)

# A clean modern server: SSL2/3 + TLS1.0/1.1 disabled, strong ciphers, RSA-2048
# sha256 cert valid for years, secure renegotiation. Day is space-padded like
# real sslscan/OpenSSL output ("Jan  1").
GOOD_XML = """<?xml version="1.0"?>
<document title="SSLScan Results" version="2.1.5">
 <ssltest host="good.example.com" port="443">
  <protocol type="ssl" version="2" enabled="0"/>
  <protocol type="ssl" version="3" enabled="0"/>
  <protocol type="tls" version="1.0" enabled="0"/>
  <protocol type="tls" version="1.1" enabled="0"/>
  <protocol type="tls" version="1.2" enabled="1"/>
  <protocol type="tls" version="1.3" enabled="1"/>
  <renegotiation supported="1" secure="1"/>
  <cipher status="preferred" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-GCM-SHA384" strength="acceptable"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-RSA-AES128-GCM-SHA256" strength="acceptable"/>
  <certificates>
   <certificate type="full">
    <signature-algorithm>sha256WithRSAEncryption</signature-algorithm>
    <pk error="false" type="RSA" bits="2048"/>
    <subject>good.example.com</subject>
    <issuer>Example CA</issuer>
    <not-valid-before>Jan  1 00:00:00 2025 GMT</not-valid-before>
    <not-valid-after>Jan  1 00:00:00 2099 GMT</not-valid-after>
   </certificate>
  </certificates>
 </ssltest>
</document>"""

# A failing server: TLS 1.0 enabled, an RC4 cipher, insecure renegotiation, an
# expired cert with a 1024-bit RSA key and a SHA-1 signature.
BAD_XML = """<?xml version="1.0"?>
<document title="SSLScan Results" version="2.1.5">
 <ssltest host="bad.example.com" port="443">
  <protocol type="ssl" version="2" enabled="0"/>
  <protocol type="ssl" version="3" enabled="0"/>
  <protocol type="tls" version="1.0" enabled="1"/>
  <protocol type="tls" version="1.1" enabled="0"/>
  <protocol type="tls" version="1.2" enabled="1"/>
  <renegotiation supported="1" secure="0"/>
  <cipher status="accepted" sslversion="TLSv1.0" bits="128" cipher="ECDHE-RSA-RC4-SHA" strength="weak"/>
  <certificates>
   <certificate type="full">
    <signature-algorithm>sha1WithRSAEncryption</signature-algorithm>
    <pk error="false" type="RSA" bits="1024"/>
    <not-valid-after>Jan  1 00:00:00 2000 GMT</not-valid-after>
   </certificate>
  </certificates>
 </ssltest>
</document>"""


def _findings(xml: str):
    ssltest = _first_ssltest(ET.fromstring(xml))
    assert ssltest is not None
    checks = _evaluate_checklist(ssltest)
    host = ssltest.get("host", "")
    return checks, _checks_to_findings(host, checks)


def test_clean_server_passes_every_check():
    checks, findings = _findings(GOOD_XML)
    assert findings == []                       # nothing fails → no findings
    assert all(c.passed for c in checks)
    # protocols + weak-cipher + 3 cert checks + renegotiation
    names = {c.name for c in checks}
    assert "SSL 2.0 disabled" in names
    assert "Strong key (RSA≥2048 / EC≥256)" in names
    assert "Secure renegotiation" in names


def test_failing_server_flags_the_right_checks():
    _checks, findings = _findings(BAD_XML)
    titles = {f.title for f in findings}
    # Titles state the PROBLEM (fail_title), not the passing control name.
    assert titles == {
        "TLS: TLS 1.0 enabled",
        "TLS: Weak ciphers supported (RC4/3DES/EXPORT/NULL/anon)",
        "TLS: Certificate expired",
        "TLS: Weak public key (below RSA-2048 / EC-256)",
        "TLS: Weak certificate signature algorithm (SHA-1/MD5)",
        "TLS: Insecure client-initiated renegotiation supported",
    }
    # SSL 2.0 / 3.0 / TLS 1.1 were disabled → must NOT appear as failures
    assert "TLS: SSL 2.0 enabled" not in titles
    assert "TLS: TLS 1.1 enabled" not in titles
    assert all(f.source == "sslscan" for f in findings)


def test_failing_titles_state_the_problem_not_the_secure_state():
    """Regression: a failing check must not surface the pass-condition name.

    A negotiated TLS 1.0 previously rendered as 'TLS: TLS 1.0 disabled' — a real
    vuln that reads like a passing control. The finding title now states the
    problem ('enabled'), while evidence['check'] keeps the control name so the
    group_key / suppression fingerprint is unchanged.
    """
    _checks, findings = _findings(BAD_XML)
    tls10 = next(f for f in findings if f.title == "TLS: TLS 1.0 enabled")
    assert "disabled" not in tls10.title
    assert tls10.evidence["check"] == "TLS 1.0 disabled"   # stable group_key anchor
    assert tls10.group_key == "TLS 1.0 disabled"
    assert tls10.evidence["detail"] == "protocol negotiated"


def test_cert_expiring_soon_vs_expired_titles():
    """A cert with <30 but >0 days reads 'expiring soon'; a negative-days cert
    reads 'expired' — distinct fail_titles from the same check."""
    soon_xml = BAD_XML.replace(
        "Jan  1 00:00:00 2000 GMT",  # long-expired
        (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y") + " GMT",
    )
    _checks, findings = _findings(soon_xml)
    titles = {f.title for f in findings}
    assert "TLS: Certificate expiring soon (<30 days)" in titles
    assert "TLS: Certificate expired" not in titles


def test_weak_cipher_evidence_carries_offenders():
    _checks, findings = _findings(BAD_XML)
    weak = next(f for f in findings if "weak ciphers" in f.title.lower())
    assert "RC4" in weak.evidence["detail"]
