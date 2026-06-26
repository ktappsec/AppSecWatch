"""Manual suppression: fingerprint/apply (engine) + SuppressionManager (DB)."""
from __future__ import annotations

from watchtower.api.db import Database
from watchtower.api.suppressions import SuppressionManager
from watchtower.audit.suppress import apply_suppressions, finding_key, finding_matches
from watchtower.models import AIFindingVerdict, Finding


def F(**kw) -> Finding:
    return Finding(**{"source": "headers", "severity": "medium", "title": "t", **kw})


def test_finding_key_variants():
    assert finding_key(F(check_id="hsts.missing")) == "hsts.missing"
    assert finding_key(F(source="nuclei", check_id=None, evidence={"template_id": "CVE-x"})) == "CVE-x"
    assert finding_key(F(source="sslscan", evidence={"check": "weak-cipher"})) == "weak-cipher"
    assert finding_key(F(source="js_lib", evidence={"library": "jquery", "version": "3.4.1"})) == "jquery@3.4.1"


def test_apply_host_scoped():
    f1 = F(host="a.com", check_id="hsts.missing")
    f2 = F(host="b.com", check_id="hsts.missing")
    n = apply_suppressions([f1, f2], {"headers|a.com|hsts.missing"})
    assert n == 1 and f1.suppressed and not f2.suppressed
    assert f1.ai_verdict.source == "manual"


def test_apply_global_scope():
    f = F(host="c.com", check_id="hsts.missing")
    assert finding_matches(f, {"headers|*|hsts.missing"})
    apply_suppressions([f], {"headers|*|hsts.missing"})
    assert f.suppressed


def test_apply_skips_already_suppressed():
    f = F(host="a.com", check_id="x", ai_verdict=AIFindingVerdict(suppressed=True, source="ai_headers"))
    n = apply_suppressions([f], {"headers|a.com|x"})
    assert n == 0 and f.ai_verdict.source == "ai_headers"  # AI verdict preserved


def test_suppression_manager(tmp_path):
    m = SuppressionManager(Database(tmp_path / "t.db"))
    r = m.add(source="headers", host="a.com", key="hsts.missing", reason="fp")
    assert r["fingerprint"] == "headers|a.com|hsts.missing"
    g = m.add(source="nuclei", host=None, key="CVE-x", scope="global")
    assert g["host"] == "*" and g["fingerprint"] == "nuclei|*|CVE-x"
    assert m.fingerprints() == {"headers|a.com|hsts.missing", "nuclei|*|CVE-x"}
    assert m.delete("headers|a.com|hsts.missing") is True
    assert m.fingerprints() == {"nuclei|*|CVE-x"}
