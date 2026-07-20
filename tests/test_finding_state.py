"""Unified finding_state: suppression migration/parity + resolve engine."""
from __future__ import annotations

from appsecwatch.api.db import Database
from appsecwatch.api.finding_state import FindingStateManager
from appsecwatch.api.suppressions import SuppressionManager
from appsecwatch.audit.taxonomy import classify_findings
from appsecwatch.models import Finding


def F(**kw) -> Finding:
    f = Finding(**{"source": "headers", "severity": "medium", "title": "t", **kw})
    classify_findings([f])
    return f


def _sync(m, findings, hosts, cov, scan_id, group=None):
    return m.sync(findings, scanned_hosts=set(hosts), coverage=cov, group=group, scan_id=scan_id)


# --------------------------------------------------------------------------- #
# Suppression migration + manager parity
# --------------------------------------------------------------------------- #

def test_legacy_suppression_migrates_into_finding_state(tmp_path):
    path = tmp_path / "t.db"
    db1 = Database(path)
    # Seed a legacy suppressions row, then re-open so _init_schema backfills it.
    db1.execute(
        "INSERT INTO suppressions (fingerprint, source, host, key, scope, reason, created_at) "
        "VALUES ('headers|a.com|hsts.missing','headers','a.com','hsts.missing','host','fp','t0')"
    )
    db1.close()
    db2 = Database(path)
    m = FindingStateManager(db2)
    assert "headers|a.com|hsts.missing" in m.suppressed_fingerprints()
    row = m.get("headers|a.com|hsts.missing")
    assert row["status"] == "suppressed" and row["reason"] == "fp"


def test_suppression_manager_parity(tmp_path):
    m = SuppressionManager(Database(tmp_path / "t.db"))
    m.add(source="headers", host="a.com", key="hsts.missing", reason="fp")
    g = m.add(source="nuclei", host=None, key="CVE-x", scope="global")
    assert g["host"] == "*"
    assert m.fingerprints() == {"headers|a.com|hsts.missing", "nuclei|*|CVE-x"}
    assert m.delete("headers|a.com|hsts.missing") is True          # manual-only → removed
    assert m.fingerprints() == {"nuclei|*|CVE-x"}


# --------------------------------------------------------------------------- #
# Resolve engine
# --------------------------------------------------------------------------- #

def test_resolves_after_two_consecutive_absences(tmp_path):
    m = FindingStateManager(Database(tmp_path / "t.db"))
    cov = {"headers": {"ran": True}}
    finding = F(host="h1", check_id="hsts.missing")

    _sync(m, [finding], {"h1"}, cov, "s1")
    assert m.get("headers|h1|hsts.missing")["status"] == "open"

    d2 = _sync(m, [], {"h1"}, cov, "s2")           # absent #1
    assert m.get("headers|h1|hsts.missing")["status"] == "open"
    assert m.get("headers|h1|hsts.missing")["consecutive_absent"] == 1
    assert d2["resolved"] == 0

    d3 = _sync(m, [], {"h1"}, cov, "s3")           # absent #2 → resolved
    assert m.get("headers|h1|hsts.missing")["status"] == "resolved"
    assert d3["resolved"] == 1


def test_absence_not_counted_when_source_skipped(tmp_path):
    m = FindingStateManager(Database(tmp_path / "t.db"))
    finding = F(host="h1", check_id="hsts.missing")
    _sync(m, [finding], {"h1"}, {"headers": {"ran": True}}, "s1")
    # headers skipped in the next two scans → never resolves
    _sync(m, [], {"h1"}, {"headers": {"ran": False}}, "s2")
    _sync(m, [], {"h1"}, {"headers": {"ran": False}}, "s3")
    row = m.get("headers|h1|hsts.missing")
    assert row["status"] == "open" and row["consecutive_absent"] == 0


def test_resolved_reopens_when_seen_again(tmp_path):
    m = FindingStateManager(Database(tmp_path / "t.db"))
    cov = {"headers": {"ran": True}}
    finding = F(host="h1", check_id="hsts.missing")
    _sync(m, [finding], {"h1"}, cov, "s1")
    _sync(m, [], {"h1"}, cov, "s2")
    _sync(m, [], {"h1"}, cov, "s3")
    assert m.get("headers|h1|hsts.missing")["status"] == "resolved"
    d = _sync(m, [finding], {"h1"}, cov, "s4")     # back → reopened
    assert m.get("headers|h1|hsts.missing")["status"] == "open"
    assert m.get("headers|h1|hsts.missing")["consecutive_absent"] == 0
    assert d["reopened"] == 1


def test_suppressed_is_sticky_across_absences(tmp_path):
    db = Database(tmp_path / "t.db")
    m = FindingStateManager(db)
    finding = F(host="h1", check_id="hsts.missing")
    _sync(m, [finding], {"h1"}, {"headers": {"ran": True}}, "s1")
    m.set_status("headers|h1|hsts.missing", "suppressed")
    _sync(m, [], {"h1"}, {"headers": {"ran": True}}, "s2")
    _sync(m, [], {"h1"}, {"headers": {"ran": True}}, "s3")
    assert m.get("headers|h1|hsts.missing")["status"] == "suppressed"  # never auto-resolved


def test_diff_counts_new_and_recurring(tmp_path):
    m = FindingStateManager(Database(tmp_path / "t.db"))
    cov = {"headers": {"ran": True}}
    a = F(host="h1", check_id="hsts.missing")
    b = F(host="h1", check_id="xcto.missing", severity="low")
    d1 = _sync(m, [a], {"h1"}, cov, "s1")
    assert d1["new"] == 1 and d1["recurring"] == 0
    d2 = _sync(m, [a, b], {"h1"}, cov, "s2")
    assert d2["new"] == 1 and d2["recurring"] == 1


def test_analytics_group_resolves_from_asset_inventory(tmp_path):
    """A roots/all-assets scan stamps no group on its findings, but the group
    filter must still attribute them via the live asset inventory (host==fqdn).
    Regression: analytics(group=...) filtered the stamped column only and so
    returned an empty dataset for every group on non-group-targeted scans."""
    db = Database(tmp_path / "t.db")
    m = FindingStateManager(db)
    cov = {"headers": {"ran": True}}
    # Two findings on two hosts, both synced with group=None (roots scan).
    a = F(host="h1.example.com", check_id="hsts.missing")
    b = F(host="h2.other.com", check_id="hsts.missing")
    _sync(m, [a], {"h1.example.com"}, cov, "s1", group=None)
    _sync(m, [b], {"h2.other.com"}, cov, "s1", group=None)
    # The inventory assigns each host to a group (e.g. after CSV import / discovery).
    db.execute('INSERT INTO assets (fqdn, "group", priority) VALUES (?, ?, ?)',
               ("h1.example.com", "teamA", 7))
    db.execute('INSERT INTO assets (fqdn, "group") VALUES (?, ?)',
               ("h2.other.com", "teamB"))

    assert m.analytics()["open_total"] == 2                    # unfiltered: both
    a_stats = m.analytics(group="teamA")
    assert a_stats["open_total"] == 1                          # resolved via join
    assert a_stats["by_priority"] == [{"priority": 7, "open": 1}]
    assert m.analytics(group="teamB")["open_total"] == 1
    assert m.analytics(group="nope")["open_total"] == 0        # unknown group → empty

    # The finding-state listing filters by the same resolved group.
    assert [r["host"] for r in m.list(group="teamA")] == ["h1.example.com"]
    assert m.list(group="teamB")[0]["host"] == "h2.other.com"


def test_tags_roundtrip(tmp_path):
    m = FindingStateManager(Database(tmp_path / "t.db"))
    finding = F(host="h1", check_id="hsts.missing")
    _sync(m, [finding], {"h1"}, {"headers": {"ran": True}}, "s1")
    m.set_tags("headers|h1|hsts.missing", ["sent-to-dev", "  ", "ticket-123"])
    assert m.get("headers|h1|hsts.missing")["tags"] == '["sent-to-dev", "ticket-123"]'
    listed = m.list(host="h1")
    assert listed[0]["tags"] == ["sent-to-dev", "ticket-123"]
