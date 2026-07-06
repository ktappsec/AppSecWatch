"""Pure cross-scan diff + source-ran gating (audit/lifecycle.py)."""
from __future__ import annotations

from appsecwatch.audit.lifecycle import diff_findings, source_ran
from appsecwatch.models import Finding


def F(**kw) -> Finding:
    return Finding(**{"source": "headers", "severity": "medium", "title": "t", **kw})


def test_source_ran_parent_and_subtoken():
    assert source_ran("headers", {"headers": {"ran": True}}) is True
    assert source_ran("headers", {"headers": {"ran": False}}) is False
    # sub-token wins over parent
    assert source_ran("csp", {"headers.csp": {"ran": False}, "headers": {"ran": True}}) is False
    # unknown coverage → assume ran (matches report _ran default)
    assert source_ran("nuclei", {}) is True


def test_diff_new_recurring_resolved():
    prior = {"headers|a|hsts.missing", "headers|a|xcto.missing"}
    current = [F(host="a", check_id="hsts.missing"), F(host="a", check_id="csp.missing", source="csp")]
    d = diff_findings(current, prior, {"headers": {"ran": True}})
    assert d["new"] == 1        # csp.missing
    assert d["recurring"] == 1  # hsts.missing
    assert d["resolved"] == 1   # xcto.missing (headers ran)


def test_resolved_gated_on_source_ran():
    prior = {"headers|a|hsts.missing"}
    # headers did NOT run this scan → the absent finding is NOT counted resolved
    d = diff_findings([], prior, {"headers": {"ran": False}})
    assert d["resolved"] == 0
