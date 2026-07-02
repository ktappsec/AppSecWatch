"""Capability selection resolution (DESIGN.md §2.8) — parents + sub-tokens.

resolve_selection returns (active_caps, coverage, discovery_only, plan).
"""
from __future__ import annotations

import pytest

from watchtower.stages.capabilities import (
    ALL_TOKENS,
    NUCLEI_SEVERITIES,
    SelectionError,
    resolve_selection,
)


# --------------------------------------------------------------------------- #
# parent-level behavior (back-compat)
# --------------------------------------------------------------------------- #
def test_default_runs_everything_except_opt_in():
    active, cov, discovery, plan = resolve_selection()
    # zap is opt-in: a default scan runs every capability EXCEPT zap.
    assert active == set(ALL_TOKENS) - {"zap"}
    assert "zap" not in active
    assert cov["zap"]["ran"] is False and cov["zap"]["reason"] == "not run"
    assert discovery is False
    assert cov["recon"]["ran"] is True and cov["recon"]["reason"] == "prerequisite"
    assert all(cov[t]["ran"] for t in ALL_TOKENS if t != "zap")
    # full spine, all ai steps, config-default nuclei severities
    assert plan.recon_steps == frozenset({"subfinder", "dns", "tlsx", "httpx"})
    assert plan.ai_steps == frozenset({"profile", "triage", "supply-chain", "summary"})
    assert plan.nuclei_severities is None
    assert cov["recon"]["partial"] is False
    assert cov["ai"]["partial"] is False


def test_only_tls_keeps_spine_excludes_others():
    active, cov, discovery, _ = resolve_selection(only={"tls"})
    assert active == {"recon", "tls"}
    assert discovery is False
    assert cov["tls"] == {"ran": True, "reason": "user-selected"}
    assert cov["nuclei"]["ran"] is False
    assert cov["nuclei"]["reason"] == "excluded by --only"
    assert cov["recon"]["reason"] == "prerequisite"
    assert cov["recon"]["partial"] is False  # audit active → full spine


def test_only_ai_auto_includes_crawler():
    active, cov, _, _ = resolve_selection(only={"ai"})
    assert "supply-chain" in active
    assert "ai" in active
    assert cov["supply-chain"] == {"ran": True, "reason": "auto-included"}
    assert cov["ai"]["reason"] == "user-selected"
    assert cov["ai"]["partial"] is False


def test_only_recon_is_discovery_only():
    active, cov, discovery, plan = resolve_selection(only={"recon"})
    assert discovery is True
    assert active == {"recon"}
    assert cov["recon"]["reason"] == "discovery-only"
    assert cov["nuclei"]["ran"] is False and cov["nuclei"]["reason"] == "discovery-only"
    assert plan.recon_steps == frozenset({"subfinder", "dns", "tlsx", "httpx"})


def test_skip_nuclei():
    active, cov, _, _ = resolve_selection(skip={"nuclei"})
    assert "nuclei" not in active
    # zap stays out too: opt-in caps never ride along on a --skip selection.
    assert active == set(ALL_TOKENS) - {"nuclei", "zap"}
    assert cov["nuclei"]["ran"] is False and cov["nuclei"]["reason"] == "skipped by --skip"


def test_zap_is_opt_in():
    # Default + skip never activate zap.
    assert "zap" not in resolve_selection()[0]
    assert "zap" not in resolve_selection(skip={"nuclei"})[0]
    assert "zap" not in resolve_selection(skip={"zap"})[0]
    # Only an explicit --only zap turns it on, and keeps the recon spine.
    active, cov, discovery, _ = resolve_selection(only={"zap"})
    assert active == {"recon", "zap"}
    assert discovery is False
    assert cov["zap"] == {"ran": True, "reason": "user-selected"}  # not a sub-tokened cap
    # zap composes with other audit caps in one --only.
    active2, _, _, _ = resolve_selection(only={"zap", "tls"})
    assert active2 == {"recon", "zap", "tls"}


def test_skip_supply_chain_keeps_ai_but_drops_crawler():
    active, cov, _, plan = resolve_selection(skip={"supply-chain"})
    assert "ai" in active
    assert "supply-chain" not in active
    assert cov["supply-chain"]["ran"] is False
    # ai keeps profile + triage + summary, loses the supply step → partial
    assert plan.ai_steps == frozenset({"profile", "triage", "summary"})
    assert cov["ai"]["partial"] is True


def test_skip_all_audit_is_discovery_only():
    active, _, discovery, _ = resolve_selection(
        skip={"takeovers", "tls", "nuclei", "headers", "supply-chain", "ai"}
    )
    assert discovery is True
    assert active == {"recon"}


# --------------------------------------------------------------------------- #
# sub-tokens — ai
# --------------------------------------------------------------------------- #
def test_only_ai_triage_runs_triage_only():
    active, cov, discovery, plan = resolve_selection(only={"ai.triage"})
    assert active == {"recon", "ai"}
    assert discovery is False
    assert plan.ai_steps == frozenset({"triage"})
    assert "supply-chain" not in active  # triage does NOT pull the crawler
    assert cov["ai"]["partial"] is True
    assert cov["ai"]["sub"]["ai.triage"]["ran"] is True
    assert cov["ai"]["sub"]["ai.supply-chain"]["ran"] is False


def test_ai_headers_alias_resolves_to_triage():
    active, cov, discovery, plan = resolve_selection(only={"ai.headers"})
    assert plan.ai_steps == frozenset({"triage"})
    assert cov["ai"]["sub"]["ai.triage"]["ran"] is True


def test_only_ai_supply_chain_pulls_crawler():
    active, cov, _, plan = resolve_selection(only={"ai.supply-chain"})
    assert "supply-chain" in active
    assert cov["supply-chain"]["reason"] == "auto-included"
    assert plan.ai_steps == frozenset({"supply-chain"})


def test_only_ai_profile_no_analysis_stage():
    active, cov, _, plan = resolve_selection(only={"ai.profile"})
    assert "ai" in active
    assert plan.ai_steps == frozenset({"profile"})
    assert cov["ai"]["partial"] is True


def test_skip_ai_supply_chain_keeps_crawler():
    active, cov, _, plan = resolve_selection(skip={"ai.supply-chain"})
    assert "supply-chain" in active            # crawler still runs
    assert plan.ai_steps == frozenset({"profile", "triage", "summary"})
    assert cov["ai"]["partial"] is True


# --------------------------------------------------------------------------- #
# sub-tokens — headers
# --------------------------------------------------------------------------- #
def test_only_headers_keeps_spine_runs_both_substeps():
    active, cov, discovery, plan = resolve_selection(only={"headers"})
    assert active == {"recon", "headers"}
    assert discovery is False
    assert plan.header_steps == frozenset({"csp", "best-practice"})
    assert cov["headers"]["ran"] is True
    assert cov["headers"]["partial"] is False
    assert cov["headers"]["sub"]["headers.csp"]["ran"] is True
    assert cov["headers"]["sub"]["headers.best-practice"]["ran"] is True


def test_only_headers_csp_subset_is_partial():
    active, cov, discovery, plan = resolve_selection(only={"headers.csp"})
    assert active == {"recon", "headers"}
    assert discovery is False
    assert plan.header_steps == frozenset({"csp"})
    assert cov["headers"]["partial"] is True
    assert cov["headers"]["sub"]["headers.csp"]["ran"] is True
    assert cov["headers"]["sub"]["headers.best-practice"]["ran"] is False
    # headers does not pull AI or other audit caps
    assert "ai" not in active and "nuclei" not in active


def test_skip_headers_best_practice_keeps_csp():
    _, cov, _, plan = resolve_selection(skip={"headers.best-practice"})
    assert plan.header_steps == frozenset({"csp"})
    assert cov["headers"]["ran"] is True
    assert cov["headers"]["partial"] is True


def test_skip_headers_parent_drops_capability():
    active, cov, _, _ = resolve_selection(skip={"headers"})
    assert "headers" not in active
    assert cov["headers"]["ran"] is False


def test_headers_default_full():
    _, cov, _, plan = resolve_selection()
    assert plan.header_steps == frozenset({"csp", "best-practice"})
    assert cov["headers"]["ran"] is True and cov["headers"]["partial"] is False


# --------------------------------------------------------------------------- #
# sub-tokens — nuclei (severity)
# --------------------------------------------------------------------------- #
def test_only_nuclei_severity_subset():
    active, cov, _, plan = resolve_selection(only={"nuclei.high", "nuclei.critical"})
    assert active == {"recon", "nuclei"}
    assert plan.nuclei_severities == ("critical", "high")
    assert cov["nuclei"]["partial"] is True
    assert cov["nuclei"]["sub"]["nuclei.high"]["ran"] is True
    assert cov["nuclei"]["sub"]["nuclei.low"]["ran"] is False


def test_skip_nuclei_severity():
    _, cov, _, plan = resolve_selection(skip={"nuclei.low"})
    assert set(plan.nuclei_severities) == set(NUCLEI_SEVERITIES) - {"low"}
    assert cov["nuclei"]["ran"] is True
    assert cov["nuclei"]["partial"] is True


def test_parent_nuclei_uses_config_default():
    _, _, _, plan = resolve_selection(only={"nuclei"})
    assert plan.nuclei_severities is None  # signals 'use config severities'


def test_nuclei_info_opt_in():
    _, _, _, plan = resolve_selection(only={"nuclei.info"})
    assert plan.nuclei_severities == ("info",)


# --------------------------------------------------------------------------- #
# sub-tokens — recon
# --------------------------------------------------------------------------- #
def test_only_recon_subfinder_discovery_narrowing():
    active, cov, discovery, plan = resolve_selection(only={"recon.subfinder"})
    assert discovery is True
    assert active == {"recon"}
    assert plan.recon_steps == frozenset({"subfinder"})
    assert cov["recon"]["partial"] is True


def test_only_recon_dns_does_not_pull_subfinder():
    # subfinder is now OPTIONAL (enumeration) — dns no longer auto-includes it.
    _, _, discovery, plan = resolve_selection(only={"recon.dns"})
    assert discovery is True
    assert plan.recon_steps == frozenset({"dns"})


def test_skip_subfinder_quick_scan():
    # skip subfinder while auditing → spine runs dns+httpx (no enumeration).
    _, _, discovery, plan = resolve_selection(skip={"recon.subfinder"})
    assert discovery is False
    assert "subfinder" not in plan.recon_steps
    assert {"dns", "httpx"} <= plan.recon_steps


def test_skip_recon_tlsx_keeps_rest_of_spine():
    _, cov, _, plan = resolve_selection(skip={"recon.tlsx"})
    assert plan.recon_steps == frozenset({"subfinder", "dns", "httpx"})
    assert cov["recon"]["ran"] is True
    assert cov["recon"]["partial"] is True


def test_skip_required_recon_step_rejected():
    with pytest.raises(SelectionError) as e:
        resolve_selection(skip={"recon.httpx"})
    assert "recon.tlsx" in str(e.value)


def test_audit_with_only_forces_full_spine():
    # --only nuclei.high also needs live servers → full spine runs.
    _, cov, _, plan = resolve_selection(only={"nuclei.high"})
    assert plan.recon_steps == frozenset({"subfinder", "dns", "tlsx", "httpx"})
    assert cov["recon"]["partial"] is False


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
def test_only_and_skip_mutually_exclusive():
    with pytest.raises(SelectionError):
        resolve_selection(only={"tls"}, skip={"nuclei"})


def test_unknown_token_rejected():
    with pytest.raises(SelectionError) as e:
        resolve_selection(only={"bogus"})
    assert "bogus" in str(e.value)


def test_unknown_subtoken_rejected():
    with pytest.raises(SelectionError):
        resolve_selection(only={"nuclei.bogus"})


def test_unknown_skip_token_rejected():
    with pytest.raises(SelectionError):
        resolve_selection(skip={"nuclei", "nope"})
