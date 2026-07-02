"""build_pipeline assembly (the parts reachable without playwright/sslscan).

The audit-phase factories import heavy deps lazily, so here we exercise the
discovery-only path (no audit) plus selection validation and coverage
passthrough. The full token logic is covered in test_capabilities.py.
"""
from __future__ import annotations

import pytest

from watchtower.config import LLMConfig, WatchTowerConfig
from watchtower.stages.base import Stage
from watchtower.stages.pipeline import build_pipeline
from watchtower.stages.capabilities import SelectionError


class _DummyReport(Stage):
    name = "report"

    async def run(self, state, run_dir, cfg, ipinfo, log):  # pragma: no cover
        pass


class _DummyCompress(Stage):
    name = "compress"

    async def run(self, state, run_dir, cfg, ipinfo, log):  # pragma: no cover
        pass


def _cfg() -> WatchTowerConfig:
    return WatchTowerConfig(
        roots=["example.com"],
        mmdb_path="/dev/null",
        llm=LLMConfig(base_url="http://localhost/v1", model="m"),
    )


def test_discovery_only_is_spine_plus_report():
    stages, coverage = build_pipeline(
        _cfg(), only={"recon"},
        include_report=_DummyReport(), include_compress=None,
    )
    names = [s.name for s in stages]
    assert names == [
        "recon.subfinder", "recon.dnsx-triage", "recon.tlsx-loop", "recon.httpx", "report",
    ]
    assert coverage["recon"]["reason"] == "discovery-only"
    assert coverage["tls"]["ran"] is False


def test_compress_stage_appended_when_supplied():
    stages, _ = build_pipeline(
        _cfg(), only={"recon"},
        include_report=_DummyReport(), include_compress=_DummyCompress(),
    )
    assert stages[-1].name == "compress"


def test_bad_token_raises_before_assembly():
    with pytest.raises(SelectionError):
        build_pipeline(
            _cfg(), only={"nope"},
            include_report=_DummyReport(), include_compress=None,
        )


def test_only_and_skip_together_raises():
    with pytest.raises(SelectionError):
        build_pipeline(
            _cfg(), only={"tls"}, skip={"nuclei"},
            include_report=_DummyReport(), include_compress=None,
        )


def _stage(stages, name):
    """Find a stage by name, descending into ParallelStage children."""
    for s in stages:
        if s.name == name:
            return s
        for child in getattr(s, "children", ()):
            if child.name == name:
                return child
    return None


def test_recon_subtoken_discovery_subset():
    stages, cov = build_pipeline(
        _cfg(), only={"recon.subfinder", "recon.dns"},
        include_report=_DummyReport(), include_compress=None,
    )
    names = [s.name for s in stages]
    assert names == ["recon.subfinder", "recon.dnsx-triage", "report"]
    assert cov["recon"]["partial"] is True


def test_nuclei_severity_subtoken_configures_stage():
    # --only nuclei.high → full spine + only the nuclei audit stage, severity-scoped.
    stages, _ = build_pipeline(
        _cfg(), only={"nuclei.high", "nuclei.critical"},
        include_report=_DummyReport(), include_compress=None,
    )
    nuclei = _stage(stages, "audit.nuclei")
    assert nuclei is not None
    assert nuclei.severities == ["critical", "high"]
    # tls/supply-chain not selected → not assembled
    assert _stage(stages, "audit.sslscan") is None


def test_ai_triage_subtoken_configures_stage():
    stages, _ = build_pipeline(
        _cfg(), only={"ai.triage"},
        include_report=_DummyReport(), include_compress=None,
    )
    ai = _stage(stages, "ai.analyze")
    assert ai is not None
    assert ai.do_triage is True and ai.do_supply is False
    # profile sub-token not selected → no profile stage
    assert _stage(stages, "ai.profile") is None


def test_ai_headers_alias_still_works():
    # Deprecated `ai.headers` resolves to `ai.triage` (back-compat).
    stages, _ = build_pipeline(
        _cfg(), only={"ai.headers"},
        include_report=_DummyReport(), include_compress=None,
    )
    ai = _stage(stages, "ai.analyze")
    assert ai is not None and ai.do_triage is True and ai.do_supply is False


def test_profile_runs_at_head_of_ai_analyze():
    # ai.profile must run AFTER the audit fan-out (so it can read the crawler
    # capture) and BEFORE ai.analyze (triage/supply use the profile).
    stages, _ = build_pipeline(
        _cfg(), include_report=_DummyReport(), include_compress=None,
    )
    names = [s.name for s in stages]
    assert names.index("audit.parallel") < names.index("ai.profile") < names.index("ai.analyze")


def test_ai_summary_runs_at_tail_of_ai_analyze():
    # ai.summary must run AFTER ai.analyze (it summarizes the post-triage findings)
    # and be the last ai-analyze stage, immediately before the report.
    stages, _ = build_pipeline(
        _cfg(), include_report=_DummyReport(), include_compress=None,
    )
    names = [s.name for s in stages]
    assert names.index("ai.analyze") < names.index("ai.summary")
    assert names.index("ai.profile") < names.index("ai.summary")
    assert names.index("ai.summary") == names.index("report") - 1


def test_ai_summary_only_builds_stage_without_aistage():
    # --only ai.summary builds the summary stage even though no AIStage is created
    # (the tail append must precede the empty-phase guard).
    stages, _ = build_pipeline(
        _cfg(), only={"ai.summary"},
        include_report=_DummyReport(), include_compress=None,
    )
    assert _stage(stages, "ai.summary") is not None
    assert _stage(stages, "ai.analyze") is None
    assert _stage(stages, "ai.profile") is None


def test_skip_ai_summary_drops_only_the_summary():
    stages, _ = build_pipeline(
        _cfg(), skip={"ai.summary"},
        include_report=_DummyReport(), include_compress=None,
    )
    assert _stage(stages, "ai.summary") is None
    # the rest of the ai phase still runs
    assert _stage(stages, "ai.analyze") is not None
    assert _stage(stages, "ai.profile") is not None


def test_profile_only_has_no_summary():
    stages, _ = build_pipeline(
        _cfg(), only={"ai.profile"},
        include_report=_DummyReport(), include_compress=None,
    )
    assert _stage(stages, "ai.profile") is not None
    assert _stage(stages, "ai.summary") is None
    assert _stage(stages, "ai.analyze") is None


def test_render_always_forces_crawler_without_supply_analysis():
    cfg = _cfg()
    cfg.ai.profile.render = "always"
    stages, cov = build_pipeline(
        cfg, only={"ai.profile"},
        include_report=_DummyReport(), include_compress=None,
    )
    # The crawler is force-included so the profiler gets a render, and coverage says so.
    assert _stage(stages, "audit.crawler") is not None
    assert cov["supply-chain"] == {"ran": True, "reason": "forced for profile.render=always"}
    # ...but supply-chain ANALYSIS is not added (no ai.analyze), and the profile runs.
    assert _stage(stages, "ai.profile") is not None
    assert _stage(stages, "ai.analyze") is None


def test_render_auto_skip_supply_chain_has_no_crawler_but_profiles():
    cfg = _cfg()  # render defaults to "auto"
    stages, cov = build_pipeline(
        cfg, skip={"supply-chain"},
        include_report=_DummyReport(), include_compress=None,
    )
    assert _stage(stages, "audit.crawler") is None
    assert cov["supply-chain"]["ran"] is False
    # Profiling still runs (it falls back to httpx signals at runtime).
    assert _stage(stages, "ai.profile") is not None


def test_headers_subtoken_configures_stage():
    # --only headers.csp → full spine + only the deterministic headers stage,
    # scoped to CSP (best-practice off).
    stages, cov = build_pipeline(
        _cfg(), only={"headers.csp"},
        include_report=_DummyReport(), include_compress=None,
    )
    headers = _stage(stages, "audit.headers")
    assert headers is not None
    assert headers.do_csp is True and headers.do_best_practice is False
    assert cov["headers"]["partial"] is True
    # other audit caps not selected
    assert _stage(stages, "audit.nuclei") is None


def test_headers_parent_runs_both_substeps():
    stages, _ = build_pipeline(
        _cfg(), only={"headers"},
        include_report=_DummyReport(), include_compress=None,
    )
    headers = _stage(stages, "audit.headers")
    assert headers is not None
    assert headers.do_csp is True and headers.do_best_practice is True


def test_ai_profile_only_runs_profile_no_analysis():
    stages, _ = build_pipeline(
        _cfg(), only={"ai.profile"},
        include_report=_DummyReport(), include_compress=None,
    )
    assert _stage(stages, "ai.profile") is not None
    assert _stage(stages, "ai.analyze") is None  # _ai factory returns None


def test_default_assembles_full_spine_plus_audit():
    # No selection → full recon spine + ai.profile + the audit parallel group.
    stages, coverage = build_pipeline(
        _cfg(), include_report=_DummyReport(), include_compress=None,
    )
    names = [s.name for s in stages]
    assert names[:4] == [
        "recon.subfinder", "recon.dnsx-triage", "recon.tlsx-loop", "recon.httpx",
    ]
    assert _stage(stages, "audit.headers") is not None
    assert coverage["recon"]["reason"] == "prerequisite"


def _cfg_zap() -> WatchTowerConfig:
    cfg = _cfg()
    cfg.zap.enabled = True
    cfg.zap.base_url = "http://zap:8090"
    cfg.zap.targets = ["https://app.example.com"]
    return cfg


def test_zap_built_when_selected_and_configured():
    stages, cov = build_pipeline(
        _cfg_zap(), only={"zap"},
        include_report=_DummyReport(), include_compress=None,
    )
    assert _stage(stages, "audit.zap") is not None
    assert cov["zap"]["ran"] is True and cov["zap"]["reason"] == "user-selected"


def test_zap_absent_by_default_even_when_configured():
    # Opt-in: a default scan never builds the ZAP stage, even with the daemon set.
    stages, cov = build_pipeline(
        _cfg_zap(), include_report=_DummyReport(), include_compress=None,
    )
    assert _stage(stages, "audit.zap") is None
    assert cov["zap"]["ran"] is False


def test_zap_selected_but_unconfigured_builds_no_stage():
    # only=zap but the daemon is disabled → factory returns None (no stage),
    # even though coverage marks it user-selected.
    stages, cov = build_pipeline(
        _cfg(), only={"zap"},
        include_report=_DummyReport(), include_compress=None,
    )
    assert _stage(stages, "audit.zap") is None
    assert cov["zap"]["ran"] is True  # selected, but the factory no-op'd
