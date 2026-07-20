"""AI analysis stage."""
from __future__ import annotations

from pathlib import Path

from appsecwatch.ai.analyzer import analyze_all
from appsecwatch.audit.lifecycle import source_ran
from appsecwatch.stages.base import Stage, StageResult


class AIStage(Stage):
    name = "ai.analyze"

    def __init__(self, do_triage: bool = True, do_supply: bool = True) -> None:
        # Which AI analyses to run — set from the ai.triage / ai.supply-chain
        # sub-tokens. Defaults to both (parent `ai` selection).
        self.do_triage = do_triage
        self.do_supply = do_supply

    def _triage_dir(self, run_dir: Path) -> Path:
        return run_dir / "03_ai" / "triage"

    def _supply_dir(self, run_dir: Path) -> Path:
        return run_dir / "03_ai" / "supply_chain"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        # Group ALL deterministic findings by host so the per-host triage call can
        # reference them (context + cross-source soft-suppression). The same
        # Finding objects live in state, so a suppression verdict attaches in place.
        # ZAP findings join triage too — for NORMAL false-positive suppression
        # only (no cross-source dedup; ZAP overlap with headers/nuclei is tolerated
        # as separate source-labeled rows). High/critical ZAP actives sit above the
        # suppression max_severity ceiling, so they always stay visible.
        findings_map: dict[str, list] = {}
        for f in (
            state.nuclei_findings + state.takeover_findings + state.tls_findings
            + state.header_findings + state.js_lib_findings + state.secret_findings
            + state.zap_findings
        ):
            if f.host:
                findings_map.setdefault(f.host, []).append(f)

        supp = cfg.ai.suppression
        # The deterministic `csp` scanner owns the CSP rows when it ran — AI CSP
        # findings would just duplicate them (see ai/policy.looks_like_csp).
        csp_covered = source_ran("csp", state.coverage)
        t_findings, s_findings, call_errors = await analyze_all(
            live_servers=state.live_servers,
            page_signals=state.page_signals,
            artifacts=state.crawler_artifacts,
            profiles=state.app_profiles,
            cfg=cfg.llm,
            triage_dir=self._triage_dir(run_dir),
            supply_dir=self._supply_dir(run_dir),
            log=log,
            concurrency=cfg.concurrency.llm,
            do_triage=self.do_triage,
            do_supply=self.do_supply,
            findings_by_host=findings_map,
            suppress=supp.enabled,
            suppress_min_confidence=supp.min_confidence,
            suppress_max_severity=supp.max_severity,
            require_profile=supp.require_profile,
            protect_expected_controls=supp.protect_expected_controls,
            csp_covered=csp_covered,
            prompt_overrides=cfg.ai.prompts.as_overrides(),
        )
        if self.do_triage:
            state.ai_headers_findings = t_findings
        if self.do_supply:
            state.ai_supply_findings = s_findings
        # Per-host degraded AI calls (triage/supply analysis that hard-failed).
        return StageResult(list(call_errors))
