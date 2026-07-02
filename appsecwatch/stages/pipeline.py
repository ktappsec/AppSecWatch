"""Pipeline assembly — shared by the CLI and the Python API.

`build_pipeline` is the single place the capability tokens, dependency
resolution, and stage ordering live. To add a new selectable scanner, register
a Capability in `capabilities.py` (see API.md §7); to add a non-selectable stage,
extend the assembly here.
"""
from __future__ import annotations

from appsecwatch.config import AppSecWatchConfig
from appsecwatch.stages.base import ParallelStage, Stage
from appsecwatch.stages.capabilities import (
    ALL_TOKENS,
    CAPABILITIES,
    PHASE_ORDER,
    RECON_STEPS,
    Capability,
    SelectionError,
    resolve_selection,
)
from appsecwatch.stages.exec_summary import ExecSummaryStage
from appsecwatch.stages.profile import AIProfileStage
from appsecwatch.stages.recon import (
    DnsxAndTriageStage,
    HttpxStage,
    SubfinderStage,
    TlsxLoopStage,
)

__all__ = [
    "build_pipeline",
    "default_pipeline",
    "CAPABILITIES",
    "Capability",
    "ALL_TOKENS",
    "SelectionError",
    "resolve_selection",
]


def build_pipeline(
    cfg: AppSecWatchConfig,
    *,
    only: set[str] | None = None,
    skip: set[str] | None = None,
    include_report: Stage,
    include_compress: Stage | None,
    include_exec_pdf: Stage | None = None,
) -> tuple[list[Stage], dict[str, dict]]:
    """Assemble the ordered stage list for a selection, plus the coverage manifest.

    Args:
        only/skip: capability-token selection (mutually exclusive).

    Returns:
        (stages, coverage). `coverage` is written to manifest.json and threaded
        into the report.
    """
    active, coverage, discovery_only, plan = resolve_selection(only, skip)

    # ai.profile is framework-special: it runs at the HEAD of the ai-analyze phase
    # (after the audit fan-out) so it can consume the crawler's rendered capture
    # when available. It never gates the deterministic scanners.
    profile_active = (
        not discovery_only
        and "ai" in active
        and cfg.ai.profiling
        and "profile" in plan.ai_steps
    )
    # profile.render == "always" forces a browser render per host: pull in the
    # crawler (the `supply-chain` capability) even when supply-chain wasn't selected.
    # This runs CrawlerStage only — supply-chain *analysis* stays gated on
    # plan.ai_steps, so it adds a browser pass but no extra LLM calls.
    if profile_active and cfg.ai.profile.render == "always" and "supply-chain" not in active:
        active = active | {"supply-chain"}
        coverage = {
            **coverage,
            "supply-chain": {"ran": True, "reason": "forced for profile.render=always"},
        }

    # ai.summary is framework-special like ai.profile, but runs at the TAIL of the
    # ai-analyze phase (after triage suppression) so it summarizes the final visible
    # findings. One LLM call per run; degrades to deterministic exec prose.
    summary_active = (
        not discovery_only
        and "ai" in active
        and "summary" in plan.ai_steps
    )

    stages: list[Stage] = []

    # Assemble the spine from the resolved recon sub-steps, in order.
    recon_map = {
        "subfinder": SubfinderStage,
        "dns": DnsxAndTriageStage,
        "tlsx": TlsxLoopStage,
        "httpx": HttpxStage,
    }
    for step in RECON_STEPS:
        if step in plan.recon_steps:
            stages.append(recon_map[step]())

    if not discovery_only:
        for phase in PHASE_ORDER:
            phase_stages: list[Stage] = []
            for tok in ALL_TOKENS:
                cap = CAPABILITIES.get(tok)
                if cap is None or cap.phase != phase or tok not in active:
                    continue
                s = cap.factory(cfg, plan)
                if s is not None:
                    phase_stages.append(s)
            # The profiler leads the ai-analyze phase: the AppProfile must be ready
            # before triage/supply analysis, and only now (post-audit) is the
            # crawler's rendered capture available to it.
            if phase == "ai-analyze" and profile_active:
                phase_stages.insert(0, AIProfileStage())
            # Tail: the executive-summary call (must precede the empty-phase guard,
            # so an `--only ai.summary` selection — which builds no AIStage — isn't
            # dropped).
            if phase == "ai-analyze" and summary_active:
                phase_stages.append(ExecSummaryStage())
            if not phase_stages:
                continue
            if phase == "audit":
                stages.append(ParallelStage("audit.parallel", *phase_stages))
            else:
                stages.extend(phase_stages)

    stages.append(include_report)
    # executive.pdf (best-effort) renders from executive.html, so after the report
    # and before compression (which leaves run-root files untouched anyway).
    if include_exec_pdf is not None:
        stages.append(include_exec_pdf)
    if include_compress is not None:
        stages.append(include_compress)
    return stages, coverage


def default_pipeline(
    cfg: AppSecWatchConfig,
    *,
    include_report: Stage,
    include_compress: Stage | None,
) -> list[Stage]:
    """No-selection convenience wrapper (full pipeline). Coverage discarded."""
    stages, _ = build_pipeline(
        cfg, include_report=include_report, include_compress=include_compress
    )
    return stages
