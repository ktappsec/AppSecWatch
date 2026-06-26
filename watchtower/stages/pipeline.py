"""Pipeline assembly — shared by the CLI and the Python API.

`build_pipeline` is the single place the capability tokens, dependency
resolution, and stage ordering live. To add a new selectable scanner, register
a Capability in `capabilities.py` (see API.md §7); to add a non-selectable stage,
extend the assembly here.
"""
from __future__ import annotations

from watchtower.config import WatchTowerConfig
from watchtower.stages.base import ParallelStage, Stage
from watchtower.stages.capabilities import (
    ALL_TOKENS,
    CAPABILITIES,
    PHASE_ORDER,
    RECON_STEPS,
    Capability,
    SelectionError,
    resolve_selection,
)
from watchtower.stages.profile import AIProfileStage
from watchtower.stages.recon import (
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
    cfg: WatchTowerConfig,
    *,
    only: set[str] | None = None,
    skip: set[str] | None = None,
    include_report: Stage,
    include_compress: Stage | None,
) -> tuple[list[Stage], dict[str, dict]]:
    """Assemble the ordered stage list for a selection, plus the coverage manifest.

    Args:
        only/skip: capability-token selection (mutually exclusive).

    Returns:
        (stages, coverage). `coverage` is written to manifest.json and threaded
        into the report.
    """
    active, coverage, discovery_only, plan = resolve_selection(only, skip)

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
        # ai.profile is framework-special: pre-audit, only when ai is active,
        # profiling is enabled, and the profile sub-step is selected. It never
        # gates the deterministic scanners.
        if "ai" in active and cfg.ai.profiling and "profile" in plan.ai_steps:
            stages.append(AIProfileStage())

        for phase in PHASE_ORDER:
            phase_stages: list[Stage] = []
            for tok in ALL_TOKENS:
                cap = CAPABILITIES.get(tok)
                if cap is None or cap.phase != phase or tok not in active:
                    continue
                s = cap.factory(cfg, plan)
                if s is not None:
                    phase_stages.append(s)
            if not phase_stages:
                continue
            if phase == "audit":
                stages.append(ParallelStage("audit.parallel", *phase_stages))
            else:
                stages.extend(phase_stages)

    stages.append(include_report)
    if include_compress is not None:
        stages.append(include_compress)
    return stages, coverage


def default_pipeline(
    cfg: WatchTowerConfig,
    *,
    include_report: Stage,
    include_compress: Stage | None,
) -> list[Stage]:
    """No-selection convenience wrapper (full pipeline). Coverage discarded."""
    stages, _ = build_pipeline(
        cfg, include_report=include_report, include_compress=include_compress
    )
    return stages
