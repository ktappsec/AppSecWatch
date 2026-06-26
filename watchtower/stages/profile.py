"""AIProfileStage — context-aware per-application profiling (DESIGN.md §2.3.1).

Runs early (after httpx, before the audit fan-out) so the inferred AppProfile is
available to the header + supply-chain prompts. It never gates the deterministic
scanners. Skipped entirely when ai.profiling is off.
"""
from __future__ import annotations

from pathlib import Path

from watchtower.ai.analyzer import profile_all
from watchtower.stages.base import Stage, StageResult


class AIProfileStage(Stage):
    name = "ai.profile"

    def _dir(self, run_dir: Path) -> Path:
        return run_dir / "03_ai" / "profile"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        state.app_profiles = await profile_all(
            state.page_signals,
            self._dir(run_dir),
            cfg.llm,
            log,
            concurrency=cfg.concurrency.llm,
        )
        # A host that hard-failed profiling degrades to default prompts — surface it.
        return StageResult([
            (host, p.error or "profiling failed")
            for host, p in state.app_profiles.items()
            if not p.usable
        ])
