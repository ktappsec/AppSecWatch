"""AIProfileStage — context-aware per-application profiling (DESIGN.md §2.3.1).

Runs at the HEAD of the ai-analyze phase (after the audit fan-out) so it can read
the crawler's rendered capture when available; the AppProfile is produced before
the triage + supply-chain prompts that consume it. Input source is
`cfg.ai.profile.render` (auto|always|never): auto/always use the crawler's rendered
text + curated surface when a crawl happened, else httpx pre-JS signals. It never
gates the deterministic scanners. Skipped entirely when ai.profiling is off.
"""
from __future__ import annotations

from pathlib import Path

from appsecwatch.ai.analyzer import profile_all
from appsecwatch.stages.base import Stage, StageResult


class AIProfileStage(Stage):
    name = "ai.profile"

    def _dir(self, run_dir: Path) -> Path:
        return run_dir / "03_ai" / "profile"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        surface_by_host = None
        rendered_by_host = None
        # auto/always: enrich the profiler with the crawler's rendered text + curated
        # surface manifest for any host the crawler captured. `never` keeps today's
        # httpx pre-JS input. (The crawler only ran if supply-chain was selected or
        # render=always forced it — see build_pipeline.)
        if cfg.ai.profile.render != "never" and state.crawler_artifacts:
            from appsecwatch.audit.surface import curated_surface

            surface_by_host = {a.host: curated_surface(a) for a in state.crawler_artifacts}
            rendered_by_host = {
                a.host: a.rendered_text
                for a in state.crawler_artifacts
                if a.rendered_text
            }
        state.app_profiles = await profile_all(
            state.page_signals,
            self._dir(run_dir),
            cfg.llm,
            log,
            concurrency=cfg.concurrency.llm,
            surface_by_host=surface_by_host,
            rendered_by_host=rendered_by_host,
            prompt_overrides=cfg.ai.prompts.as_overrides(),
            language=cfg.report.language,
        )
        # A host that hard-failed profiling degrades to default prompts — surface it.
        return StageResult([
            (host, p.error or "profiling failed")
            for host, p in state.app_profiles.items()
            if not p.usable
        ])
