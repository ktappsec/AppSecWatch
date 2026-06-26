"""Late pipeline stage that applies manual suppressions before the report.

Runs after every finding-producing stage and just before ReportStage, so the
report + severity histogram reflect server-injected manual suppressions (the Web
API loads them from the DB and hands the set to run_scan).
"""
from __future__ import annotations

from watchtower.audit.suppress import apply_suppressions
from watchtower.stages.base import Stage


class SuppressionStage(Stage):
    name = "suppression"

    def __init__(self, suppress_set: set[str]) -> None:
        self.suppress_set = suppress_set

    async def run(self, state, run_dir, cfg, ipinfo, log):
        if self.suppress_set:
            n = apply_suppressions(state.all_findings(), self.suppress_set)
            if n:
                log.info(f"manual suppressions applied: {n}")
        return None
