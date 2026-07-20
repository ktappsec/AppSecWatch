"""Late pipeline stage that applies manual suppressions before the report.

Runs after every finding-producing stage and just before ReportStage, so the
report + severity histogram reflect server-injected manual suppressions (the Web
API loads them from the DB and hands the set to run_scan).
"""
from __future__ import annotations

from appsecwatch.audit.liveness import apply_coverage_suppressions
from appsecwatch.audit.suppress import apply_suppressions
from appsecwatch.models import asset_error
from appsecwatch.stages.base import Stage


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


class LivenessGateStage(Stage):
    """Pre-report liveness gate. Two related concerns, both keyed on what httpx
    actually returned:

      1. Coverage suppression — hide findings on hosts that returned a blocked/error
         response (not a real application surface) so posture + severity counts
         exclude that noise, while the findings stay auditable in findings.json.
      2. Degraded-run flag — when httpx returned ZERO live servers despite recon
         resolving live assets, the edge blocked the probe and nothing was audited.
         Record it so the run is not mistaken for a clean, finding-free scan (sets
         state.degraded + a StageError so --strict exits non-zero)."""

    name = "liveness-gate"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        n = apply_coverage_suppressions(state.all_findings(), state.live_servers)
        if n:
            blocked = sum(1 for s in state.live_servers if not s.assessed)
            log.info(
                f"coverage suppressions applied: {n} finding(s) on "
                f"{blocked} not-assessed host(s)"
            )

        # Degraded: httpx probed nothing live despite resolvable live assets.
        live_assets = len(state.live())
        if not state.live_servers and live_assets >= 1 and self._httpx_ran(state):
            reason = (
                f"httpx returned 0 live web servers for {live_assets} live asset(s) — "
                "the target edge likely blocked the probe; nothing was audited"
            )
            state.degraded = True
            state.degraded_reason = reason
            state.errors.append(asset_error("recon.httpx", None, reason))
            log.warn(reason, event="scan_degraded")
        return None

    @staticmethod
    def _httpx_ran(state) -> bool:
        sub = (state.coverage.get("recon", {}) or {}).get("sub", {}) or {}
        # Default True: if coverage is unavailable (explicit stage list), a 0-server
        # result with live assets is still worth flagging.
        return bool(sub.get("recon.httpx", {}).get("ran", True))
