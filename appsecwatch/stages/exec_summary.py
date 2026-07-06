"""ExecSummaryStage — the optional AI executive-narrative pass (`ai.summary`).

Runs at the TAIL of the ai-analyze phase (after triage suppression), makes ONE
whole-run LLM call, and stores the validated narrative on `state.exec_summary`.
The executive report's deterministic core is computed independently at render time,
so a degrade here (or this stage not running at all) just means the report falls
back to templated prose — it never gates anything.

The deterministic top-risk SELECTION is shared with the renderer
(`select_top_risks`); the AI returns notes keyed by the ephemeral `ref`, which we
re-bind to each risk's stable key so the merge survives a later selection shift
(e.g. manual suppression, which runs after this stage).
"""
from __future__ import annotations

from collections import Counter

from appsecwatch.stages.base import Stage, StageResult

_SEVERITIES = ("critical", "high", "medium", "low", "info")


class ExecSummaryStage(Stage):
    name = "ai.summary"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        from appsecwatch.ai.analyzer import summarize_run
        from appsecwatch.report.aggregator import posture_rating, select_top_risks

        visible = [f for f in state.all_findings() if not f.suppressed]
        counts = Counter(f.severity for f in visible)
        totals = {s: counts.get(s, 0) for s in _SEVERITIES}
        rating, volume_note = posture_rating(totals)
        risks = select_top_risks(visible)
        payload = [
            {"ref": r.ref, "title": r.title, "source": r.source,
             "severity": r.severity, "host_count": r.host_count}
            for r in risks
        ]
        scale = {
            "live": len(state.live()),
            "live_servers": len(state.live_servers),
            "dead": len(state.dead()),
        }

        result = await summarize_run(
            posture={"rating": rating, "volume_note": volume_note},
            counts=totals,
            scale=scale,
            risks=payload,
            cfg=cfg.llm,
            log=log,
            prompt_overrides=cfg.ai.prompts.as_overrides(),
            language=cfg.report.language,
        )

        # Re-bind each note (keyed by ephemeral ref) to the stable risk key, so the
        # renderer merges by key after re-selecting the final visible top-N.
        ref_to_key = {r.ref: r.key for r in risks}
        for note in result.risk_notes:
            note.key = ref_to_key.get(note.ref, "")

        state.exec_summary = result

        out = run_dir / "03_ai" / "exec_summary"
        out.mkdir(parents=True, exist_ok=True)
        (out / "summary.json").write_text(result.model_dump_json(indent=2))

        if not result.usable:
            return StageResult([(None, f"executive summary degraded: {result.error}")])
        return None
