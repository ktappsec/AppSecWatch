"""Failure visibility: stage crashes + per-asset failures land in one sink
(state.errors), and roll up into a RunSummary."""
from __future__ import annotations

from watchtower.config import LLMConfig, WatchTowerConfig
from watchtower.logging import RunLogger
from watchtower.models import AppProfile, Finding, LiveWebServer, TLSHostReport
from watchtower.report.aggregator import build_run_summary
from watchtower.stages import audit, profile
from watchtower.stages.base import Stage, execute_stages
from watchtower.stages.state import ScanState


def _cfg() -> WatchTowerConfig:
    return WatchTowerConfig(
        roots=["example.com"], mmdb_path="/dev/null",
        llm=LLMConfig(base_url="http://localhost/v1", model="m"),
    )


# ---- execute_stages: crash capture + timing -------------------------------

async def test_execute_stages_records_error_type_and_timing(tmp_path):
    class Boom(Stage):
        name = "audit.boom"
        async def run(self, state, run_dir, cfg, ipinfo, log):
            raise KeyError("nope")

    class Okay(Stage):
        name = "recon.ok"
        async def run(self, state, run_dir, cfg, ipinfo, log):
            pass

    state = ScanState()
    log = RunLogger(tmp_path, mode="quiet")
    await execute_stages([Okay(), Boom()], state, tmp_path, _cfg(), None, log)
    log.close()

    assert "recon.ok" in state.completed_stages
    assert "audit.boom" not in state.completed_stages       # crash → not completed
    boom = [e for e in state.errors if e.stage == "audit.boom"]
    assert boom and boom[0].error_type == "KeyError"
    assert "audit.boom" in state.stage_durations and "recon.ok" in state.stage_durations
    assert state.current_stage is None                      # cleared at the end


# ---- per-asset failures returned at the stage seam ------------------------

async def test_sslyze_stage_returns_per_host_errors(tmp_path, monkeypatch):
    async def fake_run_sslyze(*a, **k):
        return ([TLSHostReport(host="a.com", error="timeout after 600s"),
                 TLSHostReport(host="b.com", checks=[])], [])
    monkeypatch.setattr(audit, "run_sslyze", fake_run_sslyze)

    state = ScanState()
    state.live_servers = [LiveWebServer(url="https://a.com", host="a.com")]
    log = RunLogger(tmp_path, mode="quiet")
    # The stage hands its per-asset failures back; it never touches the sink itself.
    result = await audit.SslyzeStage().run(state, tmp_path, _cfg(), None, log)
    log.close()

    assert result.asset_errors == [("a.com", "timeout after 600s")]
    assert state.errors == []


async def test_profile_stage_returns_degraded_hosts(tmp_path, monkeypatch):
    async def fake_profile_all(*a, **k):
        return {"h1": AppProfile(host="h1", error="boom"),
                "h2": AppProfile(host="h2", confidence="high")}
    monkeypatch.setattr(profile, "profile_all", fake_profile_all)

    state = ScanState()
    log = RunLogger(tmp_path, mode="quiet")
    result = await profile.AIProfileStage().run(state, tmp_path, _cfg(), None, log)
    log.close()

    assert result.asset_errors == [("h1", "boom")]


async def test_executor_folds_asset_errors_into_sink(tmp_path, monkeypatch):
    """End-to-end: execute_stages stamps a stage's returned asset errors with the
    stage name and folds them into the single sink."""
    async def fake_run_sslyze(*a, **k):
        return ([TLSHostReport(host="a.com", error="timeout after 600s"),
                 TLSHostReport(host="b.com", checks=[])], [])
    monkeypatch.setattr(audit, "run_sslyze", fake_run_sslyze)

    state = ScanState()
    state.live_servers = [LiveWebServer(url="https://a.com", host="a.com")]
    log = RunLogger(tmp_path, mode="quiet")
    await execute_stages([audit.SslyzeStage()], state, tmp_path, _cfg(), None, log)
    log.close()

    errs = [e for e in state.errors if e.stage == "audit.sslyze" and e.error_type == "asset"]
    assert len(errs) == 1 and errs[0].target == "a.com"


# ---- build_run_summary ----------------------------------------------------

def test_build_run_summary_counts():
    state = ScanState()
    state.nuclei_findings = [Finding(source="nuclei", host="h", severity="high", title="x")]
    state.sslyze_findings = [Finding(source="sslyze", host="h", severity="medium", title="y")]
    state.tls_reports = [TLSHostReport(host="a", error="t"), TLSHostReport(host="b", checks=[])]
    state.app_profiles = {"h": AppProfile(host="h", error="e"),
                          "h2": AppProfile(host="h2", confidence="high")}
    state.stage_durations = {"audit.sslyze": 5.0, "audit.nuclei": 2.0}
    from watchtower.models import StageError, asset_error
    state.errors = [
        asset_error("audit.sslyze", "a", "t"),                          # per-host failure
        StageError(stage="audit.nuclei", message="KeyError", error_type="KeyError"),  # crash
    ]
    counts = {"levels": {"warn": 4, "error": 1}, "events": {"tool_timeout": 2}}

    s = build_run_summary(state, duration_s=12.66, log_counts=counts)
    assert s.duration_s == 12.7
    assert s.findings_total == 2
    assert s.findings_by_severity["high"] == 1 and s.findings_by_severity["medium"] == 1
    assert s.errors_total == 2
    assert s.errors_by_stage == {"audit.sslyze": 1, "audit.nuclei": 1}
    assert s.ai == {"profiled": 1, "degraded": 1}
    assert s.tls == {"hosts": 2, "ok": 1, "errored": 1}
    assert s.events["tool_timeout"] == 2 and s.events["warn"] == 4 and s.events["error"] == 1
    names = {st.name for st in s.stages}
    assert names == {"audit.sslyze", "audit.nuclei"}
