"""OWASP ZAP active-scan runner — daemon fully mocked via httpx.MockTransport.

No real ZAP is needed: every JSON/OTHER endpoint is scripted, so these tests
exercise the spider→ascan→alerts workflow, severity mapping, instance grouping,
graceful degradation, and cancellation cleanup deterministically.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from watchtower.audit.zap_runner import (
    ZAP_RISK_TO_SEVERITY,
    alerts_to_findings,
    run_zap,
)
from watchtower.config import ZapConfig
from watchtower.logging import RunLogger


def _cfg(**over) -> ZapConfig:
    base = dict(
        enabled=True, base_url="http://zap.test:8090", api_key="k",
        max_minutes_total=60, max_minutes_per_host=20, spider_max_minutes=5,
        poll_interval_seconds=0.01, request_timeout=5,
    )
    base.update(over)
    return ZapConfig(**base)


@pytest.fixture
def log(tmp_path):
    return RunLogger(tmp_path, mode="quiet", verbose=False)


def _json(data) -> httpx.Response:
    return httpx.Response(200, json=data)


# Two SQLi instances (same pluginId+host, different URLs) + one XSS instance.
_ALERTS = [
    {"pluginId": "40018", "alert": "SQL Injection", "name": "SQL Injection",
     "risk": "High", "confidence": "Medium", "cweid": "89", "wascid": "19",
     "url": "https://app.example.com/login", "param": "user",
     "description": "SQLi", "solution": "Parameterize", "reference": "ref"},
    {"pluginId": "40018", "alert": "SQL Injection", "name": "SQL Injection",
     "risk": "High", "confidence": "Medium", "cweid": "89", "wascid": "19",
     "url": "https://app.example.com/search", "param": "q",
     "description": "SQLi", "solution": "Parameterize", "reference": "ref"},
    {"pluginId": "40012", "alert": "Reflected XSS", "name": "Reflected XSS",
     "risk": "Medium", "confidence": "High", "cweid": "79", "wascid": "8",
     "url": "https://app.example.com/q", "param": "q",
     "description": "XSS", "solution": "Encode", "reference": "ref"},
]


def _make_transport(calls: list[str], *, ascan_status="100", alerts=None,
                    fail_version=False):
    """Script the ZAP API. `calls` records every path hit (for cleanup assertions).
    `ascan_status` < 100 forces the poll loop to spin (used by the cancel test)."""
    alerts = _ALERTS if alerts is None else alerts

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(path)
        if path == "/JSON/core/view/version/":
            if fail_version:
                raise httpx.ConnectError("connection refused", request=request)
            return _json({"version": "2.15.0"})
        if path == "/JSON/context/action/newContext/":
            return _json({"contextId": "1"})
        if path == "/JSON/spider/action/scan/":
            return _json({"scan": "0"})
        if path == "/JSON/spider/view/status/":
            return _json({"status": "100"})
        if path == "/JSON/ascan/action/scan/":
            return _json({"scan": "1"})
        if path == "/JSON/ascan/view/status/":
            return _json({"status": ascan_status})
        if path == "/JSON/alert/view/alerts/":
            return _json({"alerts": list(alerts)})
        if path == "/OTHER/core/other/jsonreport/":
            return httpx.Response(200, content=b'{"site": []}')
        # newSession / includeInContext / setOption* / stopAllScans / removeContext / ajax
        return _json({"Result": "OK"})

    return httpx.MockTransport(handler)


# --- severity map + grouping --------------------------------------------------

def test_severity_map_has_no_critical():
    assert set(ZAP_RISK_TO_SEVERITY.values()) == {"high", "medium", "low", "info"}
    assert "critical" not in ZAP_RISK_TO_SEVERITY.values()


@pytest.mark.parametrize("risk,sev", [
    ("High", "high"), ("Medium", "medium"), ("Low", "low"),
    ("Informational", "info"), ("Bogus", "info"),
])
def test_alert_risk_maps_to_severity(risk, sev):
    [f] = alerts_to_findings([{"pluginId": "1", "alert": "x", "risk": risk,
                               "url": "https://h/"}])
    assert f.severity == sev


def test_alerts_grouped_by_plugin_and_host():
    findings = alerts_to_findings(_ALERTS)
    assert len(findings) == 2  # SQLi (2 instances) + XSS (1) -> 2 findings
    sqli = next(f for f in findings if f.check_id == "zap.40018")
    assert sqli.source == "zap"
    assert sqli.severity == "high"
    assert sqli.evidence["instance_count"] == 2
    assert set(sqli.evidence["instances"]) == {
        "https://app.example.com/login", "https://app.example.com/search"}
    assert sqli.evidence["params"] == ["user", "q"] or sqli.evidence["params"] == ["q", "user"]
    assert sqli.host == "app.example.com"
    # group_key is the stable check_id so it collapses across hosts in the report.
    assert sqli.group_key == "zap.40018"


# --- full workflow ------------------------------------------------------------

async def test_run_zap_full_workflow(tmp_path, log):
    calls: list[str] = []
    findings, errors = await run_zap(
        ["https://app.example.com"], tmp_path, _cfg(), log,
        run_id="run1", transport=_make_transport(calls),
    )
    assert errors == []
    assert {f.check_id for f in findings} == {"zap.40018", "zap.40012"}
    # raw artifacts written
    assert (tmp_path / "zap-report.json").exists()
    alert_files = list(tmp_path.glob("alerts-*.json"))
    assert len(alert_files) == 1
    assert json.loads(alert_files[0].read_text())  # non-empty
    # the expected workflow endpoints were exercised, in scope
    assert "/JSON/context/action/includeInContext/" in calls
    assert "/JSON/ascan/action/scan/" in calls
    assert "/JSON/alert/view/alerts/" in calls
    # cleanup always runs
    assert "/JSON/ascan/action/stopAllScans/" in calls
    assert "/JSON/context/action/removeContext/" in calls


async def test_run_zap_empty_targets_noops(tmp_path, log):
    findings, errors = await run_zap([], tmp_path, _cfg(), log, run_id="r")
    assert findings == [] and errors == []


# --- degradation --------------------------------------------------------------

async def test_unreachable_daemon_degrades(tmp_path, log):
    calls: list[str] = []
    findings, errors = await run_zap(
        ["https://app.example.com"], tmp_path, _cfg(), log,
        run_id="r", transport=_make_transport(calls, fail_version=True),
    )
    assert findings == []
    assert errors and errors[0][0] is None and "unreachable" in errors[0][1]


# --- cancellation -------------------------------------------------------------

async def test_cancellation_stops_scans_and_reraises(tmp_path, log):
    calls: list[str] = []
    # ascan never completes (status 50) -> poll loop spins on asyncio.sleep,
    # giving us a cancellation point.
    transport = _make_transport(calls, ascan_status="50")
    task = asyncio.create_task(run_zap(
        ["https://app.example.com"], tmp_path, _cfg(), log,
        run_id="r", transport=transport,
    ))
    await asyncio.sleep(0.1)  # let it reach the ascan poll loop
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # cleanup ran despite the cancel
    assert "/JSON/ascan/action/stopAllScans/" in calls
    assert "/JSON/context/action/removeContext/" in calls


# --- ZapStage scope-lock (defense-in-depth) -----------------------------------

async def test_zapstage_drops_out_of_scope_targets(tmp_path, log, monkeypatch):
    import watchtower.audit.zap_runner as zr
    from watchtower.config import WatchTowerConfig
    from watchtower.stages.audit import ZapStage
    from watchtower.stages.state import ScanState

    received: dict = {}

    async def fake_run_zap(targets, out_dir, cfg, log, *, run_id, transport=None):
        received["targets"] = list(targets)
        return [], []

    monkeypatch.setattr(zr, "run_zap", fake_run_zap)

    cfg = WatchTowerConfig(
        roots=["example.com"],
        llm={"base_url": "http://llm", "model": "m"},
        zap={"enabled": True, "base_url": "http://zap:8090",
             "targets": ["https://app.example.com", "https://evil.test/x"]},
    )
    result = await ZapStage().run(ScanState(), tmp_path, cfg, None, log)
    # only the in-scope target reached run_zap
    assert received["targets"] == ["https://app.example.com"]
    # the out-of-scope target is recorded as an asset error
    assert any("out of scope" in m for _t, m in result.asset_errors)
