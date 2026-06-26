"""Web API tests — scan execution is mocked, so no external tools are needed.

`run_scan` is monkeypatched in `watchtower.api.jobs` (where it is imported by name).
The fake populates the injected ScanState and writes a report.html so the
result/report/lifecycle paths are exercised end-to-end through the real
JobManager, FastAPI app, auth, allowlist, and idempotency code.
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest
from fastapi.testclient import TestClient

from watchtower.api.config import ServerConfig
from watchtower.api.security import callback_host_allowed, sign_webhook
from watchtower.api.server import create_app
from watchtower.models import Finding

API_KEY = "secret-key-1"
H = {"Authorization": f"Bearer {API_KEY}"}


def _server_config(tmp_path, *, api_keys=(API_KEY,), max_concurrent=2, max_queue=10,
                   base_config=None):
    return ServerConfig(
        output_root=str(tmp_path / "runs"),
        bind={"host": "127.0.0.1", "port": 8080},
        limits={"max_concurrent_scans": max_concurrent, "max_queue_depth": max_queue},
        webhook={"callback_host_allowlist": ["svc.internal"], "timeout_seconds": 5},
        docs_enabled=True,
        base_config_raw={
            "mmdb_path": "/dev/null",
            "llm": {"base_url": "http://llm.local", "model": "test-model"},
        } if base_config is None else base_config,
        api_keys=list(api_keys),
        webhook_secret="whsecret",
    )


def _make_fake_run(*, findings=1, block_event=None, fail=False):
    """Build a fake run_scan coroutine.

    block_event: an asyncio.Event the fake awaits before finishing (used to hold a
    scan in `running` for backpressure/cancel tests).
    """
    async def fake_run(*args, **kwargs):
        state = kwargs["state"]
        run_dir = kwargs["run_dir"]
        state.coverage = {"recon": {"ran": True, "reason": "prerequisite"}}
        state.completed_stages.append("recon.httpx")
        for i in range(findings):
            state.nuclei_findings.append(
                Finding(source="nuclei", host="app.example.com", severity="high",
                        title=f"finding-{i}")
            )
        (run_dir / "report.html").write_text("<html><body>report</body></html>")
        if fail:
            raise RuntimeError("boom")
        if block_event is not None:
            await block_event.wait()
        return run_dir / "report.html"

    return fake_run


def _client(tmp_path, monkeypatch, fake_run=None, config=None):
    fake_run = fake_run or _make_fake_run()
    monkeypatch.setattr("watchtower.api.jobs.run_scan", fake_run)
    app = create_app(config or _server_config(tmp_path))
    return TestClient(app)


def _wait_state(client, job_id, target, timeout=5.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = client.get(f"/scans/{job_id}", headers=H).json()
        if last["state"] == target:
            return last
        time.sleep(0.03)
    raise AssertionError(f"{job_id} never reached {target}; last={last}")


REQ = {"roots": ["example.com"]}


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
def test_no_key_401(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json=REQ)
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "unauthorized"


def test_bad_key_401(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json=REQ, headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401


def test_valid_key_202(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json=REQ, headers=H)
        assert r.status_code == 202
        body = r.json()
        assert body["state"] == "queued"
        assert body["links"]["self"].endswith(body["id"])


def test_xapikey_header_accepted(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json=REQ, headers={"X-API-Key": API_KEY})
        assert r.status_code == 202


def test_healthz_no_auth(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.get("/healthz")
        assert r.status_code == 200 and r.json()["status"] == "ok"


def test_auth_disabled_when_no_keys(tmp_path, monkeypatch):
    cfg = _server_config(tmp_path, api_keys=())
    with _client(tmp_path, monkeypatch, config=cfg) as client:
        r = client.post("/scans", json=REQ)  # no auth header
        assert r.status_code == 202


# --------------------------------------------------------------------------- #
# allowlist guardrail
# --------------------------------------------------------------------------- #
def test_any_root_accepted_no_allowlist(tmp_path, monkeypatch):
    # No scan-target allowlist: the per-scan roots is the only scope.
    with _client(tmp_path, monkeypatch) as client:
        assert client.post("/scans", json={"roots": ["anything.example"]}, headers=H).status_code == 202
        assert client.post("/scans", json={"roots": ["a.org", "b.net"]}, headers=H).status_code == 202


def test_unconfigured_boot_blocks_scan_until_configured(tmp_path, monkeypatch):
    # UI-only boot: empty base_config → scans refused (409) until llm/mmdb are set.
    cfg = _server_config(tmp_path, base_config={})
    with _client(tmp_path, monkeypatch, config=cfg) as client:
        r = client.post("/scans", json={"roots": ["app.example.com"]}, headers=H)
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "not_configured"
        # configure via the UI-managed endpoint, then the same scan runs
        client.put("/config", json={"base_config": {
            "mmdb_path": "/dev/null",
            "llm": {"base_url": "http://llm.local", "model": "m"},
        }}, headers=H)
        assert client.post("/scans", json={"roots": ["app.example.com"]}, headers=H).status_code == 202


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
def test_only_and_skip_together_422(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json={**REQ, "only": ["tls"], "skip": ["ai"]}, headers=H)
        assert r.status_code == 422


def test_missing_roots_422(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json={}, headers=H)
        assert r.status_code == 422


def test_bad_capability_token_422(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json={**REQ, "only": ["bogus"]}, headers=H)
        assert r.status_code == 422
        assert r.json()["error"]["code"] in ("invalid_selection", "validation_error")


def test_subtoken_selection_accepted(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json={**REQ, "only": ["nuclei.high", "ai.triage"]}, headers=H)
        assert r.status_code == 202


def test_bad_subtoken_422(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json={**REQ, "only": ["nuclei.bogus"]}, headers=H)
        assert r.status_code == 422


def test_capabilities_exposes_subtokens(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        caps = client.get("/capabilities", headers=H).json()
        assert "ai.triage" in caps["subtokens"]["ai"]
        assert "nuclei.high" in caps["subtokens"]["nuclei"]
        assert "recon.tlsx" in caps["subtokens"]["recon"]
        # the deterministic headers capability + its sub-tokens
        assert "headers" in caps["capabilities"]
        assert "headers.csp" in caps["subtokens"]["headers"]
        assert "headers.best-practice" in caps["subtokens"]["headers"]


def test_headers_subtoken_selection_accepted(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json={**REQ, "only": ["headers.csp"]}, headers=H)
        assert r.status_code == 202


# --------------------------------------------------------------------------- #
# AI prompts (editable system-prompt registry)
# --------------------------------------------------------------------------- #
def test_list_prompts_returns_registry(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.get("/prompts", headers=H)
        assert r.status_code == 200
        slots = r.json()["slots"]
        ids = {s["id"] for s in slots}
        assert "triage_system_default" in ids and "profile_system" in ids
        for s in slots:
            assert s["default_text"]
            assert s["override"] is None and s["modified"] is False
            assert s["effective"] == s["default_text"]


def test_put_prompt_sets_then_clears_override(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        # set an override
        r = client.put("/prompts/triage_system_default",
                       json={"text": "CUSTOM TRIAGE PROMPT"}, headers=H)
        assert r.status_code == 200
        slot = next(s for s in r.json()["slots"] if s["id"] == "triage_system_default")
        assert slot["modified"] is True
        assert slot["override"] == "CUSTOM TRIAGE PROMPT"
        assert slot["effective"] == "CUSTOM TRIAGE PROMPT"
        # it persists into the base scan config (ai.prompts)
        cfg = client.get("/config", headers=H).json()
        assert cfg["base_config"]["ai"]["prompts"]["triage_system_default"] == "CUSTOM TRIAGE PROMPT"

        # blank clears it (revert to default)
        r = client.put("/prompts/triage_system_default", json={"text": "  "}, headers=H)
        slot = next(s for s in r.json()["slots"] if s["id"] == "triage_system_default")
        assert slot["modified"] is False and slot["override"] is None


def test_put_unknown_prompt_slot_404(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.put("/prompts/nope", json={"text": "x"}, headers=H)
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "not_found"


def test_preview_prompt_renders_candidate_and_shape(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/prompts/triage_system_default/preview",
                        json={"text": "CANARY-SYSTEM"}, headers=H)
        assert r.status_code == 200
        body = r.json()
        assert "CANARY-SYSTEM" in body["system"]
        assert "suppressions" in body["user"]          # shape-hint present in preview
        assert "ref" in body["user"]


def test_bad_headers_subtoken_422(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json={**REQ, "only": ["headers.bogus"]}, headers=H)
        assert r.status_code == 422


# --------------------------------------------------------------------------- #
# assets inventory + scan targeting
# --------------------------------------------------------------------------- #
def test_assets_crud_and_import(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.post("/assets", json={"fqdn": "a.example.com", "group": "G1"},
                           headers=H).status_code == 201
        # invalid domain -> 422
        assert client.post("/assets", json={"fqdn": "nodot"}, headers=H).status_code == 422
        # CSV import (header + invalid skipped)
        r = client.post("/assets/import",
                        json={"csv": "domain,group\nb.example.com,G1\nbad\nc.example.com,G2\n"},
                        headers=H)
        assert r.status_code == 200 and r.json() == {"added": 2, "updated": 0, "skipped": 2}
        names = {a["fqdn"] for a in client.get("/assets", headers=H).json()}
        assert names == {"a.example.com", "b.example.com", "c.example.com"}
        assert [a["fqdn"] for a in client.get("/assets?group=G2", headers=H).json()] == ["c.example.com"]
        groups = {g["group"]: g["count"] for g in client.get("/assets/groups", headers=H).json()}
        assert groups == {"G1": 2, "G2": 1}
        assert client.delete("/assets/a.example.com", headers=H).status_code == 200


def test_scan_by_group_resolves_roots(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        client.post("/assets", json={"fqdn": "root1.com", "group": "Bank"}, headers=H)
        client.post("/assets", json={"fqdn": "root2.com", "group": "Bank"}, headers=H)
        r = client.post("/scans", json={"group": "Bank"}, headers=H)
        assert r.status_code == 202
        assert r.json()["group"] == "Bank"
        assert set(r.json()["roots"]) == {"root1.com", "root2.com"}


def test_scan_empty_group_422(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scans", json={"group": "DoesNotExist"}, headers=H)
        assert r.status_code == 422
        assert r.json()["error"]["code"] == "empty_target"


def test_scan_requires_exactly_one_target(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.post("/scans", json={}, headers=H).status_code == 422            # none
        assert client.post("/scans", json={"roots": ["a.com"], "all_assets": True},
                           headers=H).status_code == 422                                # two
        assert client.post("/scans", json={"all_assets": True}, headers=H).status_code == 422  # no assets


def test_assets_require_auth(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.get("/assets").status_code == 401


def test_scan_templates_crud(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/scan-templates", headers=H,
                        json={"name": "quick", "skip": ["recon.subfinder"], "throttle": "gentle"})
        assert r.status_code == 201 and r.json()["throttle"] == "gentle"
        tid = r.json()["id"]
        assert [t["name"] for t in client.get("/scan-templates", headers=H).json()] == ["quick"]
        assert client.delete(f"/scan-templates/{tid}", headers=H).status_code == 200
        assert client.get("/scan-templates", headers=H).json() == []


def test_asset_findings_endpoint_no_scan(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        client.post("/assets", json={"fqdn": "x.com"}, headers=H)  # imported, no last scan
        assert client.get("/assets/x.com/findings", headers=H).json() == []


def test_assets_bulk_ops(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        for d, g in [("a.com", "G1"), ("b.com", "G1"), ("c.com", "G2")]:
            client.post("/assets", json={"fqdn": d, "group": g}, headers=H)
        r = client.post("/assets/bulk", headers=H,
                        json={"action": "set_group", "fqdns": ["a.com", "b.com"], "group": "GX"})
        assert r.status_code == 200 and r.json()["affected"] == 2
        r2 = client.post("/assets/bulk", headers=H,
                         json={"action": "delete", "filter": {"group": "GX"}})
        assert r2.json()["affected"] == 2
        assert {a["fqdn"] for a in client.get("/assets", headers=H).json()} == {"c.com"}


def test_capabilities_throttle_details(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        c = client.get("/capabilities", headers=H).json()
        assert c["throttle_profiles"] == ["paranoid", "gentle", "normal", "aggressive", "insane"]
        assert c["throttle_details"]["paranoid"]["httpx_threads"] == 1
        assert c["throttle_details"]["insane"]["httpx_threads"] == 200


def test_reevaluate_endpoint(tmp_path, monkeypatch):
    from watchtower.models import TriagedAsset
    monkeypatch.setattr("watchtower.util.ipinfo.IPInfoLookup",
                        type("F", (), {"__init__": lambda s, *a, **k: None, "close": lambda s: None}))
    monkeypatch.setattr(
        "watchtower.recon.triage.triage_records",
        lambda recs, roots, ip: [
            TriagedAsset(fqdn=r["host"], a_records=r["a"], cname_chain=r["cname"],
                         asn=1, as_org="X", bucket="in_scope", reason="x") for r in recs],
    )
    with _client(tmp_path, monkeypatch) as client:
        client.post("/assets", json={"fqdn": "a.com", "group": "G"}, headers=H)
        r = client.post("/assets/reevaluate", headers=H)
        assert r.status_code == 200 and r.json()["total"] >= 1


def test_schedules_crud(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/schedules", headers=H, json={
            "name": "weekly bank", "target": {"group": "Bank"},
            "cadence": "weekly", "at_time": "02:00", "weekday": 6,
        })
        assert r.status_code == 201
        sid = r.json()["id"]
        assert r.json()["next_run_at"] and r.json()["cadence"] == "weekly"
        assert [s["id"] for s in client.get("/schedules", headers=H).json()] == [sid]
        u = client.put(f"/schedules/{sid}", headers=H,
                       json={"cadence": "daily", "at_time": "03:00", "enabled": False})
        assert u.status_code == 200 and u.json()["cadence"] == "daily" and u.json()["enabled"] is False
        assert client.delete(f"/schedules/{sid}", headers=H).status_code == 200
        assert client.get("/schedules", headers=H).json() == []


def test_schedule_bad_cadence_422(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/schedules", headers=H, json={"cadence": "fortnightly"})
        assert r.status_code == 422


def test_nuclei_catalog_and_reindex(tmp_path, monkeypatch):
    # Point reindex at an empty templates dir → deterministic 200 / 0 indexed.
    tdir = tmp_path / "templates"
    tdir.mkdir()
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(tdir))
    with _client(tmp_path, monkeypatch) as client:
        assert client.get("/nuclei/templates", headers=H).json() == []
        r = client.post("/nuclei/reindex", headers=H)
        assert r.status_code == 200 and r.json()["indexed"] == 0


def test_nuclei_custom_crud(tmp_path, monkeypatch):
    import watchtower.api.nuclei_custom as ncmod
    monkeypatch.setattr(ncmod.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/nuclei/custom", headers=H,
                        json={"name": "My", "yaml": "id: my-check\ninfo:\n  name: My\n  severity: info\n"})
        assert r.status_code == 201 and r.json()["valid"] is True
        tid = r.json()["id"]
        assert [t["id"] for t in client.get("/nuclei/custom", headers=H).json()] == [tid]
        # the valid custom template is mirrored into the searchable catalog
        assert [t["id"] for t in client.get("/nuclei/templates?source=custom", headers=H).json()] == ["my-check"]
        assert client.delete(f"/nuclei/custom/{tid}", headers=H).status_code == 200


def test_nuclei_generate_degrades_gracefully(tmp_path, monkeypatch):
    # The fixture has an LLM configured but unreachable → generate must return a
    # graceful invalid result (200), not 500.
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/nuclei/custom/generate", headers=H, json={"description": "detect X"})
        assert r.status_code == 200
        assert r.json()["valid"] is False and r.json()["error"]


def test_suppressions_crud(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/suppressions", headers=H, json={
            "source": "headers", "host": "a.com", "key": "hsts.missing", "reason": "fp",
        })
        assert r.status_code == 201
        fp = r.json()["fingerprint"]
        assert fp == "headers|a.com|hsts.missing"
        g = client.post("/suppressions", headers=H, json={
            "source": "nuclei", "key": "CVE-x", "scope": "global",
        })
        assert g.json()["host"] == "*" and g.json()["fingerprint"] == "nuclei|*|CVE-x"
        assert {s["fingerprint"] for s in client.get("/suppressions", headers=H).json()} == {
            fp, "nuclei|*|CVE-x"}
        assert client.delete(f"/suppressions/{fp}", headers=H).status_code == 200
        assert [s["fingerprint"] for s in client.get("/suppressions", headers=H).json()] == [
            "nuclei|*|CVE-x"]


# --------------------------------------------------------------------------- #
# runtime config (GET/PUT /config) — UI-managed store
# --------------------------------------------------------------------------- #
def _store_path(tmp_path):
    return tmp_path / "runs" / ".config" / "server-config.json"


def test_get_config_returns_effective(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        cfg = client.get("/config", headers=H).json()
        assert "allowed_roots" not in cfg          # no scan-target allowlist
        assert cfg["base_config"]["llm"]["base_url"] == "http://llm.local"


def test_put_config_persists_and_applies(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        body = {"base_config": {
            "mmdb_path": "/dev/null",
            "llm": {"base_url": "http://llm.local", "model": "swapped-model"},
        }}
        r = client.put("/config", json=body, headers=H)
        assert r.status_code == 200
        assert r.json()["base_config"]["llm"]["model"] == "swapped-model"
        # persisted to the writable store
        stored = json.loads(_store_path(tmp_path).read_text())
        assert stored["base_config"]["llm"]["model"] == "swapped-model"
        # GET reflects it
        assert client.get("/config", headers=H).json()["base_config"]["llm"]["model"] == "swapped-model"


def test_put_config_change_applies_to_next_scan(tmp_path, monkeypatch):
    # Start unconfigured → scan 409; PUT a valid config → next scan runs, no restart.
    cfg = _server_config(tmp_path, base_config={})
    with _client(tmp_path, monkeypatch, config=cfg) as client:
        assert client.post("/scans", json={"roots": ["x.com"]}, headers=H).status_code == 409
        client.put("/config", json={"base_config": {
            "mmdb_path": "/dev/null", "llm": {"base_url": "http://llm.local", "model": "m"}}},
            headers=H)
        assert client.post("/scans", json={"roots": ["x.com"]}, headers=H).status_code == 202


def test_llm_api_key_is_write_only(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        base = {"mmdb_path": "/dev/null",
                "llm": {"base_url": "http://llm.local", "model": "m", "api_key": "realkey123"}}
        client.put("/config", json={"base_config": base}, headers=H)
        # GET masks the key
        assert client.get("/config", headers=H).json()["base_config"]["llm"]["api_key"] == "********"
        # the real key is persisted in the store
        assert json.loads(_store_path(tmp_path).read_text())["base_config"]["llm"]["api_key"] == "realkey123"
        # PUT with the mask keeps the existing key (write-only passthrough)
        masked = {"mmdb_path": "/dev/null",
                  "llm": {"base_url": "http://llm.local", "model": "m2", "api_key": "********"}}
        client.put("/config", json={"base_config": masked}, headers=H)
        stored = json.loads(_store_path(tmp_path).read_text())["base_config"]["llm"]
        assert stored["api_key"] == "realkey123" and stored["model"] == "m2"


def test_put_invalid_config_422(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        # llm.base_url is required by WatchTowerConfig → validation fails
        r = client.put("/config", json={
            "base_config": {"mmdb_path": "/dev/null", "llm": {"model": "m"}},
        }, headers=H)
        assert r.status_code == 422


def test_config_store_loaded_on_boot(tmp_path, monkeypatch):
    # Pre-seed the store; a fresh app must treat it as authoritative.
    store = _store_path(tmp_path)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps({
        "base_config": {"mmdb_path": "/dev/null",
                        "llm": {"base_url": "http://boot.local", "model": "boot-model"}},
    }))
    with _client(tmp_path, monkeypatch) as client:
        cfg = client.get("/config", headers=H).json()
        assert cfg["base_config"]["llm"]["model"] == "boot-model"
        assert client.post("/scans", json={"roots": ["x.com"]}, headers=H).status_code == 202


def test_config_requires_auth(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.get("/config").status_code == 401
        assert client.put("/config", json={"base_config": {}}).status_code == 401


def test_serve_with_no_config_file_boots_unconfigured(monkeypatch):
    # `serve` with no -c: load_server_config(None) must build a usable, empty,
    # allowlist-free ServerConfig (the UI-managed / store-primary path).
    from watchtower.api.config import load_server_config
    monkeypatch.delenv("WATCHTOWER_LLM_API_KEY", raising=False)
    monkeypatch.delenv("WATCHTOWER_API_KEYS", raising=False)
    cfg = load_server_config(None)
    assert cfg.base_config_raw == {}
    assert not hasattr(cfg, "allowed_roots")  # the allowlist concept is gone
    assert cfg.auth_enabled is False


# --------------------------------------------------------------------------- #
# idempotency + dedupe
# --------------------------------------------------------------------------- #
def test_idempotency_key_returns_same_job(tmp_path, monkeypatch):
    block = asyncio.Event()
    with _client(tmp_path, monkeypatch, _make_fake_run(block_event=block)) as client:
        h = {**H, "Idempotency-Key": "abc-123"}
        r1 = client.post("/scans", json=REQ, headers=h)
        r2 = client.post("/scans", json=REQ, headers=h)
        assert r1.status_code == 202
        assert r2.status_code == 200  # replay → existing job, not a new 202
        assert r1.json()["id"] == r2.json()["id"]


def test_inflight_dedupe(tmp_path, monkeypatch):
    block = asyncio.Event()
    with _client(tmp_path, monkeypatch, _make_fake_run(block_event=block)) as client:
        r1 = client.post("/scans", json=REQ, headers=H)
        r2 = client.post("/scans", json=REQ, headers=H)  # identical, still in-flight
        assert r1.json()["id"] == r2.json()["id"]
        assert r2.status_code == 200


# --------------------------------------------------------------------------- #
# backpressure
# --------------------------------------------------------------------------- #
def test_backpressure_429(tmp_path, monkeypatch):
    cfg = _server_config(tmp_path, max_concurrent=1, max_queue=1)
    block = asyncio.Event()
    # distinct roots so dedupe doesn't merge them
    with _client(tmp_path, monkeypatch, _make_fake_run(block_event=block), config=cfg) as client:
        a = client.post("/scans", json={"roots": ["a.example.com"]}, headers=H)
        _wait_state(client, a.json()["id"], "running")
        b = client.post("/scans", json={"roots": ["b.example.com"]}, headers=H)
        assert b.status_code == 202  # queued (depth 1)
        c = client.post("/scans", json={"roots": ["c.example.com"]}, headers=H)
        assert c.status_code == 429
        assert c.headers.get("Retry-After")
        assert c.json()["error"]["code"] == "queue_full"


# --------------------------------------------------------------------------- #
# lifecycle + result/report
# --------------------------------------------------------------------------- #
def test_lifecycle_completed(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, _make_fake_run(findings=3)) as client:
        sub = client.post("/scans", json=REQ, headers=H).json()
        job_id = sub["id"]
        done = _wait_state(client, job_id, "completed")
        assert done["finding_count"] == 3
        assert "recon.httpx" in done["completed_stages"]

        result = client.get(f"/scans/{job_id}/result", headers=H)
        assert result.status_code == 200
        rj = result.json()
        assert rj["state"] == "completed"
        assert rj["histogram_totals"]["high"] == 3
        assert len(rj["findings"]) == 3

        report = client.get(f"/scans/{job_id}/report", headers=H)
        assert report.status_code == 200
        assert "report" in report.text


def test_result_409_before_finish(tmp_path, monkeypatch):
    block = asyncio.Event()
    with _client(tmp_path, monkeypatch, _make_fake_run(block_event=block)) as client:
        job_id = client.post("/scans", json=REQ, headers=H).json()["id"]
        _wait_state(client, job_id, "running")
        r = client.get(f"/scans/{job_id}/result", headers=H)
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "not_finished"


def test_failed_scan_recorded(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, _make_fake_run(fail=True)) as client:
        job_id = client.post("/scans", json=REQ, headers=H).json()["id"]
        done = _wait_state(client, job_id, "failed")
        assert done["error"] and "boom" in done["error"]


def test_list_and_get_404(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        client.post("/scans", json=REQ, headers=H)
        lst = client.get("/scans", headers=H).json()
        assert lst["total"] >= 1
        assert client.get("/scans/nope", headers=H).status_code == 404


def test_log_endpoint(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        job_id = client.post("/scans", json=REQ, headers=H).json()["id"]
        _wait_state(client, job_id, "completed")
        r = client.get(f"/scans/{job_id}/log?tail=10", headers=H)
        assert r.status_code == 200  # ndjson (may be empty for the mocked run)


# --------------------------------------------------------------------------- #
# cancel
# --------------------------------------------------------------------------- #
def test_cancel_running(tmp_path, monkeypatch):
    block = asyncio.Event()  # never set → the fake blocks until cancelled
    with _client(tmp_path, monkeypatch, _make_fake_run(block_event=block)) as client:
        job_id = client.post("/scans", json=REQ, headers=H).json()["id"]
        _wait_state(client, job_id, "running")
        r = client.post(f"/scans/{job_id}/cancel", headers=H)
        assert r.status_code == 200
        assert r.json()["state"] == "cancelled"


def test_cancel_already_terminal_409(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        job_id = client.post("/scans", json=REQ, headers=H).json()["id"]
        _wait_state(client, job_id, "completed")
        r = client.post(f"/scans/{job_id}/cancel", headers=H)
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "already_terminal"


# --------------------------------------------------------------------------- #
# reindex (startup)
# --------------------------------------------------------------------------- #
def test_reindex_marks_running_interrupted(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    stale = runs / "2026-01-01T00-00-00Z-stale"
    stale.mkdir(parents=True)
    # Legacy record carrying the removed mode/target keys — reindex must tolerate
    # them (Pydantic ignores extras) and still flip running → interrupted.
    (stale / "job.json").write_text(
        '{"id":"2026-01-01T00-00-00Z-stale","state":"running","mode":"quick",'
        '"target":"https://app.example.com","roots":["example.com"],'
        '"submitted_at":"2026-01-01T00:00:00Z"}'
    )
    with _client(tmp_path, monkeypatch) as client:
        r = client.get("/scans/2026-01-01T00-00-00Z-stale", headers=H)
        assert r.status_code == 200
        assert r.json()["state"] == "interrupted"


# --------------------------------------------------------------------------- #
# webhook (unit)
# --------------------------------------------------------------------------- #
def test_sign_webhook_stable():
    sig = sign_webhook(b'{"a":1}', "whsecret")
    assert sig.startswith("sha256=")
    assert sign_webhook(b'{"a":1}', "whsecret") == sig  # deterministic


def test_callback_host_allowlist():
    assert callback_host_allowed("https://svc.internal/ingest", ["svc.internal"])
    assert not callback_host_allowed("https://evil.com/ingest", ["svc.internal"])


@pytest.mark.asyncio
async def test_send_webhook_skips_non_allowlisted(tmp_path, monkeypatch):
    import httpx

    from watchtower.api import security

    cfg = _server_config(tmp_path)

    class _Boom:
        def __init__(self, *a, **k):
            raise AssertionError("httpx must not be used for a non-allowlisted host")

    monkeypatch.setattr(httpx, "AsyncClient", _Boom)
    # host not in allowlist → returns without ever constructing a client
    await security.send_webhook(cfg, "https://evil.com/ingest", "scan.completed", {"id": "x"})


def test_webhook_fired_on_completion(tmp_path, monkeypatch):
    calls = []

    async def fake_send(server, url, event, payload):
        calls.append((url, event, payload))

    monkeypatch.setattr("watchtower.api.jobs.send_webhook", fake_send)
    with _client(tmp_path, monkeypatch) as client:
        job_id = client.post(
            "/scans",
            json={**REQ, "callback_url": "https://svc.internal/ingest"},
            headers=H,
        ).json()["id"]
        _wait_state(client, job_id, "completed")
        # give the post-completion webhook a tick to fire
        for _ in range(50):
            if calls:
                break
            time.sleep(0.03)
        assert calls and calls[0][1] == "scan.completed"
        assert calls[0][2]["id"] == job_id
