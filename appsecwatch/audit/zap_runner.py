"""OWASP ZAP active-scan runner — async REST client over a sidecar daemon.

Unlike every other audit tool, ZAP is NOT a `run_tool` subprocess: it runs as a
separate long-lived sidecar container (`ghcr.io/zaproxy/zaproxy`) and we drive it
over the ZAP JSON REST API with `httpx` (already a core dep). The flow per run:
spider → (optional) ajax-spider → active scan → poll status against a Python
deadline → collect alerts → write the raw report. On any deadline or a `/cancel`
(`asyncio.CancelledError`) we stop the scans and remove the context so nothing is
left running on the daemon.

Design invariants (see AGENTS.md / DESIGN.md):
- **Active-scan only, opt-in.** This fires live payloads, so the capability is
  gated (ZapConfig.enabled + base_url) and scoped to operator-specified targets.
- **Degrade, never crash.** A daemon that is unreachable/erroring yields no
  findings + an asset error; the overall scan continues.
- **Cancellation-safe.** Cleanup (stop scans + remove context) runs in `finally`;
  `CancelledError` is re-raised.
- **Secret-safe logging.** The API key travels as the `X-ZAP-API-Key` header, so
  it never lands in a logged URL.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from appsecwatch.config import ZapConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import Finding, Severity
from appsecwatch.util.domains import host_to_filename

# ZAP risk text → AppSecWatch severity. ZAP has no "critical" tier, so nothing maps
# to it by design (its highest is High).
ZAP_RISK_TO_SEVERITY: dict[str, Severity] = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


class ZapError(RuntimeError):
    """A ZAP daemon/API error. Mirrors LLMError — caught by run_zap to degrade."""


def _host_of(url: str) -> str:
    try:
        return urlparse(url if "://" in url else f"//{url}").hostname or ""
    except Exception:
        return ""


def _scope_regex(target: str) -> str:
    """A ZAP context-scope regex locking attacks to the target host (any port/path)."""
    host = _host_of(target) or target
    return rf"^https?://{re.escape(host)}(:[0-9]+)?(/.*)?$"


class ZapClient:
    """Thin async wrapper over the ZAP JSON REST API.

    `transport` is an injection seam: tests pass an `httpx.MockTransport` so the
    whole suite runs with no real daemon.
    """

    def __init__(
        self,
        cfg: ZapConfig,
        log: RunLogger,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.cfg = cfg
        self.log = log
        headers = {"X-ZAP-API-Key": cfg.api_key} if cfg.api_key else {}
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            headers=headers,
            timeout=cfg.request_timeout,
            transport=transport,
        )

    async def _get(self, path: str, **params: object) -> dict:
        """One JSON API call. Raises ZapError on transport/HTTP/parse failure."""
        clean = {k: v for k, v in params.items() if v is not None}
        try:
            r = await self._client.get(path, params=clean)
        except httpx.HTTPError as e:
            raise ZapError(f"zap HTTP error on {path}: {e}") from e
        if r.status_code >= 400:
            raise ZapError(f"zap HTTP {r.status_code} on {path}: {r.text[:200]}")
        try:
            return r.json()
        except Exception as e:  # noqa: BLE001 — any decode failure is a ZapError
            raise ZapError(f"zap bad JSON on {path}: {e}") from e

    # --- core / session / context ---------------------------------------------
    async def version(self) -> str:
        return str((await self._get("/JSON/core/view/version/")).get("version", ""))

    async def new_session(self) -> None:
        await self._get("/JSON/core/action/newSession/")

    async def new_context(self, name: str) -> str:
        return str((await self._get(
            "/JSON/context/action/newContext/", contextName=name
        )).get("contextId", ""))

    async def include_in_context(self, name: str, target: str) -> None:
        await self._get(
            "/JSON/context/action/includeInContext/",
            contextName=name, regex=_scope_regex(target),
        )

    async def remove_context(self, name: str) -> None:
        await self._get("/JSON/context/action/removeContext/", contextName=name)

    async def set_limits(self, *, spider_min: int, host_min: int) -> None:
        """Push the time caps to ZAP's own engine options (a secondary guard to the
        Python poll-deadline, which remains primary)."""
        await self._get("/JSON/spider/action/setOptionMaxDuration/", Integer=spider_min)
        await self._get("/JSON/ascan/action/setOptionMaxScanDurationInMins/", Integer=host_min)
        if self.cfg.ajax_spider:
            await self._get("/JSON/ajaxSpider/action/setOptionMaxDuration/", Integer=spider_min)

    # --- spider ----------------------------------------------------------------
    async def spider(self, target: str, context_name: str) -> str:
        return str((await self._get(
            "/JSON/spider/action/scan/", url=target, contextName=context_name, recurse="true"
        )).get("scan", ""))

    async def spider_status(self, scan_id: str) -> int:
        return int((await self._get("/JSON/spider/view/status/", scanId=scan_id)).get("status", 0))

    # --- ajax spider (optional) ------------------------------------------------
    async def ajax_spider(self, target: str, context_name: str) -> None:
        await self._get(
            "/JSON/ajaxSpider/action/scan/", url=target, contextName=context_name, inScope="true"
        )

    async def ajax_status(self) -> str:
        return str((await self._get("/JSON/ajaxSpider/view/status/")).get("status", "stopped"))

    # --- active scan -----------------------------------------------------------
    async def ascan(self, target: str, context_id: str) -> str:
        return str((await self._get(
            "/JSON/ascan/action/scan/",
            url=target, recurse="true", inScopeOnly="true",
            scanPolicyName=self.cfg.scan_policy or None, contextId=context_id or None,
        )).get("scan", ""))

    async def ascan_status(self, scan_id: str) -> int:
        return int((await self._get("/JSON/ascan/view/status/", scanId=scan_id)).get("status", 0))

    # --- alerts / report / stop ------------------------------------------------
    async def alerts(self, target: str) -> list[dict]:
        data = await self._get(
            "/JSON/alert/view/alerts/", baseurl=target, start=0, count=self.cfg.alert_cap
        )
        return list(data.get("alerts", []))

    async def json_report(self) -> bytes:
        try:
            r = await self._client.get("/OTHER/core/other/jsonreport/")
        except httpx.HTTPError as e:
            raise ZapError(f"zap HTTP error on json report: {e}") from e
        if r.status_code >= 400:
            raise ZapError(f"zap HTTP {r.status_code} on json report")
        return r.content

    async def stop_all(self) -> None:
        """Stop every running spider/ajax/active scan (cleanup + deadline path)."""
        for path in (
            "/JSON/spider/action/stopAllScans/",
            "/JSON/ascan/action/stopAllScans/",
            "/JSON/ajaxSpider/action/stop/",
        ):
            try:
                await self._get(path)
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass

    async def close(self) -> None:
        await self._client.aclose()


async def _poll_until(get_status, *, done, deadline: float, interval: float,
                      log: RunLogger, label: str) -> bool:
    """Poll `get_status()` until `done(status)` or `deadline` (monotonic). Returns
    True if it completed, False if the deadline was hit first. Transient poll
    errors are tolerated (treated as not-done) so one blip doesn't abort a scan."""
    while True:
        try:
            status = await get_status()
        except (ZapError, httpx.HTTPError) as e:
            log.debug(f"zap: status poll error for {label}: {e}")
            status = None
        if status is not None and done(status):
            return True
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(interval)


def alerts_to_findings(alerts: list[dict]) -> list[Finding]:
    """Group ZAP alert instances by (pluginId, host) into one Finding each.

    ZAP returns one row per instance (URL); we collapse them so the report shows
    one row per issue-class-per-host with the instance URLs listed in evidence —
    the same UX as nuclei. `check_id=zap.<pluginId>` drives Finding.group_key, so
    the same issue further collapses across hosts in the report.
    """
    groups: dict[tuple[str, str], list[dict]] = {}
    for a in alerts:
        plugin_id = str(a.get("pluginId") or a.get("pluginid") or "")
        host = _host_of(str(a.get("url", "")))
        groups.setdefault((plugin_id, host), []).append(a)

    findings: list[Finding] = []
    for (plugin_id, host), group in groups.items():
        rep = group[0]
        risk = str(rep.get("risk", ""))
        params = sorted({str(a.get("param")) for a in group if a.get("param")})
        findings.append(Finding(
            source="zap",
            host=host or None,
            severity=ZAP_RISK_TO_SEVERITY.get(risk, "info"),
            title=str(rep.get("alert") or rep.get("name") or f"ZAP plugin {plugin_id}"),
            description=str(rep.get("description", "")),
            check_id=f"zap.{plugin_id}" if plugin_id else None,
            evidence={
                "plugin_id": plugin_id,
                "risk": risk,
                "confidence": rep.get("confidence"),
                "cwe": rep.get("cweid"),
                "wasc": rep.get("wascid"),
                "solution": rep.get("solution"),
                "reference": rep.get("reference"),
                "instance_count": len(group),
                "instances": [a.get("url") for a in group][:50],
                "params": params,
            },
        ))
    return findings


async def _scan_target(
    client: ZapClient, target: str, context_name: str, context_id: str,
    cfg: ZapConfig, log: RunLogger, out_dir: Path, total_deadline: float,
) -> list[Finding]:
    """Spider + (optional ajax) + active-scan one target, then collect its alerts.
    Bounded by the per-host cap and the overall total deadline."""
    now = time.monotonic()
    host_deadline = min(now + cfg.max_minutes_per_host * 60, total_deadline)
    spider_deadline = min(now + cfg.spider_max_minutes * 60, host_deadline)

    log.info(f"zap: spidering {target}", event="zap_scan_started", target=target)
    spider_id = await client.spider(target, context_name)
    if not await _poll_until(
        lambda: client.spider_status(spider_id), done=lambda s: s >= 100,
        deadline=spider_deadline, interval=cfg.poll_interval_seconds,
        log=log, label=f"spider {target}",
    ):
        log.warn(f"zap: spider deadline hit for {target}", event="zap_timeout",
                 phase="spider", target=target)

    if cfg.ajax_spider:
        await client.ajax_spider(target, context_name)
        await _poll_until(
            client.ajax_status, done=lambda s: s != "running",
            deadline=spider_deadline, interval=cfg.poll_interval_seconds,
            log=log, label=f"ajax {target}",
        )

    log.info(f"zap: active scan {target}", event="zap_ascan_started", target=target)
    ascan_id = await client.ascan(target, context_id)
    if not await _poll_until(
        lambda: client.ascan_status(ascan_id), done=lambda s: s >= 100,
        deadline=host_deadline, interval=cfg.poll_interval_seconds,
        log=log, label=f"ascan {target}",
    ):
        log.warn(f"zap: active-scan deadline hit for {target} — partial results kept",
                 event="zap_timeout", phase="ascan", target=target)

    alerts = await client.alerts(target)
    host = _host_of(target) or target
    (out_dir / f"alerts-{host_to_filename(host)}.json").write_text(
        json.dumps(alerts, indent=2)
    )
    findings = alerts_to_findings(alerts)
    log.info(
        f"zap: {target} → {len(findings)} finding(s) from {len(alerts)} alert instance(s)",
        event="zap_done", target=target, findings=len(findings), alerts=len(alerts),
    )
    return findings


async def run_zap(
    targets: list[str],
    out_dir: Path,
    cfg: ZapConfig,
    log: RunLogger,
    *,
    run_id: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[list[Finding], list[tuple[str | None, str]]]:
    """Drive ZAP active scans for `targets` and return (findings, asset_errors).

    NEVER raises on a daemon/API error (degrades to asset_errors so the run
    continues). Re-raises `asyncio.CancelledError` after stopping scans + removing
    the context, so an aborted run leaves nothing live on the daemon.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    if not targets:
        return [], []

    client = ZapClient(cfg, log, transport=transport)
    context_name = f"wt-{run_id}"
    findings: list[Finding] = []
    errors: list[tuple[str | None, str]] = []
    total_deadline = time.monotonic() + cfg.max_minutes_total * 60

    try:
        # Reachability — a dead daemon degrades the capability, never the run.
        try:
            version = await client.version()
        except (ZapError, httpx.HTTPError) as e:
            log.warn(f"zap: daemon unreachable ({e}) — skipping capability",
                     event="zap_unreachable")
            return [], [(None, f"zap daemon unreachable: {e}")]
        log.info(f"zap: daemon v{version}, {len(targets)} target(s)",
                 event="zap_begin", targets=len(targets))

        try:
            await client.new_session()  # best-effort isolation
        except (ZapError, httpx.HTTPError):
            pass

        try:
            context_id = await client.new_context(context_name)
            for t in targets:
                await client.include_in_context(context_name, t)
            await client.set_limits(
                spider_min=cfg.spider_max_minutes, host_min=cfg.max_minutes_per_host
            )
        except (ZapError, httpx.HTTPError) as e:
            log.warn(f"zap: setup failed ({e}) — skipping", event="zap_setup_failed")
            return [], [(None, f"zap setup failed: {e}")]

        for t in targets:
            if time.monotonic() >= total_deadline:
                log.warn(f"zap: total time budget exhausted, skipping {t}",
                         event="zap_budget", target=t)
                errors.append((t, "skipped: overall ZAP time budget exhausted"))
                continue
            try:
                findings.extend(await _scan_target(
                    client, t, context_name, context_id, cfg, log, out_dir, total_deadline
                ))
            except (ZapError, httpx.HTTPError) as e:
                log.warn(f"zap: scan failed for {t} ({e})",
                         event="zap_target_error", target=t)
                errors.append((t, f"zap scan error: {e}"))

        try:
            (out_dir / "zap-report.json").write_bytes(await client.json_report())
        except (ZapError, httpx.HTTPError) as e:
            log.debug(f"zap: could not fetch json report ({e})")

        return findings, errors

    except asyncio.CancelledError:
        log.warn("zap: cancelled — stopping scans + removing context",
                 event="zap_cancelled")
        raise
    finally:
        # Always tear down so an aborted/finished run leaves nothing on the daemon.
        try:
            await client.stop_all()
        except Exception:  # noqa: BLE001
            pass
        try:
            await client.remove_context(context_name)
        except Exception:  # noqa: BLE001
            pass
        try:
            await client.close()
        except Exception:  # noqa: BLE001
            pass
