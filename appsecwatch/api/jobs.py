"""JobManager — the async heart of the Web API.

Owns a semaphore (max_concurrent_scans), a bounded queue (max_queue_depth), the
in-memory job index, the per-running-job live ScanState, and idempotency maps.
`runs/` is the durable record: every state transition rewrites `job.json`, and on
startup the index is rebuilt from disk (a job left `running` with no live task is
marked `interrupted`).

Concurrency model (WEB_API_PLAN §2.2): a single dispatcher loop pulls job ids
from the queue and, once a semaphore slot frees, launches `_run_job` as a task.
`_run_job` flips state queued→running, awaits the real runner with an injected
run_dir + shared ScanState (so progress is observable), then writes the terminal
state, a machine-readable `result.json`, and fires the optional webhook.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from appsecwatch.api.config import ServerConfig
from appsecwatch.api.models import TERMINAL_STATES, JobRecord, ScanRequest
from appsecwatch.api.result import (
    build_scan_result,
    count_findings,
    render_partial_report,
    write_scan_result,
)
from appsecwatch.api.security import send_webhook
from appsecwatch.config import AppSecWatchConfig
from appsecwatch.runner import make_run_dir, run_scan
from appsecwatch.stages.capabilities import SelectionError, resolve_selection

from pydantic import ValidationError
from appsecwatch.stages.state import ScanState

log = logging.getLogger("appsecwatch.api")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _elapsed_s(started_at: str | None, finished_at: str | None) -> float:
    if not started_at:
        return 0.0
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(finished_at) if finished_at else datetime.now(timezone.utc)
        return round(max(0.0, (end - start).total_seconds()), 1)
    except ValueError:
        return 0.0


def _fingerprint(req: ScanRequest) -> str:
    """Stable (roots + params) hash for in-flight dedupe (decision 14)."""
    payload = json.dumps(
        {
            "roots": sorted(req.roots or []),
            "only": sorted(req.only or []),
            "skip": sorted(req.skip or []),
            "throttle": req.throttle,
            "zap_targets": sorted(req.zap_targets or []),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _first_error(exc: ValidationError) -> str:
    """One-line summary of why the base scan config is invalid (for the 409)."""
    errs = exc.errors()
    if not errs:
        return "server not configured (set the scan config first)"
    e = errs[0]
    loc = ".".join(str(p) for p in e.get("loc", ()) if p != "roots")
    detail = f"{loc}: {e.get('msg')}" if loc else str(e.get("msg"))
    return f"server not configured — {detail} (set the scan config in the UI)"


class QueueFull(Exception):
    """Both the running slots and the queue are full → 429 Retry-After."""


class NotConfigured(Exception):
    """The base scan config is missing/invalid (e.g. UI-only boot before the
    operator set the llm endpoint) → 409 with the validation detail."""


class ZapRejected(Exception):
    """An opt-in ZAP active scan was requested but the safety gate refused it:
    daemon not enabled/configured, no targets, or targets out of scope → 409."""


class JobManager:
    def __init__(self, server: ServerConfig, asset_manager=None, history=None,
                 suppressions=None, nuclei_custom=None, finding_state=None,
                 search=None, notifier=None) -> None:
        self.server = server
        self.assets = asset_manager  # AssetManager | None (for recon→assets sync)
        self.history = history       # ScanHistory | None (scans index)
        self.suppressions = suppressions  # SuppressionManager | None
        self.nuclei_custom = nuclei_custom  # CustomTemplateManager | None
        self.finding_state = finding_state  # FindingStateManager | None (cross-scan lifecycle)
        self.search = search         # FTSIndex | None (all-in-one search)
        self.notifier = notifier     # Notifier | None (new-domain alerts)
        self.output_root = Path(server.output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.semaphore = asyncio.Semaphore(server.limits.max_concurrent_scans)
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.tasks: dict[str, asyncio.Task] = {}
        self.index: dict[str, JobRecord] = {}
        self.states: dict[str, ScanState] = {}
        self.run_dirs: dict[str, Path] = {}
        self.idempotency: dict[str, str] = {}
        self._dispatcher: asyncio.Task | None = None

    # ----- lifecycle ------------------------------------------------------- #
    async def start(self) -> None:
        self.reindex()
        self._dispatcher = asyncio.create_task(self._dispatch_loop())

    async def stop(self) -> None:
        if self._dispatcher:
            self._dispatcher.cancel()
        for task in list(self.tasks.values()):
            task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)
        if self._dispatcher:
            await asyncio.gather(self._dispatcher, return_exceptions=True)

    def reindex(self) -> None:
        """Rebuild the index from `runs/*/job.json`; orphaned running/queued →
        interrupted (WEB_API_PLAN §2.4)."""
        for jp in sorted(self.output_root.glob("*/job.json")):
            try:
                rec = JobRecord.model_validate_json(jp.read_text())
            except Exception as e:  # noqa: BLE001 — skip unreadable records
                log.warning("reindex: skipping %s (%r)", jp, e)
                continue
            if rec.state in ("running", "queued"):
                rec.state = "interrupted"
                rec.finished_at = rec.finished_at or _now_iso()
                rec.error = rec.error or "process restarted before completion"
                self._persist_to(jp.parent, rec)
            self.index[rec.id] = rec
            self.run_dirs[rec.id] = jp.parent
            if rec.idempotency_key:
                self.idempotency[rec.idempotency_key] = rec.id
        log.info("reindex complete: %d job(s) loaded", len(self.index))

    # ----- queries --------------------------------------------------------- #
    def get(self, job_id: str) -> JobRecord | None:
        return self.index.get(job_id)

    def list(
        self, *, state: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[JobRecord], int]:
        records = sorted(self.index.values(), key=lambda r: r.submitted_at, reverse=True)
        if state:
            records = [r for r in records if r.state == state]
        total = len(records)
        return records[offset : offset + limit], total

    def live_state(self, job_id: str) -> ScanState | None:
        return self.states.get(job_id)

    def run_dir(self, job_id: str) -> Path | None:
        return self.run_dirs.get(job_id)

    # ----- submit ---------------------------------------------------------- #
    def submit(
        self, req: ScanRequest, *, idempotency_key: str | None = None,
        source: str = "manual", schedule_id: str | None = None,
    ) -> tuple[JobRecord, bool]:
        """Create + enqueue a job. Returns (record, created). `created=False` when
        an idempotency hit or in-flight dedupe returned an existing job.

        Raises NotConfigured (→409), SelectionError (→422), QueueFull (→429).
        """
        # Idempotency-Key replay → same job.
        if idempotency_key and idempotency_key in self.idempotency:
            existing = self.index.get(self.idempotency[idempotency_key])
            if existing:
                return existing, False

        # Validate the capability selection up front (→ 422 before anything runs).
        only = set(req.only) if req.only else None
        skip = set(req.skip) if req.skip else None
        resolve_selection(only, skip)

        # Readiness gate: the merged scan config must validate (llm set; mmdb is
        # optional now — display-only ASN enrichment, no longer a scan gate).
        # On a UI-only boot before the operator configured anything, this is how a
        # scan is refused — there is no scan-target allowlist (roots is the scope).
        try:
            cfg = self._build_config(req.roots, req.throttle,
                                     zap_targets=req.zap_targets,
                                     zap_ajax_spider=req.zap_ajax_spider)
        except ValidationError as e:
            raise NotConfigured(_first_error(e))

        # Opt-in ZAP active-scan gate (→ 409): only when zap is selected. Enforces
        # the admin enable + in-scope-targets contract; /capabilities already hides
        # zap when disabled, this is the authoritative server-side check.
        if "zap" in (req.only or []):
            self._check_zap(cfg, req.zap_targets)

        # In-flight dedupe by (roots + params).
        fp = _fingerprint(req)
        for rec in self.index.values():
            if rec.params_fingerprint == fp and rec.state in ("queued", "running"):
                return rec, False

        # Backpressure: 429 only when BOTH the running slots and the queue are
        # full (decision 10). Count by record state, not queue.qsize(): the
        # dispatcher eagerly dequeues one id and blocks at the semaphore, so a
        # still-"queued" record may already be out of the asyncio queue.
        running = sum(1 for r in self.index.values() if r.state == "running")
        queued = sum(1 for r in self.index.values() if r.state == "queued")
        if (
            running >= self.server.limits.max_concurrent_scans
            and queued >= self.server.limits.max_queue_depth
        ):
            raise QueueFull

        run_dir = self._reserve_run_dir(req)
        job_id = run_dir.name
        record = JobRecord(
            id=job_id,
            state="queued",
            roots=req.roots,
            group=req.group,
            only=req.only,
            skip=req.skip,
            throttle=req.throttle,
            profile_render=req.profile_render,
            zap_targets=req.zap_targets,
            zap_ajax_spider=req.zap_ajax_spider,
            compress=req.compress,
            source=source,
            schedule_id=schedule_id,
            submitted_at=_now_iso(),
            callback_url=req.callback_url,
            idempotency_key=idempotency_key,
            params_fingerprint=fp,
        )
        self.index[job_id] = record
        self.run_dirs[job_id] = run_dir
        if idempotency_key:
            self.idempotency[idempotency_key] = job_id
        self._persist(record)
        self.queue.put_nowait(job_id)
        log.info("job queued: %s", job_id)
        return record, True

    def _reserve_run_dir(self, req: ScanRequest) -> Path:
        return make_run_dir(self.output_root, list(req.roots or []))

    # ----- cancel ---------------------------------------------------------- #
    async def cancel(self, job_id: str) -> JobRecord | None:
        rec = self.index.get(job_id)
        if rec is None:
            return None
        if rec.state in TERMINAL_STATES:
            return rec  # caller maps "already terminal" → 409
        if rec.state == "queued":
            # The dispatcher skips any non-queued record when it dequeues it.
            rec.state = "cancelled"
            rec.finished_at = _now_iso()
            self._persist(rec)
            log.info("job cancelled (was queued): %s", job_id)
            return rec
        # running → cancel the task; _run_job renders the partial + writes terminal.
        task = self.tasks.get(job_id)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return self.index.get(job_id)

    # ----- dispatcher + execution ----------------------------------------- #
    async def _dispatch_loop(self) -> None:
        while True:
            job_id = await self.queue.get()
            rec = self.index.get(job_id)
            if rec is None or rec.state != "queued":
                self.queue.task_done()
                continue  # cancelled-while-queued, or vanished
            await self.semaphore.acquire()
            # Re-check after the (possibly long) wait for a slot.
            rec = self.index.get(job_id)
            if rec is None or rec.state != "queued":
                self.semaphore.release()
                self.queue.task_done()
                continue
            task = asyncio.create_task(self._run_job(job_id))
            self.tasks[job_id] = task
            self.queue.task_done()

    async def _run_job(self, job_id: str) -> None:
        rec = self.index[job_id]
        run_dir = self.run_dirs[job_id]
        state = ScanState()
        self.states[job_id] = state
        rec.state = "running"
        rec.started_at = _now_iso()
        self._persist(rec)
        log.info("job running: %s", job_id)

        only = set(rec.only) if rec.only else None
        skip = set(rec.skip) if rec.skip else None
        try:
            supp = None
            if self.suppressions is not None:
                try:
                    supp = await asyncio.to_thread(self.suppressions.fingerprints)
                except Exception as e:  # noqa: BLE001
                    log.warning("suppression load failed for %s: %r", job_id, e)
            # Cross-scan report data (report note + exec risk-trend chart). Scoped
            # to this scan's target so the note reflects the same estate; best-effort.
            prior_open: set[str] | None = None
            report_history: list[dict] | None = None
            if self.finding_state is not None:
                try:
                    prior_open = await asyncio.to_thread(
                        self.finding_state.open_fingerprints,
                        group=rec.group, roots=rec.roots,
                    )
                except Exception as e:  # noqa: BLE001
                    log.warning("prior-open load failed for %s: %r", job_id, e)
            if self.history is not None:
                try:
                    report_history = await asyncio.to_thread(
                        self.history.trends, rec.group, 30
                    )
                except Exception as e:  # noqa: BLE001
                    log.warning("trend history load failed for %s: %r", job_id, e)
            cfg = self._merged_config(rec)
            # Materialize enabled custom nuclei templates into the run dir + add to -t.
            if self.nuclei_custom is not None:
                try:
                    cdir = await asyncio.to_thread(
                        self.nuclei_custom.materialize_enabled, run_dir / "custom-templates"
                    )
                    if cdir:
                        cfg.tools.nuclei.templates = list(cfg.tools.nuclei.templates) + [cdir]
                except Exception as e:  # noqa: BLE001
                    log.warning("custom-template materialize failed for %s: %r", job_id, e)
            await run_scan(
                cfg, self.output_root, "quiet", False,
                compress=rec.compress, only=only, skip=skip,
                run_dir=run_dir, state=state, suppressions=supp,
                prior_open=prior_open, report_history=report_history,
            )
            rec.state = "completed"
            await self._sync_assets(rec, state)
            await self._sync_finding_state(rec, state)
            self._finish(rec, run_dir, state)
            await self._fire_webhook(rec)
        except asyncio.CancelledError:
            rec.state = "cancelled"
            log.info("job cancelled (was running): %s", job_id)
            await self._render_partial(rec, run_dir, state)
            self._finish(rec, run_dir, state)
            await self._fire_webhook(rec)
            raise  # let the awaiting cancel() observe the cancellation
        except Exception as e:  # noqa: BLE001 — bootstrap/render failure
            rec.state = "failed"
            rec.error = str(e)
            log.warning("job failed: %s (%r)", job_id, e)
            self._finish(rec, run_dir, state)
            await self._fire_webhook(rec)
        finally:
            self.semaphore.release()
            self.tasks.pop(job_id, None)

    def _build_config(self, roots, throttle, profile_render=None,
                      zap_targets=None, zap_ajax_spider=None) -> AppSecWatchConfig:
        """Merge per-request params over the live base config + validate. Raises
        ValidationError when the base config is missing/invalid (→ NotConfigured).
        Re-validating re-applies the throttle profile cleanly (config._apply_throttle
        only fills fields the operator did not set)."""
        raw = dict(self.server.base_config_raw)
        raw["roots"] = list(roots or [])
        if throttle:
            raw["throttle"] = throttle
        if profile_render:
            ai = dict(raw.get("ai") or {})
            ai["profile"] = {**dict(ai.get("profile") or {}), "render": profile_render}
            raw["ai"] = ai
        # Per-request zap overrides ride on cfg.zap.* so the (cfg, plan)-built
        # ZapStage reads them without a stage-factory signature change. ajax_spider
        # is a nullable override (None = use the server-config default).
        zap_over: dict = {}
        if zap_targets:
            zap_over["targets"] = list(zap_targets)
        if zap_ajax_spider is not None:
            zap_over["ajax_spider"] = zap_ajax_spider
        if zap_over:
            raw["zap"] = {**dict(raw.get("zap") or {}), **zap_over}
        return AppSecWatchConfig.model_validate(raw)

    def _merged_config(self, rec: JobRecord) -> AppSecWatchConfig:
        return self._build_config(rec.roots, rec.throttle, rec.profile_render,
                                  zap_targets=rec.zap_targets,
                                  zap_ajax_spider=rec.zap_ajax_spider)

    @staticmethod
    def _check_zap(cfg: AppSecWatchConfig, zap_targets: list[str]) -> None:
        """Authoritative ZAP active-scan gate (→ ZapRejected → 409): the daemon must
        be enabled + configured, and every target must be in scope (under a scan
        root). Mirrors the defense-in-depth filter in ZapStage."""
        if not (cfg.zap.enabled and cfg.zap.base_url):
            raise ZapRejected("zap active scan is not enabled/configured on this server")
        if not zap_targets:
            raise ZapRejected("zap selected but no zap_targets provided")
        from urllib.parse import urlparse

        from appsecwatch.util.domains import under_any_root
        oos = [
            t for t in zap_targets
            if not under_any_root(
                urlparse(t if "://" in t else f"//{t}").hostname or t, cfg.roots)
        ]
        if oos:
            raise ZapRejected(
                f"zap_targets out of scope (not under the scan roots): {', '.join(oos)}")

    async def _sync_assets(self, rec: JobRecord, state: ScanState) -> None:
        """Write discovered (triaged) assets back into the inventory. Best-effort:
        a sync failure must never fail the scan."""
        if self.assets is None or not state.triaged:
            return
        # Merge per-host tech: httpx (-tech-detect on live servers) + AI (profile).
        from appsecwatch.audit.tech import merge_tech
        tech_by_host: dict[str, list[dict]] = {}
        profile_by_host: dict[str, dict] = {}
        for s in state.live_servers:
            ai_tech = []
            prof = state.app_profiles.get(s.host)
            if prof is not None:
                ai_tech = getattr(prof, "detected_tech", []) or []
                if getattr(prof, "usable", False):
                    profile_by_host[s.host] = prof.model_dump()
            merged = merge_tech(s.tech, ai_tech)
            if merged:
                tech_by_host[s.host] = merged
        # Per-asset finding counts (visible only). Seed every scanned host at 0 so a
        # re-scan that clears findings also clears stale counts.
        sev0 = lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        finding_counts: dict[str, dict] = {s.host: sev0() for s in state.live_servers}
        for f in state.all_findings():
            if f.host and not f.suppressed:
                finding_counts.setdefault(f.host, sev0())
                if f.severity in finding_counts[f.host]:
                    finding_counts[f.host][f.severity] += 1
        # Curated EASM surface (names only) from the crawler capture, for the hosts
        # that were crawled (full scan or render=always).
        from appsecwatch.audit.surface import curated_surface
        surface_by_host: dict[str, dict] = {
            a.host: curated_surface(a) for a in state.crawler_artifacts
        }
        # Fold in the per-host JS-library inventory (URL + in-memory content scan)
        # so the asset tech list reflects detected libraries too (dedup by name).
        try:
            from appsecwatch.audit.js_libs import library_inventory
            for host, libs in library_inventory(state.crawler_artifacts).items():
                existing = tech_by_host.get(host, [])
                names = {t["name"].lower() for t in existing}
                for x in libs:
                    label = f"{x['name']} {x['version']}".strip()
                    if label.lower() not in names:
                        existing.append({"name": label, "source": "js_lib"})
                        names.add(label.lower())
                if existing:
                    tech_by_host[host] = existing
        except Exception as e:  # noqa: BLE001
            log.warning("js-lib inventory merge failed for %s: %r", rec.id, e)
        try:
            n, new_fqdns = await asyncio.to_thread(
                self.assets.sync_discovered, state.triaged, rec.roots or [], rec.id,
                rec.group, tech_by_host, profile_by_host, finding_counts,
                surface_by_host,
            )
            log.info("assets sync: %s upserted from %s (%s new)", n, rec.id, len(new_fqdns))
            await self._notify_new_domains(rec, new_fqdns)
            await self._sync_search(rec, state)
        except Exception as e:  # noqa: BLE001
            log.warning("assets sync failed for %s: %r", rec.id, e)

    async def _notify_new_domains(self, rec: JobRecord, new_fqdns: list[str]) -> None:
        """Fire a 'new domain discovered' notification (in-app + configured channels)
        when recon surfaced FQDNs never seen before. Best-effort."""
        if not new_fqdns or self.notifier is None:
            return
        from appsecwatch.api.notify import Event
        preview = ", ".join(new_fqdns[:20]) + (" …" if len(new_fqdns) > 20 else "")
        try:
            await self.notifier.dispatch(Event(
                type="asset.new",
                title=f"{len(new_fqdns)} new domain(s) discovered",
                body=preview,
                payload={"fqdns": new_fqdns, "count": len(new_fqdns)},
                group=rec.group, scan_id=rec.id,
            ))
        except Exception as e:  # noqa: BLE001
            log.warning("new-domain notify failed for %s: %r", rec.id, e)

    async def _sync_search(self, rec: JobRecord, state: ScanState) -> None:
        """Reindex the scanned assets + their visible findings into the FTS index."""
        if self.search is None or self.assets is None:
            return
        try:
            def _reindex() -> None:
                for s in state.live_servers:
                    row = self.assets.get(s.host)
                    if row:
                        self.search.reindex_asset(row)
                visible = [f for f in state.all_findings() if not f.suppressed]
                hosts = {s.host for s in state.live_servers} | {f.host for f in visible if f.host}
                self.search.index_findings(rec.id, visible, hosts)
            await asyncio.to_thread(_reindex)
        except Exception as e:  # noqa: BLE001
            log.warning("search reindex failed for %s: %r", rec.id, e)

    async def _sync_finding_state(self, rec: JobRecord, state: ScanState) -> None:
        """Update the unified cross-scan finding-state and record the per-scan diff
        (new/recurring/resolved) on the JobRecord. Best-effort."""
        if self.finding_state is None:
            return
        try:
            from appsecwatch.audit.taxonomy import classify_findings
            current = state.all_findings()
            classify_findings(current)  # idempotent; ensures class/category set
            scanned_hosts = ({s.host for s in state.live_servers}
                             | {a.fqdn for a in state.triaged}
                             | {f.host for f in current if f.host})
            diff = await asyncio.to_thread(
                self.finding_state.sync, current,
                scanned_hosts=scanned_hosts, coverage=state.coverage,
                group=rec.group, scan_id=rec.id,
            )
            rec.diff = diff
            log.info("finding-state sync %s: %s", rec.id, diff)
        except Exception as e:  # noqa: BLE001
            log.warning("finding-state sync failed for %s: %r", rec.id, e)

    async def _render_partial(
        self, rec: JobRecord, run_dir: Path, state: ScanState
    ) -> None:
        try:
            cfg = self._merged_config(rec)
            meta_roots = rec.roots or []
            run_meta = {
                "label": rec.id,
                "roots": meta_roots,
                "started_at": rec.started_at,
                "finished_at": "",
                "duration": "",
            }
            versions = self._load_versions(run_dir)
            await render_partial_report(
                state, run_dir, run_meta=run_meta, versions=versions, cfg=cfg
            )
        except Exception as e:  # noqa: BLE001 — partial render is best-effort
            log.warning("partial report render failed for %s: %r", rec.id, e)

    @staticmethod
    def _load_versions(run_dir: Path) -> dict:
        try:
            return json.loads((run_dir / "versions.json").read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def _finish(self, rec: JobRecord, run_dir: Path, state: ScanState) -> None:
        """Persist terminal state + write the machine-readable result.json."""
        rec.finished_at = rec.finished_at or _now_iso()
        rec.current_stage = None
        rec.completed_stages = list(state.completed_stages)
        rec.coverage = state.coverage or rec.coverage
        rec.finding_count = count_findings(state)
        rec.degraded = state.degraded
        try:
            # The executive HTML is always written by ReportStage; expose the PDF
            # URL only when the (best-effort) PDF actually landed.
            exec_pdf_url = (
                f"/scans/{rec.id}/executive.pdf"
                if (run_dir / "executive.pdf").is_file() else None
            )
            result = build_scan_result(
                rec.id, state,
                report_url=f"/scans/{rec.id}/report", job_state=rec.state,
                executive_url=f"/scans/{rec.id}/executive",
                executive_pdf_url=exec_pdf_url,
            )
            result["diff"] = rec.diff   # cross-scan new/recurring/resolved (may be None)
            write_scan_result(run_dir, result)
        except Exception as e:  # noqa: BLE001
            log.warning("result.json write failed for %s: %r", rec.id, e)
        if self.history is not None:
            try:
                from appsecwatch.report.aggregator import risk_score, severity_histogram
                visible = [f for f in state.all_findings() if not f.suppressed]
                hist = severity_histogram(visible)
                by_sev = {sev: sum(by.values()) for sev, by in hist.items()}
                self.history.record(
                    rec, rec.finding_count,
                    by_severity=by_sev, risk_score=risk_score(by_sev),
                )
            except Exception as e:  # noqa: BLE001
                log.warning("scans-history record failed for %s: %r", rec.id, e)
        self._persist(rec)
        self.states.pop(rec.id, None)

    async def _fire_webhook(self, rec: JobRecord) -> None:
        if not rec.callback_url:
            return
        event = {
            "completed": "scan.completed",
            "failed": "scan.failed",
            "cancelled": "scan.cancelled",
        }.get(rec.state, "scan.completed")
        payload = {
            "id": rec.id,
            "state": rec.state,
            "finished_at": rec.finished_at,
            "finding_count": rec.finding_count,
            "result_url": f"/scans/{rec.id}/result",
            "report_url": f"/scans/{rec.id}/report",
            "executive_url": f"/scans/{rec.id}/executive",
        }
        await send_webhook(self.server, rec.callback_url, event, payload)

    # ----- persistence ----------------------------------------------------- #
    def _persist(self, rec: JobRecord) -> None:
        self._persist_to(self.run_dirs[rec.id], rec)

    @staticmethod
    def _persist_to(run_dir: Path, rec: JobRecord) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "job.json").write_text(rec.model_dump_json(indent=2))
