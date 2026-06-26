"""FastAPI app factory + routes + lifespan.

Two run modes:
  * `create_app` — standalone API (routes at root). Used by `watchtower serve`
    when no UI build is present, and by the tests.
  * `create_combined_app` — single-image deploy: the API is mounted under `/api`
    and the built Next.js UI (static export) is served at `/`. Same origin, so
    no CORS and no baked API URL; the `/scans` page and `GET /api/scans` no
    longer collide.

Every error is returned as a consistent `{"error": {code, message}}` envelope.
All routes require an API key except `GET /healthz`.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.staticfiles import StaticFiles

from watchtower import __version__
from watchtower.api.assets import AssetManager
from watchtower.api.auth import require_api_key
from watchtower.api.config import ConfigError, ConfigManager, ServerConfig
from watchtower.api.db import Database, default_db_path
from watchtower.api.history import ScanHistory
from watchtower.api.jobs import JobManager, NotConfigured, QueueFull
from watchtower.api.nuclei_catalog import NucleiCatalog, default_templates_dir
from watchtower.api.nuclei_custom import CustomTemplateManager
from watchtower.api.scan_templates import ScanTemplateManager
from watchtower.api.scheduler import ScheduleManager
from watchtower.api.suppressions import SuppressionManager
from watchtower.api.models import (
    TERMINAL_STATES,
    Asset,
    AssetBulkRequest,
    AssetGroup,
    AssetImportResult,
    AssetUpsert,
    ReevaluateResult,
    ConfigUpdate,
    ConfigView,
    JobLinks,
    JobList,
    JobRecord,
    JobStatus,
    CustomTemplate,
    CustomTemplateUpsert,
    GenerateRequest,
    GenerateResponse,
    NucleiCategory,
    NucleiTemplate,
    PromptPreview,
    PromptPreviewRequest,
    PromptSlot,
    PromptUpdate,
    PromptsView,
    ScanRequest,
    ScanTemplate,
    ScanTemplateUpsert,
    Schedule,
    ScheduleUpsert,
    Suppression,
    SuppressionCreate,
    error_response,
)
from watchtower.api.result import count_findings, load_scan_result
from watchtower.ai.prompts import PROMPT_SLOTS, assemble_preview
from watchtower.stages.capabilities import ALL_TOKENS, SUBTOKENS, SelectionError

log = logging.getLogger("watchtower.api")

_STATUS_CODE_NAMES = {
    400: "bad_request", 401: "unauthorized", 403: "forbidden",
    404: "not_found", 409: "conflict", 422: "unprocessable", 429: "rate_limited",
}


class _AssetImport(BaseModel):
    csv: str


def _links(job_id: str) -> JobLinks:
    base = f"/scans/{job_id}"
    return JobLinks(
        self=base, result=f"{base}/result", report=f"{base}/report",
        log=f"{base}/log", cancel=f"{base}/cancel",
    )


def _elapsed_for(rec: JobRecord) -> float:
    from watchtower.api.jobs import _elapsed_s

    return _elapsed_s(rec.started_at, rec.finished_at)


def _to_status(manager: JobManager, rec: JobRecord) -> JobStatus:
    """Project a JobRecord to the wire shape, overlaying live progress for a
    running job from its in-memory ScanState."""
    current_stage = rec.current_stage
    completed = rec.completed_stages
    finding_count = rec.finding_count
    state = manager.live_state(rec.id)
    if state is not None and rec.state == "running":
        current_stage = state.current_stage
        completed = list(state.completed_stages)
        finding_count = count_findings(state)
    return JobStatus(
        id=rec.id, state=rec.state, roots=rec.roots, group=rec.group,
        only=rec.only, skip=rec.skip, throttle=rec.throttle,
        submitted_at=rec.submitted_at, started_at=rec.started_at,
        finished_at=rec.finished_at, current_stage=current_stage,
        completed_stages=completed,
        elapsed_s=_elapsed_for(rec), finding_count=finding_count,
        source=rec.source, schedule_id=rec.schedule_id,
        coverage=rec.coverage, error=rec.error, links=_links(rec.id),
    )


def _summarize_validation(exc: RequestValidationError) -> str:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", []) if p != "body")
        parts.append(f"{loc}: {err.get('msg')}" if loc else str(err.get("msg")))
    return "; ".join(parts) or "validation failed"


def _summarize_pydantic(exc: ValidationError) -> str:
    """Flatten a WatchTowerConfig validation failure into one line for the envelope."""
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", []))
        parts.append(f"{loc}: {err.get('msg')}" if loc else str(err.get("msg")))
    return "invalid scan config — " + ("; ".join(parts) or "validation failed")


def _build_prompts_view(overrides: dict) -> PromptsView:
    """Merge the built-in PROMPT_SLOTS registry with the current overrides."""
    slots = []
    for sid, meta in PROMPT_SLOTS.items():
        raw = overrides.get(sid)
        ovr = raw if (isinstance(raw, str) and raw.strip()) else None
        slots.append(PromptSlot(
            id=sid, label=meta["label"], description=meta["description"],
            default_text=meta["default_text"], override=ovr,
            modified=ovr is not None,
            effective=ovr if ovr is not None else meta["default_text"],
        ))
    return PromptsView(slots=slots)


def _install(app: FastAPI, config: ServerConfig) -> None:
    """Attach CORS, error handlers, and all routes to `app`. Reused by the
    standalone app and the mounted /api sub-app (handlers read state off the app
    they run on, so both modes work unchanged)."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(HTTPException)
    async def _http_exc(request: Request, exc: HTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            content = detail
        else:
            code = _STATUS_CODE_NAMES.get(exc.status_code, "error")
            content = error_response(code, str(detail))
        return JSONResponse(status_code=exc.status_code, content=content, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_response("validation_error", _summarize_validation(exc)),
        )

    def manager(request: Request) -> JobManager:
        return request.app.state.manager

    def config_manager(request: Request) -> ConfigManager:
        return request.app.state.config_manager

    def assets_mgr(request: Request) -> AssetManager:
        return request.app.state.assets

    def scheduler(request: Request) -> ScheduleManager:
        return request.app.state.scheduler

    def suppressions_mgr(request: Request) -> SuppressionManager:
        return request.app.state.suppressions

    def catalog_mgr(request: Request) -> NucleiCatalog:
        return request.app.state.catalog

    def custom_mgr(request: Request) -> CustomTemplateManager:
        return request.app.state.custom_templates

    def scan_tpl_mgr(request: Request) -> ScanTemplateManager:
        return request.app.state.scan_templates

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/config", dependencies=[Depends(require_api_key)])
    async def get_config(request: Request) -> ConfigView:
        return ConfigView(**config_manager(request).effective())

    @app.put("/config", dependencies=[Depends(require_api_key)])
    async def put_config(body: ConfigUpdate, request: Request) -> ConfigView:
        cm = config_manager(request)
        raw = manager(request).server.base_config_raw
        old_ranges = (raw.get("sanctioned_cidrs"), raw.get("sanctioned_asns"))
        try:
            view = ConfigView(**cm.update(body.base_config))
        except ConfigError as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                error_response("validation_error", str(e)),
            )
        except ValidationError as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                error_response("validation_error", _summarize_pydantic(e)),
            )
        # Auto re-evaluate asset buckets when the sanctioned ranges changed.
        new_ranges = (raw.get("sanctioned_cidrs"), raw.get("sanctioned_asns"))
        if new_ranges != old_ranges and raw.get("mmdb_path"):
            try:
                await asyncio.to_thread(
                    assets_mgr(request).reevaluate,
                    mmdb_path=raw["mmdb_path"],
                    sanctioned_cidrs=raw.get("sanctioned_cidrs") or [],
                    sanctioned_asns=raw.get("sanctioned_asns") or [],
                )
            except Exception as e:  # noqa: BLE001 — never fail the config save on re-eval
                log.warning("auto re-evaluate failed: %r", e)
        return view

    # ----- AI prompts (editable system-prompt registry) ------------------- #
    @app.get("/prompts", dependencies=[Depends(require_api_key)])
    async def list_prompts(request: Request) -> PromptsView:
        return _build_prompts_view(config_manager(request).prompt_overrides())

    @app.put("/prompts/{slot_id}", dependencies=[Depends(require_api_key)])
    async def put_prompt(slot_id: str, body: PromptUpdate, request: Request) -> PromptsView:
        if slot_id not in PROMPT_SLOTS:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                error_response("not_found", f"no such prompt slot: {slot_id}"),
            )
        cm = config_manager(request)
        overrides = dict(cm.prompt_overrides())
        text = (body.text or "").strip()
        if text:
            overrides[slot_id] = text
        else:
            overrides.pop(slot_id, None)   # blank → revert to built-in default
        cm.set_prompt_overrides(overrides)
        return _build_prompts_view(cm.prompt_overrides())

    @app.post("/prompts/{slot_id}/preview", dependencies=[Depends(require_api_key)])
    async def preview_prompt(
        slot_id: str, body: PromptPreviewRequest, request: Request
    ) -> PromptPreview:
        if slot_id not in PROMPT_SLOTS:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                error_response("not_found", f"no such prompt slot: {slot_id}"),
            )
        text = body.text if (body.text and body.text.strip()) \
            else PROMPT_SLOTS[slot_id]["default_text"]
        system, user = assemble_preview(slot_id, text)
        return PromptPreview(system=system, user=user)

    # ----- assets inventory ----------------------------------------------- #
    @app.get("/assets", dependencies=[Depends(require_api_key)])
    async def list_assets(
        request: Request,
        group: str | None = Query(default=None),
        bucket: str | None = Query(default=None),
        source: str | None = Query(default=None),
        q: str | None = Query(default=None),
    ) -> list[Asset]:
        rows = await asyncio.to_thread(
            assets_mgr(request).list, group=group, bucket=bucket, source=source, q=q
        )
        return [Asset(**r) for r in rows]

    @app.get("/assets/groups", dependencies=[Depends(require_api_key)])
    async def list_asset_groups(request: Request) -> list[AssetGroup]:
        rows = await asyncio.to_thread(assets_mgr(request).groups)
        return [AssetGroup(**r) for r in rows]

    @app.post("/assets", status_code=status.HTTP_201_CREATED,
              dependencies=[Depends(require_api_key)])
    async def add_asset(body: AssetUpsert, request: Request) -> Asset:
        am = assets_mgr(request)
        try:
            await asyncio.to_thread(am.upsert_imported, body.fqdn, body.group, body.notes)
        except ValueError as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, error_response("invalid_asset", str(e))
            )
        return Asset(**(await asyncio.to_thread(am.get, body.fqdn)))

    @app.put("/assets/{fqdn}", dependencies=[Depends(require_api_key)])
    async def update_asset(fqdn: str, body: AssetUpsert, request: Request) -> Asset:
        am = assets_mgr(request)
        try:
            await asyncio.to_thread(am.upsert_imported, fqdn, body.group, body.notes)
        except ValueError as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, error_response("invalid_asset", str(e))
            )
        a = await asyncio.to_thread(am.get, fqdn)
        if a is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such asset"))
        return Asset(**a)

    @app.delete("/assets/{fqdn}", dependencies=[Depends(require_api_key)])
    async def delete_asset(fqdn: str, request: Request):
        if not await asyncio.to_thread(assets_mgr(request).delete, fqdn):
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such asset"))
        return {"deleted": fqdn}

    @app.post("/assets/import", dependencies=[Depends(require_api_key)])
    async def import_assets(body: _AssetImport, request: Request) -> AssetImportResult:
        res = await asyncio.to_thread(assets_mgr(request).import_csv, body.csv)
        return AssetImportResult(**res)

    @app.post("/assets/bulk", dependencies=[Depends(require_api_key)])
    async def bulk_assets(body: AssetBulkRequest, request: Request):
        am = assets_mgr(request)
        filt = body.filter.model_dump() if body.filter else None
        if body.action == "delete":
            n = await asyncio.to_thread(am.bulk_delete, fqdns=body.fqdns, filter=filt)
        else:  # set_group
            n = await asyncio.to_thread(
                am.bulk_set_group, group=body.group, fqdns=body.fqdns, filter=filt
            )
        return {"affected": n}

    @app.post("/assets/reevaluate", dependencies=[Depends(require_api_key)])
    async def reevaluate_assets(request: Request) -> ReevaluateResult:
        raw = manager(request).server.base_config_raw
        mmdb = raw.get("mmdb_path")
        if not mmdb:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                error_response("not_configured", "mmdb_path not set (needed to re-evaluate)"),
            )
        res = await asyncio.to_thread(
            assets_mgr(request).reevaluate,
            mmdb_path=mmdb,
            sanctioned_cidrs=raw.get("sanctioned_cidrs") or [],
            sanctioned_asns=raw.get("sanctioned_asns") or [],
        )
        return ReevaluateResult(**res)

    @app.get("/assets/{fqdn}/findings", dependencies=[Depends(require_api_key)])
    async def asset_findings(fqdn: str, request: Request):
        """Visible findings for this asset from its last scan (host=fqdn)."""
        a = await asyncio.to_thread(assets_mgr(request).get, fqdn)
        if not a or not a.get("last_scan_id"):
            return []
        run_dir = Path(config.output_root) / a["last_scan_id"]
        res = await asyncio.to_thread(load_scan_result, run_dir)
        if not res:
            return []
        host = fqdn.lower().rstrip(".")
        return [
            f for f in res.get("findings", [])
            if (f.get("host") or "").lower() == host
            and not ((f.get("ai_verdict") or {}).get("suppressed"))
        ]

    # ----- schedules ------------------------------------------------------ #
    @app.get("/schedules", dependencies=[Depends(require_api_key)])
    async def list_schedules(request: Request) -> list[Schedule]:
        rows = await asyncio.to_thread(scheduler(request).list)
        return [Schedule(**r) for r in rows]

    @app.post("/schedules", status_code=status.HTTP_201_CREATED,
              dependencies=[Depends(require_api_key)])
    async def create_schedule(body: ScheduleUpsert, request: Request) -> Schedule:
        try:
            row = await asyncio.to_thread(scheduler(request).create, body.model_dump())
        except ValueError as e:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                error_response("invalid_schedule", str(e)))
        return Schedule(**row)

    @app.put("/schedules/{sid}", dependencies=[Depends(require_api_key)])
    async def update_schedule(sid: str, body: ScheduleUpsert, request: Request) -> Schedule:
        try:
            row = await asyncio.to_thread(scheduler(request).update, sid, body.model_dump())
        except ValueError as e:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                error_response("invalid_schedule", str(e)))
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such schedule"))
        return Schedule(**row)

    @app.delete("/schedules/{sid}", dependencies=[Depends(require_api_key)])
    async def delete_schedule(sid: str, request: Request):
        if not await asyncio.to_thread(scheduler(request).delete, sid):
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such schedule"))
        return {"deleted": sid}

    # ----- suppressions --------------------------------------------------- #
    @app.get("/suppressions", dependencies=[Depends(require_api_key)])
    async def list_suppressions(request: Request) -> list[Suppression]:
        rows = await asyncio.to_thread(suppressions_mgr(request).list)
        return [Suppression(**r) for r in rows]

    @app.post("/suppressions", status_code=status.HTTP_201_CREATED,
              dependencies=[Depends(require_api_key)])
    async def add_suppression(body: SuppressionCreate, request: Request) -> Suppression:
        row = await asyncio.to_thread(
            suppressions_mgr(request).add,
            source=body.source, host=body.host, key=body.key,
            scope=body.scope, reason=body.reason,
        )
        return Suppression(**row)

    @app.delete("/suppressions/{fingerprint:path}", dependencies=[Depends(require_api_key)])
    async def delete_suppression(fingerprint: str, request: Request):
        if not await asyncio.to_thread(suppressions_mgr(request).delete, fingerprint):
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such suppression"))
        return {"deleted": fingerprint}

    # ----- nuclei template catalog ---------------------------------------- #
    @app.get("/nuclei/templates", dependencies=[Depends(require_api_key)])
    async def nuclei_templates(
        request: Request,
        q: str | None = Query(default=None),
        category: str | None = Query(default=None),
        tag: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        source: str | None = Query(default=None),
        limit: int = Query(default=200),
    ) -> list[NucleiTemplate]:
        rows = await asyncio.to_thread(
            catalog_mgr(request).search, q=q, category=category, tag=tag,
            severity=severity, source=source, limit=limit,
        )
        return [NucleiTemplate(**r) for r in rows]

    @app.get("/nuclei/categories", dependencies=[Depends(require_api_key)])
    async def nuclei_categories(request: Request) -> list[NucleiCategory]:
        rows = await asyncio.to_thread(catalog_mgr(request).categories)
        return [NucleiCategory(**r) for r in rows]

    @app.post("/nuclei/reindex", dependencies=[Depends(require_api_key)])
    async def nuclei_reindex(request: Request):
        root = default_templates_dir()
        if root is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                error_response("no_templates", "nuclei-templates dir not found (set NUCLEI_TEMPLATES_DIR)"),
            )
        n = await asyncio.to_thread(catalog_mgr(request).index, root)
        return {"indexed": n, "root": str(root)}

    # ----- custom nuclei templates ---------------------------------------- #
    @app.get("/nuclei/custom", dependencies=[Depends(require_api_key)])
    async def list_custom(request: Request) -> list[CustomTemplate]:
        rows = await asyncio.to_thread(custom_mgr(request).list)
        return [CustomTemplate(**r) for r in rows]

    @app.post("/nuclei/custom", status_code=status.HTTP_201_CREATED,
              dependencies=[Depends(require_api_key)])
    async def create_custom(body: CustomTemplateUpsert, request: Request) -> CustomTemplate:
        row = await asyncio.to_thread(
            custom_mgr(request).create, name=body.name, yaml_text=body.yaml, enabled=body.enabled
        )
        return CustomTemplate(**row)

    @app.put("/nuclei/custom/{tid}", dependencies=[Depends(require_api_key)])
    async def update_custom(tid: str, body: CustomTemplateUpsert, request: Request) -> CustomTemplate:
        row = await asyncio.to_thread(
            custom_mgr(request).update, tid, name=body.name, yaml_text=body.yaml, enabled=body.enabled
        )
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such template"))
        return CustomTemplate(**row)

    @app.delete("/nuclei/custom/{tid}", dependencies=[Depends(require_api_key)])
    async def delete_custom(tid: str, request: Request):
        if not await asyncio.to_thread(custom_mgr(request).delete, tid):
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such template"))
        return {"deleted": tid}

    @app.post("/nuclei/custom/generate", dependencies=[Depends(require_api_key)])
    async def generate_custom(body: GenerateRequest, request: Request) -> GenerateResponse:
        from watchtower.config import LLMConfig

        raw = manager(request).server.base_config_raw.get("llm") or {}
        if not raw.get("base_url") or not raw.get("model"):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                error_response("not_configured", "LLM not configured (set it in the UI)"),
            )
        try:
            llm = LLMConfig.model_validate(raw)
        except ValidationError as e:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                error_response("not_configured", _summarize_pydantic(e)))
        out = await custom_mgr(request).generate(body.description, llm)
        return GenerateResponse(**out)

    # ----- scan option templates ------------------------------------------ #
    @app.get("/scan-templates", dependencies=[Depends(require_api_key)])
    async def list_scan_templates(request: Request) -> list[ScanTemplate]:
        rows = await asyncio.to_thread(scan_tpl_mgr(request).list)
        return [ScanTemplate(**r) for r in rows]

    @app.post("/scan-templates", status_code=status.HTTP_201_CREATED,
              dependencies=[Depends(require_api_key)])
    async def create_scan_template(body: ScanTemplateUpsert, request: Request) -> ScanTemplate:
        row = await asyncio.to_thread(scan_tpl_mgr(request).create, body.model_dump())
        return ScanTemplate(**row)

    @app.delete("/scan-templates/{tid}", dependencies=[Depends(require_api_key)])
    async def delete_scan_template(tid: str, request: Request):
        if not await asyncio.to_thread(scan_tpl_mgr(request).delete, tid):
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such template"))
        return {"deleted": tid}

    @app.get("/capabilities", dependencies=[Depends(require_api_key)])
    async def capabilities(request: Request):
        from watchtower.config import THROTTLE_PROFILE_NAMES, throttle_profile_details
        return {
            "version": __version__,
            "capabilities": ALL_TOKENS,
            "subtokens": {parent: list(subs) for parent, subs in SUBTOKENS.items()},
            "throttle_profiles": list(THROTTLE_PROFILE_NAMES),
            # Per-profile knob summary so the UI can SHOW what each tier does.
            "throttle_details": throttle_profile_details(),
            # Where state lives — so the operator knows what to mount for persistence.
            "paths": {
                "output_root": str(config.output_root),
                "config_store": str(config_manager(request).store_path),
                "db": str(default_db_path(config.output_root)),
            },
        }

    @app.post(
        "/scans",
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_api_key)],
    )
    async def submit_scan(req: ScanRequest, request: Request, response: Response):
        idem = request.headers.get("Idempotency-Key") or request.query_params.get("Idempotency-Key")
        mgr = manager(request)
        # Resolve a group/assets/all target → root domains from the inventory.
        if not req.roots:
            roots = await asyncio.to_thread(
                assets_mgr(request).resolve_roots,
                group=req.group, assets=req.assets, all_assets=req.all_assets,
            )
            if not roots:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    error_response("empty_target", "target resolved to no root domains"),
                )
            req = req.model_copy(update={"roots": roots})
        try:
            record, created = mgr.submit(req, idempotency_key=idem)
        except NotConfigured as e:
            raise HTTPException(
                status.HTTP_409_CONFLICT, error_response("not_configured", str(e))
            )
        except SelectionError as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, error_response("invalid_selection", str(e))
            )
        except QueueFull:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                error_response("queue_full", "server at capacity; retry later"),
                headers={"Retry-After": "30"},
            )
        response.status_code = status.HTTP_202_ACCEPTED if created else status.HTTP_200_OK
        return _to_status(mgr, record)

    @app.get("/scans", dependencies=[Depends(require_api_key)])
    async def list_scans(
        request: Request,
        state: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> JobList:
        mgr = manager(request)
        records, total = mgr.list(state=state, limit=limit, offset=offset)
        return JobList(jobs=[_to_status(mgr, r) for r in records], total=total)

    @app.get("/scans/{job_id}", dependencies=[Depends(require_api_key)])
    async def get_scan(job_id: str, request: Request) -> JobStatus:
        mgr = manager(request)
        rec = mgr.get(job_id)
        if rec is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such scan"))
        return _to_status(mgr, rec)

    @app.get("/scans/{job_id}/result", dependencies=[Depends(require_api_key)])
    async def get_result(job_id: str, request: Request):
        mgr = manager(request)
        rec = mgr.get(job_id)
        if rec is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such scan"))
        if rec.state not in TERMINAL_STATES:
            raise HTTPException(
                status.HTTP_409_CONFLICT, error_response("not_finished", "scan not finished")
            )
        run_dir = mgr.run_dir(job_id)
        result = load_scan_result(run_dir) if run_dir else None
        if result is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                error_response("no_result", "result not available for this run"),
            )
        return result

    @app.get("/scans/{job_id}/report", dependencies=[Depends(require_api_key)])
    async def get_report(job_id: str, request: Request):
        mgr = manager(request)
        rec = mgr.get(job_id)
        if rec is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such scan"))
        run_dir = mgr.run_dir(job_id)
        report = (run_dir / "report.html") if run_dir else None
        if report is None or not report.is_file():
            raise HTTPException(
                status.HTTP_409_CONFLICT, error_response("no_report", "report not yet rendered")
            )
        return FileResponse(report, media_type="text/html")

    @app.get("/scans/{job_id}/log", dependencies=[Depends(require_api_key)])
    async def get_log(
        job_id: str, request: Request, tail: int = Query(default=200, ge=1, le=10000)
    ):
        mgr = manager(request)
        rec = mgr.get(job_id)
        if rec is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such scan"))
        run_dir = mgr.run_dir(job_id)
        log_file = (run_dir / "run.log.jsonl") if run_dir else None
        if log_file is None or not log_file.is_file():
            return PlainTextResponse("", media_type="application/x-ndjson")
        lines = log_file.read_text().splitlines()[-tail:]
        return PlainTextResponse("\n".join(lines), media_type="application/x-ndjson")

    @app.post("/scans/{job_id}/cancel", dependencies=[Depends(require_api_key)])
    async def cancel_scan(job_id: str, request: Request) -> JobStatus:
        mgr = manager(request)
        rec = mgr.get(job_id)
        if rec is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, error_response("not_found", "no such scan"))
        if rec.state in TERMINAL_STATES:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                error_response("already_terminal", f"scan already {rec.state}"),
            )
        updated = await mgr.cancel(job_id)
        return _to_status(mgr, updated or rec)


def _docs_urls(config: ServerConfig) -> dict:
    if config.docs_enabled:
        return {"docs_url": "/docs", "redoc_url": None, "openapi_url": "/openapi.json"}
    return {"docs_url": None, "redoc_url": None, "openapi_url": None}


def _warn_if_open(config: ServerConfig) -> None:
    if not config.auth_enabled:
        log.warning(
            "AUTH DISABLED: no WATCHTOWER_API_KEYS configured — the API is OPEN. "
            "There is no scan-target allowlist, so anyone who can reach this API "
            "can point the scanner at ANY host. Set WATCHTOWER_API_KEYS before "
            "exposing this server."
        )


def create_app(config: ServerConfig) -> FastAPI:
    """Standalone API (routes at root) with its own JobManager lifecycle."""
    # Apply the persisted runtime store onto `config` in place BEFORE the
    # JobManager reads it (the store is the primary source of truth).
    cfg_manager = ConfigManager(config)
    db = Database(default_db_path(config.output_root))
    assets = AssetManager(db)
    history = ScanHistory(db)
    suppressions = SuppressionManager(db)
    catalog = NucleiCatalog(db)
    custom_templates = CustomTemplateManager(db, catalog=catalog)
    scan_templates = ScanTemplateManager(db)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.config = config
        app.state.manager = JobManager(
            config, asset_manager=assets, history=history, suppressions=suppressions,
            nuclei_custom=custom_templates,
        )
        await app.state.manager.start()
        app.state.scheduler = ScheduleManager(db, assets, app.state.manager)
        await app.state.scheduler.start()
        _warn_if_open(config)
        yield
        await app.state.scheduler.stop()
        await app.state.manager.stop()
        db.close()

    app = FastAPI(
        title="WatchTower Web API",
        version=__version__,
        description="Submit external AppSec scans, track progress, retrieve results.",
        lifespan=lifespan,
        **_docs_urls(config),
    )
    app.state.config = config
    app.state.config_manager = cfg_manager
    app.state.assets = assets
    app.state.suppressions = suppressions
    app.state.catalog = catalog
    app.state.custom_templates = custom_templates
    app.state.scan_templates = scan_templates
    _install(app, config)
    return app


class _SPAStaticFiles(StaticFiles):
    """Static file server with a SPA-style 404 fallback to index.html, so a hard
    refresh on any client route still loads the app."""

    async def get_response(self, path, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


def create_combined_app(config: ServerConfig, ui_dir: str | Path) -> FastAPI:
    """Single-image app: API under /api, built UI served at /."""
    cfg_manager = ConfigManager(config)  # apply runtime store before serving
    db = Database(default_db_path(config.output_root))
    assets = AssetManager(db)
    history = ScanHistory(db)
    suppressions = SuppressionManager(db)
    catalog = NucleiCatalog(db)
    custom_templates = CustomTemplateManager(db, catalog=catalog)
    scan_templates = ScanTemplateManager(db)

    api_app = FastAPI(
        title="WatchTower Web API",
        version=__version__,
        description="Submit external AppSec scans, track progress, retrieve results.",
        **_docs_urls(config),
    )
    api_app.state.config = config
    api_app.state.config_manager = cfg_manager
    api_app.state.assets = assets
    api_app.state.suppressions = suppressions
    api_app.state.catalog = catalog
    api_app.state.custom_templates = custom_templates
    api_app.state.scan_templates = scan_templates
    _install(api_app, config)

    @asynccontextmanager
    async def lifespan(parent: FastAPI):
        # The mounted sub-app's lifespan does not run, so own the JobManager here
        # and attach it to the sub-app's state (where the route handlers read it).
        api_app.state.manager = JobManager(
            config, asset_manager=assets, history=history, suppressions=suppressions,
            nuclei_custom=custom_templates,
        )
        await api_app.state.manager.start()
        api_app.state.scheduler = ScheduleManager(db, assets, api_app.state.manager)
        await api_app.state.scheduler.start()
        _warn_if_open(config)
        yield
        await api_app.state.scheduler.stop()
        await api_app.state.manager.stop()
        db.close()

    parent = FastAPI(title="WatchTower", version=__version__, lifespan=lifespan,
                     docs_url=None, redoc_url=None, openapi_url=None)
    parent.mount("/api", api_app)
    parent.mount("/", _SPAStaticFiles(directory=str(ui_dir), html=True), name="ui")
    return parent


def serve(
    config_path: str | Path | None = None,
    host: str | None = None,
    port: int | None = None,
    ui_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
) -> None:
    """Entry point for `watchtower serve` — load config, build app, run uvicorn.

    `config_path` is OPTIONAL: with no server.yaml the server boots UI-managed
    (config comes from the runtime store / the UI). `output_dir` overrides where
    run dirs + the config store live (handy for UI-only local runs where the
    default `/data/runs` isn't writable). If a UI build directory is given (CLI
    `--ui-dir` or `WATCHTOWER_UI_DIR`), the UI is served from the same process (API
    under /api); otherwise the API runs standalone at root."""
    import uvicorn

    from watchtower.api.config import load_server_config

    config = load_server_config(config_path)
    if output_dir:
        config.output_root = str(output_dir)
    if config_path is None:
        log.info("no -c/--config given — booting UI-managed (config from the store/UI)")
    ui_dir = ui_dir or os.environ.get("WATCHTOWER_UI_DIR")
    if ui_dir and Path(ui_dir).is_dir():
        app = create_combined_app(config, ui_dir)
        log.info("serving bundled UI from %s (API under /api)", ui_dir)
    else:
        if ui_dir:
            log.warning("WATCHTOWER_UI_DIR=%s not found; serving API only", ui_dir)
        app = create_app(config)
    uvicorn.run(
        app,
        host=host or config.bind.host,
        port=port or config.bind.port,
        log_level="info",
    )
