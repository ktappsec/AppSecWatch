"""HTTP request/response models + the persisted job record.

These are the API's public contract (the FastAPI app turns them into the
OpenAPI schema at /docs). `JobRecord` is the durable per-run `job.json`; the
on-the-wire `JobStatus` is derived from it plus live state + HATEOAS links.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from watchtower.config import ThrottleProfile
from watchtower.models import (
    AppProfile,
    CertInfo,
    Finding,
    LiveWebServer,
    TLSHostReport,
    TriagedAsset,
)

JobState = Literal[
    "queued", "running", "completed", "failed", "cancelled", "interrupted"
]
TERMINAL_STATES: frozenset[str] = frozenset(
    {"completed", "failed", "cancelled", "interrupted"}
)


# --------------------------------------------------------------------------- #
# Request
# --------------------------------------------------------------------------- #
class ScanRequest(BaseModel):
    """Submit body for POST /scans (server-side base config supplies secrets).

    Exactly one target must be given: ad-hoc `roots`, an asset `group` (iştirak),
    specific `assets`, or `all_assets`. group/assets/all resolve to root domains
    from the inventory before the scan runs.
    """

    roots: list[str] | None = Field(default=None, description="Ad-hoc root domains")
    group: str | None = Field(default=None, description="Asset group (iştirak) to scan")
    assets: list[str] | None = Field(default=None, description="Specific asset FQDNs to scan")
    all_assets: bool = Field(default=False, description="Scan all imported assets")
    only: list[str] | None = Field(default=None, description="Capability tokens to run exclusively")
    skip: list[str] | None = Field(default=None, description="Capability tokens to exclude")
    throttle: ThrottleProfile | None = None
    compress: bool = True
    callback_url: str | None = Field(
        default=None, description="Optional webhook; host must be in callback_host_allowlist"
    )

    @model_validator(mode="after")
    def _check(self) -> "ScanRequest":
        if self.only is not None and self.skip is not None:
            raise ValueError("only and skip are mutually exclusive")
        targets = [bool(self.roots), self.group is not None, bool(self.assets), self.all_assets]
        if sum(targets) != 1:
            raise ValueError(
                "exactly one target required: roots | group | assets | all_assets"
            )
        return self


# --------------------------------------------------------------------------- #
# Persisted job record (job.json) + on-the-wire status
# --------------------------------------------------------------------------- #
class JobRecord(BaseModel):
    """Self-describing per-run record written to `<run_dir>/job.json`.

    On startup the JobManager globs these to rebuild its index (WEB_API_PLAN §3).
    """

    id: str
    state: JobState
    roots: list[str] | None = None
    group: str | None = None
    only: list[str] | None = None
    skip: list[str] | None = None
    throttle: ThrottleProfile | None = None
    compress: bool = True
    source: str = "manual"               # manual | schedule
    schedule_id: str | None = None
    submitted_at: str
    started_at: str | None = None
    finished_at: str | None = None
    current_stage: str | None = None
    completed_stages: list[str] = Field(default_factory=list)
    coverage: dict[str, dict] = Field(default_factory=dict)
    finding_count: int = 0
    error: str | None = None
    callback_url: str | None = None
    idempotency_key: str | None = None
    # (target + params) fingerprint for in-flight dedupe; not part of the response.
    params_fingerprint: str | None = None


class JobLinks(BaseModel):
    self: str
    result: str
    report: str
    log: str
    cancel: str


class JobStatus(BaseModel):
    """Poll response — the JobRecord projected for callers, with links + elapsed."""

    id: str
    state: JobState
    roots: list[str] | None = None
    group: str | None = None
    only: list[str] | None = None
    skip: list[str] | None = None
    throttle: ThrottleProfile | None = None
    submitted_at: str
    started_at: str | None = None
    finished_at: str | None = None
    current_stage: str | None = None
    completed_stages: list[str] = Field(default_factory=list)
    elapsed_s: float = 0.0
    finding_count: int = 0
    source: str = "manual"
    schedule_id: str | None = None
    coverage: dict[str, dict] = Field(default_factory=dict)
    error: str | None = None
    links: JobLinks


class JobList(BaseModel):
    jobs: list[JobStatus]
    total: int


# --------------------------------------------------------------------------- #
# Machine-readable result (/result)
# --------------------------------------------------------------------------- #
class ScanResult(BaseModel):
    """Assembled from the run dir — findings as JSON, not scraped HTML."""

    id: str
    state: JobState
    coverage: dict[str, dict] = Field(default_factory=dict)
    histogram: dict[str, dict[str, int]] = Field(default_factory=dict)
    histogram_totals: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    tls: list[TLSHostReport] = Field(default_factory=list)
    tls_certs: list[CertInfo] = Field(default_factory=list)
    app_profiles: dict[str, AppProfile] = Field(default_factory=dict)
    assets: list[TriagedAsset] = Field(default_factory=list)
    live_servers: list[LiveWebServer] = Field(default_factory=list)
    wildcards: list[str] = Field(default_factory=list)
    summary: dict[str, Any] | None = None
    report_url: str


# --------------------------------------------------------------------------- #
# Assets inventory
# --------------------------------------------------------------------------- #
class Asset(BaseModel):
    fqdn: str
    group: str | None = None
    source: str = "discovered"           # imported | discovered
    root: str | None = None
    bucket: str | None = None            # in_scope | shadow_it | dead
    a_records: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    asn: int | None = None
    as_org: str | None = None
    tech: list[dict[str, Any]] = Field(default_factory=list)
    profile: dict[str, Any] | None = None        # AI AppProfile (when ai.profile ran)
    finding_counts: dict[str, int] = Field(default_factory=dict)  # last scan, by severity
    notes: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    last_scan_id: str | None = None


class AssetUpsert(BaseModel):
    """POST/PUT body for a single imported asset."""
    fqdn: str
    group: str | None = None
    notes: str | None = None


class AssetGroup(BaseModel):
    group: str | None = None
    count: int = 0
    last_scan_id: str | None = None


class AssetImportResult(BaseModel):
    added: int = 0
    updated: int = 0
    skipped: int = 0


class AssetBulkFilter(BaseModel):
    group: str | None = None
    bucket: str | None = None
    source: str | None = None


class AssetBulkRequest(BaseModel):
    """Bulk op over explicit fqdns OR a filter (exactly one selection)."""
    action: Literal["delete", "set_group"]
    fqdns: list[str] | None = None
    filter: AssetBulkFilter | None = None
    group: str | None = None             # target group for set_group


class ReevaluateResult(BaseModel):
    total: int = 0
    changed: int = 0


# --------------------------------------------------------------------------- #
# Scan option templates (reusable presets; no target)
# --------------------------------------------------------------------------- #
class ScanTemplateUpsert(BaseModel):
    name: str
    only: list[str] | None = None
    skip: list[str] | None = None
    throttle: ThrottleProfile | None = None
    compress: bool = True


class ScanTemplate(BaseModel):
    id: str
    name: str
    only: list[str] | None = None
    skip: list[str] | None = None
    throttle: ThrottleProfile | None = None
    compress: bool = True
    created_at: str | None = None


# --------------------------------------------------------------------------- #
# Nuclei catalog + custom templates
# --------------------------------------------------------------------------- #
class NucleiTemplate(BaseModel):
    id: str
    name: str | None = None
    severity: str | None = None
    tags: list[str] = Field(default_factory=list)
    category: str | None = None
    path: str | None = None
    source: str = "bundled"


class NucleiCategory(BaseModel):
    category: str | None = None
    count: int = 0


class CustomTemplate(BaseModel):
    id: str
    name: str | None = None
    yaml: str
    enabled: bool = True
    valid: bool = False
    error: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class CustomTemplateUpsert(BaseModel):
    name: str | None = None
    yaml: str
    enabled: bool = True


class GenerateRequest(BaseModel):
    description: str


class GenerateResponse(BaseModel):
    yaml: str
    valid: bool = False
    error: str = ""


# --------------------------------------------------------------------------- #
# Suppressions
# --------------------------------------------------------------------------- #
class SuppressionCreate(BaseModel):
    source: str
    host: str | None = None               # ignored when scope='global'
    key: str                              # check_id | template_id | sslscan check | lib@ver | title
    scope: Literal["host", "global"] = "host"
    reason: str = ""


class Suppression(BaseModel):
    fingerprint: str
    source: str
    host: str | None = None
    key: str
    scope: str = "host"
    reason: str = ""
    created_at: str | None = None


# --------------------------------------------------------------------------- #
# Schedules
# --------------------------------------------------------------------------- #
class ScheduleTarget(BaseModel):
    roots: list[str] | None = None
    group: str | None = None
    assets: list[str] | None = None
    all_assets: bool = False


class ScheduleUpsert(BaseModel):
    name: str | None = None
    target: ScheduleTarget = Field(default_factory=ScheduleTarget)
    only: list[str] | None = None
    skip: list[str] | None = None
    throttle: ThrottleProfile | None = None
    compress: bool = True
    cadence: Literal["hourly", "daily", "weekly"]
    at_time: str | None = None            # "HH:MM" UTC
    weekday: int | None = None            # 0=Mon..6=Sun (weekly)
    enabled: bool = True


class Schedule(BaseModel):
    id: str
    name: str | None = None
    target: dict[str, Any] = Field(default_factory=dict)
    only: list[str] | None = None
    skip: list[str] | None = None
    throttle: ThrottleProfile | None = None
    compress: bool = True
    cadence: str
    at_time: str | None = None
    weekday: int | None = None
    enabled: bool = True
    next_run_at: str | None = None
    last_run_at: str | None = None
    last_job_id: str | None = None
    created_at: str | None = None


# --------------------------------------------------------------------------- #
# Runtime config (GET/PUT /config)
# --------------------------------------------------------------------------- #
class ConfigView(BaseModel):
    """Effective server config for GET /config. `base_config` is the scan config
    (a free-form dict mirroring WatchTowerConfig minus per-request `roots`); its
    `llm.api_key` is masked. There is no scan-target allowlist."""

    base_config: dict[str, Any] = Field(default_factory=dict)


class ConfigUpdate(BaseModel):
    """PUT /config body — full replacement of the base scan config. A blank/masked
    `base_config.llm.api_key` keeps the stored key (write-only secret)."""

    base_config: dict[str, Any]


# --------------------------------------------------------------------------- #
# AI prompts (editable system-prompt registry — the AI Tuning page)
# --------------------------------------------------------------------------- #
class PromptSlot(BaseModel):
    """One editable AI system-prompt slot: the built-in default plus the current
    override (if any). `effective` is what the engine actually sends."""

    id: str
    label: str
    description: str
    default_text: str
    override: str | None = None
    modified: bool = False
    effective: str = ""


class PromptsView(BaseModel):
    slots: list[PromptSlot] = Field(default_factory=list)


class PromptUpdate(BaseModel):
    """PUT /prompts/{id} body. A null/blank `text` clears the override (reverts to
    the built-in default)."""

    text: str | None = None


class PromptPreviewRequest(BaseModel):
    """POST /prompts/{id}/preview body — candidate system text to render."""

    text: str = ""


class PromptPreview(BaseModel):
    """The exact (system, user) message the engine would send for the slot, using
    the candidate text + a representative fixture. No LLM call."""

    system: str
    user: str


# --------------------------------------------------------------------------- #
# Error envelope
# --------------------------------------------------------------------------- #
class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorEnvelope(BaseModel):
    error: ErrorBody


def error_response(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}
