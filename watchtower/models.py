from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Status = Literal["live", "dead"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
FindingSource = Literal[
    "nuclei", "takeover", "sslscan",
    "headers", "csp",                       # deterministic security-header checks
    "js_lib",                               # vulnerable JS library (retire.js-style)
    "ai_headers", "ai_supply_chain",
]


class AIFindingVerdict(BaseModel):
    """An AI judgment attached to a *deterministic* finding (any source — the
    `ai.triage` pass spans nuclei/TLS/js_lib/headers/takeover, not just headers).

    `suppressed=True` hides the finding by default in the report and drops it from
    the severity histogram — but the finding is NEVER deleted (it stays in
    findings.json and a collapsible 'Suppressed' section), so the call is fully
    auditable and reversible. Honors the 'AI never gates deterministic scanners'
    invariant in spirit: an AI degrade leaves `ai_verdict` unset, so every
    deterministic finding stands at full severity.

    A verdict with `suppressed=False` is advisory only — the AI's FP opinion
    surfaced next to a finding the suppression gate declined to hide.
    """
    suppressed: bool = False
    confidence: Confidence = "low"
    reason: str = ""
    source: Literal["ai_headers", "ai_triage", "manual"] = "ai_triage"


class TriagedAsset(BaseModel):
    fqdn: str
    a_records: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    asn: int | None = None
    as_org: str | None = None
    status: Status
    reason: str


class LiveWebServer(BaseModel):
    url: str
    host: str
    status_code: int | None = None
    title: str | None = None
    tech: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    source: FindingSource
    host: str | None = None
    severity: Severity
    title: str
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    # Stable identifier for a rule-based (deterministic) finding, unique within a
    # host. The AI references it to suppress/annotate a specific check; None for
    # LLM-sourced or non-deterministic findings.
    check_id: str | None = None
    # AI judgment on a deterministic finding (see AIFindingVerdict). Set by the
    # ai.triage pass for any source; an AI degrade leaves it None (finding stands).
    ai_verdict: AIFindingVerdict | None = None

    @property
    def suppressed(self) -> bool:
        """True when the AI soft-suppressed this finding (hidden + uncounted,
        never deleted). Drives report/severity-count exclusion."""
        return self.ai_verdict is not None and self.ai_verdict.suppressed

    def evidence_rows(self) -> list[tuple[str, str]]:
        """Project the source-specific `evidence` dict into ordered
        (label, value) display rows, dropping empties.

        The single place that knows each source's evidence shape, so the report
        renders a Finding's evidence without reaching into source-specific keys.
        nuclei and takeover share one shape (both come from `parse_nuclei_jsonl`).
        """
        ev = self.evidence
        if self.source in ("nuclei", "takeover"):
            rows = [("template", ev.get("template_id")), ("matched", ev.get("matched_at"))]
        elif self.source == "sslscan":
            rows = [("check", ev.get("check")), ("detail", ev.get("detail"))]
        else:  # headers / csp / ai_headers / ai_supply_chain — "type"/"check_id" internal
            rows = [(k, v) for k, v in ev.items() if k not in ("type", "check_id")]
        return [(k, str(v)) for k, v in rows if v not in (None, "", [], {})]

    @property
    def evidence_summary(self) -> str:
        """Compact one-line evidence for table cells."""
        return " · ".join(v for _, v in self.evidence_rows())


class TLSCheck(BaseModel):
    name: str
    passed: bool
    detail: str = ""
    # Severity carried as data, so the Finding projection reads it directly
    # instead of re-deriving severity by string-matching the check name.
    severity: Severity = "medium"


class TLSHostReport(BaseModel):
    host: str
    checks: list[TLSCheck] = Field(default_factory=list)
    error: str | None = None

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def total(self) -> int:
        return len(self.checks)


class CertInfo(BaseModel):
    """Per-IP certificate dossier captured during the recon tlsx cert-grab — the
    same single connection that harvests SANs (no extra requests). Inventory only;
    does not produce findings. `self_signed`/`expired` are derived in Python."""
    ip: str = ""
    subject_cn: str | None = None
    sans: list[str] = Field(default_factory=list)
    issuer: str | None = None
    serial: str | None = None
    sha256: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    expired: bool = False
    self_signed: bool = False
    wildcard: bool = False


class CrawlerArtifact(BaseModel):
    host: str
    url: str
    status: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    scripts: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class PageSignals(BaseModel):
    """Per-host signals parsed from the httpx response (raw, pre-JS HTML).

    The input the AI profiler reasons over. Built during the httpx stage so no
    extra crawler work is needed.
    """
    host: str
    headers: dict[str, str] = Field(default_factory=dict)   # response headers, lower-cased keys
    # Raw Set-Cookie header values, one per cookie (the `headers` dict collapses
    # duplicates, so cookie-flag analysis reads this list instead).
    set_cookies: list[str] = Field(default_factory=list)
    title: str | None = None
    meta_description: str | None = None
    og_tags: dict[str, str] = Field(default_factory=dict)
    body_snippet: str = ""                                  # stripped visible text, <= 2 KB, pre-JS
    form_count: int = 0
    has_password_input: bool = False
    tech: list[str] = Field(default_factory=list)           # carried from httpx tech-detect


class AppProfile(BaseModel):
    """AI-inferred per-application context (DESIGN.md §2.3.1).

    Validated from the profiler's JSON. Lenient defaults so a partial reply is
    still usable; an out-of-enum `audience`/`confidence` still triggers
    validation failure → retry → graceful degrade to the default prompts.
    """
    host: str = ""
    app_type: str = "unknown web application"
    audience: Literal["public", "internal", "partner", "unknown"] = "unknown"
    confidence: Literal["low", "medium", "high"] = "low"
    reasoning: str = ""
    # capability flags
    handles_auth: bool = False
    handles_pii: bool = False
    handles_payments: bool = False
    has_file_upload: bool = False
    is_api: bool = False
    # controls this specific app *ought* to have, given its type
    expected_controls: list[str] = Field(default_factory=list)
    # AI-inferred technologies (merged with httpx -tech-detect, source-tagged, at
    # surfacing time). Complements httpx; never gates anything.
    detected_tech: list[str] = Field(default_factory=list)
    # set when profiling hard-failed for the host (=> downstream uses default prompts)
    error: str | None = None

    @property
    def usable(self) -> bool:
        """True when this profile should drive context-aware prompts."""
        return self.error is None


class StageError(BaseModel):
    stage: str
    target: str | None = None      # the host/asset the error relates to, when known
    message: str
    # exception class name for code crashes (e.g. "KeyError"); "asset" for an
    # expected operational per-host failure (timeout, nav error, AI degrade).
    error_type: str | None = None
    ts: str | None = None          # UTC ISO timestamp the error was recorded


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def asset_error(stage: str, target: str | None, message: str) -> StageError:
    """Construct a per-asset (operational) error record for state.errors."""
    return StageError(
        stage=stage, target=target, message=message, error_type="asset", ts=_now_iso()
    )


class StageOutcome(BaseModel):
    name: str
    duration_s: float = 0.0
    errors: int = 0


class RunSummary(BaseModel):
    """End-of-run rollup — written to summary.json, logged, and shown in the report."""
    duration_s: float = 0.0
    findings_total: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    assets: dict[str, int] = Field(default_factory=dict)        # live/dead/live_servers/wildcards
    errors_total: int = 0
    errors_by_stage: dict[str, int] = Field(default_factory=dict)
    stages: list[StageOutcome] = Field(default_factory=list)
    ai: dict[str, int] = Field(default_factory=dict)            # profiled / degraded
    tls: dict[str, int] = Field(default_factory=dict)           # hosts / ok / errored
    events: dict[str, int] = Field(default_factory=dict)        # warn/error + key tool events
