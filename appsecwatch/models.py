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
    "secret",                               # client-side secret exposed in a JS bundle
    "zap",                                  # OWASP ZAP active scan (opt-in)
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
    # `coverage` = a deterministic (non-AI) suppression applied because the host was
    # not assessable (blocked/error response) — reuses this hide-but-never-delete
    # machinery so those findings stay in findings.json but drop from posture/counts.
    # `policy` = the other deterministic (non-AI) suppression: `ai/policy.py` decides
    # the flip-prone low-value header classes in Python instead of asking the LLM
    # (e.g. clickjacking on a host profiled as a non-browser API).
    source: Literal["ai_headers", "ai_triage", "manual", "coverage", "policy"] = "ai_triage"


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
    # Assessability: did this response present a real application surface? False for
    # 5xx/no-response/WAF-block pages (see audit/liveness.classify_assessability).
    # A not-assessed host has its findings suppressed (coverage verdict) and is listed
    # separately instead of counting toward posture. Defaults keep old artifacts valid.
    assessed: bool = True
    not_assessed_reason: str | None = None


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
    # Controlled-taxonomy classification (audit/taxonomy.py). Stamped by a
    # classification pass before serialization so result.json + the report context
    # carry them (a Pydantic @property is not dumped). None until classified.
    finding_class: str | None = None    # e.g. "headers.hsts-missing"
    category: str | None = None         # e.g. "headers" (a CATEGORY_LABELS key)

    @property
    def suppressed(self) -> bool:
        """True when the AI soft-suppressed this finding (hidden + uncounted,
        never deleted). Drives report/severity-count exclusion."""
        return self.ai_verdict is not None and self.ai_verdict.suppressed

    @property
    def group_key(self) -> str:
        """Stable identity for dedup/grouping + manual-suppression fingerprints:
        the rule ``check_id`` when present (AI findings now derive one from their
        ``title``, the cross-host-stable signal), else a source-specific natural
        key, else the title. Reused
        by ``suppress.finding_key``, ``select_top_risks``, and the report's
        per-source grouping so the same issue collapses across hosts instead of
        emitting one row per host."""
        # check_id covers headers/csp/js_lib + AI (title-derived) + zap (zap.<pluginId>).
        if self.check_id:
            return self.check_id
        ev = self.evidence or {}
        if self.source in ("nuclei", "takeover"):
            return ev.get("template_id") or self.title
        if self.source == "sslscan":
            return ev.get("check") or self.title
        if self.source == "js_lib":
            lib = ev.get("library")
            return f"{lib}@{ev.get('version', '')}" if lib else self.title
        return self.title

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
        elif self.source == "secret":
            # `preview` is masked (boundary chars only) — safe to render; the raw
            # value is never stored. `url`+`line` locate it for the code owner.
            rows = [
                ("rule", ev.get("rule")),
                ("preview", ev.get("preview")),
                ("script", ev.get("url")),
                ("line", ev.get("line")),
            ]
        elif self.source == "zap":
            rows = [
                ("plugin", ev.get("plugin_id")),
                ("risk", ev.get("risk")),
                ("confidence", ev.get("confidence")),
                ("cwe", ev.get("cwe")),
                ("instances", ev.get("instance_count")),
                ("params", ", ".join(ev.get("params") or [])),
                ("solution", ev.get("solution")),
            ]
        else:  # headers / csp / ai_headers / ai_supply_chain — internal keys hidden
            rows = [(k, v) for k, v in ev.items() if k not in ("type", "check_id", "class")]
        return [(k, str(v)) for k, v in rows if v not in (None, "", [], {})]

    @property
    def evidence_summary(self) -> str:
        """Compact one-line evidence for table cells."""
        return " · ".join(v for _, v in self.evidence_rows())


class TLSCheck(BaseModel):
    name: str
    passed: bool
    detail: str = ""
    # Problem-phrased title used when the check FAILS. `name` states the SECURE
    # condition we test FOR ("TLS 1.0 disabled"); emitting that verbatim as a
    # finding title reads backwards (a real vuln looks like a passing control),
    # so a failing check surfaces `fail_title` ("TLS 1.0 enabled") instead.
    # Falls back to `name` when unset. Does NOT affect `group_key`/suppression
    # fingerprints — those key on evidence["check"] (== name), so retitling here
    # never churns cross-scan identity.
    fail_title: str = ""
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
    # DNS attribution (filled by annotate_certs_dns after the re-feed loop; no extra
    # lookups). The dossier is IP-keyed — a cert on IP X names whatever host it was
    # issued for via subject_cn/SANs, NOT necessarily a host whose DNS points at X.
    # These make that gap explicit so an expired cert on a stale IP isn't misread as
    # the live host's posture.
    resolving_names: list[str] = Field(default_factory=list)  # scanned FQDNs whose DNS resolves to this IP
    subject_cn_ips: list[str] = Field(default_factory=list)   # IPs subject_cn actually resolves to (empty = unknown/wildcard)


class CrawlerArtifact(BaseModel):
    host: str
    url: str
    status: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    scripts: list[dict[str, Any]] = Field(default_factory=list)
    # Broadened, STRUCTURE-ONLY capture (names/urls/flags — never any value or
    # body; runs/<id>/ is a shareable, emailable artifact set). Every capture is
    # best-effort: a failure is recorded in `errors`, never raised.
    resources: list[dict[str, Any]] = Field(default_factory=list)   # {url, type, status, method}
    # Requests that FAILED at the network layer (blocked/reset/aborted/DNS/timeout).
    # These fire Playwright's `requestfailed`, NOT `response`, so without capturing
    # them a bot-blocked crawl (only the document loads, 0 subresources) is
    # byte-identical to a genuinely script-free page. Names/urls/reason only —
    # structure-only invariant holds (no bodies).
    failed_requests: list[dict[str, Any]] = Field(default_factory=list)  # {url, type, method, failure}
    cookies: list[dict[str, Any]] = Field(default_factory=list)     # name + flags, NO value
    local_storage_keys: list[str] = Field(default_factory=list)     # key names only
    session_storage_keys: list[str] = Field(default_factory=list)   # key names only
    # JS libraries detected by scanning script BODIES in memory (version not in the
    # URL). Only {library, version, url} is kept — never the body. See audit/js_libs.
    detected_libs: list[dict[str, Any]] = Field(default_factory=list)
    # Secrets detected by scanning script BODIES in memory (curated precision-first
    # ruleset). Only {rule, url, line, preview} is kept — `preview` is MASKED
    # (boundary chars only), never the raw value; the body is never persisted.
    # See audit/secrets.py. Shareable-artifact invariant holds.
    detected_secrets: list[dict[str, Any]] = Field(default_factory=list)
    rendered_text: str = ""                                         # body.innerText, normalized + <=2KB
    screenshot: str | None = None                                   # per-host PNG filename (dashboard only)
    errors: list[str] = Field(default_factory=list)


class PageSignals(BaseModel):
    """Per-host signals parsed from the httpx response (raw, pre-JS HTML).

    The input the AI profiler reasons over. Built during the httpx stage so no
    extra crawler work is needed.
    """
    host: str
    status_code: int | None = None                          # httpx HTTP status (None = no response)
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


class ExecRiskNote(BaseModel):
    """An AI-written plain-language note for ONE of the deterministically-selected
    executive top-risks. `ref` is the ephemeral index the risk was given in the
    prompt payload (the only handle the LLM is given). `key` is NOT supplied by the
    LLM — the exec summary stage fills it post-validation by mapping ref→the risk's
    stable key, so the renderer merges notes by key and survives a later selection
    shift (e.g. manual suppression running after the AI call)."""
    ref: int
    why: str = ""
    key: str = ""


class ExecutiveSummary(BaseModel):
    """Optional AI prose overlay for executive.html (the `ai.summary` call).

    The executive report's deterministic core (posture rating, severity counts,
    coverage/scale, top-risk SELECTION) is computed in Python and ALWAYS renders;
    this object only carries the narrative overlay. Lenient defaults + the
    `error`/`usable` contract (mirrors AppProfile/AIResponse) so a degrade is just
    `ExecutiveSummary(error=...)` and the renderer falls back to templated prose."""
    posture_narrative: str = ""
    risk_notes: list[ExecRiskNote] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    error: str | None = None

    @property
    def usable(self) -> bool:
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
    # Whole-scan degraded (httpx returned 0 live servers despite live assets) +
    # count of hosts probed but not assessable (blocked/error responses).
    degraded: bool = False
    degraded_reason: str | None = None
    not_assessed: int = 0
