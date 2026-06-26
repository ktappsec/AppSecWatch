"""ScanState — typed shared bag of stage outputs.

Each stage mutates a slice. The aggregator reads the whole state at the end.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from watchtower.models import (
    AppProfile,
    CertInfo,
    CrawlerArtifact,
    Finding,
    LiveWebServer,
    PageSignals,
    RunSummary,
    StageError,
    TLSHostReport,
    TriagedAsset,
)


class ScanState(BaseModel):
    # Recon
    subdomains: list[str] = Field(default_factory=list)
    triaged: list[TriagedAsset] = Field(default_factory=list)
    wildcards: list[str] = Field(default_factory=list)
    tls_certs: list[CertInfo] = Field(default_factory=list)  # recon cert inventory (tlsx)
    live_servers: list[LiveWebServer] = Field(default_factory=list)
    page_signals: dict[str, PageSignals] = Field(default_factory=dict)  # host -> signals

    # AI context
    app_profiles: dict[str, AppProfile] = Field(default_factory=dict)   # host -> profile

    # Audit
    takeover_findings: list[Finding] = Field(default_factory=list)
    tls_findings: list[Finding] = Field(default_factory=list)
    nuclei_findings: list[Finding] = Field(default_factory=list)
    tls_reports: list[TLSHostReport] = Field(default_factory=list)
    crawler_artifacts: list[CrawlerArtifact] = Field(default_factory=list)
    # Deterministic security-header findings (the `headers` capability). The
    # ai.headers stage may attach AIFindingVerdicts (soft-suppression) to these.
    header_findings: list[Finding] = Field(default_factory=list)
    # Vulnerable JS libraries (retire.js-style) over crawler scripts.
    js_lib_findings: list[Finding] = Field(default_factory=list)

    # AI
    ai_headers_findings: list[Finding] = Field(default_factory=list)
    ai_supply_findings: list[Finding] = Field(default_factory=list)

    # Bookkeeping
    coverage: dict[str, dict] = Field(default_factory=dict)  # capability manifest
    errors: list[StageError] = Field(default_factory=list)
    completed_stages: list[str] = Field(default_factory=list)
    current_stage: str | None = None                        # live progress hook (Web API)
    stage_durations: dict[str, float] = Field(default_factory=dict)  # stage name -> seconds
    summary: RunSummary | None = None                       # set by ReportStage at run end

    def all_findings(self) -> list[Finding]:
        """Every Finding across all sources — the single canonical collection used
        by counting, the result builder, and manual suppression."""
        return (
            list(self.nuclei_findings)
            + list(self.takeover_findings)
            + list(self.tls_findings)
            + list(self.header_findings)
            + list(self.js_lib_findings)
            + list(self.ai_headers_findings)
            + list(self.ai_supply_findings)
        )

    def in_scope(self) -> list[TriagedAsset]:
        return [a for a in self.triaged if a.bucket == "in_scope"]

    def shadow_it(self) -> list[TriagedAsset]:
        return [a for a in self.triaged if a.bucket == "shadow_it"]

    def dead(self) -> list[TriagedAsset]:
        return [a for a in self.triaged if a.bucket == "dead"]
