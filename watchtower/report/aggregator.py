"""Aggregator: ingest all stage artifacts into a single report context dict."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any

from watchtower.models import (
    AppProfile,
    CrawlerArtifact,
    Finding,
    LiveWebServer,
    RunSummary,
    ShadowITGroup,
    StageOutcome,
    TLSHostReport,
    TriagedAsset,
)
from watchtower.util.domains import etld_plus_one

if TYPE_CHECKING:
    from watchtower.stages.state import ScanState

_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Headers shown in the per-host presence matrix (Security Headers section).
_MATRIX_HEADERS = (
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "XFO"),
    ("x-content-type-options", "XCTO"),
    ("referrer-policy", "Referrer"),
    ("permissions-policy", "Permissions"),
)


def _header_matrix(page_signals: dict | None) -> list[dict]:
    """Per-host presence grid for the key security headers (CSP frame-ancestors
    counts as XFO for the clickjacking column)."""
    rows: list[dict] = []
    for host, sig in sorted((page_signals or {}).items()):
        headers = getattr(sig, "headers", {}) or {}
        csp = (headers.get("content-security-policy") or "").lower()
        cells = []
        for key, label in _MATRIX_HEADERS:
            present = bool(headers.get(key))
            if key == "x-frame-options" and not present and "frame-ancestors" in csp:
                present = True  # clickjacking covered via CSP
            cells.append({"label": label, "present": present})
        rows.append({"host": host, "cells": cells})
    return rows


def build_run_summary(
    state: "ScanState", *, duration_s: float, log_counts: dict[str, dict[str, int]]
) -> RunSummary:
    """Roll the final ScanState + logger counters into a RunSummary.

    Written to summary.json, logged at run end, and shown in the report. Reuses
    `severity_histogram` and the `ScanState` bucket helpers; the per-asset failures
    harvested into `state.errors` give truthful error counts.
    """
    all_findings = (
        list(state.nuclei_findings) + list(state.takeover_findings)
        + list(state.tls_findings) + list(state.header_findings)
        + list(state.ai_headers_findings) + list(state.ai_supply_findings)
    )
    # Soft-suppressed findings are excluded from the severity rollup (but kept on
    # disk + in the report's collapsible 'Suppressed' section).
    visible = [f for f in all_findings if not f.suppressed]
    hist = severity_histogram(visible)
    sev_totals = {sev: sum(by.values()) for sev, by in hist.items()}

    by_stage = Counter(e.stage for e in state.errors)
    stages = [
        StageOutcome(name=name, duration_s=dur, errors=by_stage.get(name, 0))
        for name, dur in state.stage_durations.items()
    ]

    profiled = sum(1 for p in state.app_profiles.values() if p.usable)
    tls_errored = sum(1 for r in state.tls_reports if r.error)

    levels = log_counts.get("levels", {})
    events = log_counts.get("events", {})
    ev: dict[str, int] = {}
    for k in ("tool_timeout", "tool_nonzero", "rate_limit_signal", "sslscan_no_output"):
        if events.get(k):
            ev[k] = events[k]
    for lvl in ("warn", "error"):
        if levels.get(lvl):
            ev[lvl] = levels[lvl]

    return RunSummary(
        duration_s=round(duration_s, 1),
        findings_total=len(visible),
        findings_by_severity=sev_totals,
        assets={
            "in_scope": len(state.in_scope()),
            "shadow_it": len(state.shadow_it()),
            "dead": len(state.dead()),
            "live_servers": len(state.live_servers),
            "wildcards": len(state.wildcards),
        },
        errors_total=len(state.errors),
        errors_by_stage=dict(by_stage),
        stages=stages,
        ai={"profiled": profiled, "degraded": len(state.app_profiles) - profiled},
        tls={"hosts": len(state.tls_reports), "ok": len(state.tls_reports) - tls_errored,
             "errored": tls_errored},
        events=ev,
    )


def group_shadow_it(assets: list[TriagedAsset]) -> list[ShadowITGroup]:
    """Group Shadow IT assets by CNAME target eTLD+1, falling back to AS org."""
    by_cname: dict[str, list[TriagedAsset]] = defaultdict(list)
    by_asn: dict[str, list[TriagedAsset]] = defaultdict(list)

    for asset in assets:
        if asset.bucket != "shadow_it":
            continue
        if asset.cname_chain:
            # Use the last CNAME hop's eTLD+1 as the group key.
            key = etld_plus_one(asset.cname_chain[-1])
            by_cname[key].append(asset)
        else:
            label = f"AS{asset.asn or '?'} {asset.as_org or 'Unknown'}"
            by_asn[label].append(asset)

    groups: list[ShadowITGroup] = []
    for key, items in sorted(by_cname.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        groups.append(ShadowITGroup(key=key, grouping="cname", assets=items))
    for key, items in sorted(by_asn.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        groups.append(ShadowITGroup(key=key, grouping="asn", assets=items))
    return groups


def severity_histogram(findings: list[Finding]) -> dict[str, dict[str, int]]:
    """Return {severity: {source: count}} for the report header."""
    hist: dict[str, Counter[str]] = {
        "critical": Counter(),
        "high": Counter(),
        "medium": Counter(),
        "low": Counter(),
        "info": Counter(),
    }
    for f in findings:
        hist.setdefault(f.severity, Counter())[f.source] += 1
    return {sev: dict(counts) for sev, counts in hist.items()}


def build_report_context(
    *,
    run_meta: dict[str, Any],
    triaged: list[TriagedAsset],
    wildcards: list[str],
    live_servers: list[LiveWebServer],
    nuclei_findings: list[Finding],
    takeover_findings: list[Finding],
    tls_findings: list[Finding],
    tls_reports: list[TLSHostReport],
    ai_headers_findings: list[Finding],
    ai_supply_findings: list[Finding],
    crawler_artifacts: list[CrawlerArtifact],
    errors: list[dict[str, Any]],
    versions: dict[str, Any],
    header_findings: list[Finding] | None = None,
    js_lib_findings: list[Finding] | None = None,
    page_signals: dict | None = None,
    tls_certs: list | None = None,
    app_profiles: dict[str, AppProfile] | None = None,
    coverage: dict[str, dict] | None = None,
    summary: RunSummary | None = None,
) -> dict[str, Any]:
    in_scope = [a for a in triaged if a.bucket == "in_scope"]
    shadow = [a for a in triaged if a.bucket == "shadow_it"]
    dead = [a for a in triaged if a.bucket == "dead"]

    header_findings = list(header_findings or [])
    js_lib_findings = list(js_lib_findings or [])
    all_findings: list[Finding] = (
        list(nuclei_findings)
        + list(takeover_findings)
        + list(tls_findings)
        + header_findings
        + js_lib_findings
        + list(ai_headers_findings)
        + list(ai_supply_findings)
    )
    # Suppressed findings are kept (collapsible section + findings.json) but
    # excluded from the histogram and the per-source finding tables.
    visible = [f for f in all_findings if not f.suppressed]
    suppressed = [f for f in all_findings if f.suppressed]
    header_visible = [f for f in header_findings if not f.suppressed]

    histogram = severity_histogram(visible)
    shadow_groups = group_shadow_it(shadow)

    # TLS fleet rollup
    tls_total_checks = sum(r.total for r in tls_reports)
    tls_passed = sum(r.pass_count for r in tls_reports)
    tls_failed = tls_total_checks - tls_passed
    tls_worst = sorted(tls_reports, key=lambda r: r.pass_count - r.total)[:5]

    # Coverage strip: ordered list of {token, ran, reason} for the report header.
    coverage = coverage or {}
    coverage_strip = [
        {"token": tok, **coverage[tok]}
        for tok in ("recon", "takeovers", "tls", "nuclei", "headers", "supply-chain", "ai")
        if tok in coverage
    ]

    def _ran(tok: str) -> bool:
        # Absent coverage (e.g. hand-assembled stages=[...]) => treat as run.
        return coverage.get(tok, {"ran": True})["ran"]

    return {
        "run": run_meta,
        "versions": versions,
        "errors": errors,
        "summary": summary,
        "coverage": coverage,
        "coverage_strip": coverage_strip,
        "ran": {
            "takeovers": _ran("takeovers"),
            "tls": _ran("tls"),
            "nuclei": _ran("nuclei"),
            "headers": _ran("headers"),
            "supply_chain": _ran("supply-chain"),
            "ai": _ran("ai"),
        },
        "app_profiles": app_profiles or {},
        "recon": {
            "in_scope": in_scope,
            "shadow_it": shadow,
            "dead": dead,
            "wildcards": wildcards,
            "live_servers": live_servers,
        },
        "shadow_groups": shadow_groups,
        "histogram": histogram,
        "histogram_totals": {
            sev: sum(by_src.values()) for sev, by_src in histogram.items()
        },
        "findings": {
            # Suppressed findings (any source) move to the collapsible "suppressed"
            # section and out of the per-source tables + histogram.
            "nuclei": [f for f in nuclei_findings if not f.suppressed],
            "takeovers": [f for f in takeover_findings if not f.suppressed],
            "tls": [f for f in tls_findings if not f.suppressed],
            "headers": [f for f in header_visible if f.source == "headers"],
            "csp": [f for f in header_visible if f.source == "csp"],
            "js_lib": [f for f in js_lib_findings if not f.suppressed],
            "ai_headers": ai_headers_findings,
            "ai_supply_chain": ai_supply_findings,
            "suppressed": suppressed,
            "all": all_findings,
        },
        "header_matrix": _header_matrix(page_signals),
        "tls": {
            "reports": tls_reports,
            "total_checks": tls_total_checks,
            "passed": tls_passed,
            "failed": tls_failed,
            "worst_hosts": tls_worst,
        },
        "tls_certs": list(tls_certs or []),
        "crawler": crawler_artifacts,
    }
