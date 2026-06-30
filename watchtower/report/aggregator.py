"""Aggregator: ingest all stage artifacts into a single report context dict."""
from __future__ import annotations

import base64
import mimetypes
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from watchtower.models import (
    AppProfile,
    CrawlerArtifact,
    ExecutiveSummary,
    Finding,
    LiveWebServer,
    RunSummary,
    StageOutcome,
    TLSHostReport,
    TriagedAsset,
)

if TYPE_CHECKING:
    from watchtower.config import ReportConfig
    from watchtower.stages.state import ScanState

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Deterministic fallback "why it matters" prose per finding source, used when no AI
# overlay is available (ai.summary off/degraded). Kept plain and leadership-readable.
_WHY_BY_SOURCE = {
    "nuclei": "Flagged by an active vulnerability check; review and remediate on the affected hosts.",
    "takeover": "A dangling DNS record could let an attacker claim the subdomain and serve content under your name.",
    "sslscan": "Weak or misconfigured TLS lets traffic be intercepted or downgraded.",
    "headers": "A missing or weak security header removes a browser-side defense against common web attacks.",
    "csp": "Content-Security-Policy gaps weaken protection against cross-site scripting and injection.",
    "js_lib": "A known-vulnerable JavaScript library is loaded; update it to a patched version.",
    "ai_headers": "Identified during analysis as a header/configuration weakness worth attention.",
    "ai_supply_chain": "A third-party script dependency widens the supply-chain attack surface.",
}
_DEFAULT_WHY = "Review the affected hosts and remediate."

# Deterministic remediation themes per source, for the next-steps fallback.
_RECO_BY_SOURCE = {
    "headers": "Add the missing security headers (HSTS, CSP, X-Content-Type-Options, …) across the estate.",
    "csp": "Define and tighten a Content-Security-Policy on public-facing applications.",
    "sslscan": "Remediate TLS misconfigurations and retire weak protocols and ciphers.",
    "takeover": "Remove or reclaim dangling DNS records pointing at unclaimed third-party services.",
    "js_lib": "Upgrade outdated or vulnerable JavaScript libraries.",
    "nuclei": "Triage and patch the vulnerabilities surfaced by active scanning.",
    "ai_headers": "Address the configuration weaknesses surfaced during analysis.",
    "ai_supply_chain": "Review third-party script dependencies and remove the unused ones.",
}


@dataclass(frozen=True)
class ExecRisk:
    """One deterministically-selected executive top-risk (a group of findings that
    share a source+title). `ref` is the ephemeral index handed to the LLM; `key` is
    the stable identity the AI note is re-bound to for a timing-safe merge."""
    ref: int
    key: str
    title: str
    source: str
    severity: str
    hosts: tuple[str, ...]
    host_count: int
    why: str = ""        # filled at context-build time (AI overlay or deterministic)


def _dominant_severity(histogram_totals: dict[str, int]) -> str | None:
    """The highest severity bucket that has ≥1 visible finding."""
    for sev in _SEVERITIES:  # critical → info
        if histogram_totals.get(sev, 0) > 0:
            return sev
    return None


def posture_rating(histogram_totals: dict[str, int]) -> tuple[str, str]:
    """(rating, volume_note) from the VISIBLE severity totals.

    Rating = highest severity present (crit→CRITICAL, high→HIGH, medium→MODERATE,
    else LOW — fully transparent). The note quantifies the dominant bucket;
    build_executive_context enriches it with a host count.
    """
    _RATING = {"critical": "CRITICAL", "high": "HIGH", "medium": "MODERATE",
               "low": "LOW", "info": "LOW"}
    dominant = _dominant_severity(histogram_totals)
    if dominant is None:
        return "LOW", "no findings"
    rating = _RATING[dominant]
    n = histogram_totals.get(dominant, 0)
    note = f"{n} {dominant}-severity finding{'' if n == 1 else 's'}"
    return rating, note


def select_top_risks(visible: list[Finding], *, limit: int = 5) -> list[ExecRisk]:
    """Deterministically select the executive top-N risks from the VISIBLE findings.

    Grouped by stable key ``f"{source}|{group_key}"`` (check_id-or-title, so the
    same issue collapses across hosts); ranked by severity desc, then
    distinct-host count desc, then key asc — a total order independent of input
    ordering, so the summary stage and the renderer always select the same set.
    ``ref`` is the list index (the handle the LLM keys its notes on); the stage
    re-binds each returned note to ``key`` so the merge survives a later selection
    shift. ``why`` is left blank here and filled by build_executive_context.
    """
    groups: dict[str, dict] = {}
    for f in visible:
        key = f"{f.source}|{f.group_key}"
        g = groups.get(key)
        if g is None:
            g = {"title": f.title, "source": f.source, "severity": f.severity, "hosts": set()}
            groups[key] = g
        elif _SEV_RANK.get(f.severity, 0) > _SEV_RANK.get(g["severity"], 0):
            g["severity"] = f.severity  # keep the worst severity in the group
        if f.host:
            g["hosts"].add(f.host)
    ordered = sorted(
        groups.items(),
        key=lambda kv: (-_SEV_RANK.get(kv[1]["severity"], 0), -len(kv[1]["hosts"]), kv[0]),
    )
    risks: list[ExecRisk] = []
    for ref, (key, g) in enumerate(ordered[:limit]):
        hosts = tuple(sorted(g["hosts"]))
        risks.append(ExecRisk(
            ref=ref, key=key, title=g["title"], source=g["source"],
            severity=g["severity"], hosts=hosts, host_count=len(hosts),
        ))
    return risks


def _embed_logo(logo_path: str | None) -> str | None:
    """base64 data-URI for an operator logo so executive.html stays self-contained.
    Best-effort — a missing/unreadable file just yields no logo (never raises)."""
    if not logo_path:
        return None
    try:
        p = Path(logo_path)
        data = p.read_bytes()
        mime = mimetypes.guess_type(p.name)[0] or "image/png"
        return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"
    except Exception:
        return None


def build_executive_context(
    *,
    run_meta: dict[str, Any],
    histogram_totals: dict[str, int],
    visible: list[Finding],
    recon: dict[str, list],
    coverage_strip: list[dict],
    report_cfg: "ReportConfig | None" = None,
    exec_summary: ExecutiveSummary | None = None,
) -> dict[str, Any]:
    """Build the executive one-pager context: deterministic core (ALWAYS complete)
    plus an optional AI prose overlay merged by stable key. `visible` MUST be the
    same suppression-filtered finding list the technical report uses."""
    rating, base_note = posture_rating(histogram_totals)

    # Enrich the volume note with the dominant bucket's distinct-host count.
    dominant = _dominant_severity(histogram_totals)
    volume_note = base_note
    if dominant is not None:
        dom_hosts = {f.host for f in visible if f.severity == dominant and f.host}
        if dom_hosts:
            volume_note = f"{base_note}, {len(dom_hosts)} host{'' if len(dom_hosts) == 1 else 's'}"

    risks = select_top_risks(visible)

    # AI overlay (best-effort): merge notes by stable key; fall back to templated prose.
    ai_usable = bool(exec_summary and exec_summary.usable)
    ai_why = {n.key: n.why for n in (exec_summary.risk_notes if ai_usable else []) if n.key and n.why}
    enriched: list[ExecRisk] = []
    for r in risks:
        why = ai_why.get(r.key) or _WHY_BY_SOURCE.get(r.source, _DEFAULT_WHY)
        enriched.append(ExecRisk(
            ref=r.ref, key=r.key, title=r.title, source=r.source, severity=r.severity,
            hosts=r.hosts, host_count=r.host_count, why=why,
        ))

    scope = ", ".join(run_meta.get("roots") or [])
    org_name = (report_cfg.org_name if report_cfg else None) or scope or "—"
    classification = (report_cfg.classification if report_cfg else "Confidential") or "Confidential"
    logo_data_uri = _embed_logo(report_cfg.logo_path if report_cfg else None)

    # Narrative paragraph: AI when usable+non-empty, else deterministic.
    counts_sentence = ", ".join(
        f"{histogram_totals.get(s, 0)} {s}" for s in _SEVERITIES if histogram_totals.get(s, 0)
    ) or "no findings of note"
    det_narrative = (
        f"This external application-security assessment of {scope or 'the in-scope estate'} "
        f"rates the overall posture {rating} ({counts_sentence}). "
        f"The most significant exposures are summarized below."
    )
    narrative = (exec_summary.posture_narrative.strip()
                 if (ai_usable and exec_summary.posture_narrative.strip()) else det_narrative)

    # Recommendations: AI when present, else deterministic themes from the top risks' sources.
    if ai_usable and exec_summary.recommendations:
        recommendations = list(exec_summary.recommendations)
    else:
        seen: set[str] = set()
        recommendations = []
        for r in risks:
            theme = _RECO_BY_SOURCE.get(r.source)
            if theme and theme not in seen:
                seen.add(theme)
                recommendations.append(theme)

    return {
        "org_name": org_name,
        "classification": classification,
        "logo_data_uri": logo_data_uri,
        "scope": scope,
        "date": run_meta.get("finished_at") or run_meta.get("started_at") or "",
        "rating": rating,
        "volume_note": volume_note,
        "counts": {s: histogram_totals.get(s, 0) for s in _SEVERITIES},
        "scale": {
            "live": len(recon.get("live") or []),
            "dead": len(recon.get("dead") or []),
            "live_servers": len(recon.get("live_servers") or []),
        },
        "coverage_strip": coverage_strip,
        "narrative": narrative,
        "risks": enriched,
        "recommendations": recommendations,
        "ai_used": ai_usable,
    }

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
    `severity_histogram` and the `ScanState` liveness helpers (live/dead); the
    per-asset failures harvested into `state.errors` give truthful error counts.
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
            "live": len(state.live()),
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
    report_cfg: "ReportConfig | None" = None,
    exec_summary: ExecutiveSummary | None = None,
) -> dict[str, Any]:
    live = [a for a in triaged if a.status == "live"]
    dead = [a for a in triaged if a.status == "dead"]

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

    histogram_totals = {sev: sum(by_src.values()) for sev, by_src in histogram.items()}
    recon_ctx = {
        "live": live,
        "dead": dead,
        "wildcards": wildcards,
        "live_servers": live_servers,
    }
    # Executive one-pager context (deterministic core + optional AI overlay), built
    # from the SAME `visible` list so the technical and executive views never diverge.
    executive = build_executive_context(
        run_meta=run_meta,
        histogram_totals=histogram_totals,
        visible=visible,
        recon=recon_ctx,
        coverage_strip=coverage_strip,
        report_cfg=report_cfg,
        exec_summary=exec_summary,
    )

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
        "recon": recon_ctx,
        "histogram": histogram,
        "histogram_totals": histogram_totals,
        "executive": executive,
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
