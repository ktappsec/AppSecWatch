"""AI analyzer: per-host profiling + header/supply-chain fan-out.

Decisions enforced here (DESIGN.md §2.3):
  - A profiling pass infers an AppProfile per host (when ai.profiling is on),
    fed into the analysis prompts. Header analysis is sourced from httpx
    response headers (PageSignals); the supply half needs the crawler's scripts.
  - 1st/3rd-party computed in Python via tldextract BEFORE the LLM sees scripts.
  - Pydantic-validated JSON response. Retry once on parse failure. Graceful
    degrade on second failure — the pipeline never fails. A host that hard-fails
    profiling falls back to the default (context-light) prompts.
  - Per-host calls via asyncio.Semaphore (default cap 4).
"""
from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlparse

from pydantic import ValidationError

from watchtower.ai.client import LLMClient, LLMError
from watchtower.ai.prompts import (
    build_profile_prompt,
    build_summary_prompt,
    build_supply_chain_prompt,
    build_triage_prompt,
)
from watchtower.ai.schemas import AIResponse
from watchtower.config import LLMConfig
from watchtower.logging import RunLogger
from watchtower.models import (
    AIFindingVerdict,
    AppProfile,
    CrawlerArtifact,
    ExecutiveSummary,
    Finding,
    LiveWebServer,
    PageSignals,
)
from watchtower.audit.cookies import is_infra_cookie
from watchtower.util.domains import etld_plus_one, host_to_filename

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# AI findings carry no rule check_id; we derive a stable one from the model's
# `type` tag (slugified) so identical issues dedup/group across hosts and become
# class-suppressible. A blank type → None (falls back to title-based grouping).
_AI_CHECK_SLUG_RE = re.compile(r"[^a-z0-9]+")
# Slugified `type` tags that are NOT vulnerabilities — positive/absence
# observations and analyst "verify X" reminders. Dropped outright (LLM-fabricated,
# not deterministic scanner facts, so nothing to retain/audit).
_AI_NONFINDING_TYPES = frozenset({
    "positive-observation", "no-scripts-loaded", "best-practice-reminder",
    "missing-control-check", "server-config-concern",
})

# All validated-call targets carry an `error`/`usable` contract for graceful degrade.
ValidatedModel = TypeVar("ValidatedModel", AppProfile, AIResponse, ExecutiveSummary)


def _extract_json(text: str) -> str:
    """Be tolerant of LLMs that wrap JSON in markdown fences."""
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    m = _JSON_FENCE_RE.search(text)
    if m:
        return m.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    return text


def _label_party(host_url: str, scripts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    host_etld1 = etld_plus_one(urlparse(host_url).hostname or "")
    labeled = []
    for s in scripts:
        url = s.get("url") or ""
        script_host = urlparse(url).hostname or ""
        script_etld1 = etld_plus_one(script_host)
        party = "1st" if script_etld1 and script_etld1 == host_etld1 else "3rd"
        labeled.append({
            "url": url,
            "party": party,
            "etld_plus_one": script_etld1,
            "status": s.get("status"),
            "initiator_url": s.get("initiator_url"),
        })
    return labeled


async def _validated_call(
    client: LLMClient,
    system: str,
    user: str,
    model_cls: type[ValidatedModel],
    log: RunLogger,
    label: str,
) -> ValidatedModel:
    """Call LLM, parse + validate JSON against `model_cls`. One retry on failure.

    Always returns an instance of `model_cls`. On a hard failure (LLM error or
    unparseable after the retry), the instance has its `error` field set so
    callers can degrade gracefully via `.usable` — no union, no isinstance.
    """
    last_err = ""
    for attempt in (1, 2):
        try:
            raw = await client.chat(system, user, label=label)
        except LLMError as e:
            last_err = str(e)
            log.warn(f"ai {label} LLM error attempt {attempt}: {e}")
            continue

        try:
            parsed = json.loads(_extract_json(raw))
            return model_cls.model_validate(parsed)
        except (json.JSONDecodeError, ValidationError) as e:
            last_err = f"{type(e).__name__}: {e}"
            log.warn(f"ai {label} parse fail attempt {attempt}: {last_err}")
            if attempt == 1:
                user = user + (
                    "\n\nYour previous reply was not valid JSON matching the schema. "
                    "Respond ONLY with the JSON object, nothing else."
                )
                continue

    return model_cls(error=last_err or "unknown LLM failure")


def _suppressable_payload(
    findings: list[Finding], max_sev_rank: int
) -> tuple[list[dict[str, Any]], dict[int, Finding]]:
    """Findings eligible for AI suppression (severity <= ceiling), each tagged with
    an ephemeral integer `ref` the AI references. Returns (payload, ref->finding).

    Findings above the ceiling are omitted entirely — never offered to the AI, so
    they can never be hidden, and they don't inflate the prompt.
    """
    payload: list[dict[str, Any]] = []
    ref_map: dict[int, Finding] = {}
    ref = 0
    for f in findings:
        if _SEV_RANK.get(f.severity, 99) > max_sev_rank:
            continue
        ref_map[ref] = f
        payload.append({
            "ref": ref,
            "source": f.source,
            "severity": f.severity,
            "title": f.title,
            "detail": f.evidence_summary or f.description or "",
            "check_id": f.check_id,
        })
        ref += 1
    return payload, ref_map


def _apply_suppressions(
    ref_map: dict[int, Finding],
    suppressions,
    profile: AppProfile | None,
    *,
    enabled: bool,
    min_confidence: str,
    require_profile: bool,
) -> int:
    """Attach AI verdicts to deterministic findings (mutates in place).

    A verdict is honored (finding hidden) when suppression is enabled, the AI
    marked it suppressed with sufficient confidence, and — only when
    `require_profile` — the host has a usable, non-low-confidence profile.
    Otherwise the AI's opinion is attached as advisory (suppressed=False) and the
    finding stays visible. Returns the count hidden.
    """
    min_rank = _CONF_RANK.get(min_confidence, 1)
    profile_ok = (not require_profile) or (
        profile is not None and profile.usable and profile.confidence != "low"
    )
    hidden = 0
    for s in suppressions:
        f = ref_map.get(s.ref)
        if f is None:
            continue
        gate_ok = (
            enabled and s.suppressed and profile_ok
            and _CONF_RANK.get(s.confidence, 0) >= min_rank
        )
        f.ai_verdict = AIFindingVerdict(
            suppressed=gate_ok, confidence=s.confidence, reason=s.reason,
            source="ai_triage",
        )
        if gate_ok:
            hidden += 1
    return hidden


def _ai_check_id(source: str, type_tag: str) -> str | None:
    slug = _AI_CHECK_SLUG_RE.sub("-", (type_tag or "").strip().lower()).strip("-")
    return f"{source}.{slug}" if slug else None


def _ai_evidence_cookie(ev: dict[str, Any]) -> str | None:
    """Best-effort cookie NAME from an AI finding's evidence, for infra-cookie
    filtering. `cookie`/`cookie_name`/`name` may be a bare name or a full
    Set-Cookie string — take the token before '='."""
    raw = ev.get("cookie_name") or ev.get("cookie") or ev.get("name")
    if not isinstance(raw, str):
        return None
    return raw.split("=", 1)[0].strip()


def _ai_findings_to_findings(host: str, source: str, ai_resp: AIResponse) -> list[Finding]:
    out: list[Finding] = []
    for f in ai_resp.findings:
        check_id = _ai_check_id(source, f.type)
        slug = check_id.split(".", 1)[1] if check_id else ""
        # Drop AI-fabricated non-findings (positive/absence observations, analyst
        # reminders) and load-balancer/WAF/RUM cookie noise — high-signal only.
        if slug in _AI_NONFINDING_TYPES:
            continue
        cookie = _ai_evidence_cookie(f.evidence)
        if cookie and is_infra_cookie(cookie):
            continue
        out.append(Finding(
            source=source,  # type: ignore[arg-type]
            host=host,
            severity=f.severity,
            title=f.title,
            description=f.description,
            evidence=f.evidence | {"type": f.type},
            check_id=check_id,
        ))
    return out


async def profile_all(
    page_signals: dict[str, PageSignals],
    profiles_dir: Path,
    cfg: LLMConfig,
    log: RunLogger,
    concurrency: int = 4,
    prompt_overrides: Mapping[str, str] | None = None,
    surface_by_host: dict[str, dict] | None = None,
    rendered_by_host: dict[str, str] | None = None,
) -> dict[str, AppProfile]:
    """Infer an AppProfile per host from PageSignals. Writes 03_ai/profile/<host>.json.

    A hard failure for a host yields an AppProfile with `error` set (downstream
    falls back to the default prompts for that host).
    """
    profiles_dir.mkdir(parents=True, exist_ok=True)
    if not page_signals:
        log.info("ai.profile: no page signals to profile")
        return {}

    client = LLMClient(cfg)
    sem = asyncio.Semaphore(concurrency)
    profiles: dict[str, AppProfile] = {}

    async def per_host(host: str, signals: PageSignals) -> None:
        async with sem:
            system, user = build_profile_prompt(
                signals, prompt_overrides,
                rendered_text=(rendered_by_host or {}).get(host),
                surface=(surface_by_host or {}).get(host),
            )
            result = await _validated_call(
                client, system, user, AppProfile, log, f"profile[{host}]"
            )
            result.host = host
            profiles[host] = result
            path = profiles_dir / f"{host_to_filename(host)}.json"
            path.write_text(result.model_dump_json(indent=2))

    try:
        await asyncio.gather(*(per_host(h, s) for h, s in page_signals.items()))
    finally:
        await client.close()

    usable = sum(1 for p in profiles.values() if p.usable)
    log.info(f"ai.profile: {usable}/{len(profiles)} hosts profiled (rest degraded to defaults)")
    return profiles


async def summarize_run(
    *,
    posture: dict[str, Any],
    counts: dict[str, int],
    scale: dict[str, int],
    risks: list[dict[str, Any]],
    cfg: LLMConfig,
    log: RunLogger,
    prompt_overrides: Mapping[str, str] | None = None,
) -> ExecutiveSummary:
    """ONE whole-run executive-narrative call (the `ai.summary` capability).

    Returns an ExecutiveSummary; on any failure it carries `error` set so the
    renderer falls back to deterministic prose (the no-gating invariant). `risks`
    is the projected top-risk payload (ref/title/source/severity/host_count); the
    returned notes are keyed by the ephemeral `ref` — the caller re-binds them to
    the stable risk key. The call label `summary` selects `cfg.models['summary']`
    (else the base model)."""
    client = LLMClient(cfg)
    try:
        system, user = build_summary_prompt(posture, counts, scale, risks, prompt_overrides)
        return await _validated_call(client, system, user, ExecutiveSummary, log, "summary")
    finally:
        await client.close()


def _build_work_map(
    live_servers: list[LiveWebServer],
    page_signals: dict[str, PageSignals],
    artifacts: list[CrawlerArtifact],
) -> dict[str, dict[str, Any]]:
    """Merge per-host inputs: headers (httpx-preferred) + scripts (crawler)."""
    work: dict[str, dict[str, Any]] = {}
    for srv in live_servers:
        work.setdefault(srv.host, {"url": srv.url, "headers": {}, "scripts": None})
    for host, ps in page_signals.items():
        w = work.setdefault(host, {"url": f"https://{host}", "headers": {}, "scripts": None})
        if ps.headers:
            w["headers"] = ps.headers
    for art in artifacts:
        w = work.setdefault(art.host, {"url": art.url, "headers": {}, "scripts": None})
        w["scripts"] = art.scripts
        if not w["headers"]:
            w["headers"] = art.headers
        if art.url:
            w["url"] = art.url
    return work


async def analyze_all(
    *,
    live_servers: list[LiveWebServer],
    page_signals: dict[str, PageSignals],
    artifacts: list[CrawlerArtifact],
    profiles: dict[str, AppProfile],
    cfg: LLMConfig,
    triage_dir: Path,
    supply_dir: Path,
    log: RunLogger,
    concurrency: int = 4,
    do_triage: bool = True,
    do_supply: bool = True,
    findings_by_host: dict[str, list[Finding]] | None = None,
    suppress: bool = False,
    suppress_min_confidence: str = "medium",
    suppress_max_severity: str = "medium",
    require_profile: bool = False,
    prompt_overrides: Mapping[str, str] | None = None,
) -> tuple[list[Finding], list[Finding], list[tuple[str, str]]]:
    """Run triage + supply-chain analysis per host, fanned out via semaphore.

    Triage runs for any host that has response headers (httpx PageSignals, falling
    back to crawler headers) OR any deterministic finding eligible for suppression
    (severity <= the ceiling). It suppresses false-positives across ALL sources
    (nuclei/TLS/js_lib/headers/takeover) by ephemeral `ref`, and may add new header
    findings. Supply-chain analysis runs only for hosts the crawler captured
    scripts for. The per-host AppProfile (if usable) makes both prompts
    context-aware.

    `do_triage` / `do_supply` gate each analysis independently (the
    `ai.triage` / `ai.supply-chain` sub-tokens). When a half is off its prompt is
    skipped entirely — no LLM calls, no findings.

    Returns:
        (triage_findings, supply_chain_findings, call_errors). call_errors is a
        list of (host, message) for hosts whose triage/supply call hard-failed
        (degraded), so the stage can surface them in the consolidated error sink.
    """
    triage_dir.mkdir(parents=True, exist_ok=True)
    supply_dir.mkdir(parents=True, exist_ok=True)

    findings_map = findings_by_host or {}
    work = _build_work_map(live_servers, page_signals, artifacts)
    # Hosts with findings but no live/crawler entry still deserve triage.
    for host in findings_map:
        work.setdefault(host, {"url": f"https://{host}", "headers": {}, "scripts": None})
    if not work:
        log.info("ai: nothing to analyze")
        return [], [], []

    max_sev_rank = _SEV_RANK.get(suppress_max_severity, 2)
    client = LLMClient(cfg)
    sem = asyncio.Semaphore(concurrency)
    triage_findings: list[Finding] = []
    supply_findings: list[Finding] = []
    call_errors: list[tuple[str, str]] = []
    hidden_total = 0

    async def per_host(host: str, w: dict[str, Any]) -> None:
        nonlocal hidden_total
        profile = profiles.get(host)
        async with sem:
            # Prompt 1 — triage: cross-source FP suppression + new header findings.
            payload, ref_map = _suppressable_payload(
                findings_map.get(host, []), max_sev_rank
            )
            if do_triage and (w["headers"] or payload):
                sys_msg, user_msg = build_triage_prompt(
                    w["url"], w["headers"], payload, profile, prompt_overrides
                )
                result = await _validated_call(
                    client, sys_msg, user_msg, AIResponse, log, f"triage[{host}]"
                )
                t_path = triage_dir / f"{host_to_filename(host)}.json"
                t_path.write_text(result.model_dump_json(indent=2))
                if result.usable:
                    triage_findings.extend(_ai_findings_to_findings(host, "ai_headers", result))
                    # Soft-suppress deterministic findings the AI flagged as FP
                    # (gated). A degrade never reaches here, so nothing is hidden.
                    hidden_total += _apply_suppressions(
                        ref_map, result.suppressions, profile,
                        enabled=suppress, min_confidence=suppress_min_confidence,
                        require_profile=require_profile,
                    )
                else:
                    call_errors.append((host, f"triage analysis degraded: {result.error}"))

            # Prompt 2 — supply chain (only when the crawler captured scripts)
            if do_supply and w["scripts"] is not None:
                labeled = _label_party(w["url"], w["scripts"])
                sys_msg, user_msg = build_supply_chain_prompt(
                    w["url"], labeled, profile, prompt_overrides
                )
                result = await _validated_call(
                    client, sys_msg, user_msg, AIResponse, log, f"supply[{host}]"
                )
                s_path = supply_dir / f"{host_to_filename(host)}.json"
                s_path.write_text(result.model_dump_json(indent=2))
                if result.usable:
                    supply_findings.extend(_ai_findings_to_findings(host, "ai_supply_chain", result))
                else:
                    call_errors.append((host, f"supply-chain analysis degraded: {result.error}"))

    try:
        await asyncio.gather(*(per_host(h, w) for h, w in work.items()))
    finally:
        await client.close()

    log.info(
        f"ai: triage={len(triage_findings)} findings, supply_chain={len(supply_findings)} findings"
        + (f", {hidden_total} deterministic finding(s) suppressed" if hidden_total else "")
        + (f", {len(call_errors)} degraded call(s)" if call_errors else "")
    )
    return triage_findings, supply_findings, call_errors
