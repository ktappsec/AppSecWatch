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

from appsecwatch.ai.client import LLMClient, LLMError
from appsecwatch.ai.prompts import (
    build_profile_prompt,
    build_summary_prompt,
    build_supply_chain_prompt,
    build_triage_prompt,
)
from appsecwatch.ai.policy import (
    POLICY_CHECK_IDS,
    looks_like_csp,
    policy_verdict,
    protected_control,
)
from appsecwatch.ai.schemas import AIResponse
from appsecwatch.config import LLMConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import (
    AIFindingVerdict,
    AppProfile,
    CrawlerArtifact,
    ExecutiveSummary,
    Finding,
    LiveWebServer,
    PageSignals,
)
from appsecwatch.audit.cookies import is_infra_cookie
from appsecwatch.audit.taxonomy import classify
from appsecwatch.util.domains import etld_plus_one, host_to_filename

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)

# Ceiling on AI-INVENTED finding severity, per source. The model routinely inflates
# its own findings to critical (e.g. a missing header → "critical") — a mirror of the
# suppression ceiling that already caps what the AI may HIDE. Deterministic sources
# keep the full range; only ai_headers/ai_supply_chain are clamped, so the AI can
# never unilaterally drive a CRITICAL posture. See DESIGN.md / AI-layer audit.
_AI_SEV_CEILING = {"ai_headers": "high", "ai_supply_chain": "high"}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# AI findings carry no rule check_id; we derive a stable one from the finding's
# TITLE (slugified) so identical issues dedup/group across hosts and become
# class-suppressible. The title — not the model's free-form `type` tag — is the
# cross-host-stable signal: the per-host LLM calls keep the human title consistent
# for the same issue but routinely emit a *different* `type` slug, which (when used
# as the key) split two visibly-identical findings into separate report rows. A
# blank title → None (falls back to raw-title grouping).
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
    """Extract the first top-level JSON object, tolerant of markdown fences AND of
    trailing content after the object.

    Some models emit a valid object then append a second object or commentary on a
    following line (`{...}\\n{...}`); a strict ``json.loads`` over the whole blob then
    raises 'Extra data' and the call degrades. ``raw_decode`` parses exactly one value
    from the first ``{`` and ignores whatever follows, recovering those responses."""
    text = text.strip()
    m = _JSON_FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()
    start = text.find("{")
    if start != -1:
        try:
            obj, _end = json.JSONDecoder().raw_decode(text, start)
            return json.dumps(obj)
        except json.JSONDecodeError:
            pass
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

    Two classes of finding are omitted entirely — never offered to the AI, so they
    can never be hidden, and they don't inflate the prompt:
      - severity above the ceiling (`max_sev_rank`);
      - the `POLICY_CHECK_IDS` classes, which `ai.policy` decides deterministically
        (the LLM flipped its verdict on them run-to-run — see policy.py).
    """
    payload: list[dict[str, Any]] = []
    ref_map: dict[int, Finding] = {}
    ref = 0
    for f in findings:
        if _SEV_RANK.get(f.severity, 99) > max_sev_rank:
            continue
        if (f.check_id or "").strip().lower() in POLICY_CHECK_IDS:
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
    protect_expected_controls: bool = True,
) -> tuple[int, int]:
    """Attach AI verdicts to deterministic findings (mutates in place).

    A verdict is honored (finding hidden) when suppression is enabled, the AI
    marked it suppressed with sufficient confidence, the finding is not a
    protected expected control on a sensitive host (see `ai.policy`), and — only
    when `require_profile` — the host has a usable, non-low-confidence profile.
    Otherwise the AI's opinion is attached as advisory (suppressed=False) and the
    finding stays visible. Returns (hidden, declined_as_protected).
    """
    min_rank = _CONF_RANK.get(min_confidence, 1)
    profile_ok = (not require_profile) or (
        profile is not None and profile.usable and profile.confidence != "low"
    )
    hidden = 0
    declined = 0
    for s in suppressions:
        f = ref_map.get(s.ref)
        if f is None:
            continue
        # On an app handling auth/PII/payments, a control the app is EXPECTED to have
        # is never hidden on the AI's say-so (the model talked itself past `hsts.weak`
        # on banking hosts by inventing a preload threshold). Verdict still attached,
        # advisory — the call stays auditable.
        control = protected_control(f, profile) if protect_expected_controls else None
        gate_ok = (
            enabled and s.suppressed and profile_ok and control is None
            and _CONF_RANK.get(s.confidence, 0) >= min_rank
        )
        reason = s.reason
        if control is not None and s.suppressed:
            declined += 1
            reason = (
                f"AI suppression declined — {control} is an expected control on this app "
                f"(handles auth/PII/payments). AI's reason: {s.reason or '(none given)'}"
            )
        f.ai_verdict = AIFindingVerdict(
            suppressed=gate_ok, confidence=s.confidence, reason=reason,
            source="ai_triage",
        )
        if gate_ok:
            hidden += 1
    return hidden, declined


def _apply_policy(findings: list[Finding], profile: AppProfile | None) -> int:
    """Deterministic verdicts for the withheld classes (`ai.policy`). Returns hidden.

    These findings never reach the LLM, so this is the ONLY thing that can hide them.
    Never overwrites an existing verdict (the liveness/coverage gate and manual
    suppression own their findings)."""
    hidden = 0
    for f in findings:
        if f.ai_verdict is not None:
            continue
        verdict = policy_verdict(f, profile)
        if verdict is not None:
            f.ai_verdict = verdict
            hidden += 1
    return hidden


def _ai_slug(text: str) -> str:
    return _AI_CHECK_SLUG_RE.sub("-", (text or "").strip().lower()).strip("-")


def _ai_check_id(source: str, finding_class: str) -> str:
    """Stable per-issue id for an AI finding, derived from its controlled-taxonomy
    CLASS (source.class). Two hosts — or two scans — reporting the same issue get
    the same class → the same id → they collapse to one grouped row and correlate
    across scans. (Deriving it from the model's free-text title/type instead splits
    them whenever the LLM varies the wording between the independent per-host/scan
    calls — the regression this replaced.)"""
    return f"{source}.{finding_class}"


def _ai_evidence_cookie(ev: dict[str, Any]) -> str | None:
    """Best-effort cookie NAME from an AI finding's evidence, for infra-cookie
    filtering. The model puts the cookie under any of several keys
    (`cookie_name`/`cookie`/`name`/`set-cookie`/`set_cookie`/`value`) as either a bare
    name or a full Set-Cookie string — take the token before '='. Missing the
    `set-cookie`/`value` keys let ~50 F5 infra cookies slip the drop-guard."""
    raw = (
        ev.get("cookie_name") or ev.get("cookie") or ev.get("name")
        or ev.get("set-cookie") or ev.get("set_cookie") or ev.get("value")
    )
    if not isinstance(raw, str):
        return None
    return raw.split("=", 1)[0].strip()


def _ai_findings_to_findings(
    host: str, source: str, ai_resp: AIResponse, *, drop_csp: bool = False
) -> list[Finding]:
    out: list[Finding] = []
    for f in ai_resp.findings:
        # Drop AI-fabricated non-findings (positive/absence observations, analyst
        # reminders) and load-balancer/WAF/RUM cookie noise — high-signal only.
        # The non-finding gate keys on the model's `type` class (not the grouping
        # id, which is now title-derived).
        if _ai_slug(f.type) in _AI_NONFINDING_TYPES:
            continue
        cookie = _ai_evidence_cookie(f.evidence)
        if cookie and is_infra_cookie(cookie):
            continue
        # When the deterministic `csp` scanner ran, it OWNS the CSP rows. The model
        # re-emitted them as its own findings (~69 duplicate rows in the audited runs)
        # despite the prompt rule — this is the code-level backstop.
        if drop_csp and looks_like_csp(f.type, f.finding_class, f.title):
            continue
        ev = f.evidence | {"type": f.type}
        if f.finding_class:
            ev = ev | {"class": f.finding_class}   # honored by classify() when valid
        # Clamp AI-invented severity to the per-source ceiling (backstop against the
        # model minting its own criticals; see _AI_SEV_CEILING).
        ceiling = _AI_SEV_CEILING.get(source)
        severity = f.severity
        if ceiling and _SEV_RANK.get(severity, 0) > _SEV_RANK[ceiling]:
            severity = ceiling  # type: ignore[assignment]
        finding = Finding(
            source=source,  # type: ignore[arg-type]
            host=host,
            severity=severity,
            title=f.title,
            description=f.description,
            evidence=ev,
        )
        # Anchor identity on the controlled taxonomy class (coerces an out-of-vocab
        # or missing class), not the drifting title.
        cat, cls = classify(finding)
        finding.finding_class = cls
        finding.category = cat
        finding.check_id = _ai_check_id(source, cls)
        out.append(finding)
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
    language: str = "en",
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
                language=language,
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
    language: str = "en",
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
        system, user = build_summary_prompt(posture, counts, scale, risks, prompt_overrides,
                                             language=language)
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
    protect_expected_controls: bool = True,
    csp_covered: bool = False,
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

    The deterministic `ai.policy` layer rides along with triage: the flip-prone
    low-value header classes are withheld from the prompt and decided in Python,
    and an AI verdict that would hide an expected control on an auth/PII/payments
    host is declined (`protect_expected_controls`). `csp_covered` (the deterministic
    `csp` scanner ran) drops AI-emitted CSP duplicates.

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
    policy_hidden_total = 0
    declined_total = 0

    async def per_host(host: str, w: dict[str, Any]) -> None:
        nonlocal hidden_total, policy_hidden_total, declined_total
        profile = profiles.get(host)
        async with sem:
            # Prompt 1 — triage: cross-source FP suppression + new header findings.
            payload, ref_map = _suppressable_payload(
                findings_map.get(host, []), max_sev_rank
            )
            if do_triage:
                # Deterministic pass first: the withheld low-value header classes are
                # decided here, not by the model (they aren't in `payload` at all).
                # No LLM involved, so it holds even when the call below degrades.
                if suppress:
                    policy_hidden_total += _apply_policy(
                        findings_map.get(host, []), profile
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
                    triage_findings.extend(_ai_findings_to_findings(
                        host, "ai_headers", result, drop_csp=csp_covered,
                    ))
                    # Soft-suppress deterministic findings the AI flagged as FP
                    # (gated). A degrade never reaches here, so nothing is hidden.
                    hidden, declined = _apply_suppressions(
                        ref_map, result.suppressions, profile,
                        enabled=suppress, min_confidence=suppress_min_confidence,
                        require_profile=require_profile,
                        protect_expected_controls=protect_expected_controls,
                    )
                    hidden_total += hidden
                    declined_total += declined
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
        + (f", {policy_hidden_total} suppressed by policy (N/A on this app type)"
           if policy_hidden_total else "")
        + (f", {declined_total} AI suppression(s) declined (expected control on a "
           f"sensitive app)" if declined_total else "")
        + (f", {len(call_errors)} degraded call(s)" if call_errors else "")
    )
    return triage_findings, supply_findings, call_errors
