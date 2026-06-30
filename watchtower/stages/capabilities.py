"""Capability registry + selection resolution (DESIGN.md §2.8).

Capability tokens are the stable, user-facing names that `--only`/`--skip` (and
the `only=`/`skip=` API params) operate on, decoupled from internal stage names.

Two levels of granularity:
  * **Parent tokens** — the six capabilities: `recon, takeovers, tls, nuclei,
    supply-chain, ai`. Selecting a parent runs all of its sub-steps.
  * **Sub-tokens** — finer slices of three of them, dotted:
      - `recon.subfinder`, `recon.dns`, `recon.tlsx`, `recon.httpx`
      - `ai.profile`, `ai.triage`, `ai.supply-chain`  (`ai.headers` is a
        deprecated alias of `ai.triage`)
      - `nuclei.critical|high|medium|low` (and opt-in `nuclei.info`) → `-severity`
    Selecting a sub-token runs just that slice (plus its dependencies).

This module owns the token vocabulary, the token→stage mapping, dependency
resolution (auto-include), discovery-only detection, and the coverage manifest.
Both the CLI and the runner route through `resolve_selection`, so selection logic
lives in exactly one place.

Stage factories import their (heavy) stage classes lazily, so importing this
module — and calling `resolve_selection` — stays free of playwright/sslscan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from watchtower.config import WatchTowerConfig
from watchtower.stages.base import Stage

# Phases the registry covers, in pipeline order. The recon spine and the
# pre-audit ai.profile stage are framework-special (handled in build_pipeline),
# not registry entries.
PHASE_ORDER = ("takeovers", "audit", "ai-analyze")

# ---- Sub-token vocabulary ------------------------------------------------- #
# recon spine steps, in execution order. subfinder→dns→httpx are the mandatory
# chain whenever any audit/AI capability runs; tlsx (cert-SAN re-feed) is the one
# optional enrichment you may drop with `--skip recon.tlsx`.
RECON_STEPS = ("subfinder", "dns", "tlsx", "httpx")
# httpx needs triaged targets (it probes state.live()), so dns+httpx are the
# floor. subfinder (enumeration) + tlsx are optional → skipping subfinder = a quick
# scan of exactly the roots/assets given.
RECON_REQUIRED = ("dns", "httpx")
RECON_OPTIONAL = ("subfinder", "tlsx")

AI_STEPS = ("profile", "triage", "supply-chain", "summary")

# Deprecated capability tokens → their current name. Applied before validation so
# saved scan-templates/schedules that stored the old token keep working.
_TOKEN_ALIASES = {"ai.headers": "ai.triage"}

# Deterministic security-header checks (the `headers` capability) split into a
# CSP analysis and the OWASP best-practice catalog. `cors` is RESERVED for a
# follow-up (active Origin-reflection probing) and intentionally not yet here.
HEADER_STEPS = ("csp", "best-practice")

# Parent `nuclei` runs the config's severities (default = these four). Sub-tokens
# override to a subset. `info` is selectable but not part of the parent default.
NUCLEI_SEVERITIES = ("critical", "high", "medium", "low")
NUCLEI_ALL_SEVERITIES = ("critical", "high", "medium", "low", "info")

# parent → its sub-tokens (dotted). Parents not listed here are atomic.
SUBTOKENS: dict[str, tuple[str, ...]] = {
    "recon": tuple(f"recon.{s}" for s in RECON_STEPS),
    "ai": tuple(f"ai.{s}" for s in AI_STEPS),
    "headers": tuple(f"headers.{s}" for s in HEADER_STEPS),
    "nuclei": tuple(f"nuclei.{s}" for s in NUCLEI_ALL_SEVERITIES),
}

AUDIT_CAPS = frozenset({"takeovers", "tls", "nuclei", "supply-chain", "ai", "headers"})


@dataclass(frozen=True)
class Capability:
    """A user-selectable scanning capability.

    factory:    builds the Stage for a given (config, plan). Returns None to skip
                (e.g. `ai` when no analysis sub-steps are active). Imports its
                stage class lazily to keep this module import-light.
    phase:      one of PHASE_ORDER — controls placement + parallelization.
    depends_on: other tokens whose output this one needs; auto-included unless
                the dependency was explicitly skipped.
    """
    factory: Callable[[WatchTowerConfig, "SelectionPlan"], Stage | None]
    phase: str
    depends_on: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SelectionPlan:
    """The resolved sub-step detail build_pipeline needs to configure stages."""
    recon_steps: frozenset[str] = frozenset(RECON_STEPS)
    ai_steps: frozenset[str] = frozenset(AI_STEPS)
    header_steps: frozenset[str] = frozenset(HEADER_STEPS)
    # None → use the config's nuclei severities; a tuple → override (-severity).
    nuclei_severities: tuple[str, ...] | None = None


def _takeovers(cfg: WatchTowerConfig, plan: SelectionPlan) -> Stage:
    from watchtower.stages.audit import TakeoversStage
    return TakeoversStage()


def _tls(cfg: WatchTowerConfig, plan: SelectionPlan) -> Stage:
    from watchtower.stages.audit import SslscanStage
    return SslscanStage()


def _nuclei(cfg: WatchTowerConfig, plan: SelectionPlan) -> Stage:
    from watchtower.stages.audit import NucleiStage
    sev = list(plan.nuclei_severities) if plan.nuclei_severities is not None else None
    return NucleiStage(severities=sev)


def _crawler(cfg: WatchTowerConfig, plan: SelectionPlan) -> Stage:
    from watchtower.stages.audit import CrawlerStage
    return CrawlerStage()


def _headers(cfg: WatchTowerConfig, plan: SelectionPlan) -> Stage | None:
    from watchtower.stages.audit import HeadersStage
    do_csp = "csp" in plan.header_steps
    do_bp = "best-practice" in plan.header_steps
    if not (do_csp or do_bp):
        return None
    return HeadersStage(do_csp=do_csp, do_best_practice=do_bp)


def _ai(cfg: WatchTowerConfig, plan: SelectionPlan) -> Stage | None:
    from watchtower.stages.ai import AIStage
    do_triage = "triage" in plan.ai_steps
    do_supply = "supply-chain" in plan.ai_steps
    if not (do_triage or do_supply):
        return None  # profile-only selection → AIProfileStage covers it
    return AIStage(do_triage=do_triage, do_supply=do_supply)


CAPABILITIES: dict[str, Capability] = {
    "takeovers":    Capability(_takeovers, "takeovers"),
    "tls":          Capability(_tls, "audit"),
    "nuclei":       Capability(_nuclei, "audit"),
    "supply-chain": Capability(_crawler, "audit"),
    "headers":      Capability(_headers, "audit"),
    "ai":           Capability(_ai, "ai-analyze", depends_on=("supply-chain",)),
}

# "recon" is the implicit discovery spine — always a prerequisite, and a
# standalone discovery-only destination via `--only recon`.
ALL_TOKENS: list[str] = ["recon", *CAPABILITIES.keys()]
ALL_SUBTOKENS: list[str] = [t for subs in SUBTOKENS.values() for t in subs]
VALID_TOKENS: frozenset[str] = frozenset(ALL_TOKENS) | frozenset(ALL_SUBTOKENS)


class SelectionError(ValueError):
    """Invalid --only/--skip selection."""


def _split(tokens: set[str]) -> tuple[set[str], dict[str, set[str]]]:
    """Partition a token set into parents and {parent: {leaf,...}}."""
    parents: set[str] = set()
    children: dict[str, set[str]] = {}
    for t in tokens:
        if "." in t:
            parent, leaf = t.split(".", 1)
            children.setdefault(parent, set()).add(leaf)
        else:
            parents.add(t)
    return parents, children


def _check_tokens(tokens: set[str], flag: str) -> None:
    bad = sorted(tokens - VALID_TOKENS)
    if bad:
        raise SelectionError(
            f"unknown capability token(s) for {flag}: {', '.join(bad)}. "
            f"valid tokens: {', '.join(ALL_TOKENS)} "
            f"(sub-tokens: {', '.join(ALL_SUBTOKENS)})"
        )


def _expand_recon(steps: set[str]) -> set[str]:
    """Add the internal prerequisites of selected recon steps (discovery-only).
    subfinder is NOT auto-added — it's optional (enumeration); dns is the floor."""
    s = set(steps)
    if s & {"httpx", "tlsx"}:
        s.add("dns")
    return s


def _resolve_only(only: set[str]):
    parents, children = _split(only)

    ai_steps: set[str] = set()
    if "ai" in parents:
        ai_steps = set(AI_STEPS)
    elif "ai" in children:
        ai_steps = set(children["ai"])

    header_steps: set[str] = set()
    if "headers" in parents:
        header_steps = set(HEADER_STEPS)
    elif "headers" in children:
        header_steps = set(children["headers"])

    if "nuclei" in parents:
        nuclei_sev: set[str] | None = None      # config default
        nuclei_on = True
    elif "nuclei" in children:
        nuclei_sev = set(children["nuclei"])
        nuclei_on = bool(nuclei_sev)
    else:
        nuclei_sev = None
        nuclei_on = False

    takeovers_on = "takeovers" in parents
    tls_on = "tls" in parents
    supply_on = "supply-chain" in parents
    headers_on = bool(header_steps)
    ai_on = bool(ai_steps)

    auto: set[str] = set()
    if "supply-chain" in ai_steps and not supply_on:  # ai.supply-chain needs the crawler
        supply_on = True
        auto.add("supply-chain")

    audit_active = takeovers_on or tls_on or nuclei_on or supply_on or headers_on or ai_on

    if not audit_active:
        # Discovery-only: run exactly the selected recon slice (full spine if the
        # recon parent was named).
        recon_steps = set(RECON_STEPS) if "recon" in parents else _expand_recon(
            children.get("recon", set())
        )
        return set(recon_steps), ai_steps, header_steps, nuclei_sev, {"recon"}, True, auto

    # Audit/AI active → the full recon spine runs (back-compat); any recon
    # sub-tokens in --only are subsumed.
    recon_steps = set(RECON_STEPS)
    caps: set[str] = {"recon"}
    if takeovers_on:
        caps.add("takeovers")
    if tls_on:
        caps.add("tls")
    if nuclei_on:
        caps.add("nuclei")
    if supply_on:
        caps.add("supply-chain")
    if headers_on:
        caps.add("headers")
    if ai_on:
        caps.add("ai")
    return recon_steps, ai_steps, header_steps, nuclei_sev, caps, False, auto


def _resolve_skip(skip: set[str]):
    parents_skip, children_skip = _split(skip)

    recon_skip = children_skip.get("recon", set())
    bad_recon = recon_skip - set(RECON_OPTIONAL)
    if bad_recon:
        raise SelectionError(
            f"only {', '.join('recon.' + s for s in RECON_OPTIONAL)} may be skipped; the spine "
            f"({', '.join('recon.' + s for s in RECON_REQUIRED)}) is mandatory — "
            f"cannot skip: {', '.join('recon.' + s for s in sorted(bad_recon))}"
        )

    recon_steps = set(RECON_STEPS)
    ai_steps = set(AI_STEPS)
    header_steps = set(HEADER_STEPS)
    nuclei_sev: set[str] | None = None
    caps = set(ALL_TOKENS)

    for p in parents_skip:
        caps.discard(p)
        if p == "recon":
            recon_steps = set()
        if p == "headers":
            header_steps = set()

    for opt in RECON_OPTIONAL:
        if opt in recon_skip:
            recon_steps.discard(opt)
    if "ai" in children_skip:
        ai_steps -= children_skip["ai"]
    if "headers" in children_skip:
        header_steps -= children_skip["headers"]
    if "nuclei" in children_skip:
        nuclei_sev = set(NUCLEI_SEVERITIES) - children_skip["nuclei"]

    # A skipped crawler means the AI supply-chain step has no input.
    if "supply-chain" not in caps:
        ai_steps.discard("supply-chain")
    if not ai_steps:
        caps.discard("ai")
    if not header_steps:
        caps.discard("headers")
    if nuclei_sev is not None and not nuclei_sev:
        caps.discard("nuclei")

    audit_active = bool(caps & AUDIT_CAPS)

    if not audit_active:
        return recon_steps, ai_steps, header_steps, nuclei_sev, {"recon"}, True, set()

    # The spine cannot be skipped while anything else runs — re-assert it
    # (minus the optional tlsx, if that was the skip).
    caps.add("recon")
    recon_steps = set(RECON_STEPS)
    for opt in RECON_OPTIONAL:
        if opt in recon_skip:
            recon_steps.discard(opt)
    return recon_steps, ai_steps, header_steps, nuclei_sev, caps, False, set()


def _parent_coverage(
    tok: str, caps: set[str], discovery_only: bool,
    only: set[str] | None, skip: set[str] | None, auto: set[str],
) -> dict:
    ran = tok in caps
    if tok == "recon":
        reason = "discovery-only" if discovery_only else ("prerequisite" if ran else "not run")
    elif ran:
        if tok in auto:
            reason = "auto-included"
        elif only is None and skip is None:
            reason = "default"
        else:
            reason = "user-selected"
    else:
        if discovery_only:
            reason = "discovery-only"
        elif only is not None:
            reason = "excluded by --only"
        elif skip is not None:
            reason = "skipped by --skip"
        else:
            reason = "not run"
    return {"ran": ran, "reason": reason}


def _active_sub(parent: str, plan: SelectionPlan) -> tuple[tuple[str, ...], set[str], set[str]]:
    """(display order, active leaves, applicable leaves for the partial calc)."""
    if parent == "recon":
        return RECON_STEPS, set(plan.recon_steps), set(RECON_STEPS)
    if parent == "ai":
        return AI_STEPS, set(plan.ai_steps), set(AI_STEPS)
    if parent == "headers":
        return HEADER_STEPS, set(plan.header_steps), set(HEADER_STEPS)
    if parent == "nuclei":
        active = set(NUCLEI_SEVERITIES) if plan.nuclei_severities is None else set(plan.nuclei_severities)
        return NUCLEI_ALL_SEVERITIES, active, set(NUCLEI_SEVERITIES)
    return (), set(), set()


def _sub_coverage(parent: str, plan: SelectionPlan, parent_ran: bool) -> tuple[dict, bool]:
    order, active, applicable = _active_sub(parent, plan)
    sub: dict[str, dict] = {}
    for leaf in order:
        ran = parent_ran and leaf in active
        if not parent_ran:
            reason = "parent not run"
        elif ran:
            reason = "selected"
        else:
            reason = "not selected"
        sub[f"{parent}.{leaf}"] = {"ran": ran, "reason": reason}
    partial = parent_ran and ({s for s in applicable if s in active} != applicable)
    return sub, partial


def _build_coverage(
    caps: set[str], plan: SelectionPlan, discovery_only: bool,
    only: set[str] | None, skip: set[str] | None, auto: set[str],
) -> dict[str, dict]:
    cov: dict[str, dict] = {}
    for tok in ALL_TOKENS:
        entry = _parent_coverage(tok, caps, discovery_only, only, skip, auto)
        if tok in SUBTOKENS:
            sub, partial = _sub_coverage(tok, plan, entry["ran"])
            entry["sub"] = sub
            entry["partial"] = partial
        cov[tok] = entry
    return cov


def resolve_selection(
    only: set[str] | None = None,
    skip: set[str] | None = None,
) -> tuple[set[str], dict[str, dict], bool, SelectionPlan]:
    """Resolve a selection to (active capabilities, coverage manifest,
    discovery_only, SelectionPlan).

    Rules (DESIGN.md §2.8.3, extended for sub-tokens):
      - --only and --skip are mutually exclusive.
      - A parent token expands to all its sub-steps; a sub-token runs just that
        slice. Existing parent-only selections behave exactly as before.
      - The recon spine is retained as a prerequisite whenever any audit/AI
        capability runs (subfinder→dns→httpx mandatory; tlsx optional via
        `--skip recon.tlsx`). A selection of recon sub-tokens alone is
        discovery-only.
      - Dependencies auto-include (e.g. `ai.supply-chain` pulls the crawler),
        unless explicitly skipped.
    """
    if only is not None and skip is not None:
        raise SelectionError("--only and --skip are mutually exclusive")

    if only is not None:
        only = {_TOKEN_ALIASES.get(t, t) for t in only}
        _check_tokens(only, "--only")
        recon_steps, ai_steps, header_steps, nuclei_sev, caps, discovery_only, auto = \
            _resolve_only(only)
    elif skip is not None:
        skip = {_TOKEN_ALIASES.get(t, t) for t in skip}
        _check_tokens(skip, "--skip")
        recon_steps, ai_steps, header_steps, nuclei_sev, caps, discovery_only, auto = \
            _resolve_skip(skip)
    else:
        recon_steps, ai_steps, header_steps, nuclei_sev = \
            set(RECON_STEPS), set(AI_STEPS), set(HEADER_STEPS), None
        caps, discovery_only, auto = set(ALL_TOKENS), False, set()

    plan = SelectionPlan(
        recon_steps=frozenset(recon_steps),
        ai_steps=frozenset(ai_steps),
        header_steps=frozenset(header_steps),
        nuclei_severities=tuple(s for s in NUCLEI_ALL_SEVERITIES if s in nuclei_sev)
        if nuclei_sev is not None else None,
    )
    coverage = _build_coverage(caps, plan, discovery_only, only, skip, auto)
    return caps, coverage, discovery_only, plan
