"""Pure cross-scan finding-lifecycle math (no DB, no heavy deps).

Shared by the engine (the report's "N new / M recurring / K resolved" note) and
the server (`api/finding_state.FindingStateManager` persistence), so both compute
the same thing. The one subtle rule lives here: a finding's ABSENCE only counts
toward resolution when the scan actually RAN the capability that produces it —
skipping `headers` must never resolve header findings.
"""
from __future__ import annotations

from appsecwatch.audit.suppress import finding_fingerprint
from appsecwatch.models import Finding

# Finding source → the coverage token(s) whose `ran` flag proves the source could
# have been produced this scan. Most-specific sub-token first, then the parent.
_SOURCE_TOKENS: dict[str, tuple[str, ...]] = {
    "nuclei": ("nuclei",),
    "takeover": ("takeovers",),
    "sslscan": ("tls",),
    "headers": ("headers.best-practice", "headers"),
    "csp": ("headers.csp", "headers"),
    "js_lib": ("supply-chain",),
    "zap": ("zap",),
    "ai_headers": ("ai.triage", "ai"),
    "ai_supply_chain": ("ai.supply-chain", "ai"),
}


def source_ran(source: str, coverage: dict | None) -> bool:
    """True when the capability producing `source` ran this scan (so a finding's
    absence is meaningful). Unknown coverage → True (matches the report's `_ran`
    default for hand-assembled pipelines); an explicitly-skipped capability is
    marked ran=False in coverage, so this returns False and nothing resolves."""
    coverage = coverage or {}
    for tok in _SOURCE_TOKENS.get(source, ()):
        entry = coverage.get(tok)
        if isinstance(entry, dict):
            return bool(entry.get("ran", True))
    return True


def _source_of(fingerprint: str) -> str:
    return fingerprint.split("|", 1)[0]


def diff_findings(
    current: list[Finding],
    prior_open: set[str] | None,
    coverage: dict | None = None,
) -> dict[str, int]:
    """Compare this scan's findings against the previously-open fingerprint set.

    Returns counts ``{new, recurring, resolved}``. `resolved` only counts prior
    fingerprints whose producing source actually ran this scan (see `source_ran`).
    `prior_open` should already be scoped to this scan's target group/roots.
    """
    prior_open = prior_open or set()
    present = {finding_fingerprint(f) for f in current}
    new = present - prior_open
    recurring = present & prior_open
    resolved = {
        fp for fp in (prior_open - present) if source_ran(_source_of(fp), coverage)
    }
    return {"new": len(new), "recurring": len(recurring), "resolved": len(resolved)}
