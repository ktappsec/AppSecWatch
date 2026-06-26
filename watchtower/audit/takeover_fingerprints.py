"""Deterministic subdomain-takeover detection over the stored CNAME chain.

Complements the nuclei `http/takeovers/` templates, which require a *resolving*
host + a live HTTP body fingerprint (so they cover the live/resolving class). This
covers the class nuclei structurally cannot: a **dangling CNAME** — a host with no
A records (a `dead` record, i.e. the CNAME target is NXDOMAIN) that still points
at a claimable SaaS provider. No network: matches `TriagedAsset.cname_chain`
against a bundled provider DB (`data/takeover_fingerprints.json`, derived from
can-i-take-over-xyz). Emits `source='takeover'` Findings.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from watchtower.models import Finding, TriagedAsset

_DB_PATH = Path(__file__).parent / "data" / "takeover_fingerprints.json"


@lru_cache(maxsize=1)
def load_db() -> list[dict[str, Any]]:
    return json.loads(_DB_PATH.read_text()).get("services", [])


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _cname_matches(hop: str, suffix: str) -> bool:
    """Dot-boundary suffix match so `evil-github.io.attacker.com` doesn't match
    `github.io`."""
    hop = hop.lower().rstrip(".")
    suffix = suffix.lower().strip(".")
    return bool(suffix) and (hop == suffix or hop.endswith("." + suffix))


def scan_cname_takeovers(
    assets: list[TriagedAsset], db: list[dict[str, Any]] | None = None
) -> list[Finding]:
    """Return takeover Findings for dangling CNAMEs pointing at known providers.

    `assets` should be the **dead** bucket (no A records → CNAME target NXDOMAIN).
    A host whose CNAME chain matches a claimable provider is a takeover candidate;
    severity is `high` for currently-claimable services, `medium` (review) for
    edge-case/fixed ones.
    """
    services = db if db is not None else load_db()
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for a in assets:
        chain = getattr(a, "cname_chain", None) or []
        host = getattr(a, "fqdn", None)
        if not chain:
            continue
        for hop in chain:
            for svc in services:
                if not any(_cname_matches(hop, s) for s in svc.get("cname", [])):
                    continue
                name = svc["service"]
                if (host, name) in seen:
                    break
                seen.add((host, name))
                vulnerable = svc.get("vulnerable", True)
                sev = "high" if vulnerable else "medium"
                if vulnerable:
                    desc = (
                        f"{host} has no A records (dangling) but its CNAME points to "
                        f"{hop} ({name}). A dangling CNAME to a claimable {name} "
                        f"resource is a subdomain-takeover risk — register the target "
                        f"to confirm/remediate."
                    )
                else:
                    desc = (
                        f"{host} has a dangling CNAME to {hop} ({name}); {name} is an "
                        f"edge case per can-i-take-over-xyz — review whether the "
                        f"resource is still claimable."
                    )
                findings.append(Finding(
                    source="takeover", host=host, severity=sev,
                    title=f"Dangling CNAME → {name} (possible subdomain takeover)",
                    description=desc,
                    evidence={
                        "service": name, "cname": hop,
                        "nxdomain_claimable": svc.get("nxdomain", False),
                        "reference": svc.get("reference", ""),
                    },
                    check_id=f"takeover.{_slug(name)}",
                ))
                break  # one service per hop
    return findings
