"""Recon-phase stages."""
from __future__ import annotations

import json
from pathlib import Path

from watchtower.config import WatchTowerConfig
from watchtower.logging import RunLogger
from watchtower.models import TriagedAsset
from watchtower.recon.resolve import run_dnsx
from watchtower.recon.subdomains import run_subfinder
from watchtower.recon.tls_san import tlsx_refeed_loop
from watchtower.recon.triage import triage_records
from watchtower.recon.web_probe import run_httpx
from watchtower.stages.base import Stage
from watchtower.util.ipinfo import IPInfoLookup


class SubfinderStage(Stage):
    name = "recon.subfinder"

    def _path(self, run_dir: Path) -> Path:
        return run_dir / "01_recon" / "subfinder.txt"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        state.subdomains = await run_subfinder(
            cfg.roots, self._path(run_dir), cfg.tools.subfinder, log
        )


async def _dnsx_and_triage(
    names: list[str], iter_idx: int,
    run_dir: Path, cfg: WatchTowerConfig, ipinfo: IPInfoLookup, log: RunLogger,
) -> list[TriagedAsset]:
    suffix = f"-iter{iter_idx}" if iter_idx else ""
    out = run_dir / "01_recon" / f"dnsx{suffix}.jsonl"
    records = await run_dnsx(names, out, cfg.tools.dnsx, log)
    return triage_records(records, cfg.roots, ipinfo)


class DnsxAndTriageStage(Stage):
    """First-pass dnsx + triage on the full subdomain set."""
    name = "recon.dnsx-triage"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        # Always include the roots themselves (subfinder also adds them, but it's
        # optional now — when skipped, the roots are the only candidates → a quick
        # scan of exactly what was requested).
        roots = {r.strip().lower().rstrip(".") for r in cfg.roots}
        names = sorted(set(state.subdomains) | roots)
        triaged = await _dnsx_and_triage(names, 0, run_dir, cfg, ipinfo, log)
        state.triaged = triaged


class TlsxLoopStage(Stage):
    """The bounded re-feed loop. Replaces in-scope assets with the final set."""
    name = "recon.tlsx-loop"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        async def resolve(names: list[str], iteration: int) -> list[TriagedAsset]:
            return await _dnsx_and_triage(names, iteration, run_dir, cfg, ipinfo, log)

        initial_in_scope = state.in_scope()
        final_in_scope, wildcards, certs = await tlsx_refeed_loop(
            initial_in_scope, cfg.roots, cfg.tools.tlsx,
            run_dir / "01_recon", log, resolve,
        )
        state.tls_certs = certs

        # Merge: post-loop in_scope set replaces initial; shadow_it + dead from
        # the initial pass are kept.
        seen = {a.fqdn for a in final_in_scope}
        merged: list[TriagedAsset] = list(final_in_scope)
        for a in state.triaged:
            if a.fqdn not in seen and a.bucket != "in_scope":
                merged.append(a)
                seen.add(a.fqdn)
        state.triaged = merged
        state.wildcards = wildcards

        # Persist combined triage.json (overwrites the first-pass version).
        out = run_dir / "01_recon" / "triage.json"
        out.write_text(json.dumps({
            "in_scope":  [a.model_dump() for a in state.in_scope()],
            "shadow_it": [a.model_dump() for a in state.shadow_it()],
            "dead":      [a.model_dump() for a in state.dead()],
            "wildcards": state.wildcards,
        }, indent=2))


class HttpxStage(Stage):
    name = "recon.httpx"

    def _path(self, run_dir: Path) -> Path:
        return run_dir / "01_recon" / "httpx.jsonl"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        hx = cfg.tools.httpx
        fqdns = [a.fqdn for a in state.in_scope()]
        # Outer subprocess timeout scaled to work ÷ concurrency, so slow profiles
        # (paranoid = 1 thread) aren't killed mid-pass. Floor 600s. Without this,
        # a low-thread profile on a large host set hits the 600s kill → 0 live.
        budget = max(600.0, len(fqdns) / max(1, hx.threads) * hx.timeout * 1.5)
        servers, signals = await run_httpx(
            fqdns,
            self._path(run_dir),
            hx,
            log,
            timeout=budget,
            user_agent=cfg.identity.effective_user_agent(),
            extra_headers=cfg.identity.effective_headers(),
        )
        state.live_servers = servers
        state.page_signals = signals
