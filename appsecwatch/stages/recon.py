"""Recon-phase stages."""
from __future__ import annotations

import json
from pathlib import Path

from appsecwatch.config import AppSecWatchConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import ProbeCoverage, TriagedAsset
from appsecwatch.recon.resolve import run_dnsx
from appsecwatch.recon.subdomains import run_subfinder
from appsecwatch.recon.tls_san import tlsx_refeed_loop
from appsecwatch.recon.triage import triage_records
from appsecwatch.recon.web_probe import ProbeProgress, run_httpx
from appsecwatch.stages.base import Stage
from appsecwatch.util.ipinfo import IPInfoLookup


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
    run_dir: Path, cfg: AppSecWatchConfig, ipinfo: IPInfoLookup, log: RunLogger,
) -> list[TriagedAsset]:
    suffix = f"-iter{iter_idx}" if iter_idx else ""
    out = run_dir / "01_recon" / f"dnsx{suffix}.jsonl"
    records = await run_dnsx(names, out, cfg.tools.dnsx, log)
    return triage_records(records, ipinfo)


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
    """The bounded SAN re-feed loop. Replaces the live set with the post-loop
    (expanded) set; dead records from the first pass are kept."""
    name = "recon.tlsx-loop"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        async def resolve(names: list[str], iteration: int) -> list[TriagedAsset]:
            return await _dnsx_and_triage(names, iteration, run_dir, cfg, ipinfo, log)

        initial_live = state.live()
        final_live, wildcards, certs = await tlsx_refeed_loop(
            initial_live, cfg.roots, cfg.tools.tlsx,
            run_dir / "01_recon", log, resolve,
        )
        state.tls_certs = certs

        # Merge: the post-loop live set replaces the initial live set; dead
        # records from the first pass are kept (deduped by FQDN).
        seen = {a.fqdn for a in final_live}
        merged: list[TriagedAsset] = list(final_live)
        for a in state.triaged:
            if a.fqdn not in seen and a.status != "live":
                merged.append(a)
                seen.add(a.fqdn)
        state.triaged = merged
        state.wildcards = wildcards

        # Persist combined triage.json (overwrites the first-pass version).
        out = run_dir / "01_recon" / "triage.json"
        out.write_text(json.dumps({
            "live": [a.model_dump() for a in state.live()],
            "dead": [a.model_dump() for a in state.dead()],
            "wildcards": state.wildcards,
        }, indent=2))


class HttpxStage(Stage):
    name = "recon.httpx"

    def _path(self, run_dir: Path) -> Path:
        return run_dir / "01_recon" / "httpx.jsonl"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        hx = cfg.tools.httpx
        fqdns = [a.fqdn for a in state.live()]
        # Outer subprocess timeout scaled to work ÷ concurrency, so slow profiles
        # (paranoid = 1 thread) aren't killed mid-pass. Floor 600s. Without this,
        # a low-thread profile on a large host set hits the 600s kill → 0 live.
        # NB a host that never answers costs 2x `timeout` (https + http fallback),
        # so the 1.5 multiplier is only ~75% of a fully-unreachable list — the pass
        # is EXPECTED to be cut short on a badly-blocked estate, which is why the
        # streaming path below keeps whatever it collected.
        budget = max(600.0, len(fqdns) / max(1, hx.threads) * hx.timeout * 1.5)
        progress = ProbeProgress(len(fqdns))
        servers, signals = await run_httpx(
            fqdns,
            self._path(run_dir),
            hx,
            log,
            timeout=budget,
            user_agent=cfg.identity.effective_user_agent(),
            extra_headers=cfg.identity.effective_headers(),
            progress=progress,
        )
        state.live_servers = servers
        state.page_signals = signals
        state.probe_progress = ProbeCoverage(
            total=progress.total,
            probed=progress.seen,
            responded=progress.responded,
            failed=progress.failed,
            stalled_after=progress.stalled_after,
            last_responding_host=progress.last_responding_host,
        )
