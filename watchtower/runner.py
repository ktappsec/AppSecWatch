"""Pipeline orchestrator — declarative Stage list, uniform execution.

The actual stage logic lives in watchtower.stages.*. This module wires bootstrap
(MMDB load, versions/snapshot capture) to the Stage-driven pipeline.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from watchtower import __version__
from watchtower.config import WatchTowerConfig
from watchtower.logging import RunLogger
from watchtower.stages.base import Stage, execute_stages
from watchtower.stages.pipeline import build_pipeline
from watchtower.stages.report_stage import CompressStage, ReportStage
from watchtower.stages.state import ScanState
from watchtower.util.ipinfo import IPInfoLookup
from watchtower.util.subproc import tool_version


def _write_manifest(
    run_dir: Path,
    coverage: dict[str, dict],
    only: set[str] | None,
    skip: set[str] | None,
) -> None:
    (run_dir / "manifest.json").write_text(json.dumps({
        "selection": {
            "only": sorted(only) if only else None,
            "skip": sorted(skip) if skip else None,
        },
        "capabilities": coverage,
    }, indent=2))


def _slug(roots: list[str]) -> str:
    base = "-".join(r.replace(".", "_") for r in roots[:2])
    return base[:40] if base else "scan"


_RUN_SUBDIRS = (
    "01_recon",
    "02_audit/takeovers", "02_audit/sslscan",
    "02_audit/nuclei", "02_audit/playwright",
    "03_ai/profile", "03_ai/triage", "03_ai/supply_chain",
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def _prepare_run_dir(output_root: Path, name: str) -> Path:
    """Create a run directory and its standard artifact subdirs."""
    run_dir = output_root / name
    run_dir.mkdir(parents=True, exist_ok=True)
    for sub in _RUN_SUBDIRS:
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    return run_dir


def make_run_dir(output_root: Path, roots: list[str]) -> Path:
    return _prepare_run_dir(output_root, f"{_timestamp()}-{_slug(roots)}")


async def collect_versions(cfg: WatchTowerConfig) -> dict[str, Any]:
    binaries = ["subfinder", "dnsx", "tlsx", "httpx", "nuclei"]
    versions: dict[str, Any] = {"watchtower": __version__}
    results = await asyncio.gather(*(tool_version(b) for b in binaries),
                                   return_exceptions=True)
    for b, r in zip(binaries, results):
        versions[b] = r if isinstance(r, str) else f"error: {r!r}"
    versions["llm_model"] = cfg.llm.model
    versions["llm_base_url"] = cfg.llm.base_url
    versions["captured_at"] = datetime.now(timezone.utc).isoformat()
    return versions


def _snapshot_config(cfg: WatchTowerConfig, run_dir: Path) -> None:
    """Write config.snapshot.yaml with the LLM api_key redacted."""
    dump = cfg.model_dump()
    if dump.get("llm", {}).get("api_key"):
        dump["llm"]["api_key"] = "***REDACTED***"
    (run_dir / "config.snapshot.yaml").write_text(yaml.safe_dump(dump, sort_keys=False))


def _log_throttle(cfg: WatchTowerConfig, log: RunLogger) -> None:
    """Record the effective rate-limit posture so the log shows what limits were
    in force when interpreting any later tool_timeout / rate_limit_signal events."""
    log.info(
        f"throttle profile: {cfg.throttle} "
        f"(httpx_rl={cfg.tools.httpx.rate_limit}, httpx_threads={cfg.tools.httpx.threads}, "
        f"nuclei_rl={cfg.tools.nuclei.rate_limit}, "
        f"tlsx_conc={cfg.tools.tlsx.concurrency}, dnsx_rl={cfg.tools.dnsx.rate_limit}, "
        f"sslscan_timeout={cfg.tools.sslscan.timeout}s, "
        f"conc default/tls/playwright={cfg.concurrency.default}/{cfg.concurrency.tls}/{cfg.concurrency.playwright})",
        event="throttle",
        throttle=cfg.throttle,
        httpx_rl=cfg.tools.httpx.rate_limit,
        httpx_threads=cfg.tools.httpx.threads,
        nuclei_rl=cfg.tools.nuclei.rate_limit,
        takeovers_rl=cfg.tools.takeovers.rate_limit,
        tlsx_concurrency=cfg.tools.tlsx.concurrency,
        dnsx_rl=cfg.tools.dnsx.rate_limit,
        sslscan_timeout=cfg.tools.sslscan.timeout,
        conc_default=cfg.concurrency.default,
        conc_tls=cfg.concurrency.tls,
        conc_playwright=cfg.concurrency.playwright,
    )


async def _run(
    cfg: WatchTowerConfig,
    run_dir: Path,
    *,
    log_mode: str,
    verbose: bool,
    compress: bool,
    only: set[str] | None,
    skip: set[str] | None,
    stages: list[Stage] | None,
    roots_for_meta: list[str],
    start_msg: str,
    state: ScanState | None = None,
    suppressions: set[str] | None = None,
) -> Path:
    """Shared run spine.

    Loads the MMDB up front (a failure is a fatal bootstrap error → errors.json +
    raise), then drives the Stage pipeline.

    `state`: an externally-owned ScanState. The Web API passes one in so it can
    poll `current_stage` / `completed_stages` / findings live and render a
    partial report from it on cancel. When None, a fresh one is created.
    """
    log = RunLogger(run_dir, mode=log_mode, verbose=verbose)  # type: ignore[arg-type]
    started_iso = datetime.now(timezone.utc).isoformat()
    log.info(start_msg)

    _snapshot_config(cfg, run_dir)
    _log_throttle(cfg, log)
    versions = await collect_versions(cfg)
    (run_dir / "versions.json").write_text(json.dumps(versions, indent=2))

    ipinfo: IPInfoLookup | None = None
    try:
        ipinfo = IPInfoLookup(cfg.mmdb_path, cfg.sanctioned_cidrs, cfg.sanctioned_asns)
    except Exception as e:
        log.error(f"MMDB load failed: {e}")
        (run_dir / "errors.json").write_text(
            json.dumps([{"stage": "bootstrap", "message": str(e)}], indent=2)
        )
        log.close()
        raise

    run_meta = {
        "label": run_dir.name,
        "roots": roots_for_meta,
        "started_at": started_iso,
        "finished_at": "",  # filled in by ReportStage
        "duration": "",
        "watchtower_version": __version__,
    }

    try:
        if state is None:
            state = ScanState()
        report_stage = ReportStage(run_meta, versions)
        compress_stage = CompressStage() if compress else None

        if stages is not None:
            pipeline_stages: list[Stage] = list(stages)
            coverage: dict[str, dict] = {}
        else:
            pipeline_stages, coverage = build_pipeline(
                cfg, only=only, skip=skip,
                include_report=report_stage,
                include_compress=compress_stage,
            )
        state.coverage = coverage
        # Manual suppressions (server-injected): mark matching findings just before
        # the report so the histogram + report.html reflect them.
        if suppressions:
            from watchtower.stages.suppress_stage import SuppressionStage
            supp = SuppressionStage(suppressions)
            try:
                pipeline_stages.insert(pipeline_stages.index(report_stage), supp)
            except ValueError:
                pipeline_stages.append(supp)
        _write_manifest(run_dir, coverage, only, skip)
        await execute_stages(pipeline_stages, state, run_dir, cfg, ipinfo, log)  # type: ignore[arg-type]

        # ReportStage built the summary from the final state; log it as the
        # end-of-run rollup (also emits the run_summary JSONL event).
        if state.summary is not None:
            log.summary(state.summary)
        log.info(f"Report written: {run_dir / 'report.html'}")
        return run_dir / "report.html"
    finally:
        if ipinfo is not None:
            try:
                ipinfo.close()
            except Exception:
                pass
        log.close()


async def run_scan(
    cfg: WatchTowerConfig,
    output_root: Path,
    log_mode: str,
    verbose: bool,
    compress: bool = True,
    only: set[str] | None = None,
    skip: set[str] | None = None,
    stages: list[Stage] | None = None,
    run_dir: Path | None = None,
    state: ScanState | None = None,
    suppressions: set[str] | None = None,
) -> Path:
    """Run the full pipeline.

    Args:
        only/skip: capability-token selection (mutually exclusive). See §2.8.
        stages: explicit stage list, bypassing only/skip token resolution.
        run_dir: pre-created run directory (the Web API reserves it up front);
            when None a timestamped one is created under `output_root`.
        state: externally-owned ScanState for live progress (Web API).
        suppressions: manual-suppression fingerprints (server-injected). The CLI
            passes None, so CLI scans suppress nothing.
    """
    if run_dir is None:
        run_dir = make_run_dir(output_root, cfg.roots)
    return await _run(
        cfg, run_dir,
        log_mode=log_mode, verbose=verbose, compress=compress,
        only=only, skip=skip, stages=stages,
        roots_for_meta=cfg.roots,
        start_msg=f"WatchTower v{__version__} run started → {run_dir}",
        state=state, suppressions=suppressions,
    )
