"""Report + compress stages."""
from __future__ import annotations

import json
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from watchtower.report.aggregator import build_report_context, build_run_summary
from watchtower.report.renderer import render_executive, render_report
from watchtower.stages.base import Stage

_COMPRESSIBLE_SUBDIRS = ("01_recon", "02_audit", "03_ai")


class ReportStage(Stage):
    """Renders report.html from the accumulated ScanState."""
    name = "report"

    def __init__(self, run_meta: dict, versions: dict) -> None:
        self.run_meta = run_meta
        self.versions = versions

    async def run(self, state, run_dir, cfg, ipinfo, log):
        # Update finished timestamp + duration at render time. (Previously the
        # runner set duration *after* this stage rendered from a copy, so the
        # report always showed a blank duration.)
        finished = datetime.now(timezone.utc)
        meta = dict(self.run_meta)
        meta["finished_at"] = finished.isoformat()
        duration_s = self._duration_s(meta.get("started_at"), finished)
        meta["duration"] = f"{duration_s:.1f}s"

        summary = build_run_summary(state, duration_s=duration_s, log_counts=log.counts())
        state.summary = summary
        (run_dir / "summary.json").write_text(summary.model_dump_json(indent=2))

        context = build_report_context(
            run_meta=meta,
            triaged=state.triaged,
            wildcards=state.wildcards,
            live_servers=state.live_servers,
            nuclei_findings=state.nuclei_findings,
            takeover_findings=state.takeover_findings,
            tls_findings=state.tls_findings,
            tls_reports=state.tls_reports,
            ai_headers_findings=state.ai_headers_findings,
            ai_supply_findings=state.ai_supply_findings,
            crawler_artifacts=state.crawler_artifacts,
            errors=[e.model_dump() for e in state.errors],
            versions=self.versions,
            header_findings=state.header_findings,
            js_lib_findings=state.js_lib_findings,
            page_signals=state.page_signals,
            tls_certs=state.tls_certs,
            app_profiles=state.app_profiles,
            coverage=state.coverage,
            summary=summary,
            report_cfg=getattr(cfg, "report", None),
            exec_summary=state.exec_summary,
        )
        render_report(context, run_dir / "report.html")
        # The executive one-pager shares the context (deterministic core + optional
        # AI overlay) and the themeable base template; always written.
        render_executive(context, run_dir / "executive.html")
        (run_dir / "errors.json").write_text(
            json.dumps([e.model_dump() for e in state.errors], indent=2)
        )

    @staticmethod
    def _duration_s(started_at: str | None, finished: datetime) -> float:
        if not started_at:
            return 0.0
        try:
            return max(0.0, (finished - datetime.fromisoformat(started_at)).total_seconds())
        except ValueError:
            return 0.0


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def _human(n: int) -> str:
    f = float(n)
    for u in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or u == "GiB":
            return f"{f:.1f} {u}"
        f /= 1024
    return f"{n} B"


class CompressStage(Stage):
    """Tar+gzip the bulk artifact subdirectories at end of run.

    Skips silently if the source dir doesn't exist (e.g., empty pipeline).
    """
    name = "compress"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        for sub in _COMPRESSIBLE_SUBDIRS:
            src = run_dir / sub
            if not src.is_dir():
                continue
            archive = run_dir / f"{sub}.tar.gz"
            try:
                before = _dir_size(src)
                with tarfile.open(archive, "w:gz", compresslevel=6) as tar:
                    tar.add(src, arcname=sub)
                after = archive.stat().st_size
                log.info(
                    f"compressed {sub}: {_human(before)} → {_human(after)} "
                    f"(saved {_human(before - after)})"
                )
                shutil.rmtree(src)
            except Exception as e:
                log.warn(f"compression failed for {sub}: {e}")
                if archive.exists():
                    try:
                        archive.unlink()
                    except OSError:
                        pass
