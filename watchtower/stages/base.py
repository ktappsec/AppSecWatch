"""Stage protocol + parallel composition + uniform orchestrator loop."""
from __future__ import annotations

import asyncio
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from watchtower.config import WatchTowerConfig
from watchtower.logging import RunLogger
from watchtower.models import StageError, asset_error
from watchtower.stages.state import ScanState
from watchtower.util.ipinfo import IPInfoLookup


@dataclass
class StageResult:
    """What a Stage hands back to the executor.

    Carries the stage's per-asset (operational) failures as raw
    `(target, message)` pairs — a timed-out host, a nav error, a degraded AI
    call. The executor stamps them with the stage name and folds them into the
    single error sink, so no stage needs to know about `asset_error` or
    `state.errors`. A stage with nothing to report returns `None`.
    """
    asset_errors: list[tuple[str | None, str]] = field(default_factory=list)


def _record_asset_errors(
    state: ScanState, stage_name: str, result: "StageResult | None"
) -> None:
    """Fold a stage's per-asset failures into the single sink (state.errors).

    The one place `(target, message)` pairs become attributed `StageError`s —
    reused by the linear executor and by ParallelStage (per child) so stage
    attribution stays correct under fan-out."""
    if not result:
        return
    for target, message in result.asset_errors:
        state.errors.append(asset_error(stage_name, target, message))


def _record_stage_failure(
    state: ScanState, log: RunLogger, stage_name: str, exc: BaseException
) -> None:
    """Record a stage crash into the single error sink (state.errors) with the
    exception type, and emit the full traceback to the JSONL log under --verbose."""
    state.errors.append(StageError(
        stage=stage_name,
        message=str(exc),
        error_type=type(exc).__name__,
        ts=datetime.now(timezone.utc).isoformat(),
    ))
    fields = {"stage": stage_name, "event": "stage_error", "error_type": type(exc).__name__}
    if log.verbose:
        fields["traceback"] = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )[-2000:]
    log.error(f"{stage_name} failed: {exc}", **fields)


class Stage(ABC):
    """A pipeline step. Subclasses must set `name` and implement run()."""

    name: str = "unnamed"

    @abstractmethod
    async def run(
        self,
        state: ScanState,
        run_dir: Path,
        cfg: WatchTowerConfig,
        ipinfo: IPInfoLookup,
        log: RunLogger,
    ) -> "StageResult | None":
        """Execute the stage, mutating ScanState in place.

        Return a StageResult carrying any per-asset failures, or None when the
        stage had none. The executor folds those into the error sink."""


class ParallelStage(Stage):
    """Runs N stages concurrently. Each child must touch a disjoint slice of state."""

    def __init__(self, name: str, *children: Stage) -> None:
        self.name = name
        self.children: tuple[Stage, ...] = children

    async def run(self, state, run_dir, cfg, ipinfo, log):
        async def safe(child: Stage) -> None:
            try:
                result = await child.run(state, run_dir, cfg, ipinfo, log)
                _record_asset_errors(state, child.name, result)
            except Exception as e:
                _record_stage_failure(state, log, child.name, e)
        await asyncio.gather(*(safe(c) for c in self.children))
        # Children's asset errors are already attributed to each child above.
        return None


async def execute_stages(
    stages: list[Stage],
    state: ScanState,
    run_dir: Path,
    cfg: WatchTowerConfig,
    ipinfo: IPInfoLookup,
    log: RunLogger,
) -> None:
    """Drive the pipeline uniformly: per-stage timing, current-stage tracking, and
    error capture into the single sink (state.errors)."""
    for stage in stages:
        state.current_stage = stage.name
        log.stage_start(stage.name)
        start = time.monotonic()
        errors_before = len(state.errors)
        try:
            result = await stage.run(state, run_dir, cfg, ipinfo, log)
            state.completed_stages.append(stage.name)
            _record_asset_errors(state, stage.name, result)
        except Exception as e:
            _record_stage_failure(state, log, stage.name, e)
        elapsed = round(time.monotonic() - start, 2)
        state.stage_durations[stage.name] = elapsed
        # Errors recorded during this stage = crash (if any) + harvested asset errors.
        stage_errors = len(state.errors) - errors_before
        log.stage_end(stage.name, elapsed_s=elapsed, errors=stage_errors)
    state.current_stage = None
