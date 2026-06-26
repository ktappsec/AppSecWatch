"""Run logging: an always-on structured JSONL audit log plus a pluggable
human-facing renderer (plain / quiet / rich).

`RunLogger` owns the machine truth — every call is written to `run.log.jsonl`
and tallied into level/event counters (the source for the end-of-run summary).
Human presentation is delegated to a `ProgressRenderer` chosen by `mode`, so the
terminal experience can change (plain text, quiet, or a live rich view) without
touching the JSONL contract.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:
    from watchtower.models import RunSummary

ProgressMode = Literal["plain", "rich", "quiet"]


class ProgressRenderer(Protocol):
    """Human-facing presentation of run events. JSONL is handled by RunLogger."""

    def event(self, level: str, msg: str, fields: dict[str, Any]) -> None: ...
    def stage_start(self, stage: str) -> None: ...
    def stage_end(self, stage: str, elapsed_s: float, errors: int) -> None: ...
    def summary(self, summary: "RunSummary") -> None: ...
    def close(self) -> None: ...


class PlainRenderer:
    """Timestamped stderr lines. `quiet=True` shows only warnings/errors + the
    final summary; stage start/end and info/debug are suppressed."""

    def __init__(self, *, verbose: bool = False, quiet: bool = False) -> None:
        self.verbose = verbose
        self.quiet = quiet

    def _line(self, level: str, msg: str, fields: dict[str, Any]) -> None:
        ctx = ""
        if fields.get("stage"):
            ctx = f" [{fields['stage']}]"
        elif fields.get("tool"):
            ctx = f" [{fields['tool']}]"
        if fields.get("host"):
            ctx += f" ({fields['host']})"
        prefix = f"[{time.strftime('%H:%M:%S')}] {level:>5}"
        print(f"{prefix}{ctx}  {msg}", file=sys.stderr, flush=True)

    def event(self, level: str, msg: str, fields: dict[str, Any]) -> None:
        if level == "debug" and not self.verbose:
            return
        if self.quiet and level not in {"error", "warn"}:
            return
        self._line(level, msg, fields)

    def stage_start(self, stage: str) -> None:
        if not self.quiet:
            self._line("info", f"▶ stage {stage} start", {"stage": stage})

    def stage_end(self, stage: str, elapsed_s: float, errors: int) -> None:
        if not self.quiet:
            tail = f" ({errors} error(s))" if errors else ""
            self._line("info", f"■ stage {stage} end — {elapsed_s}s{tail}", {"stage": stage})

    def summary(self, summary: "RunSummary") -> None:
        for line in _summary_lines(summary):
            print(line, file=sys.stderr, flush=True)

    def close(self) -> None:
        pass


def _summary_lines(s: "RunSummary") -> list[str]:
    """Compact, renderer-agnostic textual rollup."""
    sev = s.findings_by_severity
    sev_str = "  ".join(f"{k}:{sev.get(k, 0)}" for k in ("critical", "high", "medium", "low", "info"))
    lines = [
        "─" * 60,
        f"Run summary — {s.duration_s}s",
        f"  findings: {s.findings_total}   ({sev_str})",
        f"  assets:   live={s.assets.get('live', 0)} dead={s.assets.get('dead', 0)} "
        f"web={s.assets.get('live_servers', 0)}",
        f"  errors:   {s.errors_total}"
        + (f"   ({', '.join(f'{k}:{v}' for k, v in s.errors_by_stage.items())})" if s.errors_by_stage else ""),
    ]
    notable = {k: v for k, v in s.events.items() if v and k in (
        "tool_timeout", "tool_nonzero", "rate_limit_signal", "sslscan_no_output")}
    if notable:
        lines.append(f"  events:   {', '.join(f'{k}:{v}' for k, v in notable.items())}")
    lines.append("─" * 60)
    return lines


class RunLogger:
    """Always-on JSONL audit log + counters, with pluggable human rendering."""

    def __init__(self, run_dir: Path, mode: ProgressMode = "plain", verbose: bool = False) -> None:
        self.run_dir = run_dir
        self.mode = mode
        self.verbose = verbose
        self._lock = threading.Lock()
        self._jsonl_path = run_dir / "run.log.jsonl"
        self._jsonl = self._jsonl_path.open("a", buffering=1)
        self._level_counts: Counter[str] = Counter()
        self._event_counts: Counter[str] = Counter()
        self._renderer: ProgressRenderer = self._make_renderer(mode, verbose)

    @staticmethod
    def _make_renderer(mode: ProgressMode, verbose: bool) -> ProgressRenderer:
        if mode == "rich":
            # Lazy import: keep `rich` off the path for plain/quiet runs, and fall
            # back to plain when stderr is not a TTY (headless / piped).
            from watchtower.progress import make_rich_renderer
            renderer = make_rich_renderer(verbose=verbose)
            if renderer is not None:
                return renderer
            return PlainRenderer(verbose=verbose)
        return PlainRenderer(verbose=verbose, quiet=(mode == "quiet"))

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _emit_jsonl(self, level: str, msg: str, fields: dict[str, Any]) -> None:
        self._level_counts[level] += 1
        ev = fields.get("event")
        if ev:
            self._event_counts[ev] += 1
        record = {"ts": self._now(), "level": level, "msg": msg, **fields}
        with self._lock:
            self._jsonl.write(json.dumps(record, default=str) + "\n")

    def _emit(self, level: str, msg: str, fields: dict[str, Any]) -> None:
        self._emit_jsonl(level, msg, fields)
        self._renderer.event(level, msg, fields)

    def info(self, msg: str, **fields: Any) -> None:
        self._emit("info", msg, fields)

    def warn(self, msg: str, **fields: Any) -> None:
        self._emit("warn", msg, fields)

    def error(self, msg: str, **fields: Any) -> None:
        self._emit("error", msg, fields)

    def debug(self, msg: str, **fields: Any) -> None:
        self._emit("debug", msg, fields)

    def stage_start(self, stage: str, **fields: Any) -> None:
        self._emit_jsonl("info", f"stage {stage} start", {"stage": stage, "event": "stage_start", **fields})
        self._renderer.stage_start(stage)

    def stage_end(self, stage: str, *, elapsed_s: float = 0.0, errors: int = 0, **fields: Any) -> None:
        self._emit_jsonl(
            "info", f"stage {stage} end",
            {"stage": stage, "event": "stage_end", "elapsed_s": elapsed_s, "errors": errors, **fields},
        )
        self._renderer.stage_end(stage, elapsed_s, errors)

    def summary(self, summary: "RunSummary") -> None:
        self._emit_jsonl("info", "run summary", {"event": "run_summary", **summary.model_dump()})
        self._renderer.summary(summary)

    def counts(self) -> dict[str, dict[str, int]]:
        """Snapshot of level + event tallies (source for RunSummary.events)."""
        return {"levels": dict(self._level_counts), "events": dict(self._event_counts)}

    def close(self) -> None:
        try:
            self._renderer.close()
        except Exception:
            pass
        with self._lock:
            self._jsonl.flush()
            self._jsonl.close()
