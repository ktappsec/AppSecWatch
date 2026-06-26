"""Rich live-progress renderer for `--progress rich`.

A `ProgressRenderer` (see watchtower.logging) backed by a `rich.live.Live` view:
a stage tree that updates as stages run, a bounded panel of recent warnings /
errors, and a final summary panel. Lazy-imported by RunLogger only when
`mode == "rich"`; `make_rich_renderer` returns None on a non-TTY so the logger
falls back to plain text (headless / piped runs stay readable).

Refreshes are driven explicitly from the asyncio event-loop thread
(`auto_refresh=False`), so there is no background render thread racing the
single-threaded pipeline.
"""
from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from watchtower.models import RunSummary

_SEV_STYLES = (("critical", "red"), ("high", "red"), ("medium", "yellow"),
               ("low", "cyan"), ("info", "dim"))


def make_rich_renderer(*, verbose: bool):
    """Build a RichRenderer, or None when stderr is not a TTY (→ plain fallback)."""
    try:
        from rich.console import Console
    except Exception:
        return None
    console = Console(stderr=True)
    if not console.is_terminal:
        return None
    return RichRenderer(console, verbose=verbose)


class RichRenderer:
    def __init__(self, console: Any, *, verbose: bool = False) -> None:
        from rich.live import Live
        self.console = console
        self.verbose = verbose
        self._stages: dict[str, dict[str, Any]] = {}   # name -> {status, elapsed, errors}
        self._recent: deque[tuple[str, str]] = deque(maxlen=8)
        self._live = Live(console=console, auto_refresh=False, transient=False)
        self._started = False

    # -- rendering -----------------------------------------------------------
    def _render(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.text import Text

        tree = Text()
        for name, st in self._stages.items():
            status = st["status"]
            if status == "running":
                tree.append("  ▶ ", style="cyan")
                tree.append(name + "\n")
            else:  # done
                errs = st["errors"]
                mark, style = ("✓", "green") if errs == 0 else ("⚠", "yellow")
                tree.append(f"  {mark} ", style=style)
                tree.append(name)
                tail = f"  {st['elapsed']}s" + (f"  {errs} err" if errs else "")
                tree.append(tail + "\n", style="dim")
        if not self._stages:
            tree.append("  (starting…)\n", style="dim")

        body: list[Any] = [tree]
        if self._recent:
            ev = Text()
            for level, msg in self._recent:
                ev.append(f"{level}: ", style="red" if level == "error" else "yellow")
                ev.append(msg + "\n")
            body.append(Panel(ev, title="recent warnings / errors", border_style="dim"))
        return Group(*body)

    def _refresh(self) -> None:
        if not self._started:
            self._live.start()
            self._started = True
        self._live.update(self._render(), refresh=True)

    def _stop(self) -> None:
        if self._started:
            try:
                self._live.stop()
            except Exception:
                pass
            self._started = False

    # -- ProgressRenderer protocol ------------------------------------------
    def event(self, level: str, msg: str, fields: dict[str, Any]) -> None:
        if level in ("warn", "error"):
            ctx = f"[{fields['tool']}] " if fields.get("tool") else ""
            ctx += f"({fields['host']}) " if fields.get("host") else ""
            self._recent.append((level, ctx + msg))
            self._refresh()
        elif self.verbose and self._started:
            self.console.log(msg)

    def stage_start(self, stage: str) -> None:
        self._stages[stage] = {"status": "running", "elapsed": 0.0, "errors": 0}
        self._refresh()

    def stage_end(self, stage: str, elapsed_s: float, errors: int) -> None:
        self._stages[stage] = {"status": "done", "elapsed": elapsed_s, "errors": errors}
        self._refresh()

    def summary(self, summary: "RunSummary") -> None:
        from rich.panel import Panel
        from rich.text import Text

        self._stop()  # freeze the stage tree, then print the panel beneath it
        sev = summary.findings_by_severity
        t = Text()
        t.append(f"duration {summary.duration_s}s\n", style="bold")
        t.append("findings  ")
        for k, color in _SEV_STYLES:
            t.append(f"{k}:{sev.get(k, 0)}  ", style=color)
        a = summary.assets
        t.append(
            f"\nassets    live={a.get('live_servers', 0)} in_scope={a.get('in_scope', 0)} "
            f"shadow_it={a.get('shadow_it', 0)} dead={a.get('dead', 0)}\n"
        )
        err_style = "red" if summary.errors_total else "green"
        t.append(f"errors    {summary.errors_total}", style=err_style)
        if summary.errors_by_stage:
            t.append("  (" + ", ".join(f"{k}:{v}" for k, v in summary.errors_by_stage.items()) + ")",
                     style="dim")
        self.console.print(Panel(t, title="Run summary", border_style=err_style))

    def close(self) -> None:
        self._stop()
