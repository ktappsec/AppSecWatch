"""Renderer behavior (plain / quiet / rich) + --strict exit decision.

JSONL is the machine truth and must be identical regardless of renderer; the
renderer only changes the human-facing stderr presentation.
"""
from __future__ import annotations

import argparse
import io
import json

from watchtower import progress
from watchtower.cli import _strict_exit
from watchtower.logging import PlainRenderer, RunLogger
from watchtower.models import RunSummary


# ---- plain / quiet renderers ----------------------------------------------

def test_plain_shows_info_quiet_hides_it(capsys):
    PlainRenderer(quiet=False).event("info", "hello", {})
    PlainRenderer(quiet=True).event("info", "hidden", {})
    PlainRenderer(quiet=True).event("warn", "careful", {})
    err = capsys.readouterr().err
    assert "hello" in err
    assert "hidden" not in err          # quiet drops info
    assert "careful" in err             # quiet keeps warn


def test_plain_includes_stage_and_tool_context(capsys):
    PlainRenderer().event("warn", "slow", {"tool": "sslyze", "host": "h.example.com"})
    err = capsys.readouterr().err
    assert "[sslyze]" in err and "(h.example.com)" in err


def test_debug_only_when_verbose(capsys):
    PlainRenderer(verbose=False).event("debug", "noisy", {})
    PlainRenderer(verbose=True).event("debug", "shown", {})
    err = capsys.readouterr().err
    assert "noisy" not in err and "shown" in err


# ---- JSONL is renderer-independent ----------------------------------------

def test_jsonl_identical_across_modes(tmp_path):
    def events(mode: str) -> list:
        d = tmp_path / mode
        d.mkdir()
        lg = RunLogger(d, mode=mode)
        lg.info("hi", event="x")
        lg.warn("w", event="tool_timeout", tool="sslyze")
        lg.stage_start("s")
        lg.stage_end("s", elapsed_s=1.0, errors=0)
        lg.summary(RunSummary(duration_s=1.0))
        lg.close()
        recs = [json.loads(l) for l in (d / "run.log.jsonl").read_text().splitlines()]
        return [r.get("event") for r in recs]

    assert events("plain") == events("quiet") == ["x", "tool_timeout", "stage_start", "stage_end", "run_summary"]


def test_logger_counts(tmp_path):
    lg = RunLogger(tmp_path, mode="quiet")
    lg.warn("a", event="tool_timeout")
    lg.warn("b", event="tool_timeout")
    lg.error("c", event="stage_error")
    c = lg.counts()
    lg.close()
    assert c["events"]["tool_timeout"] == 2
    assert c["levels"]["warn"] == 2 and c["levels"]["error"] == 1


# ---- rich renderer ---------------------------------------------------------

def test_make_rich_renderer_falls_back_on_non_tty():
    # pytest captures stderr → not a terminal → plain fallback (None).
    assert progress.make_rich_renderer(verbose=False) is None


def test_rich_renderer_renders_tree_and_summary():
    import pytest
    pytest.importorskip("rich")  # rich ships in the Docker image; may be absent in dev venv
    from rich.console import Console

    console = Console(file=io.StringIO(), force_terminal=True, width=100)
    r = progress.RichRenderer(console, verbose=False)
    r.stage_start("recon.httpx")
    r.event("warn", "slow handshake", {"host": "h.example.com"})
    r.stage_end("recon.httpx", 1.2, 0)
    r.summary(RunSummary(duration_s=1.2, findings_total=2,
                         findings_by_severity={"high": 2}, errors_total=0))
    r.close()
    out = console.file.getvalue()
    assert "recon.httpx" in out
    assert "Run summary" in out


# ---- --strict exit decision -----------------------------------------------

def test_strict_exit(tmp_path):
    (tmp_path / "errors.json").write_text(json.dumps([{"stage": "x", "message": "e"}]))
    report = tmp_path / "report.html"
    report.write_text("x")
    assert _strict_exit(report, argparse.Namespace(strict=True)) == 3
    assert _strict_exit(report, argparse.Namespace(strict=False)) == 0

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "errors.json").write_text("[]")
    r2 = clean / "report.html"
    r2.write_text("x")
    assert _strict_exit(r2, argparse.Namespace(strict=True)) == 0
