"""ExecPdfStage is strictly best-effort: a missing browser or no source file must
degrade silently (no PDF, nothing recorded in state.errors, never raises). Also
covers the build_pipeline placement + the config default."""
from __future__ import annotations

import sys

import pytest

from watchtower.config import LLMConfig, ReportConfig, WatchTowerConfig
from watchtower.stages.base import Stage
from watchtower.stages.exec_pdf import ExecPdfStage
from watchtower.stages.pipeline import build_pipeline
from watchtower.stages.state import ScanState


class _Log:
    def info(self, *a, **k): pass
    def warn(self, *a, **k): pass
    def debug(self, *a, **k): pass
    def error(self, *a, **k): pass


class _Dummy(Stage):
    def __init__(self, name):
        self.name = name

    async def run(self, *a):  # pragma: no cover
        pass


def _cfg() -> WatchTowerConfig:
    return WatchTowerConfig(
        roots=["example.com"], mmdb_path="/dev/null",
        llm=LLMConfig(base_url="http://localhost/v1", model="m"),
    )


async def test_pdf_noop_when_no_executive_html(tmp_path):
    state = ScanState()
    result = await ExecPdfStage().run(state, tmp_path, _cfg(), None, _Log())
    assert result is None
    assert not (tmp_path / "executive.pdf").exists()
    assert state.errors == []


async def test_pdf_degrades_silently_when_playwright_unavailable(tmp_path, monkeypatch):
    # Force the lazy `from playwright.async_api import async_playwright` to ImportError
    # (None in sys.modules → ImportError), regardless of whether playwright is installed.
    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    (tmp_path / "executive.html").write_text("<html><body>exec</body></html>")
    state = ScanState()
    result = await ExecPdfStage().run(state, tmp_path, _cfg(), None, _Log())
    assert result is None                              # never raises / never a StageResult
    assert not (tmp_path / "executive.pdf").exists()   # degraded → no PDF
    assert state.errors == []                          # nothing recorded → --strict safe


def test_config_executive_pdf_defaults_true():
    assert ReportConfig().executive_pdf is True


def test_pipeline_places_pdf_between_report_and_compress():
    rpt, pdf, comp = _Dummy("report"), _Dummy("report.pdf"), _Dummy("compress")
    stages, _ = build_pipeline(
        _cfg(), only={"recon"},
        include_report=rpt, include_compress=comp, include_exec_pdf=pdf,
    )
    names = [s.name for s in stages]
    assert names[-3:] == ["report", "report.pdf", "compress"]


def test_pipeline_omits_pdf_when_not_supplied():
    stages, _ = build_pipeline(
        _cfg(), only={"recon"},
        include_report=_Dummy("report"), include_compress=None, include_exec_pdf=None,
    )
    assert "report.pdf" not in [s.name for s in stages]
