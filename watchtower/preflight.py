"""Dependency preflight: check binaries, MMDB, and (optionally) the LLM endpoint.

Used by `watchtower verify-deps` (CLI) and can be called from anywhere that
wants a structured readiness assessment.
"""
from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from watchtower.config import WatchTowerConfig
from watchtower.util.subproc import run_tool, tool_version

REQUIRED_BINARIES: tuple[str, ...] = ("subfinder", "dnsx", "tlsx", "httpx", "nuclei")


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class PreflightReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(CheckResult(name=name, ok=ok, detail=detail))


async def _check_binary(name: str) -> CheckResult:
    path = shutil.which(name)
    if not path:
        return CheckResult(name=f"binary:{name}", ok=False, detail="not on PATH")
    version = await tool_version(name)
    return CheckResult(name=f"binary:{name}", ok=True, detail=f"{path} ({version})")


async def _check_mmdb(path: str) -> CheckResult:
    p = Path(path)
    if not p.is_file():
        return CheckResult(name=f"mmdb:{path}", ok=False, detail="file not found")
    try:
        import maxminddb
        with maxminddb.open_database(str(p)) as r:
            meta = r.metadata()
            build_epoch = getattr(meta, "build_epoch", None) or 0
            return CheckResult(
                name=f"mmdb:{path}",
                ok=True,
                detail=f"build_epoch={build_epoch}, type={getattr(meta, 'database_type', '?')}",
            )
    except Exception as e:
        return CheckResult(name=f"mmdb:{path}", ok=False, detail=f"open failed: {e}")


async def _check_llm(base_url: str, api_key: str, model: str) -> CheckResult:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.post(
                f"{base_url.rstrip('/')}/chat/completions",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "respond with the single word ok"}],
                    "max_tokens": 5,
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if r.status_code >= 400:
            return CheckResult(
                name=f"llm:{base_url}",
                ok=False,
                detail=f"HTTP {r.status_code}: {r.text[:200]}",
            )
        return CheckResult(name=f"llm:{base_url}", ok=True, detail=f"model={model} reachable")
    except Exception as e:
        return CheckResult(name=f"llm:{base_url}", ok=False, detail=f"{type(e).__name__}: {e}")


async def run_preflight(cfg: WatchTowerConfig | None = None) -> PreflightReport:
    """Probe all binaries; if cfg supplied, also probe the MMDB and the LLM."""
    report = PreflightReport()

    bin_results = await asyncio.gather(*(_check_binary(b) for b in REQUIRED_BINARIES))
    for r in bin_results:
        report.checks.append(r)

    # Python deps that the runtime imports lazily — verify they import.
    for mod in ("pydantic", "yaml", "tldextract", "maxminddb", "httpx", "jinja2"):
        try:
            __import__(mod)
            report.add(f"python:{mod}", True, "importable")
        except Exception as e:
            report.add(f"python:{mod}", False, f"import failed: {e}")

    # Playwright + Chromium are big — check the import; skip a real launch for speed.
    try:
        __import__("playwright")
        report.add("python:playwright", True, "importable")
    except Exception as e:
        report.add("python:playwright", False, f"import failed: {e}")

    if cfg is not None:
        if cfg.mmdb_path:
            report.checks.append(await _check_mmdb(cfg.mmdb_path))
        else:
            report.add("mmdb", True, "not configured (optional — ASN enrichment disabled)")
        report.checks.append(
            await _check_llm(cfg.llm.base_url, cfg.llm.api_key, cfg.llm.model)
        )

    return report


def format_report(report: PreflightReport) -> str:
    lines: list[str] = []
    for c in report.checks:
        mark = "✓" if c.ok else "✗"
        lines.append(f"  {mark} {c.name:<32}  {c.detail}")
    lines.append("")
    lines.append("OK" if report.ok else "FAILED")
    return "\n".join(lines)
