"""Node C — Main nuclei scan against live web servers."""
from __future__ import annotations

from pathlib import Path

from watchtower.audit.nuclei_parse import parse_nuclei_jsonl
from watchtower.config import NucleiConfig
from watchtower.logging import RunLogger
from watchtower.models import Finding, LiveWebServer
from watchtower.util.subproc import run_tool


def build_nuclei_cmd(cfg: NucleiConfig, out_path: Path, *,
                     user_agent: str | None = None,
                     extra_headers: dict[str, str] | None = None) -> list[str]:
    """Assemble the nuclei argv from config. Pure (no I/O) → unit-testable.
    Explicit tags/ids/templates take precedence over -as (auto-scan). A stealth
    `user_agent` overrides cfg.user_agent; `extra_headers` are added as -H."""
    cmd: list[str] = [
        "nuclei", "-silent", "-jsonl",
        "-severity", ",".join(cfg.severities),
        "-rl", str(cfg.rate_limit),
        "-timeout", str(cfg.timeout),
        "-H", f"User-Agent: {user_agent or cfg.user_agent}",
        "-o", str(out_path),
    ]
    for k, v in (extra_headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if cfg.tags:
        cmd += ["-tags", ",".join(cfg.tags)]
    if cfg.exclude_tags:
        cmd += ["-etags", ",".join(cfg.exclude_tags)]
    if cfg.template_ids:
        cmd += ["-id", ",".join(cfg.template_ids)]
    for t in cfg.templates:
        cmd += ["-t", t]
    for t in cfg.exclude_templates:
        cmd += ["-et", t]
    explicit = bool(cfg.tags or cfg.template_ids or cfg.templates)
    if cfg.auto_scan and not explicit:
        cmd.append("-as")
    cmd.extend(cfg.extra_flags)
    return cmd


async def run_nuclei(
    live_servers: list[LiveWebServer],
    out_path: Path,
    cfg: NucleiConfig,
    log: RunLogger,
    timeout: float = 3600.0,
    *,
    user_agent: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[list[Finding], str | None]:
    """Run nuclei over the live web servers.

    Returns (findings, error). `error` is set only when the batch invocation
    failed to produce any findings (non-zero exit, no output) — a genuine scan
    failure that would otherwise vanish into a warning. The stage funnels it
    into the single error sink."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not live_servers:
        out_path.write_text("")
        log.info("nuclei: no live servers")
        return [], None

    payload = ("\n".join(s.url for s in live_servers) + "\n").encode()

    cmd = build_nuclei_cmd(cfg, out_path, user_agent=user_agent, extra_headers=extra_headers)

    log.debug("running nuclei", cmd=cmd, count=len(live_servers), rate_limit=cfg.rate_limit)
    res = await run_tool(cmd, stdin=payload, timeout=timeout, log=log, label="nuclei")
    stderr_tail = res.stderr.decode("utf-8", "replace")[-400:]
    if not res.ok:
        log.warn("nuclei exited non-zero", returncode=res.returncode, stderr=stderr_tail)

    findings: list[Finding] = []
    if out_path.exists():
        findings = parse_nuclei_jsonl(
            out_path.read_text().splitlines(),
            source="nuclei",
            default_severity="info",
            default_title="nuclei finding",
        )

    error = None
    if not res.ok and not findings:
        error = f"nuclei exited {res.returncode} with no findings: {stderr_tail.strip() or 'no output'}"
    log.info(f"nuclei: {len(findings)} findings")
    return findings, error
