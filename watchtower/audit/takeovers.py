"""Node A — Subdomain takeovers via nuclei takeover templates.

Replaces subjack per locked decision (DESIGN.md §2.2): nuclei's
`http/takeovers/` template tree is actively maintained and covers a
broader set of providers.

NB the nuclei templates all `GET {{BaseURL}}` and match a live "unclaimed-service"
body fingerprint — so they only fire on a **resolving** host. They therefore run
against LIVE hosts whose CNAME chain points to a third-party zone (resolving +
third-party CNAME), NOT dead records (no A records → nothing to fetch). The
dangling/NXDOMAIN class is handled deterministically by
`takeover_fingerprints.scan_cname_takeovers`.
"""
from __future__ import annotations

from pathlib import Path

from watchtower.audit.nuclei_parse import parse_nuclei_jsonl
from watchtower.config import TakeoversConfig
from watchtower.logging import RunLogger
from watchtower.models import Finding, TriagedAsset
from watchtower.util.subproc import run_tool


async def run_takeovers(
    candidates: list[TriagedAsset],
    out_path: Path,
    cfg: TakeoversConfig,
    log: RunLogger,
    timeout: float = 1800.0,
) -> tuple[list[Finding], str | None]:
    """Run nuclei takeover templates against resolving CNAME candidates.

    Returns (findings, error). `error` is set only when the batch invocation
    failed to produce any findings (non-zero exit, no output), so the stage can
    surface a genuine scan failure into the single error sink."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not candidates:
        out_path.write_text("")
        log.info("takeovers: no resolving CNAME candidates to scan")
        return [], None

    payload = ("\n".join(a.fqdn for a in candidates) + "\n").encode()
    cmd: list[str] = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-t", "http/takeovers/",
        "-severity", ",".join(cfg.severities),
        "-rl", str(cfg.rate_limit),
        "-o", str(out_path),
        *cfg.extra_flags,
    ]
    log.debug("running nuclei (takeovers)", cmd=cmd, count=len(candidates), rate_limit=cfg.rate_limit)
    res = await run_tool(cmd, stdin=payload, timeout=timeout, log=log, label="nuclei-takeovers")
    stderr_tail = res.stderr.decode("utf-8", "replace")[-400:]
    if not res.ok:
        log.warn("nuclei (takeovers) exited non-zero", returncode=res.returncode, stderr=stderr_tail)

    findings: list[Finding] = []
    if out_path.exists():
        findings = parse_nuclei_jsonl(
            out_path.read_text().splitlines(),
            source="takeover",
            default_severity="high",
            default_title="Subdomain takeover candidate",
        )

    error = None
    if not res.ok and not findings:
        error = f"nuclei-takeovers exited {res.returncode} with no findings: {stderr_tail.strip() or 'no output'}"
    log.info(f"takeovers: {len(findings)} findings")
    return findings, error
