from __future__ import annotations

from pathlib import Path

from watchtower.config import ToolBlock
from watchtower.logging import RunLogger
from watchtower.util.subproc import run_tool


async def run_subfinder(
    roots: list[str],
    out_path: Path,
    cfg: ToolBlock,
    log: RunLogger,
    timeout: float = 300.0,
) -> list[str]:
    """Run subfinder over all roots, write deduped subdomains to `out_path`, return them."""
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not roots:
        out_path.write_text("")
        return []

    cmd: list[str] = [
        "subfinder",
        "-silent",
        "-all",
        "-d", ",".join(roots),
        "-o", str(out_path),
        *cfg.extra_flags,
    ]
    log.debug("running subfinder", cmd=cmd)
    res = await run_tool(cmd, timeout=timeout, log=log, label="subfinder")
    if not res.ok:
        log.warn(
            "subfinder exited non-zero",
            returncode=res.returncode,
            stderr=res.stderr.decode("utf-8", "replace")[-400:],
        )

    if not out_path.exists():
        out_path.write_text("")
        return []

    seen: set[str] = set()
    for line in out_path.read_text().splitlines():
        name = line.strip().lower().rstrip(".")
        if name:
            seen.add(name)
    # Always include roots themselves as candidates.
    for r in roots:
        seen.add(r.strip().lower().rstrip("."))
    subdomains = sorted(seen)
    out_path.write_text("\n".join(subdomains) + ("\n" if subdomains else ""))
    log.info(f"subfinder discovered {len(subdomains)} unique names")
    return subdomains
