from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from watchtower.config import DnsxConfig
from watchtower.logging import RunLogger
from watchtower.util.subproc import run_tool


async def run_dnsx(
    subdomains: list[str],
    out_path: Path,
    cfg: DnsxConfig,
    log: RunLogger,
    timeout: float = 600.0,
) -> list[dict[str, Any]]:
    """Resolve all subdomains via dnsx. Returns parsed JSONL records.

    Output JSON keys we rely on:
      - host:  the queried name
      - a:     list of A records (may be missing if NXDOMAIN)
      - cname: list of CNAME targets (may be missing)
      - status_code: NOERROR / NXDOMAIN / etc.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not subdomains:
        out_path.write_text("")
        return []

    stdin_payload = ("\n".join(subdomains) + "\n").encode()
    cmd: list[str] = [
        "dnsx",
        "-silent",
        "-resp",
        "-a",
        "-cname",
        "-json",
        "-retry", "2",
        "-rl", str(cfg.rate_limit),
        *cfg.extra_flags,
    ]
    log.debug("running dnsx", cmd=cmd, count=len(subdomains), rate_limit=cfg.rate_limit)
    res = await run_tool(cmd, stdin=stdin_payload, timeout=timeout, log=log, label="dnsx")

    out_path.write_bytes(res.stdout)

    records: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    for line in res.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (obj.get("host") or "").lower().rstrip(".")
        if host:
            obj["host"] = host
            records.append(obj)
            seen_hosts.add(host)

    # dnsx omits names it couldn't resolve from JSON output. Synthesize NXDOMAIN entries.
    for s in subdomains:
        s_norm = s.lower().rstrip(".")
        if s_norm not in seen_hosts:
            records.append({"host": s_norm, "a": [], "cname": [], "status_code": "NXDOMAIN"})

    log.info(f"dnsx resolved {sum(1 for r in records if r.get('a'))}/{len(subdomains)} names")
    return records
