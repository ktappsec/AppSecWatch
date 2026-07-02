from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from appsecwatch.config import HttpxConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import LiveWebServer, PageSignals
from appsecwatch.recon.page_signals import parse_page_signals
from appsecwatch.util.subproc import run_tool


def parse_httpx_records(
    raw_lines: list[str],
) -> tuple[list[LiveWebServer], dict[str, PageSignals]]:
    """Parse httpx -json lines into live servers + per-host PageSignals."""
    live: list[LiveWebServer] = []
    signals: dict[str, PageSignals] = {}
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("input")
        if not url:
            continue
        # Prefer the FQDN we fed (`input`) over httpx's `host`, which is the
        # resolved IP — findings/report should key on the domain, not the IP.
        host = (obj.get("input") or "").lower().rstrip(".")
        if not host:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or obj.get("host") or "").lower().rstrip(".")
        live.append(
            LiveWebServer(
                url=url,
                host=host,
                status_code=obj.get("status_code") or obj.get("status-code"),
                title=obj.get("title"),
                tech=list(obj.get("tech") or obj.get("technologies") or []),
            )
        )
        if host:
            signals[host] = parse_page_signals(obj, host)
    return live, signals


async def run_httpx(
    fqdns: list[str],
    out_path: Path,
    cfg: HttpxConfig,
    log: RunLogger,
    timeout: float = 600.0,
    *,
    user_agent: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[list[LiveWebServer], dict[str, PageSignals]]:
    """Probe FQDNs with httpx; return live servers + per-host PageSignals.

    `-include-response` is requested so the raw (pre-JS) HTML body is present in
    the JSON, from which PageSignals (title/meta/og/body/forms) are parsed.
    `user_agent`/`extra_headers` come from the stealth identity (browser preset).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not fqdns:
        out_path.write_text("")
        return [], {}

    payload = ("\n".join(fqdns) + "\n").encode()
    cmd: list[str] = [
        "httpx",
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-include-response",      # raw response (headers + body) → PageSignals
        "-rl", str(cfg.rate_limit),
        "-threads", str(cfg.threads),  # concurrency — low for WAF'd targets
        "-timeout", str(cfg.timeout),
    ]
    if user_agent:
        cmd += ["-H", f"User-Agent: {user_agent}"]
    for k, v in (extra_headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    cmd += [*cfg.extra_flags]
    log.debug("running httpx", cmd=cmd, count=len(fqdns), rate_limit=cfg.rate_limit)
    res = await run_tool(cmd, stdin=payload, timeout=timeout, log=log, label="httpx")
    out_path.write_bytes(res.stdout)

    live, signals = parse_httpx_records(
        res.stdout.decode("utf-8", "replace").splitlines()
    )
    # Rate-limit / WAF signal: a burst of 403/429/503 on the probe pass.
    throttled = [s for s in live if s.status_code in (403, 429, 503)]
    if throttled:
        log.warn(
            f"httpx: {len(throttled)}/{len(live)} host(s) returned 403/429/503 — "
            f"possible rate-limiting or WAF",
            event="rate_limit_signal", tool="httpx",
            hosts=[s.host for s in throttled][:20],
        )
    log.info(f"httpx found {len(live)} live web servers")
    return live, signals
