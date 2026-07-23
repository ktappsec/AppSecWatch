from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from appsecwatch.audit.liveness import classify_assessability
from appsecwatch.config import HttpxConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import LiveWebServer, PageSignals
from appsecwatch.recon.page_signals import parse_page_signals
from appsecwatch.util.subproc import StreamOutcome, stream_tool


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
        # `-probe` makes httpx emit a record for EVERY input, including hosts that
        # never answered (`failed: true`, status_code 0, url still populated). Those
        # are progress/telemetry, NOT live servers — admitting them would invent a
        # live server per blackholed host and defeat the degraded-run detector.
        if obj.get("failed") is True:
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
        server = LiveWebServer(
            url=url,
            host=host,
            status_code=obj.get("status_code") or obj.get("status-code"),
            title=obj.get("title"),
            tech=list(obj.get("tech") or obj.get("technologies") or []),
        )
        if host:
            sig = parse_page_signals(obj, host)
            signals[host] = sig
            # Stamp assessability from the captured signals (5xx/no-response/WAF-block
            # → not a real application surface; its findings are suppressed downstream).
            server.assessed, server.not_assessed_reason = classify_assessability(sig)
        live.append(server)
    return live, signals


# A blackholed host costs exactly 2x `-timeout` (measured: https attempt + http
# fallback, 20.0s at timeout=10). On a partially-internal estate a THIRD of hosts
# failing is the normal baseline and scattered; an edge block instead shows up as a
# long UNBROKEN run of failures after the edge was demonstrably answering. 15 in a
# row is ~5 minutes of dead air at threads=2 and is not reachable by chance at the
# observed baseline.
_STALL_RUN = 15


class ProbeProgress:
    """Tracks the live httpx record stream to tell a mid-pass edge block apart from
    an estate that simply has a lot of internal-only names.

    Pure/synchronous — `observe()` returns True exactly once, on the record that
    trips the stall signal, so the driver can log it while the stage is running.
    """

    def __init__(self, total: int, stall_run: int = _STALL_RUN) -> None:
        self.total = total
        self.stall_run = stall_run
        self.seen = 0
        self.responded = 0
        self.failed = 0
        self.consecutive_failures = 0
        self.stalled_after: int | None = None   # index where the failure run began
        self.last_responding_host: str | None = None

    def observe(self, host: str, failed: bool) -> bool:
        self.seen += 1
        if failed:
            self.failed += 1
            self.consecutive_failures += 1
            # Only a block if the edge was answering earlier in THIS pass — a run
            # that starts from record 1 is an unreachable estate, not a block.
            if (
                self.stalled_after is None
                and self.responded > 0
                and self.consecutive_failures >= self.stall_run
            ):
                self.stalled_after = self.seen - self.consecutive_failures
                return True
        else:
            self.responded += 1
            self.consecutive_failures = 0
            self.last_responding_host = host
        return False

    @property
    def stalled(self) -> bool:
        return self.stalled_after is not None

    @property
    def unprobed(self) -> int:
        return max(0, self.total - self.seen)


async def run_httpx(
    fqdns: list[str],
    out_path: Path,
    cfg: HttpxConfig,
    log: RunLogger,
    timeout: float = 600.0,
    *,
    user_agent: str | None = None,
    extra_headers: dict[str, str] | None = None,
    progress: ProbeProgress | None = None,
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
        "-probe",                 # a record per INPUT (incl. `failed:true`) → the
                                  # stream doubles as progress; without it a host
                                  # that never answers emits nothing and 20s of dead
                                  # air is indistinguishable from a block.
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

    prog = progress if progress is not None else ProbeProgress(len(fqdns))
    outcome = StreamOutcome()
    lines: list[str] = []
    # Persist incrementally: a killed process must still leave the hosts it probed
    # on disk. Line-buffered so a SIGKILL loses at most the record in flight.
    with out_path.open("w", encoding="utf-8", buffering=1) as sink:
        async for line in stream_tool(
            cmd, outcome, stdin=payload, timeout=timeout, log=log, label="httpx",
        ):
            if not line.strip():
                continue
            sink.write(line + "\n")
            lines.append(line)
            host, failed = _probe_status(line)
            if host and prog.observe(host, failed):
                log.warn(
                    f"httpx: {prog.consecutive_failures} consecutive hosts timed out "
                    f"after {prog.responded} responded (last good: "
                    f"{prog.last_responding_host}) — the edge appears to have STOPPED "
                    f"ANSWERING mid-pass; {prog.unprobed} host(s) still unprobed",
                    event="probe_stalled", tool="httpx",
                    probed=prog.seen, responded=prog.responded,
                    stalled_after=prog.stalled_after, unprobed=prog.unprobed,
                    last_responding_host=prog.last_responding_host,
                )

    live, signals = parse_httpx_records(lines)
    # Rate-limit / WAF signal: a burst of 403/429/503 on the probe pass.
    throttled = [s for s in live if s.status_code in (403, 429, 503)]
    if throttled:
        log.warn(
            f"httpx: {len(throttled)}/{len(live)} host(s) returned 403/429/503 — "
            f"possible rate-limiting or WAF",
            event="rate_limit_signal", tool="httpx",
            hosts=[s.host for s in throttled][:20],
        )
    if outcome.timed_out:
        log.warn(
            f"httpx: budget exhausted after {prog.seen}/{prog.total} host(s) — "
            f"KEEPING {len(live)} live server(s) found so far "
            f"({prog.failed} host(s) did not answer)",
            event="probe_partial", tool="httpx",
            probed=prog.seen, total=prog.total, kept=len(live),
        )
    log.info(
        f"httpx found {len(live)} live web servers "
        f"({prog.seen}/{prog.total} probed, {prog.failed} no-answer)"
    )
    return live, signals


def _probe_status(line: str) -> tuple[str | None, bool]:
    """(input host, failed?) from one httpx `-probe` JSON line."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None, False
    host = (obj.get("input") or "").lower().rstrip(".") or None
    return host, obj.get("failed") is True
