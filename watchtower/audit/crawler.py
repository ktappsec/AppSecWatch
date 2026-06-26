"""Node D — Playwright supply-chain crawler.

Per locked decision (DESIGN.md §2.2): root-only per host, networkidle with
30s hard cap, 5 hosts in parallel. Captures all `script`-typed response
URLs and the document's response headers. One JSON artifact per host.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Response,
    async_playwright,
    Error as PWError,
    TimeoutError as PWTimeout,
)

from watchtower.config import PlaywrightConfig
from watchtower.logging import RunLogger
from watchtower.models import CrawlerArtifact, LiveWebServer
from watchtower.util.domains import host_to_filename


async def _crawl_one(
    browser: Browser,
    server: LiveWebServer,
    paths: list[str],
    out_dir: Path,
    cfg: PlaywrightConfig,
    log: RunLogger,
    identity: dict[str, Any] | None = None,
) -> CrawlerArtifact:
    host = server.host
    artifact = CrawlerArtifact(host=host, url=server.url, headers={}, scripts=[], errors=[])
    context_args: dict[str, Any] = {"ignore_https_errors": True}
    identity = identity or {}
    # Stealth identity wins over the tool default; a real browser context makes the
    # UA/headers/locale coherent with Chromium's own TLS/JS fingerprint.
    ua = identity.get("user_agent") or cfg.user_agent
    if ua:
        context_args["user_agent"] = ua
    if identity.get("locale"):
        context_args["locale"] = identity["locale"]
    if identity.get("headers"):
        context_args["extra_http_headers"] = identity["headers"]

    context: BrowserContext = await browser.new_context(**context_args)
    page: Page = await context.new_page()

    # Track every script-typed response (incl. dynamically injected).
    def on_response(resp: Response) -> None:
        try:
            req = resp.request
            if req.resource_type == "script":
                artifact.scripts.append({
                    "url": resp.url,
                    "status": resp.status,
                    "initiator_url": req.frame.url if req.frame else None,
                    "method": req.method,
                })
        except Exception as e:
            artifact.errors.append(f"on_response: {e}")

    page.on("response", on_response)

    try:
        target_paths = paths or ["/"]
        for i, p in enumerate(target_paths):
            target_url = urljoin(server.url, p) if p != "/" else server.url
            try:
                resp = await page.goto(
                    target_url,
                    wait_until=cfg.wait_until,
                    timeout=cfg.timeout_ms,
                )
                if i == 0 and resp is not None:
                    artifact.status = resp.status
                    headers = await resp.all_headers()
                    artifact.headers = {k.lower(): v for k, v in headers.items()}
            except PWTimeout:
                artifact.errors.append(f"timeout on {target_url}")
            except PWError as e:
                artifact.errors.append(f"navigation error on {target_url}: {e}")
    finally:
        try:
            await context.close()
        except Exception:
            pass

    # Dedup scripts by URL (preserve insertion order).
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for s in artifact.scripts:
        u = s.get("url")
        if u and u not in seen:
            seen.add(u)
            deduped.append(s)
    artifact.scripts = deduped

    out_path = out_dir / f"{host_to_filename(host)}.json"
    out_path.write_text(artifact.model_dump_json(indent=2))
    log.debug(f"crawler done: {host} ({len(artifact.scripts)} scripts)", host=host)
    return artifact


async def run_crawler(
    live_servers: list[LiveWebServer],
    paths_per_host: list[str],
    out_dir: Path,
    cfg: PlaywrightConfig,
    log: RunLogger,
    concurrency: int = 5,
    identity: dict[str, Any] | None = None,
) -> list[CrawlerArtifact]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if not live_servers:
        log.info("crawler: no live servers")
        return []

    sem = asyncio.Semaphore(concurrency)
    artifacts: list[CrawlerArtifact] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)

        async def gated(server: LiveWebServer) -> CrawlerArtifact:
            async with sem:
                try:
                    return await _crawl_one(browser, server, paths_per_host, out_dir, cfg, log, identity)
                except Exception as e:
                    log.warn(f"crawler failed for {server.host}: {e}", host=server.host)
                    return CrawlerArtifact(
                        host=server.host, url=server.url,
                        errors=[f"{type(e).__name__}: {e}"],
                    )

        results = await asyncio.gather(*(gated(s) for s in live_servers))
        artifacts.extend(results)

        await browser.close()

    log.info(f"crawler: visited {len(artifacts)} hosts")
    return artifacts
