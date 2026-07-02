"""Node D — Playwright supply-chain crawler.

Per locked decision (DESIGN.md §2.2): root-only per host, networkidle with
30s hard cap, 5 hosts in parallel. Captures every response (resources, scripts),
the document headers, cookie/storage KEY names + rendered text, and an optional
screenshot. STRUCTURE ONLY — never any cookie/storage value or response body.
One JSON artifact per host.

NB playwright is imported lazily inside the functions that drive a browser, so
this module (and its pure helpers) can be imported without the heavy browser dep
— mirroring CrawlerStage, which already lazy-imports this module.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

if TYPE_CHECKING:  # annotations only — never imported at runtime
    from playwright.async_api import Browser, BrowserContext, Page, Response

from appsecwatch.config import PlaywrightConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import CrawlerArtifact, LiveWebServer
from appsecwatch.util.domains import host_to_filename

# Mirrors recon/page_signals.py::_BODY_SNIPPET_CAP — same treatment, rendered DOM source.
_RENDERED_TEXT_CAP = 2048
# Bound the resource manifest so a chatty SPA can't bloat the artifact.
_RESOURCE_CAP = 500


def _dedup_by_url(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dedup a list of capture dicts by their `url`, preserving insertion order."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for it in items:
        u = it.get("url")
        if u and u not in seen:
            seen.add(u)
            out.append(it)
    return out


async def _capture_state(
    page: Page,
    context: BrowserContext,
    artifact: CrawlerArtifact,
    out_dir: Path,
    cfg: PlaywrightConfig,
) -> None:
    """Best-effort post-load capture of cookies (names + flags), storage KEY names,
    rendered visible text, and an optional screenshot. STRUCTURE ONLY — never reads
    any cookie/storage value. Each step is wrapped so one failure loses neither the
    others nor the crawl."""
    try:
        for c in await context.cookies():
            artifact.cookies.append({
                "name": c.get("name"),
                "domain": c.get("domain"),
                "path": c.get("path"),
                "secure": c.get("secure"),
                "http_only": c.get("httpOnly"),
                "same_site": c.get("sameSite"),
                "expires": c.get("expires"),
            })
    except Exception as e:  # noqa: BLE001
        artifact.errors.append(f"cookies: {e}")
    try:
        keys = await page.evaluate(
            "() => ({l: Object.keys(localStorage), s: Object.keys(sessionStorage)})"
        )
        artifact.local_storage_keys = list(keys.get("l") or [])
        artifact.session_storage_keys = list(keys.get("s") or [])
    except Exception as e:  # noqa: BLE001 — opaque origins throw on storage access
        artifact.errors.append(f"storage_keys: {e}")
    try:
        text = await page.evaluate("() => document.body ? document.body.innerText : ''")
        artifact.rendered_text = re.sub(r"\s+", " ", text or "").strip()[:_RENDERED_TEXT_CAP]
    except Exception as e:  # noqa: BLE001
        artifact.errors.append(f"rendered_text: {e}")
    if cfg.screenshot:
        try:
            shot = f"{host_to_filename(artifact.host)}.png"
            await page.screenshot(path=str(out_dir / shot), full_page=False)
            artifact.screenshot = shot
        except Exception as e:  # noqa: BLE001
            artifact.errors.append(f"screenshot: {e}")


async def _crawl_one(
    browser: Browser,
    server: LiveWebServer,
    paths: list[str],
    out_dir: Path,
    cfg: PlaywrightConfig,
    log: RunLogger,
    identity: dict[str, Any] | None = None,
) -> CrawlerArtifact:
    from playwright.async_api import Error as PWError, TimeoutError as PWTimeout

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

    # Track every response (incl. dynamically injected / transitively loaded). The
    # network-level hook captures scripts a script pulled in, not just <script> tags.
    def on_response(resp: Response) -> None:
        try:
            req = resp.request
            rtype = req.resource_type
            artifact.resources.append({
                "url": resp.url,
                "type": rtype,
                "status": resp.status,
                "method": req.method,
            })
            if rtype == "script":
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

        # Post-load structural capture (names/flags only — never values). Runs once,
        # after the root nav has settled, while the context is still open.
        await _capture_state(page, context, artifact, out_dir, cfg)
    finally:
        try:
            await context.close()
        except Exception:
            pass

    # Dedup by URL (preserve insertion order); bound the resource manifest.
    artifact.scripts = _dedup_by_url(artifact.scripts)
    artifact.resources = _dedup_by_url(artifact.resources)[:_RESOURCE_CAP]

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

    from playwright.async_api import async_playwright

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
