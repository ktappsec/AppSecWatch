"""Node D — Playwright supply-chain crawler.

Per locked decision (DESIGN.md §2.2): root-only per host, networkidle with
30s hard cap, 5 hosts in parallel. Captures every response (resources, scripts),
the document headers, cookie/storage KEY names + rendered text, and an optional
screenshot. STRUCTURE ONLY — never any cookie/storage value or response body.
One JSON artifact per host. Requests that FAIL at the network layer (WAF
reset/abort, DNS, timeout) are captured separately (`failed_requests`) — they
never fire `response`, so without this a bot-blocked crawl looks script-free.

NB playwright is imported lazily inside the functions that drive a browser, so
this module (and its pure helpers) can be imported without the heavy browser dep
— mirroring CrawlerStage, which already lazy-imports this module.
"""
from __future__ import annotations

import asyncio
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

if TYPE_CHECKING:  # annotations only — never imported at runtime
    from playwright.async_api import Browser, BrowserContext, Page, Request, Response

from appsecwatch.config import PlaywrightConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import CrawlerArtifact, LiveWebServer
from appsecwatch.util.domains import host_to_filename

# Mirrors recon/page_signals.py::_BODY_SNIPPET_CAP — same treatment, rendered DOM source.
_RENDERED_TEXT_CAP = 2048
# Bound the resource manifest so a chatty SPA can't bloat the artifact.
_RESOURCE_CAP = 500
# In-memory JS-library content scan bounds (bodies are read but NEVER persisted).
_CONTENT_SCAN_MAX_SCRIPTS = 80
_CONTENT_SCAN_MAX_BYTES = 3_000_000


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


def _summarize_failed_requests(artifact: CrawlerArtifact) -> None:
    """Append a one-line 'crawl degraded' note to `artifact.errors` when a
    MATERIAL share of requests failed at the network layer.

    Failed requests never fire `response`, so they're invisible in `resources`;
    a bot-blocked page (WAF resets/aborts subresources) then looks identical to a
    script-free one. This surfaces that in errors.json so the operator can tell
    'blocked' from 'no JS'. Material = the document itself failed, OR ≥3 failures,
    OR nothing but the document(s) came back — so a couple of blocked trackers on
    an otherwise-complete page stay quiet (no errors.json spam, no --strict trip).
    """
    n_fail = len(artifact.failed_requests)
    if not n_fail:
        return
    doc_failed = any(f.get("type") == "document" for f in artifact.failed_requests)
    material = n_fail >= 3 or doc_failed or len(artifact.resources) <= 2
    if not material:
        return
    reasons = Counter((f.get("failure") or "?") for f in artifact.failed_requests)
    top = ", ".join(f"{r}×{n}" for r, n in reasons.most_common(3))
    artifact.errors.append(
        f"{n_fail} request(s) failed at network layer ({top}) — page subresources "
        f"blocked/unreachable; crawl likely bot-blocked or rate-limited, "
        f"supply-chain/js-lib/profile analysis degraded"
    )


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


async def _scan_script_bodies(
    script_responses: list[Response],
    artifact: CrawlerArtifact,
    scan_secrets: bool = True,
) -> None:
    """Read each script body IN MEMORY, then run TWO deterministic scans over it:
    (1) JS-library version signatures → ``{library, version, url}``, and
    (2) client-side secret exposure → ``{rule, url, line, preview}`` (MASKED
    preview only). The body itself is NEVER persisted (runs/<id>/ stays a
    shareable artifact set). Best-effort per script; one read feeds both scans."""
    from appsecwatch.audit.js_libs import detect_in_content, load_db

    db = load_db()
    seen: set[tuple[str, str]] = set()
    secrets_db = None
    if scan_secrets:
        from appsecwatch.audit.secrets import detect_in_content as detect_secrets
        from appsecwatch.audit.secrets import load_db as load_secrets_db
        secrets_db = load_secrets_db()
    for resp in script_responses[:_CONTENT_SCAN_MAX_SCRIPTS]:
        try:
            body = await resp.text()
        except Exception:  # body gone / binary / decode error — skip
            continue
        if not body or len(body) > _CONTENT_SCAN_MAX_BYTES:
            continue
        for lib, ver in detect_in_content(body, db):
            if (lib, ver) in seen:
                continue
            seen.add((lib, ver))
            artifact.detected_libs.append({"library": lib, "version": ver, "url": resp.url})
        if secrets_db is not None:
            for hit in detect_secrets(body, secrets_db):
                artifact.detected_secrets.append({**hit, "url": resp.url})


async def _crawl_one(
    browser: Browser,
    server: LiveWebServer,
    paths: list[str],
    out_dir: Path,
    cfg: PlaywrightConfig,
    log: RunLogger,
    identity: dict[str, Any] | None = None,
    scan_secrets: bool = True,
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
        # Chromium computes the browser-managed request headers itself, per request.
        # `Sec-Fetch-*` in particular vary by resource type (document/style/script/…):
        # the identity preset carries the *navigation* values (Dest: document,
        # Mode: navigate), which are correct only for the top-level document. Forcing
        # them onto every request via extra_http_headers makes Chromium reject each
        # subresource with net::ERR_INVALID_ARGUMENT — so the page document loads but
        # every script/style/image/font fails and nothing is captured. Those headers
        # matter for the header-blind CLI tools (httpx/nuclei), not for a real browser;
        # drop them here and let Chromium emit coherent ones.
        crawler_headers = {
            k: v for k, v in identity["headers"].items()
            if not k.lower().startswith("sec-fetch-")
        }
        if crawler_headers:
            context_args["extra_http_headers"] = crawler_headers

    context: BrowserContext = await browser.new_context(**context_args)
    page: Page = await context.new_page()

    # Script Response objects captured for the in-memory body scan (below); the
    # bodies themselves are read after load and never stored.
    script_responses: list[Response] = []

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
                script_responses.append(resp)
        except Exception as e:
            artifact.errors.append(f"on_response: {e}")

    # A failed request (blocked/reset/aborted/DNS/timeout) fires `requestfailed`,
    # NOT `response` — so on_response above never sees it. Record it (names/reason
    # only) or a bot-blocked crawl looks identical to a script-free page.
    def on_request_failed(req: Request) -> None:
        try:
            artifact.failed_requests.append({
                "url": req.url,
                "type": req.resource_type,
                "method": req.method,
                "failure": (req.failure or "")[:120],
            })
        except Exception as e:
            artifact.errors.append(f"on_request_failed: {e}")

    page.on("response", on_response)
    page.on("requestfailed", on_request_failed)

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
        # In-memory JS-library content scan: read script bodies (still available
        # pre-close), match version signatures, keep ONLY {library, version, url}.
        await _scan_script_bodies(script_responses, artifact, scan_secrets=scan_secrets)
    finally:
        try:
            await context.close()
        except Exception:
            pass

    # Dedup by URL (preserve insertion order); bound the resource manifest.
    artifact.scripts = _dedup_by_url(artifact.scripts)
    artifact.resources = _dedup_by_url(artifact.resources)[:_RESOURCE_CAP]
    artifact.failed_requests = _dedup_by_url(artifact.failed_requests)[:_RESOURCE_CAP]
    _summarize_failed_requests(artifact)

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
    scan_secrets: bool = True,
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
                    return await _crawl_one(browser, server, paths_per_host, out_dir, cfg, log,
                                            identity, scan_secrets=scan_secrets)
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
