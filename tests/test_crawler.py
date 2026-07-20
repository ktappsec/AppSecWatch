"""Crawler capture shaping — the value-exclusion guarantee, at the data level.

The crawler drives a real browser, but its post-load capture (_capture_state) and
the dedup helper are pure enough to exercise with fakes — no Chromium needed. The
module imports without playwright (it is lazy-imported only when a browser runs).
"""
from __future__ import annotations

from pathlib import Path

from appsecwatch.audit.crawler import (
    _capture_state,
    _dedup_by_url,
    _summarize_failed_requests,
)
from appsecwatch.config import PlaywrightConfig
from appsecwatch.models import CrawlerArtifact


class _FakeContext:
    async def cookies(self):
        # A real cookie carries a `value`; capture must drop it.
        return [{
            "name": "JSESSIONID", "value": "SECRET-SESSION-TOKEN",
            "domain": "x.com", "path": "/", "secure": True,
            "httpOnly": True, "sameSite": "Lax", "expires": -1,
        }]


class _FakePage:
    async def evaluate(self, js: str):
        if "localStorage" in js:
            return {"l": ["access_token", "redux"], "s": ["flag"]}
        return "  Welcome \n\n  to   the   app  "

    async def screenshot(self, **_):  # pragma: no cover - screenshot disabled below
        raise AssertionError("screenshot should not be called when cfg.screenshot is False")


def test_dedup_by_url_preserves_order():
    out = _dedup_by_url([{"url": "a"}, {"url": "b"}, {"url": "a"}, {"url": "c"}])
    assert [d["url"] for d in out] == ["a", "b", "c"]


def _fail(url, type="script", failure="net::ERR_ABORTED"):
    return {"url": url, "type": type, "method": "GET", "failure": failure}


def test_bot_blocked_crawl_surfaces_a_degraded_note():
    """The scan-observed case: document loaded (1 resource) but every subresource
    was aborted. Must surface a note so it's not mistaken for a script-free page."""
    art = CrawlerArtifact(host="bank.example", url="https://bank.example")
    art.resources = [{"url": "https://bank.example/", "type": "document", "status": 200}]
    art.failed_requests = [_fail(f"https://bank.example/a{i}.js") for i in range(8)]
    _summarize_failed_requests(art)
    assert len(art.errors) == 1
    note = art.errors[0]
    assert "8 request(s) failed" in note
    assert "net::ERR_ABORTED×8" in note
    assert "bot-blocked" in note


def test_document_failure_is_always_material():
    """Even a single failure is surfaced when it's the document itself."""
    art = CrawlerArtifact(host="x", url="https://x")
    art.failed_requests = [_fail("https://x/", type="document")]
    _summarize_failed_requests(art)
    assert len(art.errors) == 1 and "1 request(s) failed" in art.errors[0]


def test_a_few_blocked_trackers_stay_quiet():
    """A healthy page with a couple of blocked trackers must NOT spam errors.json."""
    art = CrawlerArtifact(host="x", url="https://x")
    art.resources = [{"url": f"https://x/r{i}", "type": "script"} for i in range(40)]
    art.failed_requests = [_fail("https://tracker.example/px.gif", type="image")]
    _summarize_failed_requests(art)
    assert art.errors == []


def test_no_failures_no_note():
    art = CrawlerArtifact(host="x", url="https://x")
    art.resources = [{"url": "https://x/", "type": "document"}]
    _summarize_failed_requests(art)
    assert art.errors == []



async def test_capture_state_drops_values_keeps_names(tmp_path: Path):
    art = CrawlerArtifact(host="x.com", url="https://x.com")
    await _capture_state(_FakePage(), _FakeContext(), art, tmp_path, PlaywrightConfig(screenshot=False))

    # Cookie: name + flags survive; the value is gone.
    assert art.cookies == [{
        "name": "JSESSIONID", "domain": "x.com", "path": "/",
        "secure": True, "http_only": True, "same_site": "Lax", "expires": -1,
    }]
    assert not any("value" in c for c in art.cookies)

    # Storage: KEY NAMES only.
    assert art.local_storage_keys == ["access_token", "redux"]
    assert art.session_storage_keys == ["flag"]

    # Rendered text: whitespace-normalized.
    assert art.rendered_text == "Welcome to the app"

    # Screenshot disabled → none recorded, no errors.
    assert art.screenshot is None
    assert art.errors == []



async def test_capture_state_is_best_effort(tmp_path: Path):
    class _BoomCtx:
        async def cookies(self):
            raise RuntimeError("cookie jar blew up")

    class _BoomPage:
        async def evaluate(self, js: str):
            raise RuntimeError("evaluate blew up")

    art = CrawlerArtifact(host="x.com", url="https://x.com")
    # Must not raise — failures are recorded, the crawl continues.
    await _capture_state(_BoomPage(), _BoomCtx(), art, tmp_path, PlaywrightConfig(screenshot=False))
    assert art.cookies == []
    assert any("cookies:" in e for e in art.errors)
    assert any("storage_keys:" in e or "rendered_text:" in e for e in art.errors)
