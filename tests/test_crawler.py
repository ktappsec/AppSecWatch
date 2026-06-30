"""Crawler capture shaping — the value-exclusion guarantee, at the data level.

The crawler drives a real browser, but its post-load capture (_capture_state) and
the dedup helper are pure enough to exercise with fakes — no Chromium needed. The
module imports without playwright (it is lazy-imported only when a browser runs).
"""
from __future__ import annotations

from pathlib import Path

from watchtower.audit.crawler import _capture_state, _dedup_by_url
from watchtower.config import PlaywrightConfig
from watchtower.models import CrawlerArtifact


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
