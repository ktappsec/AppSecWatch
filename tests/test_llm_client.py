"""LLMClient request attribution: X-Title / HTTP-Referer headers + the OpenRouter
`user` field. No real network — the inner httpx post is monkeypatched."""
from __future__ import annotations

import types

from appsecwatch.ai.client import LLMClient
from appsecwatch.config import LLMConfig


class _Resp:
    status_code = 200
    text = ""

    def json(self):
        return {"choices": [{"message": {"content": "{}"}}]}


def _patch_post(client: LLMClient, captured: dict):
    async def fake_post(url, json=None, headers=None):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _Resp()

    client._client.post = fake_post  # type: ignore[method-assign]


def _or_cfg(**kw) -> LLMConfig:
    return LLMConfig(base_url="https://openrouter.ai/api/v1", model="m", **kw)


def test_default_headers_carry_app_title_and_referer():
    c = LLMClient(_or_cfg(app_title="AppSecWatch", app_url="https://wt.example"))
    # httpx Headers are case-insensitive.
    assert c._client.headers["x-title"] == "AppSecWatch"
    assert c._client.headers["http-referer"] == "https://wt.example"


def test_no_referer_header_when_app_url_unset():
    c = LLMClient(_or_cfg())
    assert "http-referer" not in c._client.headers
    assert c._client.headers["x-title"] == "AppSecWatch"


async def test_per_request_title_uses_call_purpose_and_user_field():
    c = LLMClient(_or_cfg())
    cap: dict = {}
    _patch_post(c, cap)
    await c.chat("s", "u", label="profile[example.com]")
    # X-Title is overridden per request with the purpose so spend groups by it.
    assert cap["headers"] == {"X-Title": "AppSecWatch: profile"}
    # OpenRouter records the `user` field — tag it with the full per-host label.
    assert cap["json"]["user"] == "profile[example.com]"


async def test_user_field_omitted_off_openrouter():
    c = LLMClient(LLMConfig(base_url="http://localhost:11434/v1", model="m"))
    cap: dict = {}
    _patch_post(c, cap)
    await c.chat("s", "u", label="triage[example.com]")
    assert "user" not in cap["json"]
    # The title header still groups by purpose (harmless if the backend ignores it).
    assert cap["headers"] == {"X-Title": "AppSecWatch: triage"}


async def test_tag_requests_off_sends_no_per_request_override():
    c = LLMClient(_or_cfg(tag_requests=False))
    cap: dict = {}
    _patch_post(c, cap)
    await c.chat("s", "u", label="supply[example.com]")
    assert cap["headers"] is None
    assert "user" not in cap["json"]
    # The static app title still rides on the client default headers.
    assert c._client.headers["x-title"] == "AppSecWatch"


async def test_no_label_keeps_static_title():
    c = LLMClient(_or_cfg())
    cap: dict = {}
    _patch_post(c, cap)
    await c.chat("s", "u")
    assert cap["headers"] is None
    assert "user" not in cap["json"]


async def test_per_call_model_override_by_purpose():
    c = LLMClient(_or_cfg(models={"profile": "cheap/fast", "triage": "smart/big"}))
    cap: dict = {}
    _patch_post(c, cap)
    await c.chat("s", "u", label="profile[example.com]")
    assert cap["json"]["model"] == "cheap/fast"


async def test_unlisted_purpose_falls_back_to_base_model():
    c = LLMClient(LLMConfig(base_url="https://openrouter.ai/api/v1", model="base/model",
                            models={"triage": "smart/big"}))
    cap: dict = {}
    _patch_post(c, cap)
    await c.chat("s", "u", label="profile[example.com]")  # 'profile' not overridden
    assert cap["json"]["model"] == "base/model"
