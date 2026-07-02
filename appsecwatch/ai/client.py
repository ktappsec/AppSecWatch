"""Thin OpenAI-compatible chat client.

Implemented against the `/v1/chat/completions` shape so it works with Ollama,
llama.cpp server, LM Studio, vLLM, and OpenAI itself.
"""
from __future__ import annotations

import httpx

from appsecwatch.config import LLMConfig


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        # response_format support is probed once: after a backend rejects it with a
        # 400/422, we stop sending it for the lifetime of this client so every
        # subsequent host doesn't pay the doubled round-trip.
        self._supports_response_format = True
        # OpenRouter records the OpenAI `user` field; gate it to OpenRouter so a
        # strict local backend never sees an unexpected field (the X-Title /
        # HTTP-Referer headers below are safe everywhere — unknown headers are
        # ignored).
        self._is_openrouter = "openrouter.ai" in cfg.base_url.lower()
        headers = {
            "Authorization": f"Bearer {cfg.api_key}",
            "Content-Type": "application/json",
        }
        if cfg.app_title:
            headers["X-Title"] = cfg.app_title
        if cfg.app_url:
            headers["HTTP-Referer"] = cfg.app_url
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            headers=headers,
            timeout=cfg.timeout_seconds,
        )

    @staticmethod
    def _purpose(label: str | None) -> str | None:
        """`profile[example.com]` -> `profile`; `nuclei-gen` -> `nuclei-gen`."""
        if not label:
            return None
        return label.split("[", 1)[0] or None

    async def chat(
        self, system: str, user: str, *, temperature: float = 0.0,
        label: str | None = None, json_mode: bool = True,
    ) -> str:
        """Call the chat endpoint. `json_mode` requests a JSON-object response
        (`response_format`); pass `json_mode=False` for callers whose contract is a
        non-JSON body (e.g. nuclei-gen returns YAML — forcing JSON would corrupt it)."""
        purpose = self._purpose(label)
        # Per-call-type model override (cfg.models keyed by purpose); falls back to
        # the base model for an unlisted purpose or an unlabeled call.
        model = (self.cfg.models.get(purpose) if purpose else None) or self.cfg.model
        payload = {
            "model": model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode and self._supports_response_format:
            # Honored by some backends; ignored by others. Dropped permanently on
            # the first 400/422 (see the probe below).
            payload["response_format"] = {"type": "json_object"}

        # Per-request attribution. Override X-Title with the call purpose so spend
        # groups by call type in OpenRouter's activity log; tag the full label onto
        # the `user` field (OpenRouter only) for per-host granularity.
        req_headers: dict[str, str] | None = None
        if self.cfg.tag_requests and label:
            if purpose and self.cfg.app_title:
                req_headers = {"X-Title": f"{self.cfg.app_title}: {purpose}"}
            if self._is_openrouter:
                payload["user"] = label

        try:
            r = await self._client.post("/chat/completions", json=payload, headers=req_headers)
        except httpx.HTTPError as e:
            raise LLMError(f"LLM HTTP error: {e}") from e

        if r.status_code >= 400:
            # Some backends reject response_format. Drop it for this client and retry.
            if r.status_code in (400, 422) and "response_format" in payload:
                self._supports_response_format = False
                payload.pop("response_format")
                try:
                    r = await self._client.post("/chat/completions", json=payload, headers=req_headers)
                except httpx.HTTPError as e:
                    raise LLMError(f"LLM HTTP error: {e}") from e

        if r.status_code >= 400:
            raise LLMError(f"LLM HTTP {r.status_code}: {r.text[:400]}")

        body = r.json()
        choices = body.get("choices") or []
        if not choices:
            raise LLMError("LLM returned no choices")
        content = choices[0].get("message", {}).get("content")
        if not isinstance(content, str):
            raise LLMError("LLM returned non-string content")
        return content

    async def close(self) -> None:
        await self._client.aclose()
