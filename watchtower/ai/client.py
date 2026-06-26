"""Thin OpenAI-compatible chat client.

Implemented against the `/v1/chat/completions` shape so it works with Ollama,
llama.cpp server, LM Studio, vLLM, and OpenAI itself.
"""
from __future__ import annotations

import httpx

from watchtower.config import LLMConfig


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        # response_format support is probed once: after a backend rejects it with a
        # 400/422, we stop sending it for the lifetime of this client so every
        # subsequent host doesn't pay the doubled round-trip.
        self._supports_response_format = True
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {cfg.api_key}",
                "Content-Type": "application/json",
            },
            timeout=cfg.timeout_seconds,
        )

    async def chat(self, system: str, user: str, *, temperature: float = 0.0) -> str:
        payload = {
            "model": self.cfg.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self._supports_response_format:
            # Honored by some backends; ignored by others. Dropped permanently on
            # the first 400/422 (see the probe below).
            payload["response_format"] = {"type": "json_object"}
        try:
            r = await self._client.post("/chat/completions", json=payload)
        except httpx.HTTPError as e:
            raise LLMError(f"LLM HTTP error: {e}") from e

        if r.status_code >= 400:
            # Some backends reject response_format. Drop it for this client and retry.
            if r.status_code in (400, 422) and "response_format" in payload:
                self._supports_response_format = False
                payload.pop("response_format")
                try:
                    r = await self._client.post("/chat/completions", json=payload)
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
