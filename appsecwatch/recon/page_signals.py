"""Parse `PageSignals` from an httpx JSON record (raw, pre-JS HTML body).

httpx is invoked with `-include-response` so each JSON line carries the raw
response. Different httpx builds expose it under slightly different keys, so the
extraction here is deliberately defensive. The body is pre-JavaScript: title /
meta / OpenGraph live in the static <head> and survive, while visible body text
is thin for SPAs (the profiler is told as much).
"""
from __future__ import annotations

import base64
import re
from html.parser import HTMLParser
from typing import Any

from appsecwatch.models import PageSignals

_BODY_SNIPPET_CAP = 2048  # bytes worth of stripped visible text


def _raw_response(obj: dict[str, Any]) -> str:
    """Best-effort recovery of the raw HTTP response (headers + body)."""
    for key in ("response", "raw", "raw_response"):
        v = obj.get(key)
        if isinstance(v, str) and v:
            return v
    b64 = obj.get("response_base64") or obj.get("raw_base64")
    if isinstance(b64, str) and b64:
        try:
            return base64.b64decode(b64).decode("utf-8", "replace")
        except Exception:
            return ""
    return ""


def _split_head_body(raw: str) -> tuple[str, str]:
    """Split a raw HTTP response into (header-block, body). Tolerant of CRLF/LF."""
    for sep in ("\r\n\r\n", "\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep):]
    return "", raw


def _parse_headers(head_block: str) -> tuple[dict[str, str], list[str]]:
    """Parse a raw header block into (headers, set_cookies).

    Returns a lower-cased single-value dict (last duplicate wins, as HTTP allows
    for most headers) AND a separate list of every `Set-Cookie` value — cookies
    are the one header where each occurrence is distinct and must be preserved
    for per-cookie flag analysis.
    """
    headers: dict[str, str] = {}
    set_cookies: list[str] = []
    lines = head_block.splitlines()
    for line in lines[1:]:  # skip the status line
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if not k:
            continue
        if k == "set-cookie":
            if v:
                set_cookies.append(v)
        headers[k] = v
    return headers, set_cookies


class _PageParser(HTMLParser):
    """Extracts title, meta description, OG tags, forms, password inputs, text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self.meta_description: str | None = None
        self.og_tags: dict[str, str] = {}
        self.form_count = 0
        self.has_password_input = False
        self._text_parts: list[str] = []
        self._in_title = False
        self._suppress_depth = 0  # inside <script>/<style>/<noscript>

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in ("script", "style", "noscript"):
            self._suppress_depth += 1
        elif tag == "form":
            self.form_count += 1
        elif tag == "input":
            if attr.get("type", "").lower() == "password":
                self.has_password_input = True
        elif tag == "meta":
            name = (attr.get("name") or "").lower()
            prop = (attr.get("property") or "").lower()
            content = attr.get("content") or ""
            if name == "description" and not self.meta_description:
                self.meta_description = content.strip() or None
            if prop.startswith("og:") and content:
                self.og_tags[prop] = content.strip()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # self-closing <meta .../> and <input .../>
        self.handle_starttag(tag, attrs)
        if tag in ("script", "style", "noscript"):
            self._suppress_depth = max(0, self._suppress_depth - 1)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style", "noscript"):
            self._suppress_depth = max(0, self._suppress_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title = ((self.title or "") + data).strip() or None
        elif self._suppress_depth == 0:
            stripped = data.strip()
            if stripped:
                self._text_parts.append(stripped)

    def body_snippet(self) -> str:
        text = re.sub(r"\s+", " ", " ".join(self._text_parts)).strip()
        return text[:_BODY_SNIPPET_CAP]


def parse_page_signals(obj: dict[str, Any], host: str) -> PageSignals:
    """Build PageSignals from one httpx JSON record."""
    raw = _raw_response(obj)
    set_cookies: list[str] = []
    if raw:
        head_block, body = _split_head_body(raw)
        headers, set_cookies = _parse_headers(head_block)
    else:
        body = obj.get("body") or ""
        headers = {}

    # httpx also emits the raw response-header block (correct wire-format names,
    # one line per Set-Cookie) under `raw_header` — the most faithful source. It
    # is headers-only (status line + header lines, no body), so parse it directly
    # rather than via _split_head_body.
    if not headers:
        rh = obj.get("raw_header")
        if isinstance(rh, str) and rh.strip():
            headers, rc = _parse_headers(rh)
            if rc and not set_cookies:
                set_cookies = rc

    # Some httpx builds expose a structured headers map. Its JSON keys use '_' for
    # '-' (e.g. `strict_transport_security`), so normalize back to wire-format
    # names — otherwise every hyphenated lookup in header_checks misses and a host
    # that actually sets the header is reported as missing it.
    structured = obj.get("header") or obj.get("response_headers")
    if isinstance(structured, dict):
        for k, v in structured.items():
            lk = str(k).lower().replace("_", "-")
            headers.setdefault(lk, str(v))
            if lk == "set-cookie" and not set_cookies:
                # structured set-cookie may be a list (multiple) or a single str.
                set_cookies = [str(c) for c in v] if isinstance(v, list) else [str(v)]

    parser = _PageParser()
    if isinstance(body, str) and body:
        try:
            parser.feed(body)
        except Exception:
            pass

    # httpx's own parsed title is usually cleaner; prefer it when present.
    title = obj.get("title") or parser.title

    return PageSignals(
        host=host,
        headers=headers,
        set_cookies=set_cookies,
        title=title or None,
        meta_description=parser.meta_description,
        og_tags=parser.og_tags,
        body_snippet=parser.body_snippet(),
        form_count=parser.form_count,
        has_password_input=parser.has_password_input,
        tech=list(obj.get("tech") or obj.get("technologies") or []),
    )
