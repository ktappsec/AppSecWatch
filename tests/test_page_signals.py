"""PageSignals parsing from httpx records (raw pre-JS HTML)."""
from __future__ import annotations

import base64

from watchtower.recon.page_signals import parse_page_signals
from watchtower.recon.web_probe import parse_httpx_records

_RAW = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Set-Cookie: sid=abc; HttpOnly\r\n"
    "\r\n"
    "<html><head><title>Acme Login</title>"
    '<meta name="description" content="Sign in to your Acme account">'
    '<meta property="og:type" content="website">'
    "</head><body><h1>Welcome back</h1>"
    '<form action="/login"><input type="text" name="user">'
    '<input type="password" name="pw"></form>'
    "<script>var secret=1;</script></body></html>"
)


def test_parses_from_raw_response():
    obj = {"response": _RAW, "host": "login.acme.com", "title": "Acme Login", "tech": ["nginx"]}
    ps = parse_page_signals(obj, "login.acme.com")
    assert ps.host == "login.acme.com"
    assert ps.title == "Acme Login"
    assert ps.meta_description == "Sign in to your Acme account"
    assert ps.og_tags["og:type"] == "website"
    assert ps.form_count == 1
    assert ps.has_password_input is True
    assert "Welcome back" in ps.body_snippet
    assert "var secret" not in ps.body_snippet          # <script> suppressed
    assert ps.headers["content-type"] == "text/html; charset=utf-8"
    assert ps.headers["set-cookie"] == "sid=abc; HttpOnly"
    assert ps.tech == ["nginx"]


def test_parses_from_body_field_when_no_raw():
    obj = {"body": "<html><head><title>Hi</title></head><body>plain text</body></html>", "host": "x"}
    ps = parse_page_signals(obj, "x")
    assert ps.title == "Hi"
    assert ps.has_password_input is False
    assert ps.form_count == 0
    assert "plain text" in ps.body_snippet
    assert ps.headers == {}


def test_parses_base64_response():
    obj = {"response_base64": base64.b64encode(_RAW.encode()).decode(), "host": "h"}
    ps = parse_page_signals(obj, "h")
    assert ps.title == "Acme Login"
    assert ps.has_password_input is True


def test_body_snippet_is_capped():
    big = "HTTP/1.1 200 OK\r\n\r\n<body>" + ("word " * 5000) + "</body>"
    ps = parse_page_signals({"response": big}, "h")
    assert len(ps.body_snippet) <= 2048


def test_httpx_title_preferred_over_parsed():
    obj = {"response": _RAW, "host": "h", "title": "Cleaner Title"}
    ps = parse_page_signals(obj, "h")
    assert ps.title == "Cleaner Title"


def test_parse_httpx_records_builds_servers_and_signals():
    import json
    line = json.dumps({
        "url": "https://login.acme.com",
        "host": "login.acme.com",
        "status_code": 200,
        "title": "Acme Login",
        "tech": ["nginx"],
        "response": _RAW,
    })
    servers, signals = parse_httpx_records([line, "", "not-json"])
    assert len(servers) == 1
    assert servers[0].host == "login.acme.com"
    assert "login.acme.com" in signals
    assert signals["login.acme.com"].has_password_input is True
