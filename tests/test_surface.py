"""curated_surface(): names-only EASM projection of a CrawlerArtifact."""
from __future__ import annotations

from appsecwatch.audit.surface import curated_surface
from appsecwatch.models import CrawlerArtifact


def _artifact() -> CrawlerArtifact:
    return CrawlerArtifact(
        host="app.example.com",
        url="https://app.example.com",
        resources=[
            {"url": "https://app.example.com/main.js", "type": "script", "status": 200, "method": "GET"},
            {"url": "https://cdn.thirdparty.io/widget.js", "type": "script", "status": 200, "method": "GET"},
            {"url": "https://api.stripe.com/v1/tokens?secret=sk_live_abc", "type": "xhr", "status": 200, "method": "POST"},
            {"url": "https://app.example.com/api/me", "type": "fetch", "status": 200, "method": "GET"},
            {"url": "https://app.example.com/logo.png", "type": "image", "status": 200, "method": "GET"},
        ],
        cookies=[{"name": "JSESSIONID", "secure": True}, {"name": "csrftoken"}],
        local_storage_keys=["access_token", "redux-persist"],
        session_storage_keys=["nav_state"],
    )


def test_third_party_split_excludes_self():
    s = curated_surface(_artifact())
    assert s["third_party_domains"] == ["stripe.com", "thirdparty.io"]
    # the app's own eTLD+1 is never listed as third-party
    assert "example.com" not in s["third_party_domains"]


def test_endpoints_are_method_host_path_without_query():
    s = curated_surface(_artifact())
    assert "POST api.stripe.com/v1/tokens" in s["endpoints"]
    assert "GET app.example.com/api/me" in s["endpoints"]
    # the query string (which can carry secrets) is dropped
    assert all("secret" not in e and "?" not in e for e in s["endpoints"])
    # static assets (images) are not endpoints
    assert not any("logo.png" in e for e in s["endpoints"])


def test_script_domains_capture_both_parties():
    s = curated_surface(_artifact())
    assert set(s["script_domains"]) == {"example.com", "thirdparty.io"}


def test_cookie_and_storage_keys_names_only():
    s = curated_surface(_artifact())
    assert s["cookie_keys"] == ["JSESSIONID", "csrftoken"]
    assert s["storage_keys"] == ["access_token", "nav_state", "redux-persist"]


def test_no_values_or_bodies_ever_surface():
    # Even if (hypothetically) a value sneaks onto a cookie dict, curated_surface
    # only ever reads names — assert the serialized surface carries no value text.
    art = _artifact()
    art.cookies[0]["value"] = "super-secret-session"
    s = curated_surface(art)
    import json
    assert "super-secret-session" not in json.dumps(s)


def test_empty_artifact_is_empty_surface():
    s = curated_surface(CrawlerArtifact(host="x.com", url="https://x.com"))
    assert s == {
        "third_party_domains": [],
        "script_domains": [],
        "endpoints": [],
        "cookie_keys": [],
        "storage_keys": [],
    }
