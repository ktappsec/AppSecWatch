"""Vulnerable-JS-library detection: URL + in-memory content + inventory."""
from __future__ import annotations

import types

from appsecwatch.audit.js_libs import (
    _affected,
    detect_in_content,
    detect_in_url,
    library_inventory,
    scan_scripts,
)


def art(host, urls=None, detected_libs=None):
    return types.SimpleNamespace(
        host=host,
        scripts=[{"url": u} for u in (urls or [])],
        detected_libs=detected_libs or [],
    )


# --------------------------------------------------------------------------- #
# URL-based detection (unchanged behavior)
# --------------------------------------------------------------------------- #
def test_detects_vulnerable_jquery():
    fs = scan_scripts([art("a.com", ["https://cdn.example.com/jquery-3.4.1.min.js"])])
    jq = [f for f in fs if f.evidence["library"] == "jquery"]
    assert jq and jq[0].source == "js_lib" and jq[0].evidence["version"] == "3.4.1"
    assert "CVE-2020-11022" in jq[0].evidence["cve"]
    assert jq[0].check_id == "js_lib.jquery.3.4.1"


def test_safe_version_no_finding():
    fs = scan_scripts([art("a.com", ["https://cdn/jquery-3.7.1.min.js"])])
    assert [f for f in fs if f.evidence["library"] == "jquery"] == []


def test_lodash_two_cves_and_dedupe():
    fs = scan_scripts([art("a.com", ["/lodash-4.17.10.min.js", "/lodash-4.17.10.min.js"])])
    libs = [f for f in fs if f.evidence["library"] == "lodash"]
    assert len(libs) == 2


def test_detect_in_url_and_ranges():
    assert detect_in_url("x/bootstrap-3.3.7.min.js") == [("bootstrap", "3.3.7")]
    assert _affected("3.4.0", {"below": "3.5.0"}) is True
    assert _affected("3.5.0", {"below": "3.5.0"}) is False
    assert _affected("3.2.0", {"atOrAbove": "3.0.0", "below": "3.4.1"}) is True
    assert _affected("4.0.0", {"atOrAbove": "3.0.0", "below": "3.4.1"}) is False


# --------------------------------------------------------------------------- #
# Content-based detection (bundled/minified — version not in the URL)
# --------------------------------------------------------------------------- #
def test_detect_in_content_from_banner():
    body = "/*! jQuery v3.4.1 | (c) OpenJS Foundation */ !function(e,t){}(...)"
    assert ("jquery", "3.4.1") in detect_in_content(body)


def test_content_detected_lib_flagged_as_vulnerable():
    # Simulates the crawler having content-scanned a bundled jquery whose URL had
    # no version (e.g. /static/app.bundle.js) — only detected_libs carries it.
    a = art("a.com", urls=["/static/app.bundle.js"],
            detected_libs=[{"library": "jquery", "version": "3.4.1", "url": "/static/app.bundle.js"}])
    fs = scan_scripts([a])
    jq = [f for f in fs if f.evidence["library"] == "jquery"]
    assert jq and jq[0].evidence["version"] == "3.4.1"


# --------------------------------------------------------------------------- #
# Inventory (all detected libs, vulnerable or not)
# --------------------------------------------------------------------------- #
def test_library_inventory_includes_non_vulnerable():
    a = art("a.com", urls=["/jquery-3.7.1.min.js"],       # safe version → no finding
            detected_libs=[{"library": "bootstrap", "version": "5.3.0", "url": "/b.js"}])
    inv = library_inventory([a])
    names = {(x["name"], x["version"]) for x in inv["a.com"]}
    assert ("jquery", "3.7.1") in names        # inventoried despite being safe
    assert ("bootstrap", "5.3.0") in names
    # a safe jquery still emits no vuln finding
    assert not [f for f in scan_scripts([a]) if f.evidence["library"] == "jquery"]
