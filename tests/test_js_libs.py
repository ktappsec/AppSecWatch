"""Vulnerable-JS-library detection: URL + in-memory content + inventory."""
from __future__ import annotations

import types

from appsecwatch.audit.js_libs import (
    _affected,
    _clean_version,
    _cmp,
    detect_in_content,
    detect_in_url,
    library_inventory,
    load_db,
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
    # Upstream lists the two 2020 XSS CVEs as separate entries, so assert across
    # findings rather than pinning which one lands first.
    assert "CVE-2020-11022" in " ".join(f.evidence["cve"] for f in jq)
    assert jq[0].check_id == "js_lib.jquery.3.4.1"


def test_safe_version_no_finding():
    fs = scan_scripts([art("a.com", ["https://cdn/jquery-3.7.1.min.js"])])
    assert [f for f in fs if f.evidence["library"] == "jquery"] == []


def test_lodash_multiple_cves_collapse_to_one():
    # cdnjs path layout — the URL form upstream's lodash `uri` extractor covers.
    # Several vuln entries cover 4.17.10; all fold into ONE finding per (host,lib,ver)
    # with every CVE listed (report/counts collapse them anyway).
    url = "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.10/lodash.min.js"
    fs = scan_scripts([art("a.com", [url, url])])
    libs = [f for f in fs if f.evidence["library"] == "lodash"]
    assert len(libs) == 1                       # one collapsed finding
    cves = libs[0].evidence["cve"]
    assert cves.count("CVE-") > 1               # multiple CVEs listed in the one row
    assert libs[0].evidence["cve_count"] == cves.count("CVE-")


def test_detect_in_url_and_ranges():
    assert detect_in_url("x/bootstrap-3.3.7.min.js") == [("bootstrap", "3.3.7")]
    assert _affected("3.4.0", {"below": "3.5.0"}) is True
    assert _affected("3.5.0", {"below": "3.5.0"}) is False
    assert _affected("3.2.0", {"atOrAbove": "3.0.0", "below": "3.4.1"}) is True
    assert _affected("4.0.0", {"atOrAbove": "3.0.0", "below": "3.4.1"}) is False


def test_excludes_pins_known_unaffected_build():
    assert _affected("1.12.4", {"below": "2.0.0"}) is True
    assert _affected("1.12.4-aem", {"below": "2.0.0", "excludes": ["1.12.4-aem"]}) is False


# --------------------------------------------------------------------------- #
# Version parsing — upstream's greedy placeholder + pre-release ordering
# --------------------------------------------------------------------------- #
def test_min_suffix_stripped_from_capture():
    """Upstream's version regex swallows `.min`; retire.js strips it after
    extracting and so must we, or every `.min.js` asset reports `3.3.7.min`."""
    assert _clean_version("3.3.7.min") == "3.3.7"
    assert _clean_version("1.2.3-min") == "1.2.3"
    assert _clean_version("4.17.21") == "4.17.21"
    assert _clean_version("notaversion") == ""


def test_implausible_capture_rejected():
    """Upstream `uri` patterns can capture a whole path segment. A real JSF asset
    (`/a4j/g/3_3_3.Finaljavascript/jquery-ui.js`) yielded a bogus 'version' that
    would land in the per-asset tech inventory."""
    assert _clean_version("3_3_3.Finaljavascript") == ""
    # ...without rejecting the pre-release shapes upstream genuinely uses
    for good in ("11", "1.12.4-aem", "13.4.20-canary.13", "1.0.0-rc.1", "1.9.0b1"):
        assert _clean_version(good) == good


def test_prerelease_sorts_below_its_release():
    """135 upstream bounds carry pre-release suffixes. A digits-only comparison
    makes 1.0.0-rc.1 sort ABOVE 1.0.0 and flags the released version."""
    assert _cmp("1.0.0", "1.0.0-rc.1") > 0
    assert _cmp("1.0.0-rc.1", "1.0.0") < 0
    assert _affected("1.0.0", {"below": "1.0.0-rc.1"}) is False
    assert _affected("0.9.9", {"below": "1.0.0-rc.1"}) is True


# --------------------------------------------------------------------------- #
# THE REGRESSION this integration fixes
# --------------------------------------------------------------------------- #
BOOTSTRAP4_BODY = (
    '/*!\n * Bootstrap v4.3.1 (https://getbootstrap.com/)\n */\n'
    'function(){var version=$.fn.jquery.split(" ")[0].split(".");'
    'if(version[0]>=4){throw new Error("Bootstrap\'s JavaScript requires at least '
    'jQuery v1.9.1 but less than v4.0.0")}}'
)


def test_bootstrap_jquery_requirement_string_is_not_a_version():
    """Bootstrap 4 names a *minimum* jQuery in a thrown error. An unanchored
    `jQuery v(\\d+...)` pattern read that as a declaration and reported jquery
    1.9.1 on 14 hosts that actually shipped jQuery 3.7.1. Upstream's patterns are
    anchored to jQuery's own banner comment, so the phrase must not match."""
    hits = detect_in_content(BOOTSTRAP4_BODY)
    assert ("jquery", "1.9.1") not in hits
    assert not any(lib == "jquery" for lib, _ in hits)
    assert ("bootstrap", "4.3.1") in hits        # the real library still detected


def test_real_jquery_banner_still_detected():
    assert ("jquery", "3.4.1") in detect_in_content("/*! jQuery v3.4.1 | (c) JS Foundation */")
    assert ("jquery", "1.11.3") in detect_in_content(
        "/*!\n * jQuery JavaScript Library v1.11.3\n * http://jquery.com/\n */")


def test_uncompilable_upstream_pattern_skipped_not_fatal():
    """Some upstream regexes are JS-only (lodash uses a variable-width
    look-behind). They must be skipped per-pattern, never drop the library."""
    db = load_db()
    assert "lodash" in db
    assert db["lodash"]["_filecontent"]          # other patterns survived
    assert len(db["lodash"]["_filecontent"]) < len(db["lodash"]["filecontent"])


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
