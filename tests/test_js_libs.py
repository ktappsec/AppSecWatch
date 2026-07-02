"""Vulnerable-JS-library detection over crawler scripts."""
from __future__ import annotations

import types

from appsecwatch.audit.js_libs import _affected, _extract_version, scan_scripts


def art(host, urls):
    return types.SimpleNamespace(host=host, scripts=[{"url": u} for u in urls])


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
    # 4.17.10 is below both 4.17.12 and 4.17.21 → two distinct CVE findings;
    # the duplicate script URL must not double-count.
    fs = scan_scripts([art("a.com", ["/lodash-4.17.10.min.js", "/lodash-4.17.10.min.js"])])
    libs = [f for f in fs if f.evidence["library"] == "lodash"]
    assert len(libs) == 2


def test_extract_version_and_ranges():
    assert _extract_version("x/bootstrap-3.3.7.min.js", ["bootstrap[.-]?(\\d+(?:\\.\\d+){1,2})"]) == "3.3.7"
    assert _affected("3.4.0", {"below": "3.5.0"}) is True
    assert _affected("3.5.0", {"below": "3.5.0"}) is False
    assert _affected("3.2.0", {"atOrAbove": "3.0.0", "below": "3.4.1"}) is True
    assert _affected("4.0.0", {"atOrAbove": "3.0.0", "below": "3.4.1"}) is False
