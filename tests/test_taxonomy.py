"""Controlled finding-class taxonomy: totality + representative mappings."""
from __future__ import annotations

import pytest

from appsecwatch.audit.taxonomy import (
    CATEGORY_LABELS,
    CATEGORY_OF,
    FINDING_CLASSES,
    classify,
    classify_findings,
)
from appsecwatch.models import Finding


def F(**kw) -> Finding:
    return Finding(**{"source": "headers", "severity": "medium", "title": "t", **kw})


def test_every_class_has_a_known_category():
    for cls in FINDING_CLASSES:
        assert cls in CATEGORY_OF
        assert CATEGORY_OF[cls] in CATEGORY_LABELS


@pytest.mark.parametrize("finding,expected_class", [
    (F(source="headers", check_id="hsts.missing"), "headers.hsts-missing"),
    (F(source="headers", check_id="clickjacking.missing"), "headers.xfo-missing"),
    (F(source="headers", check_id="cookie.secure.SESSIONID"), "headers.cookie-security"),
    (F(source="headers", check_id="info-disclosure.server"), "headers.info-leak-header"),
    (F(source="csp", check_id="csp.unsafe-inline.script-src"), "csp.unsafe-inline"),
    (F(source="csp", check_id="csp.missing"), "csp.missing"),
    (F(source="csp", check_id="csp.wildcard.script-src"), "csp.wildcard-source"),
    (F(source="sslscan", title="TLS: TLS 1.0 disabled", evidence={"check": "TLS 1.0 disabled"}),
     "tls.weak-protocol"),
    (F(source="sslscan", evidence={"check": "No weak ciphers (RC4/3DES/EXPORT/NULL/anon)"}),
     "tls.weak-cipher"),
    (F(source="sslscan", evidence={"check": "Secure renegotiation"}), "tls.insecure-renegotiation"),
    (F(source="js_lib", evidence={"library": "jquery", "version": "1.2"}), "supply.vulnerable-js-lib"),
    (F(source="takeover", check_id="takeover.github"), "infra.subdomain-takeover"),
    (F(source="nuclei", title="SQL Injection", evidence={"template_id": "sql-injection"}),
     "injection.sqli"),
    (F(source="nuclei", title="Reflected XSS", evidence={"template_id": "xss-reflected"}),
     "injection.xss"),
    (F(source="nuclei", title="phpMyAdmin panel", evidence={"template_id": "phpmyadmin-panel"}),
     "exposure.admin-panel"),
    (F(source="zap", title="Cross Site Scripting (Reflected)", evidence={"template_id": "40012"}),
     "injection.xss"),
    (F(source="ai_supply_chain", title="Script loaded without SRI", check_id="ai.sri"),
     "supply.sri-missing"),
])
def test_classify_maps(finding, expected_class):
    cat, cls = classify(finding)
    assert cls == expected_class
    assert cat == CATEGORY_OF[expected_class]


def test_ai_declared_class_wins_when_valid():
    f = F(source="ai_headers", title="whatever", evidence={"class": "csp.unsafe-eval"})
    assert classify(f) == ("csp", "csp.unsafe-eval")


def test_unknown_declared_class_falls_back():
    f = F(source="nuclei", title="mystery", evidence={"class": "not-a-real-class",
                                                      "template_id": "mystery"})
    _, cls = classify(f)
    assert cls in FINDING_CLASSES  # never emits an invalid class


def test_classify_findings_stamps_fields():
    fs = [F(source="headers", check_id="hsts.missing")]
    classify_findings(fs)
    assert fs[0].finding_class == "headers.hsts-missing"
    assert fs[0].category == "headers"
