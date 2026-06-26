"""Canonical nuclei JSONL parser — shared by the nuclei + takeover runners."""
from __future__ import annotations

import json

from watchtower.audit.nuclei_parse import parse_nuclei_jsonl


def _line(**obj) -> str:
    return json.dumps(obj)


def test_maps_fields_and_richer_evidence():
    line = _line(
        host="https://h.example.com",
        **{"template-id": "tech-detect", "matched-at": "https://h.example.com/x",
           "matcher-name": "nginx", "extracted-results": ["1.2.3"]},
        info={"name": "Nginx detected", "severity": "medium",
              "description": "found nginx", "tags": ["tech", "nginx"]},
    )
    [f] = parse_nuclei_jsonl([line], source="nuclei",
                             default_severity="info", default_title="nuclei finding")
    assert f.source == "nuclei"
    assert f.host == "https://h.example.com"
    assert f.severity == "medium"
    assert f.title == "Nginx detected"
    assert f.evidence["matcher_name"] == "nginx"
    assert f.evidence["extracted_results"] == ["1.2.3"]
    assert f.evidence["tags"] == ["tech", "nginx"]


def test_defaults_apply_when_fields_absent():
    # No info.severity / info.name => fall back to caller-supplied defaults.
    [f] = parse_nuclei_jsonl([_line(host="h", info={})], source="takeover",
                             default_severity="high", default_title="Subdomain takeover candidate")
    assert f.severity == "high"
    assert f.title == "Subdomain takeover candidate"


def test_tags_string_is_split():
    [f] = parse_nuclei_jsonl([_line(host="h", info={"tags": "a,b,c"})],
                             source="nuclei", default_severity="info", default_title="x")
    assert f.evidence["tags"] == ["a", "b", "c"]


def test_blank_and_malformed_lines_skipped():
    out = parse_nuclei_jsonl(["", "   ", "{not json", _line(host="h", info={})],
                             source="nuclei", default_severity="info", default_title="x")
    assert len(out) == 1
