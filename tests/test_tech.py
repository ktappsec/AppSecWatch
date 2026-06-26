"""httpx + AI tech merge."""
from __future__ import annotations

from watchtower.audit.tech import merge_tech


def test_merge_dedupe_and_source():
    out = merge_tech(["nginx", "React"], ["react", "PHP"])
    assert out == [
        {"name": "nginx", "source": "httpx"},
        {"name": "React", "source": "httpx"},   # httpx wins the case-insensitive clash
        {"name": "PHP", "source": "ai"},
    ]


def test_merge_empty_sides():
    assert merge_tech(None, ["X"]) == [{"name": "X", "source": "ai"}]
    assert merge_tech(["Y"], None) == [{"name": "Y", "source": "httpx"}]
    assert merge_tech([], []) == []
