"""Tests for watchtower.util.domains — small but security-relevant helpers."""
from __future__ import annotations

from watchtower.util.domains import (
    etld_plus_one,
    host_to_filename,
    is_wildcard,
    strip_wildcard,
    under_any_root,
)


def test_etld_plus_one_simple():
    assert etld_plus_one("foo.example.com") == "example.com"


def test_etld_plus_one_multi_part_suffix():
    assert etld_plus_one("foo.bar.example.co.uk") == "example.co.uk"


def test_etld_plus_one_strips_trailing_dot_and_case():
    assert etld_plus_one("Foo.Example.COM.") == "example.com"


def test_under_any_root_exact_match():
    assert under_any_root("example.com", ["example.com"]) is True


def test_under_any_root_subdomain():
    assert under_any_root("api.example.com", ["example.com"]) is True


def test_under_any_root_negative_neighbor():
    """notexample.com must NOT match root example.com — only suffix match counts."""
    assert under_any_root("notexample.com", ["example.com"]) is False


def test_under_any_root_negative_unrelated():
    assert under_any_root("other.com", ["example.com"]) is False


def test_under_any_root_multiple_roots():
    roots = ["example.com", "alt-corp.io"]
    assert under_any_root("svc.alt-corp.io", roots) is True
    assert under_any_root("svc.example.com", roots) is True
    assert under_any_root("svc.third.com", roots) is False


def test_wildcard_helpers():
    assert is_wildcard("*.example.com") is True
    assert is_wildcard("foo.example.com") is False
    assert strip_wildcard("*.example.com") == "example.com"
    assert strip_wildcard("plain.example.com") == "plain.example.com"


def test_host_to_filename_plain():
    assert host_to_filename("api.example.com") == "api.example.com"


def test_host_to_filename_neutralizes_traversal_and_port():
    # path separators, host:port, and parent-dir hops must not escape the dir.
    assert host_to_filename("h.example.com:8443") == "h.example.com_8443"
    for danger in ("../../etc/passwd", "a/b/c", "a..b", "x/../y"):
        out = host_to_filename(danger)
        assert "/" not in out and ":" not in out and ".." not in out
