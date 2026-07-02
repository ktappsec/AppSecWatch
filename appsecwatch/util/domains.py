from __future__ import annotations

from functools import lru_cache

import tldextract

# Cache the suffix list locally inside the container.
_extract = tldextract.TLDExtract(cache_dir=".tldextract_cache", suffix_list_urls=())


@lru_cache(maxsize=8192)
def etld_plus_one(name: str) -> str:
    """Return the eTLD+1 of a hostname. For 'foo.bar.example.co.uk' → 'example.co.uk'."""
    name = name.strip().lower().rstrip(".")
    parts = _extract(name)
    if parts.suffix and parts.domain:
        return f"{parts.domain}.{parts.suffix}"
    return name


def under_any_root(name: str, roots: list[str]) -> bool:
    """True if `name` is a subdomain of any configured root (or equal to a root)."""
    name = name.strip().lower().rstrip(".")
    for r in roots:
        r = r.strip().lower().rstrip(".")
        if name == r or name.endswith("." + r):
            return True
    return False


def is_wildcard(name: str) -> bool:
    return name.startswith("*.")


def strip_wildcard(name: str) -> str:
    return name[2:] if is_wildcard(name) else name


def host_to_filename(host: str) -> str:
    """Map a host to a safe per-host artifact filename stem.

    Neutralizes path separators, colons (host:port), and parent-dir hops so a
    crafted host string can't escape its stage directory.
    """
    return host.replace("/", "_").replace(":", "_").replace("..", "_")
