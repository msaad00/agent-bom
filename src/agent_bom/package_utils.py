"""Shared package and advisory reference normalization helpers.

These helpers were historically defined in ``agent_bom.models`` and are used
across scanners, cache keys, parsers, and advisory matching. Keeping them in a
small dedicated module lowers import pressure on the large models file while
preserving the same normalization rules.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

_NORMALIZE_RE = re.compile(r"[-_.]+")


@lru_cache(maxsize=16384)
def reference_host_and_path(reference: str) -> tuple[str, str]:
    """Return normalized hostname and path for a reference URL."""
    try:
        parsed = urlparse(reference)
    except ValueError:
        return "", ""
    return (parsed.hostname or "").lower(), (parsed.path or "").lower()


@lru_cache(maxsize=1024)
def host_matches_domain(host: str, domain: str) -> bool:
    """Return True when host equals domain or is a subdomain of it."""
    return host == domain or host.endswith(f".{domain}")


@lru_cache(maxsize=65536)
def normalize_package_name(name: str, ecosystem: str = "") -> str:
    """Normalize a package name for consistent matching."""
    if not name:
        return name
    eco = ecosystem.lower()
    if eco == "pypi":
        return _NORMALIZE_RE.sub("-", name).lower()
    return name.lower()


@lru_cache(maxsize=16384)
def parse_debian_source_name(source_field: str) -> Optional[str]:
    """Extract the Debian source package name from a ``Source:`` field."""
    if not source_field:
        return None
    source_name = source_field.split("(", 1)[0].strip()
    if source_name.startswith("${") and source_name.endswith("}"):
        return None
    return source_name or None


__all__ = [
    "host_matches_domain",
    "normalize_package_name",
    "parse_debian_source_name",
    "reference_host_and_path",
]
