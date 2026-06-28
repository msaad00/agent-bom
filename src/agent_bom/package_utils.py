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
from urllib.parse import unquote, urlparse

_NORMALIZE_RE = re.compile(r"[-_.]+")
_PURL_TYPE_ALIASES = {
    "golang": "go",
}


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


def normalize_package_ecosystem(ecosystem: str) -> str:
    """Normalize ecosystem aliases used by PURLs, OSV, and parsers."""
    eco = (ecosystem or "").strip().lower()
    return _PURL_TYPE_ALIASES.get(eco, eco)


def _normalize_package_version(version: str, ecosystem: str) -> str:
    """Normalize versions for identity keys without making parsing mandatory."""
    version = (version or "").strip()
    if not version:
        return ""
    try:
        from agent_bom.version_utils import normalize_version

        return normalize_version(version, normalize_package_ecosystem(ecosystem))
    except Exception:
        return version


def _purl_identity(purl: str) -> tuple[str, str, str] | None:
    """Return (ecosystem, normalized name, normalized version) from a purl."""
    if not purl:
        return None
    try:
        from packageurl import PackageURL

        parsed = PackageURL.from_string(purl)
    except Exception:
        return None

    ecosystem = normalize_package_ecosystem(parsed.type or "")
    name_parts = [part for part in (parsed.namespace, parsed.name) if part]
    raw_name = "/".join(unquote(part.strip()) for part in name_parts)
    name = normalize_package_name(raw_name, ecosystem)
    version = _normalize_package_version(parsed.version or "", ecosystem)
    if not ecosystem or not name:
        return None
    return ecosystem, name, version


def canonical_package_identity(name: str, version: str, ecosystem: str, purl: str | None = None) -> tuple[str, str, str]:
    """Return the canonical package identity used by scan, graph, and history.

    The identity intentionally mirrors scanner deduplication: ecosystem aliases
    collapse, PyPI separators/case normalize, and versions use the same
    ecosystem-specific normalization used for matching. A valid explicit PURL is
    authoritative, but it is normalized before hashing or graph ID construction.
    """
    parsed = _purl_identity(purl or "")
    if parsed is not None:
        purl_ecosystem, purl_name, purl_version = parsed
        return (
            purl_ecosystem,
            purl_name,
            purl_version or _normalize_package_version(version, purl_ecosystem),
        )
    normalized_ecosystem = normalize_package_ecosystem(ecosystem)
    return (
        normalized_ecosystem,
        normalize_package_name((name or "").strip(), normalized_ecosystem),
        _normalize_package_version(version, normalized_ecosystem),
    )


def canonical_package_key(name: str, version: str, ecosystem: str, purl: str | None = None) -> str:
    """Return a compact stable key for package maps and graph node IDs."""
    normalized_ecosystem, normalized_name, normalized_version = canonical_package_identity(name, version, ecosystem, purl)
    suffix = f"@{normalized_version}" if normalized_version else ""
    return f"{normalized_ecosystem}:{normalized_name}{suffix}"


@lru_cache(maxsize=4096)
def debian_release_branch(distro_version: str) -> str:
    """Normalize Debian ``VERSION_ID`` to the advisory release key.

    Debian security data is release-major scoped (``debian:12``), while
    container metadata may carry point releases such as ``12.5``. The scanner
    must collapse those to the major release before querying OSV/local DB rows.
    """
    raw = (distro_version or "").strip()
    if not raw:
        return raw
    return raw.split(".", 1)[0]


@lru_cache(maxsize=4096)
def ubuntu_release_branch(distro_version: str) -> str:
    """Normalize Ubuntu ``VERSION_ID`` to the advisory release key.

    Ubuntu advisory ecosystems are keyed by major.minor branch
    (``Ubuntu:22.04``), not point releases. Official images usually expose
    ``22.04``, but derivative metadata can include ``22.04.4``; truncate that
    to ``22.04`` so release-scoped lookups do not silently miss advisory rows.
    """
    raw = (distro_version or "").strip()
    if not raw:
        return raw
    parts = raw.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return f"{parts[0]}.{parts[1]}"
    return raw


@lru_cache(maxsize=4096)
def alpine_release_branch(distro_version: str) -> str:
    """Normalize an Alpine ``VERSION_ID`` to its secdb branch key (``v{major}.{minor}``).

    Alpine security advisories are published per *minor branch* (``v3.16``), not
    per point release. A full ``VERSION_ID`` such as ``3.16.9`` must be truncated
    to ``v3.16`` so apk advisory lookups resolve against the branch's advisory
    rows instead of zero rows under the (never-stored) point-release key. This
    aligns apk release keying with mainstream advisory scanners.

    Behaviour:
    - ``3.16.9`` / ``v3.16.9`` -> ``v3.16``
    - ``3.20.10`` -> ``v3.20``
    - ``3.16`` / ``v3.16`` -> ``v3.16`` (already a branch)
    - non-numeric / single-component streams (``edge``) keep prior ``v``-prefix
      behaviour so no real branch key changes meaning.
    """
    raw = (distro_version or "").strip()
    if not raw:
        return raw
    body = raw[1:] if raw.startswith("v") else raw
    parts = body.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return f"v{parts[0]}.{parts[1]}"
    return raw if raw.startswith("v") else f"v{raw}"


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
    "alpine_release_branch",
    "canonical_package_identity",
    "canonical_package_key",
    "debian_release_branch",
    "host_matches_domain",
    "normalize_package_ecosystem",
    "normalize_package_name",
    "parse_debian_source_name",
    "reference_host_and_path",
    "ubuntu_release_branch",
]
