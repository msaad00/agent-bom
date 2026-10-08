"""Canonical validation rules for ecosystem version comparison."""

from __future__ import annotations

import logging
import re
from functools import lru_cache

from agent_bom.core.versions.distro import OS_DISTRO_COMPARATOR_FAMILIES

_logger = logging.getLogger(__name__)


_SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z\-.]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z\-.]+))?$"
)


_PEP440_RE = re.compile(
    r"^v?(?P<epoch>\d+!)?(?P<major>\d+)"
    r"(?:\.(?P<minor>\d+))?"
    r"(?:\.(?P<micro>\d+))?"
    r"(?:(?P<pre>a|alpha|b|beta|c|rc|pre|preview)\d*)?"
    r"(?:\.?(?P<post>post|rev|r)\d*)?"
    r"(?:\.?(?P<dev>dev)\d*)?$",
    re.IGNORECASE,
)


_GO_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z\-.]+)?(?:\+[0-9A-Za-z\-.]+)?$")


_MAVEN_RE = re.compile(r"^\d+(?:\.\d+){0,3}(?:[.-][A-Za-z0-9\-.]+)?$")


_GO_PSEUDO_RE = re.compile(r"^v?\d+\.\d+\.\d+-(?:[0-9A-Za-z.\-]+\.)?(\d{14})-[0-9a-f]{12}$")


_HEXISH_RE = re.compile(r"^[0-9a-f]{7,40}$")


def validate_version(version: str, ecosystem: str) -> bool:
    """Check if a version string is valid for the given ecosystem.

    Returns True if the version matches the ecosystem's version format.
    """
    if not version or version in ("latest", "unknown"):
        _logger.debug("Invalid version %r for ecosystem %s", version, ecosystem)
        return False

    if ecosystem in ("npm", "cargo"):
        return _SEMVER_RE.match(version) is not None
    elif ecosystem == "pypi":
        return _PEP440_RE.match(version) is not None
    elif ecosystem == "go":
        return _GO_VERSION_RE.match(version) is not None
    elif ecosystem == "maven":
        return _MAVEN_RE.match(version) is not None
    elif ecosystem == "nuget":
        return _SEMVER_RE.match(version) is not None
    elif ecosystem in ("deb", "apk", "rpm"):
        return bool(version.strip())

    # Unknown ecosystem — accept any non-empty version
    return True


@lru_cache(maxsize=131072)
def normalize_version(version: str, ecosystem: str) -> str:
    """Normalize a version string for consistent comparison and scanning.

    - Strips leading 'v' for non-Go ecosystems
    - Normalizes PyPI pre-release tags
    - Strips pip extras from package names
    - Trims whitespace
    """
    version = version.strip()

    if not version or version in ("latest", "unknown"):
        return version

    # Strip leading v for non-Go ecosystems
    if ecosystem != "go" and version.startswith("v"):
        version = version[1:]

    # Normalize PyPI pre-release tags
    if ecosystem == "pypi":
        version = re.sub(r"\.?(alpha|a)(\d+)?", r"a\2", version, flags=re.IGNORECASE)
        version = re.sub(r"\.?(beta|b)(\d+)?", r"b\2", version, flags=re.IGNORECASE)
        version = re.sub(r"\.?(preview|rc)(\d+)?", r"rc\2", version, flags=re.IGNORECASE)
        # Legacy single-letter ``c`` spelling of ``rc`` (PEP 440 ``1.0c1`` ->
        # ``1.0rc1``). Require a trailing digit and refuse the ``c`` that sits
        # inside an already-normalized ``rc`` so we never double it into ``rrc``.
        version = re.sub(r"(?<![a-z])c(\d+)", r"rc\1", version, flags=re.IGNORECASE)
        # Post-release tags. The single-letter ``r`` spelling (PEP 440 ``1.0r5``
        # -> ``1.0.post5``) MUST require a trailing digit; otherwise it swallows
        # the ``r`` inside an ``rc`` pre-release (``1.0rc1`` -> ``1.0.postc1``),
        # corrupting normalization and comparison for every release candidate.
        version = re.sub(r"\.?(post|rev)(\d+)?", r".post\2", version, flags=re.IGNORECASE)
        version = re.sub(r"\.?r(\d+)", r".post\1", version, flags=re.IGNORECASE)
        version = re.sub(r"\.?(dev)(\d+)?", r".dev\2", version, flags=re.IGNORECASE)

    return version


def strip_pip_extras(name: str) -> tuple[str, str]:
    """Strip pip extras from a package name.

    Examples:
        "requests[security]==2.31.0" → ("requests", "2.31.0")
        "package[extra1,extra2]>=1.0" → ("package", "1.0")
        "simple-pkg" → ("simple-pkg", "")
    """
    # Strip extras bracket
    name = re.sub(r"\[.*?\]", "", name)

    # Split on version specifiers
    match = re.match(r"^([a-zA-Z0-9._-]+)\s*(?:[>=<~!]+\s*)?(.*)$", name)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return name.strip(), ""


_DISTRO_PACKAGE_FAMILIES = frozenset({"deb", "debian", "ubuntu", "apk", "alpine", "rpm", *OS_DISTRO_COMPARATOR_FAMILIES})


def is_prerelease_version(version: str, ecosystem: str) -> bool:
    """Return True when a version string represents a prerelease/canary build."""
    if not version:
        return False

    eco = ecosystem.lower()
    # A distro package version is a build the distro already shipped to that
    # release, so it is never an upstream prerelease. PEP 440 parsing would
    # misread tzdata ``2025b-0+deb11u2`` as a beta and drop a real fix.
    if eco.split(":", 1)[0].strip() in _DISTRO_PACKAGE_FAMILIES:
        return False
    candidate = version if eco == "go" else version.lstrip("v")
    try:
        from packaging.version import Version

        return Version(candidate).is_prerelease
    except Exception:  # noqa: BLE001
        normalized = normalize_version(version, ecosystem)
        candidate = normalized if eco == "go" else normalized.lstrip("v")
        try:
            from packaging.version import Version

            return Version(candidate).is_prerelease
        except Exception:  # noqa: BLE001
            pass

    if eco == "maven":
        return bool(re.search(r"-(snapshot|rc\d*|m\d+|alpha|beta|pre|preview|canary)", candidate, re.IGNORECASE))

    return bool(re.search(r"(?:-|\.)(alpha|beta|rc|pre|preview|canary|dev)\d*(?:$|\+)", candidate, re.IGNORECASE))


@lru_cache(maxsize=65536)
def _looks_like_commit_sha(version: str) -> bool:
    stripped = version.strip().lower().lstrip("v")
    if not _HEXISH_RE.fullmatch(stripped):
        return False
    if stripped.isdigit() and len(stripped) != 40:
        # All-digit tokens are versions, not abbreviated SHAs. Date-stamped OS
        # packages (ca-certificates 20230311, hwdata, tzdata) are common and
        # every one of them would otherwise become uncomparable and fail closed
        # — a missed CVE. An abbreviated SHA that happens to be all digits is
        # possible but far rarer, and mistaking it for a version only costs an
        # ordering comparison that a GIT-type range does not rely on.
        return False
    return True
