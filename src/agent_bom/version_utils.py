"""Version validation, normalization, and ecosystem-specific resolution.

Ensures accurate package version handling across all ecosystems:
npm (semver), PyPI (PEP 440), Go (v-prefix semver), Cargo (semver),
Maven (flexible versioning).
"""

from __future__ import annotations

import re

from agent_bom.http_client import request_with_retry

# ---------------------------------------------------------------------------
# Validation patterns
# ---------------------------------------------------------------------------

# npm/Cargo: strict semver (major.minor.patch with optional pre-release/build)
_SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z\-.]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z\-.]+))?$"
)

# PyPI: PEP 440
_PEP440_RE = re.compile(
    r"^v?(?P<epoch>\d+!)?(?P<major>\d+)"
    r"(?:\.(?P<minor>\d+))?"
    r"(?:\.(?P<micro>\d+))?"
    r"(?:(?P<pre>a|alpha|b|beta|c|rc|pre|preview)\d*)?"
    r"(?:\.?(?P<post>post|rev|r)\d*)?"
    r"(?:\.?(?P<dev>dev)\d*)?$",
    re.IGNORECASE,
)

# Go: v-prefix semver or vX.Y.Z-pre
_GO_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z\-.]+)?(?:\+[0-9A-Za-z\-.]+)?$")

# Maven: flexible (major.minor.patch.qualifier or major.minor.patch-qualifier)
_MAVEN_RE = re.compile(r"^\d+(?:\.\d+){0,3}(?:[.-][A-Za-z0-9\-.]+)?$")


def validate_version(version: str, ecosystem: str) -> bool:
    """Check if a version string is valid for the given ecosystem.

    Returns True if the version matches the ecosystem's version format.
    """
    if not version or version in ("latest", "unknown"):
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

    # Unknown ecosystem — accept any non-empty version
    return True


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
        version = re.sub(r"\.?(preview|c|rc)(\d+)?", r"rc\2", version, flags=re.IGNORECASE)
        version = re.sub(r"\.?(post|rev|r)(\d+)?", r".post\2", version, flags=re.IGNORECASE)
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


def compare_versions(current: str, fixed: str, ecosystem: str) -> bool:
    """Check if fixed version is newer than current version.

    Returns True if fixed > current (meaning upgrade is needed).
    Uses ``packaging.version`` for PyPI/npm/cargo, falls back to
    numeric tuple comparison for other ecosystems.

    Pre-release handling: ``1.0.0rc1 < 1.0.0`` (correct per PEP 440
    and semver).
    """
    current = normalize_version(current, ecosystem)
    fixed = normalize_version(fixed, ecosystem)

    # Try packaging.version first — handles pre-release correctly
    try:
        from packaging.version import Version

        return Version(fixed) > Version(current)
    except Exception:  # noqa: BLE001
        pass

    # Fallback: numeric tuple (splits pre-release from base version)
    def _version_tuple(v: str) -> tuple[tuple[int, ...], bool]:
        """Return (numeric_parts, is_prerelease)."""
        is_pre = bool(re.search(r"(alpha|beta|rc|dev|pre|preview|[ab]\d)", v, re.IGNORECASE))
        parts = re.findall(r"\d+", re.split(r"[-]|(?:alpha|beta|rc|dev|pre|preview)", v, flags=re.IGNORECASE)[0])
        return (tuple(int(p) for p in parts) if parts else (0,)), is_pre

    try:
        cur_nums, cur_pre = _version_tuple(current)
        fix_nums, fix_pre = _version_tuple(fixed)
        if fix_nums != cur_nums:
            return fix_nums > cur_nums
        # Same base version: stable > pre-release
        if cur_pre and not fix_pre:
            return True  # fixed is stable, current is pre-release
        if fix_pre and not cur_pre:
            return False  # fixed is pre-release, current is stable
        return False  # same base, both pre or both stable
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Additional ecosystem resolvers
# ---------------------------------------------------------------------------


def _go_encode_module(module: str) -> str:
    """Encode a Go module path for proxy.golang.org.

    The Go module proxy uses case-encoding: uppercase letters become
    ``!`` + lowercase (e.g., ``GitHub.com`` → ``!github.com``).
    Forward slashes are literal path separators in the URL.
    """
    parts: list[str] = []
    for ch in module:
        if ch.isupper():
            parts.append("!")
            parts.append(ch.lower())
        else:
            parts.append(ch)
    return "".join(parts)


async def resolve_go_metadata(
    module: str,
    client: object,
) -> tuple[str | None, str | None]:
    """Resolve latest Go module version via proxy.golang.org.

    Returns (version, None) — Go proxy doesn't provide license info.
    """

    # Go proxy requires case-encoded module paths (upper → !lower)
    # and forward slashes are kept as literal path separators.
    encoded = _go_encode_module(module)
    url = f"https://proxy.golang.org/{encoded}/@latest"
    response = await request_with_retry(client, "GET", url)  # type: ignore[arg-type]
    if response and response.status_code == 200:
        try:
            data = response.json()
            version = data.get("Version")
            return version, None
        except (ValueError, KeyError):
            pass
    return None, None


async def resolve_cargo_metadata(
    crate_name: str,
    client: object,
) -> tuple[str | None, str | None]:
    """Resolve latest Cargo crate version and license via crates.io.

    Returns (version, license).
    """

    url = f"https://crates.io/api/v1/crates/{crate_name}"
    response = await request_with_retry(client, "GET", url)  # type: ignore[arg-type]
    if response and response.status_code == 200:
        try:
            data = response.json()
            crate = data.get("crate", {})
            version = crate.get("newest_version") or crate.get("max_version")
            license_id = crate.get("license")
            return version, license_id
        except (ValueError, KeyError):
            pass
    return None, None


async def resolve_maven_metadata(
    group_id: str,
    artifact_id: str,
    client: object,
) -> tuple[str | None, None]:
    """Resolve latest Maven artifact version via Maven Central search API.

    Returns (version, None).
    """

    url = f"https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json"
    response = await request_with_retry(client, "GET", url)  # type: ignore[arg-type]
    if response and response.status_code == 200:
        try:
            data = response.json()
            docs = data.get("response", {}).get("docs", [])
            if docs:
                return docs[0].get("latestVersion"), None
        except (ValueError, KeyError):
            pass
    return None, None
