"""Version validation, normalization, comparison, and ecosystem-specific resolution.

Ensures accurate package version handling across ecosystems, including
OS package managers where lexicographic or PEP 440 comparison is wrong:

- npm / Cargo / NuGet: semver
- PyPI: PEP 440
- Go: v-prefixed semver and pseudo-versions
- Maven: flexible dotted versions
- Debian / Alpine / RPM: distro-native ordering
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from urllib.parse import quote as _url_quote

from agent_bom.http_client import request_with_retry

_logger = logging.getLogger(__name__)

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

_GO_PSEUDO_RE = re.compile(r"^v\d+\.\d+\.\d+-(\d{14})-[0-9a-f]{12}$")
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
    order = compare_version_order(current, fixed, ecosystem)
    if order is not None:
        return order < 0

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


def is_prerelease_version(version: str, ecosystem: str) -> bool:
    """Return True when a version string represents a prerelease/canary build."""
    if not version:
        return False

    eco = ecosystem.lower()
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


def _looks_like_commit_sha(version: str) -> bool:
    stripped = version.strip().lower().lstrip("v")
    return bool(_HEXISH_RE.fullmatch(stripped))


def _go_pseudo_timestamp(version: str) -> str | None:
    match = _GO_PSEUDO_RE.match(version)
    return match.group(1) if match else None


def _compare_go_versions(left: str, right: str) -> int | None:
    left_ts = _go_pseudo_timestamp(left)
    right_ts = _go_pseudo_timestamp(right)
    if left_ts and right_ts:
        return (left_ts > right_ts) - (left_ts < right_ts)
    try:
        from packaging.version import Version

        left_norm = left[1:] if left.startswith("v") else left
        right_norm = right[1:] if right.startswith("v") else right
        return (Version(left_norm) > Version(right_norm)) - (Version(left_norm) < Version(right_norm))
    except Exception:  # noqa: BLE001
        return None


def _debian_order_char(ch: str | None) -> int:
    if ch is None:
        return 0
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _compare_debian_part(left: str, right: str) -> int:
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            lc = left[i] if i < len(left) and not left[i].isdigit() else None
            rc = right[j] if j < len(right) and not right[j].isdigit() else None
            if lc == rc:
                if lc is not None:
                    i += 1
                if rc is not None:
                    j += 1
                continue
            lo = _debian_order_char(lc)
            ro = _debian_order_char(rc)
            if lo != ro:
                return (lo > ro) - (lo < ro)
            if lc is not None:
                i += 1
            if rc is not None:
                j += 1

        left_digits = ""
        while i < len(left) and left[i].isdigit():
            left_digits += left[i]
            i += 1
        right_digits = ""
        while j < len(right) and right[j].isdigit():
            right_digits += right[j]
            j += 1

        left_digits = left_digits.lstrip("0") or "0"
        right_digits = right_digits.lstrip("0") or "0"
        if len(left_digits) != len(right_digits):
            return (len(left_digits) > len(right_digits)) - (len(left_digits) < len(right_digits))
        if left_digits != right_digits:
            return (left_digits > right_digits) - (left_digits < right_digits)
    return 0


def _split_debian_version(version: str) -> tuple[int, str, str]:
    epoch_str, _, remainder = version.partition(":")
    if remainder:
        try:
            epoch = int(epoch_str)
        except ValueError:
            epoch = 0
    else:
        epoch = 0
        remainder = version
    if "-" in remainder:
        upstream, revision = remainder.rsplit("-", 1)
    else:
        upstream, revision = remainder, "0"
    return epoch, upstream, revision


def _compare_debian_versions(left: str, right: str) -> int:
    left_epoch, left_upstream, left_revision = _split_debian_version(left)
    right_epoch, right_upstream, right_revision = _split_debian_version(right)
    if left_epoch != right_epoch:
        return (left_epoch > right_epoch) - (left_epoch < right_epoch)
    upstream_cmp = _compare_debian_part(left_upstream, right_upstream)
    if upstream_cmp:
        return upstream_cmp
    return _compare_debian_part(left_revision, right_revision)


def _consume_rpm_segment(value: str, start: int) -> tuple[str, int]:
    end = start
    kind = value[start].isdigit()
    while end < len(value) and value[end].isdigit() == kind and value[end].isalnum():
        end += 1
    return value[start:end], end


def _compare_rpm_like(left: str, right: str) -> int:
    i = j = 0
    while True:
        while i < len(left) and not left[i].isalnum() and left[i] not in "~^":
            i += 1
        while j < len(right) and not right[j].isalnum() and right[j] not in "~^":
            j += 1

        if i < len(left) and left[i] == "~" or j < len(right) and right[j] == "~":
            if not (i < len(left) and left[i] == "~"):
                return 1
            if not (j < len(right) and right[j] == "~"):
                return -1
            i += 1
            j += 1
            continue

        if i < len(left) and left[i] == "^" or j < len(right) and right[j] == "^":
            if i >= len(left):
                return -1
            if j >= len(right):
                return 1
            if left[i] != "^":
                return 1
            if right[j] != "^":
                return -1
            i += 1
            j += 1
            continue

        if i >= len(left) or j >= len(right):
            break

        left_seg, i = _consume_rpm_segment(left, i)
        right_seg, j = _consume_rpm_segment(right, j)
        left_is_num = left_seg[0].isdigit()
        right_is_num = right_seg[0].isdigit()

        if left_is_num != right_is_num:
            return 1 if left_is_num else -1

        if left_is_num:
            left_norm = left_seg.lstrip("0") or "0"
            right_norm = right_seg.lstrip("0") or "0"
            if len(left_norm) != len(right_norm):
                return (len(left_norm) > len(right_norm)) - (len(left_norm) < len(right_norm))
            if left_norm != right_norm:
                return (left_norm > right_norm) - (left_norm < right_norm)
        else:
            if left_seg != right_seg:
                return (left_seg > right_seg) - (left_seg < right_seg)

    if i >= len(left) and j >= len(right):
        return 0
    return -1 if i >= len(left) else 1


def _split_epoch(version: str) -> tuple[int, str]:
    epoch_str, sep, rest = version.partition(":")
    if not sep:
        return 0, version
    try:
        return int(epoch_str), rest
    except ValueError:
        return 0, version


def _compare_rpm_versions(left: str, right: str) -> int:
    left_epoch, left_rest = _split_epoch(left)
    right_epoch, right_rest = _split_epoch(right)
    if left_epoch != right_epoch:
        return (left_epoch > right_epoch) - (left_epoch < right_epoch)
    return _compare_rpm_like(left_rest, right_rest)


def _compare_apk_versions(left: str, right: str) -> int:
    def _split_revision(value: str) -> tuple[str, int]:
        if "-r" in value:
            base, revision = value.rsplit("-r", 1)
            try:
                return base, int(revision)
            except ValueError:
                return base, 0
        return value, 0

    left_base, left_rev = _split_revision(left)
    right_base, right_rev = _split_revision(right)
    base_cmp = _compare_rpm_like(left_base, right_base)
    if base_cmp:
        return base_cmp
    return (left_rev > right_rev) - (left_rev < right_rev)


@lru_cache(maxsize=65536)
def compare_version_order(left: str, right: str, ecosystem: str) -> int | None:
    """Compare two versions using ecosystem-specific semantics.

    Returns ``-1`` when ``left < right``, ``0`` when equal, ``1`` when
    ``left > right``, and ``None`` when the versions should not be compared
    (for example git commit SHAs leaking from advisory ranges).
    """
    eco = (ecosystem or "").lower()
    if eco == "debian":
        eco = "deb"
    elif eco == "alpine":
        eco = "apk"
    elif eco == "linux":
        eco = "rpm"
    left = (left or "").strip()
    right = (right or "").strip()
    if not left or not right:
        return None
    if _looks_like_commit_sha(left) or _looks_like_commit_sha(right):
        return None

    if eco == "deb":
        return _compare_debian_versions(left, right)
    if eco == "rpm":
        return _compare_rpm_versions(left, right)
    if eco == "apk":
        return _compare_apk_versions(left, right)
    if eco == "go":
        return _compare_go_versions(left, right)

    try:
        from packaging.version import Version

        left_norm = normalize_version(left, eco)
        right_norm = normalize_version(right, eco)
        return (Version(left_norm) > Version(right_norm)) - (Version(left_norm) < Version(right_norm))
    except Exception:  # noqa: BLE001
        return None


@lru_cache(maxsize=65536)
def version_in_range(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    ecosystem: str,
) -> bool:
    """Return whether ``version`` is affected by the supplied advisory bounds."""
    intro = introduced or None
    fix = fixed or None
    last = last_affected or None

    if ecosystem.lower() == "go":
        ver_ts = _go_pseudo_timestamp(version)
        if ver_ts:
            for boundary, is_lower in ((intro, True), (fix, False), (last, False)):
                if not boundary:
                    continue
                boundary_ts = _go_pseudo_timestamp(boundary)
                if not boundary_ts:
                    continue
                if is_lower and ver_ts < boundary_ts:
                    return False
                if not is_lower and boundary == fix and ver_ts >= boundary_ts:
                    return False
                if not is_lower and boundary == last and ver_ts > boundary_ts:
                    return False
            return True

    if intro:
        intro_cmp = compare_version_order(version, intro, ecosystem)
        if intro_cmp is not None and intro_cmp < 0:
            return False
    if fix:
        fix_cmp = compare_version_order(version, fix, ecosystem)
        if fix_cmp is not None and fix_cmp >= 0:
            return False
    if last:
        last_cmp = compare_version_order(version, last, ecosystem)
        if last_cmp is not None and last_cmp > 0:
            return False
    return True


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

    url = f"https://crates.io/api/v1/crates/{_url_quote(crate_name, safe='')}"
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

    g = _url_quote(group_id, safe="")
    a = _url_quote(artifact_id, safe="")
    url = f"https://search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}&rows=1&wt=json"
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
