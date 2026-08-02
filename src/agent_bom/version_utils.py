"""Version validation, normalization, comparison, and ecosystem-specific resolution.

Ensures accurate package version handling across ecosystems, including
OS package managers where lexicographic or PEP 440 comparison is wrong:

- npm / Cargo: semver
- NuGet: NuGetVersion (semver plus a 4th Revision segment, case-insensitive
  release labels)
- PyPI: PEP 440
- Packagist / Composer: PHP ``version_compare``
- RubyGems: ``Gem::Version``
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
_GO_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z\-.]+)?(?:\+[0-9A-Za-z\-.]+)?$")

# Maven: flexible (major.minor.patch.qualifier or major.minor.patch-qualifier)
_MAVEN_RE = re.compile(r"^\d+(?:\.\d+){0,3}(?:[.-][A-Za-z0-9\-.]+)?$")

# All THREE pseudo-version forms from the Go modules reference
# (https://go.dev/ref/mod#pseudo-versions):
#   vX.0.0-yyyymmddhhmmss-abcdefabcdef            (no known base version)
#   vX.Y.Z-pre.0.yyyymmddhhmmss-abcdefabcdef      (base is a pre-release)
#   vX.Y.(Z+1)-0.yyyymmddhhmmss-abcdefabcdef      (base is a release)
# Recognising only the first form left the other two uncomparable, so an
# advisory bound written in either could not rule a version out — fail-open.
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


def _go_pseudo_timestamp(version: str) -> str | None:
    match = _GO_PSEUDO_RE.match(version)
    return match.group(1) if match else None


def _go_packaging_operand(version: str) -> str:
    """Return the ``X.Y.Z`` base of a Go version for packaging comparison.

    A pseudo-version (``vX.Y.Z-<ts>-<sha>``) is collapsed to its ``X.Y.Z``
    base so it can be ordered against an ordinary tagged bound; the
    date/sha suffix is not PEP 440-parsable on its own. Plain tags just
    lose the leading ``v``.
    """
    if _go_pseudo_timestamp(version):
        version = version.split("-", 1)[0]
    return version[1:] if version.startswith("v") else version


def _compare_go_versions(left: str, right: str) -> int | None:
    left_ts = _go_pseudo_timestamp(left)
    right_ts = _go_pseudo_timestamp(right)
    if left_ts and right_ts:
        return (left_ts > right_ts) - (left_ts < right_ts)
    try:
        from packaging.version import Version

        left_norm = _go_packaging_operand(left)
        right_norm = _go_packaging_operand(right)
        base_cmp = (Version(left_norm) > Version(right_norm)) - (Version(left_norm) < Version(right_norm))
        if base_cmp:
            return base_cmp
        # Same X.Y.Z base and exactly one side is a pseudo-version. A
        # pseudo-version is a pre-release of its base ("compares higher than its
        # base version, but lower than the next tagged version"), so it sorts
        # strictly BELOW the bare tag. Collapsing to equality here would let a
        # pseudo-version read as already past a fix bound.
        if bool(left_ts) != bool(right_ts):
            return -1 if left_ts else 1
        return 0
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


# apk suffix ordering (apk-tools ``apk_version_compare``): pre-release
# suffixes sort STRICTLY BELOW the bare release, post-release suffixes above.
#   _alpha < _beta < _pre < _rc  <  (release)  <  _cvs < _svn < _git < _hg < _p
_APK_PRE_SUFFIXES = ("alpha", "beta", "pre", "rc")
_APK_POST_SUFFIXES = ("cvs", "svn", "git", "hg", "p")
_APK_SUFFIX_RE = re.compile(r"_([a-z]+)(\d*)")


def _apk_suffix_rank(name: str) -> int:
    """Rank an apk suffix name relative to the release (0).

    Pre-release suffixes rank negative (below the release), post-release
    suffixes rank positive (above), ordered within each class. An unrecognised
    suffix ranks as release-level so it never silently outranks a real fix.
    """
    if name in _APK_PRE_SUFFIXES:
        return _APK_PRE_SUFFIXES.index(name) - len(_APK_PRE_SUFFIXES)
    if name in _APK_POST_SUFFIXES:
        return _APK_POST_SUFFIXES.index(name) + 1
    return 0


def _apk_split_suffix(base: str) -> tuple[str, str]:
    """Split the numeric/letter core from the ``_suffix`` tail of an apk base."""
    idx = base.find("_")
    if idx == -1:
        return base, ""
    return base[:idx], base[idx:]


def _apk_suffix_key(suffix: str) -> list[tuple[int, int]]:
    return [(_apk_suffix_rank(name), int(num) if num else 0) for name, num in _APK_SUFFIX_RE.findall(suffix)]


def _compare_apk_suffix_keys(left: list[tuple[int, int]], right: list[tuple[int, int]]) -> int:
    """Compare two apk suffix keys, treating an exhausted side as the release.

    A missing suffix is the release: it outranks any pre-release suffix and is
    outranked by any post-release suffix on the other side.
    """
    for i in range(max(len(left), len(right))):
        if i >= len(left):
            rank = right[i][0]
            return 1 if rank < 0 else -1 if rank > 0 else 0
        if i >= len(right):
            rank = left[i][0]
            return -1 if rank < 0 else 1 if rank > 0 else 0
        if left[i] != right[i]:
            return (left[i] > right[i]) - (left[i] < right[i])
    return 0


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

    # A ``~<commit>`` fuzzy/commit suffix is compared last, as low-priority
    # metadata; core + apk suffix ordering decide first.
    left_core, _, left_hash = left_base.partition("~")
    right_core, _, right_hash = right_base.partition("~")

    left_main, left_suffix = _apk_split_suffix(left_core)
    right_main, right_suffix = _apk_split_suffix(right_core)

    base_cmp = _compare_rpm_like(left_main, right_main)
    if base_cmp:
        return base_cmp
    suffix_cmp = _compare_apk_suffix_keys(_apk_suffix_key(left_suffix), _apk_suffix_key(right_suffix))
    if suffix_cmp:
        return suffix_cmp
    if left_hash != right_hash:
        return (left_hash > right_hash) - (left_hash < right_hash)
    return (left_rev > right_rev) - (left_rev < right_rev)


# ---------------------------------------------------------------------------
# Maven version order
#
# Implements the Apache Maven POM Reference "Version Order Specification"
# (https://maven.apache.org/pom.html#version-order-specification), i.e. the
# ``org.apache.maven.artifact.versioning.ComparableVersion`` algorithm.
#
# Without it every qualifier-bearing Maven version (``5.0.6.RELEASE``,
# ``2.5.6.SEC03``) is uncomparable, the range matcher cannot rule the version
# out, and the advisory is reported as a match — a fail-OPEN false positive.
# ---------------------------------------------------------------------------

# Qualifiers that sort BEFORE any unknown qualifier, in ascending order. The
# empty string is the release itself, so anything before it is a pre-release.
_MAVEN_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_MAVEN_RELEASE_INDEX = str(_MAVEN_QUALIFIERS.index(""))
_MAVEN_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
# Single-letter abbreviations, valid only when directly followed by a number.
_MAVEN_SHORT_QUALIFIERS = {"a": "alpha", "b": "beta", "m": "milestone"}


def _maven_qualifier_key(qualifier: str) -> str:
    """Sort key for a Maven qualifier token.

    Known qualifiers map to their single-digit index; unknown qualifiers map to
    ``"7-<qualifier>"`` so they sort lexically above every known one.
    """
    try:
        return str(_MAVEN_QUALIFIERS.index(qualifier))
    except ValueError:
        return f"{len(_MAVEN_QUALIFIERS)}-{qualifier}"


class _MavenInt:
    """A numeric Maven token."""

    __slots__ = ("value",)

    def __init__(self, raw: str) -> None:
        self.value = int(raw or "0")

    def is_null(self) -> bool:
        return self.value == 0


class _MavenStr:
    """A qualifier (non-numeric) Maven token."""

    __slots__ = ("value",)

    def __init__(self, raw: str, followed_by_digit: bool) -> None:
        value = raw
        if followed_by_digit and len(value) == 1:
            value = _MAVEN_SHORT_QUALIFIERS.get(value, value)
        self.value = _MAVEN_ALIASES.get(value, value)

    def is_null(self) -> bool:
        return _maven_qualifier_key(self.value) == _MAVEN_RELEASE_INDEX


class _MavenList(list):
    """A nested Maven token sequence (one per ``-`` separated segment)."""

    def is_null(self) -> bool:
        return len(self) == 0

    def normalize(self) -> None:
        """Trim trailing "null" tokens (0, "", final, ga) from the end."""
        for index in range(len(self) - 1, -1, -1):
            item = self[index]
            if item.is_null():
                del self[index]
            elif not isinstance(item, _MavenList):
                break


def _maven_item_rank(item: object) -> int:
    """Cross-type ordering: qualifier < list < numeric."""
    if isinstance(item, _MavenStr):
        return 0
    if isinstance(item, _MavenList):
        return 1
    return 2


def _maven_compare_items(left: object, right: object) -> int:
    """Compare two Maven tokens, where ``None`` is the padded null token."""
    if left is None and right is None:
        return 0
    if left is None:
        return -_maven_compare_items(right, None)
    if right is None:
        if isinstance(left, _MavenInt):
            return 0 if left.value == 0 else 1
        if isinstance(left, _MavenStr):
            key = _maven_qualifier_key(left.value)
            return (key > _MAVEN_RELEASE_INDEX) - (key < _MAVEN_RELEASE_INDEX)
        # A list compares against null through its first token.
        if isinstance(left, _MavenList):
            return 0 if not left else _maven_compare_items(left[0], None)
        return 0

    left_rank = _maven_item_rank(left)
    right_rank = _maven_item_rank(right)
    if left_rank != right_rank:
        return (left_rank > right_rank) - (left_rank < right_rank)

    if isinstance(left, _MavenInt) and isinstance(right, _MavenInt):
        return (left.value > right.value) - (left.value < right.value)
    if isinstance(left, _MavenStr) and isinstance(right, _MavenStr):
        left_key = _maven_qualifier_key(left.value)
        right_key = _maven_qualifier_key(right.value)
        return (left_key > right_key) - (left_key < right_key)

    # Both lists: element-wise, padding the shorter side with null.
    assert isinstance(left, _MavenList) and isinstance(right, _MavenList)
    for index in range(max(len(left), len(right))):
        left_item = left[index] if index < len(left) else None
        right_item = right[index] if index < len(right) else None
        result = _maven_compare_items(left_item, right_item)
        if result:
            return result
    return 0


def _maven_parse(version: str) -> _MavenList:
    """Tokenize a Maven version into the nested item list the spec describes."""
    version = version.strip().lower()
    root = _MavenList()
    current = root
    stack = [root]
    is_digit = False
    start = 0

    def parse_item(digit: bool, buf: str) -> object:
        return _MavenInt(buf.lstrip("0") or "0") if digit else _MavenStr(buf, False)

    def descend() -> None:
        """Append a fresh sublist to the current list and make it current."""
        nonlocal current
        nested = _MavenList()
        current.append(nested)
        current = nested
        stack.append(nested)

    for index, char in enumerate(version):
        if char == ".":
            current.append(_MavenInt("0") if index == start else parse_item(is_digit, version[start:index]))
            start = index + 1
        elif char in "-_":
            current.append(_MavenInt("0") if index == start else parse_item(is_digit, version[start:index]))
            start = index + 1
            descend()
        elif char.isdigit():
            # A character→digit transition is equivalent to a hyphen. Upstream
            # nests the qualifier itself one level deeper whenever the current
            # list already holds something, so a trailing qualifier sorts as a
            # sublist (below any number) rather than as a sibling token.
            if not is_digit and index > start:
                if current:
                    descend()
                current.append(_MavenStr(version[start:index], True))
                start = index
                descend()
            is_digit = True
        else:
            # A digit→character transition is equivalent to a hyphen.
            if is_digit and index > start:
                current.append(parse_item(True, version[start:index]))
                start = index
                descend()
            is_digit = False

    if len(version) > start:
        # Same nesting rule for the final token: ``2.0.a`` is ``2, [a]`` — a
        # sublist that sorts BELOW ``2-1``'s ``[1]`` — not the sibling ``2, 0,
        # a`` that would sort above it. Treating it as a sibling made the whole
        # cross-type ordering wrong for any version ending in a qualifier.
        if not is_digit and current:
            descend()
        current.append(parse_item(is_digit, version[start:]))

    while stack:
        stack.pop().normalize()
    return root


def _compare_maven_versions(left: str, right: str) -> int:
    """Compare two Maven versions per the Maven version order specification."""
    return _maven_compare_items(_maven_parse(left), _maven_parse(right))


# ---------------------------------------------------------------------------
# Packagist / Composer version order
#
# Composer compares versions with PHP's ``version_compare`` — composer/semver's
# ``Constraint::versionCompare`` calls it directly — documented at
# https://www.php.net/manual/en/function.version-compare.php: ``_``, ``-`` and
# ``+`` become ``.``, a ``.`` is inserted between a digit and a non-digit, and
# the resulting parts are ordered
#
#   any string not found in this list < dev < alpha = a < beta = b < RC = rc
#                                     < # < pl = p
#
# where ``#`` stands for "this side has no further part". api.osv.dev resolves
# Packagist ranges the same way, so this is also the ordering behind the live
# OSV answers the matcher is measured against.
#
# Routing Packagist through PEP 440 instead made ``packaging`` reject every
# patch-suffixed release (``2.4.5-p1``); the pre-release-strip fallback then
# removed the suffix from BOTH sides and declared them EQUAL, so an installed
# version inside ``[2.4.5-p1, 2.4.5-p2)`` read as already patched and the
# advisory was dropped.
# ---------------------------------------------------------------------------

_PHP_PART_ORDER = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "RC": 3,
    "rc": 3,
    "#": 4,
    "pl": 5,
    "p": 5,
}
# "any string not found in this list" sorts below every listed part.
_PHP_UNLISTED_PART = -1


def _php_canonicalize_version(version: str) -> str:
    """Apply PHP's documented version canonicalization."""
    if version[:1] in ("v", "V"):
        version = version[1:]
    version = re.sub(r"[-_+.]+", ".", version)
    version = re.sub(r"([^\d.])(\d)", r"\1.\2", version)
    return re.sub(r"(\d)([^\d.])", r"\1.\2", version)


def _php_compare_parts(left: str, right: str) -> int:
    left_rank = _PHP_PART_ORDER.get(left, _PHP_UNLISTED_PART)
    right_rank = _PHP_PART_ORDER.get(right, _PHP_UNLISTED_PART)
    return (left_rank > right_rank) - (left_rank < right_rank)


def _php_compare_slices(left: list[str], right: list[str]) -> int:
    for left_part, right_part in zip(left, right):
        left_numeric = left_part.isdecimal()
        right_numeric = right_part.isdecimal()
        if left_numeric and right_numeric:
            result = (int(left_part) > int(right_part)) - (int(left_part) < int(right_part))
        elif not left_numeric and not right_numeric:
            result = _php_compare_parts(left_part, right_part)
        elif left_numeric:
            # A numeric part on one side is compared as the "no further part"
            # sentinel against the other side's qualifier.
            result = _php_compare_parts("#", right_part)
        else:
            result = _php_compare_parts(left_part, "#")
        if result:
            return result

    # One side ran out of parts: a trailing NUMERIC part outranks the sentinel
    # (1.0.1 > 1.0), a trailing qualifier is ranked against it (1.0-rc < 1.0).
    if len(left) > len(right):
        tail = left[len(right) :]
        return 1 if tail[0].isdecimal() else _php_compare_slices(tail, ["#"])
    if len(left) < len(right):
        tail = right[len(left) :]
        return -1 if tail[0].isdecimal() else _php_compare_slices(["#"], tail)
    return 0


def _compare_php_versions(left: str, right: str) -> int:
    """Compare two Packagist/Composer versions per PHP ``version_compare``."""
    return _php_compare_slices(
        _php_canonicalize_version(left).split("."),
        _php_canonicalize_version(right).split("."),
    )


# ---------------------------------------------------------------------------
# NuGet version order
#
# NuGet is SemVer 2.0 with the divergences its own reference lists
# (https://learn.microsoft.com/nuget/concepts/package-versioning —
# "Where NuGetVersion diverges from Semantic Versioning"):
#   * a 4th ``Revision`` segment (``Major.Minor.Patch.Revision``);
#   * only ``Major`` is required, missing segments are zero, so ``1``, ``1.0``,
#     ``1.0.0`` and ``1.0.0.0`` are all equal;
#   * pre-release labels compare CASE-INSENSITIVELY;
#   * leading zeros are removed and build metadata is stripped.
# ``NuGet.Versioning.VersionComparer`` compares Major/Minor/Patch/Revision
# first and the release labels only on a tie, which is what this reproduces.
#
# A strict-SemVer comparator gets all four divergences wrong, so NuGet is
# implemented here rather than routed at npm's SemVer branch.
# ---------------------------------------------------------------------------

_NUGET_VERSION_RE = re.compile(r"^(?P<numbers>\d+(?:\.\d+){0,3})(?:-(?P<pre>[0-9A-Za-z.\-]+))?(?:\+(?P<build>[0-9A-Za-z.\-]+))?$")


def _parse_nuget_version(version: str) -> tuple[tuple[int, int, int, int], tuple[str, ...]] | None:
    """Return ``((major, minor, patch, revision), release_labels)`` or ``None``."""
    candidate = version.strip()
    if candidate[:1] in ("v", "V"):
        candidate = candidate[1:]
    match = _NUGET_VERSION_RE.match(candidate)
    if match is None:
        return None
    numbers = [int(part) for part in match.group("numbers").split(".")]
    numbers.extend([0] * (4 - len(numbers)))
    prerelease = match.group("pre")
    labels = tuple(label.lower() for label in prerelease.split(".")) if prerelease else ()
    return (numbers[0], numbers[1], numbers[2], numbers[3]), labels


def _compare_nuget_label(left: str, right: str) -> int:
    left_numeric = left.isdigit()
    right_numeric = right.isdigit()
    if left_numeric and right_numeric:
        return (int(left) > int(right)) - (int(left) < int(right))
    if left_numeric != right_numeric:
        # Numeric identifiers always have lower precedence than alphanumeric.
        return -1 if left_numeric else 1
    return (left > right) - (left < right)


def _compare_nuget_labels(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    if not left or not right:
        if left == right:
            return 0
        # A release outranks any pre-release of the same numeric version.
        return 1 if not left else -1
    for left_label, right_label in zip(left, right):
        result = _compare_nuget_label(left_label, right_label)
        if result:
            return result
    return (len(left) > len(right)) - (len(left) < len(right))


def _compare_nuget_versions(left: str, right: str) -> int | None:
    left_parsed = _parse_nuget_version(left)
    right_parsed = _parse_nuget_version(right)
    if left_parsed is None or right_parsed is None:
        return None
    if left_parsed[0] != right_parsed[0]:
        return 1 if left_parsed[0] > right_parsed[0] else -1
    return _compare_nuget_labels(left_parsed[1], right_parsed[1])


# ---------------------------------------------------------------------------
# RubyGems version order (``Gem::Version``)
#
# Gem versions are "a series of digits or ASCII letters separated by dots".
# ``Gem::Version`` rewrites ``-`` to ``.pre.``, splits the string into runs of
# digits or letters, then drops trailing zero segments from the numeric run and
# from the prerelease run independently (``canonical_segments``). Comparison
# pads the shorter side with ``0`` and orders a STRING segment BELOW a numeric
# one, so ``5.0.0.beta1 < 5.0.0``.
#
# PEP 440 rejects Gem's ``X.Y.Z.beta1.1`` form outright, which left every such
# advisory bound uncomparable and — because ``version_in_range`` fails closed —
# unreportable.
# ---------------------------------------------------------------------------

_GEM_VERSION_RE = re.compile(r"^\s*(?:[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)?\s*$")
_GEM_SEGMENT_RE = re.compile(r"[0-9]+|[a-z]+", re.IGNORECASE)


def _gem_canonical_segments(version: str) -> list[int | str] | None:
    """Return ``Gem::Version#canonical_segments``, or ``None`` if Gem rejects it."""
    if _GEM_VERSION_RE.match(version) is None:
        return None
    expanded = version.strip().replace("-", ".pre.")
    segments: list[int | str] = [int(segment) if segment.isdigit() else segment for segment in _GEM_SEGMENT_RE.findall(expanded)]
    # Everything from the first letter segment onwards is the prerelease run.
    split_at = next((index for index, segment in enumerate(segments) if isinstance(segment, str)), len(segments))
    canonical: list[int | str] = []
    for group in (segments[:split_at], segments[split_at:]):
        end = len(group)
        while end and group[end - 1] == 0:
            end -= 1
        canonical.extend(group[:end])
    return canonical


def _compare_gem_versions(left: str, right: str) -> int | None:
    left_segments = _gem_canonical_segments(left)
    right_segments = _gem_canonical_segments(right)
    if left_segments is None or right_segments is None:
        return None
    if left_segments == right_segments:
        return 0
    for index in range(max(len(left_segments), len(right_segments))):
        left_segment: int | str = left_segments[index] if index < len(left_segments) else 0
        right_segment: int | str = right_segments[index] if index < len(right_segments) else 0
        if left_segment == right_segment:
            continue
        if isinstance(left_segment, str) and isinstance(right_segment, int):
            return -1
        if isinstance(left_segment, int) and isinstance(right_segment, str):
            return 1
        return 1 if left_segment > right_segment else -1  # type: ignore[operator]
    return 0


_PACKAGIST_ECOSYSTEMS = frozenset({"packagist", "composer", "php"})
_NUGET_ECOSYSTEMS = frozenset({"nuget"})
_RUBYGEMS_ECOSYSTEMS = frozenset({"rubygems", "gem", "gems"})


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
    if eco == "maven":
        return _compare_maven_versions(left, right)
    if eco in _PACKAGIST_ECOSYSTEMS:
        return _compare_php_versions(left, right)
    if eco in _NUGET_ECOSYSTEMS:
        return _compare_nuget_versions(left, right)
    if eco in _RUBYGEMS_ECOSYSTEMS:
        return _compare_gem_versions(left, right)

    # npm-style ecosystems use SemVer precedence, including arbitrary
    # prerelease identifiers (not only the common canary/beta/rc tags).  The
    # packaging library intentionally interprets ``1.0.0-foo`` as a PEP 440
    # post-release, which reverses the SemVer ordering and can suppress a
    # vulnerability bounded at ``1.0.0``.  Handle strict SemVer before the
    # Python-version fallback; Python/PyPI local versions retain their PEP 440
    # behavior below.
    if eco in {"npm", "npmjs", "yarn", "pnpm", "node", "javascript", "js"}:
        semver_cmp = _compare_strict_semver(left, right)
        if semver_cmp is not None:
            return semver_cmp

    try:
        from packaging.version import Version

        left_norm = normalize_version(left, eco)
        right_norm = normalize_version(right, eco)
        return (Version(left_norm) > Version(right_norm)) - (Version(left_norm) < Version(right_norm))
    except Exception:  # noqa: BLE001
        # PEP 440 (``packaging.Version``) rejects npm-style pre-release tags
        # like ``13.4.20-canary.13`` / ``5.0.0-rc.1`` / ``1.0.0-beta.4`` which
        # are valid SemVer for npm/yarn/pnpm publishes. Without a fall-back
        # the comparator returns None, the OSV/GHSA range matcher conserva-
        # tively marks the package as affected, and downstream emits a false
        # positive (e.g. ``next@16.2.4`` flagged by an advisory whose fix is
        # ``< 13.4.20-canary.13``).
        #
        # Retry with the pre-release suffix stripped from BOTH sides so we
        # get a defensible numeric major.minor.patch comparison. This is
        # technically lossy (``13.4.20-canary.X`` is a pre-release of
        # ``13.4.20`` per SemVer 2.0), but for OSV/GHSA introduced/fixed
        # bounds the major.minor.patch view is the safe answer: operators
        # on a strictly higher major.minor.patch shouldn't be flagged.
        try:
            from packaging.version import Version

            left_stripped = _strip_semver_prerelease_tag(left)
            right_stripped = _strip_semver_prerelease_tag(right)
            left_had_pre = left_stripped != left
            right_had_pre = right_stripped != right
            if not left_had_pre and not right_had_pre:
                # No recognized pre-release tag — try local-version-style
                # suffixes (``2.6.0-NA``, ``2.6.0-cu124``) before giving up.
                return _compare_with_local_suffix_strip(left, right, eco)
            ln = normalize_version(left_stripped, eco)
            rn = normalize_version(right_stripped, eco)
            base_cmp = (Version(ln) > Version(rn)) - (Version(ln) < Version(rn))
            if base_cmp != 0:
                return base_cmp
            # Equal base release. A SemVer pre-release sorts STRICTLY BELOW the
            # release it precedes (``13.4.20-canary.13`` < ``13.4.20``). When
            # only one side carries the pre-release tag, order it below the bare
            # release — collapsing to equality here would let a canary/nightly
            # build read as already past a fix bound, hiding the vulnerability.
            if left_had_pre and not right_had_pre:
                return -1
            if right_had_pre and not left_had_pre:
                return 1
            return 0
        except Exception:  # noqa: BLE001
            # One side stripped a pre-release tag but the other still failed
            # to parse (e.g. ``2.6.0-NA`` vs a plain release) — the local-
            # suffix fall-back handles both sides uniformly.
            return _compare_with_local_suffix_strip(left, right, eco)


_SEMVER_PRERELEASE_TAGS = frozenset(
    {
        "canary",
        "beta",
        "alpha",
        "rc",
        "pre",
        "dev",
        "nightly",
        "next",
        "snapshot",
        "m",
        "preview",
    }
)


_STRICT_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")


def _compare_strict_semver(left: str, right: str) -> int | None:
    """Compare strict SemVer strings, including arbitrary prerelease tags."""
    left_match = _STRICT_SEMVER.fullmatch(left.strip())
    right_match = _STRICT_SEMVER.fullmatch(right.strip())
    if left_match is None or right_match is None:
        return None
    left_base = tuple(int(left_match.group(index)) for index in (1, 2, 3))
    right_base = tuple(int(right_match.group(index)) for index in (1, 2, 3))
    if left_base != right_base:
        return (left_base > right_base) - (left_base < right_base)
    left_pre = left_match.group(4)
    right_pre = right_match.group(4)
    if left_pre is None or right_pre is None:
        if left_pre == right_pre:
            return 0
        return -1 if left_pre is not None else 1
    left_parts = left_pre.split(".")
    right_parts = right_pre.split(".")
    for left_part, right_part in zip(left_parts, right_parts):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return (int(left_part) > int(right_part)) - (int(left_part) < int(right_part))
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return (left_part > right_part) - (left_part < right_part)
    return (len(left_parts) > len(right_parts)) - (len(left_parts) < len(right_parts))


def _strip_semver_prerelease_tag(version: str) -> str:
    """Strip a SemVer pre-release suffix from a version string.

    Recognised tag stems: ``canary, beta, alpha, rc, pre, dev, nightly,
    next, snapshot, m`` (Spring milestone), ``preview``. Everything after
    the tag (e.g. ``.13`` in ``13.4.20-canary.13``) is also discarded so
    build-metadata and serial counters fall away. Returns the input
    unchanged when no recognized suffix is present so the caller can
    detect "nothing to retry" and avoid an infinite loop.
    """
    base, separator, suffix = version.partition("-")
    if not separator:
        return version
    tag = suffix.split(".", 1)[0].lower()
    if tag in _SEMVER_PRERELEASE_TAGS:
        return base
    return version


def _split_local_style_suffix(version: str, ecosystem: str) -> tuple[str, bool] | None:
    """Split a local-version-style suffix off *version* if the base parses.

    PyPI wheel local versions leak into advisory bounds as ``2.6.0+cu124`` /
    ``2.6.0-cu124`` / ``2.6.0-NA``. Returns ``(parseable_base, had_suffix)``,
    or ``None`` when neither the full string nor any stripped base parses.
    """
    from packaging.version import Version

    try:
        Version(normalize_version(version, ecosystem))
        return version, False
    except Exception:  # noqa: BLE001
        pass
    for sep in ("+", "-"):
        base, separator, _suffix = version.partition(sep)
        if not separator or not base:
            continue
        try:
            Version(normalize_version(base, ecosystem))
        except Exception:  # noqa: BLE001
            continue
        return base, True
    return None


def _compare_with_local_suffix_strip(left: str, right: str, ecosystem: str) -> int | None:
    """Compare after stripping unrecognized local/build-style suffixes.

    Bounds like ``2.6.0-NA`` (PYSEC torch advisories) are neither PEP 440 nor
    recognized SemVer pre-releases; compare on the parseable base instead of
    returning ``None`` (which fails the range matcher open). On an equal base
    the suffixed side orders ABOVE the bare release — mirroring PEP 440
    local-version ordering — so a bare version never reads as already past a
    suffixed fix bound.
    """
    left_split = _split_local_style_suffix(left, ecosystem)
    right_split = _split_local_style_suffix(right, ecosystem)
    if left_split is None or right_split is None:
        return None
    left_base, left_suffixed = left_split
    right_base, right_suffixed = right_split
    if not (left_suffixed or right_suffixed):
        return None  # nothing was stripped — the original failure stands

    from packaging.version import Version

    left_version = Version(normalize_version(left_base, ecosystem))
    right_version = Version(normalize_version(right_base, ecosystem))
    if left_version != right_version:
        return 1 if left_version > right_version else -1
    if left_suffixed and not right_suffixed:
        return 1
    if right_suffixed and not left_suffixed:
        return -1
    return 0


def _dropped_bound_message(bound: str, ecosystem: str) -> str:
    return (
        f"advisory version bound {bound!r} ({ecosystem}) could not be compared; the affected range was dropped, so results may under-report"
    )


@lru_cache(maxsize=4096)
def _log_unparseable_bound(bound: str, ecosystem: str) -> None:
    """Log (once per distinct bound) that a range comparison was dropped.

    Either side of the comparison can be at fault — the bound itself, or an
    installed/candidate version the ecosystem's ordering cannot place (a git
    SHA leaking out of a ``GIT`` range, say) — so the wording blames neither.
    """
    _logger.warning(
        "Advisory version bound %r (%s) could not be compared; failing closed — the bound "
        "cannot establish a match, so affected-range accuracy may be reduced",
        bound,
        ecosystem,
    )


def _warn_unparseable_bound(bound: str, ecosystem: str) -> None:
    """Report a dropped advisory bound to the log AND to ``scan_warnings``.

    Failing closed on a bound we cannot compare is the right policy; dropping
    the EVIDENCE of it is not. A log line reaches nobody downstream — the JSON
    and SARIF payloads, the console summary and the exit code all saw a result
    indistinguishable from a genuinely clean one.

    The log side stays memoised so a corpus-wide sweep does not print the same
    line thousands of times, but the scan-warning side must fire on EVERY scan:
    ``record_scan_warning`` already dedupes within one scan's boundary, and a
    second scan in the same process has its own boundary.
    """
    _log_unparseable_bound(bound, ecosystem)
    from agent_bom.scanners.state import record_scan_warning

    record_scan_warning(_dropped_bound_message(bound, ecosystem))


def normalize_introduced(introduced: str | None) -> str | None:
    """Resolve an OSV ``introduced`` bound, returning ``None`` when unbounded.

    The OSV schema defines ``"0"`` as a sentinel — "a version that sorts before
    any other version" — not as a version string to compare against. Comparing
    a real version to the literal ``"0"`` gives the wrong answer whenever the
    version sorts BELOW zero in its own ecosystem's order, and Go pseudo-
    versions do exactly that: ``v0.0.0-20200622213623-75b288015ac9`` is a
    pre-release of ``0.0.0``. Every advisory window opening at the sentinel then
    excluded every pseudo-version-pinned module — a silent, total recall loss
    for the most common way an untagged Go dependency is pinned.

    Only ``introduced`` carries this sentinel. ``fixed`` and ``last_affected``
    keep their literal meaning: nothing is "fixed before every version".
    """
    if introduced is None:
        return None
    bound = introduced.strip()
    if not bound or bound == "0":
        return None
    return bound


def version_in_range(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    ecosystem: str,
) -> bool:
    """Return whether ``version`` is affected by the supplied advisory bounds.

    The decision itself is memoised; the reporting of any bound it had to drop
    is not, so a cache hit can never swallow the warning.
    """
    affected, dropped = _resolve_version_range(version, introduced, fixed, last_affected, ecosystem)
    for bound in dropped:
        _warn_unparseable_bound(bound, ecosystem)
    return affected


@lru_cache(maxsize=65536)
def _resolve_version_range(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    ecosystem: str,
) -> tuple[bool, tuple[str, ...]]:
    """Return ``(affected, dropped_bounds)`` for the supplied advisory bounds."""
    dropped: list[str] = []
    intro = normalize_introduced(introduced)
    fix = fixed or None
    last = last_affected or None

    # Git-commit bounds (common in OSS-Fuzz / OSV-2022-* advisories) cannot
    # establish semver range membership — compare_version_order returns None
    # and falling through would mark every version as affected.
    if any(boundary and _looks_like_commit_sha(boundary) for boundary in (intro, fix, last)):
        return False, ()

    if ecosystem.lower() == "go":
        ver_ts = _go_pseudo_timestamp(version)
        if ver_ts:
            for boundary, is_lower in ((intro, True), (fix, False), (last, False)):
                if not boundary:
                    continue
                boundary_ts = _go_pseudo_timestamp(boundary)
                cmp: int | None
                if boundary_ts:
                    cmp = (ver_ts > boundary_ts) - (ver_ts < boundary_ts)
                else:
                    # Tagged bound: route the pseudo-vs-tagged comparison
                    # through compare_version_order instead of skipping it,
                    # so the boundary still constrains range membership.
                    cmp = compare_version_order(version, boundary, ecosystem)
                if cmp is None:
                    continue
                if is_lower and cmp < 0:
                    return False, ()
                if not is_lower and boundary == fix and cmp >= 0:
                    return False, ()
                if not is_lower and boundary == last and cmp > 0:
                    return False, ()

    # Fail CLOSED per bound: a comparison that cannot be performed is never
    # grounds for a match. An unparseable UPPER bound (fixed / last_affected)
    # means the version cannot be placed inside the range — no match. An
    # unparseable LOWER bound (introduced) is treated as satisfied so that a
    # parseable upper bound can still confirm a real match — unless it was the
    # only bound, in which case no comparison was performed at all.
    intro_unperformed = False
    if intro:
        intro_cmp = compare_version_order(version, intro, ecosystem)
        if intro_cmp is not None and intro_cmp < 0:
            return False, tuple(dropped)
        if intro_cmp is None:
            dropped.append(intro)
            intro_unperformed = True
    if fix:
        fix_cmp = compare_version_order(version, fix, ecosystem)
        if fix_cmp is None:
            dropped.append(fix)
            return False, tuple(dropped)
        if fix_cmp >= 0:
            return False, tuple(dropped)
    if last:
        last_cmp = compare_version_order(version, last, ecosystem)
        if last_cmp is None:
            dropped.append(last)
            return False, tuple(dropped)
        if last_cmp > 0:
            return False, tuple(dropped)
    if intro_unperformed and not fix and not last:
        return False, tuple(dropped)
    return True, tuple(dropped)


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
