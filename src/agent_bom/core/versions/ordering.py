"""Canonical ordering rules for ecosystem version comparison."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import TYPE_CHECKING

from agent_bom.core.versions.distro import _compare_apk_versions, _compare_debian_versions, _compare_rpm_versions
from agent_bom.core.versions.go import _compare_go_versions
from agent_bom.core.versions.maven import _compare_maven_versions
from agent_bom.core.versions.nuget import _compare_nuget_versions
from agent_bom.core.versions.php import _compare_composer_versions, _compare_php_versions
from agent_bom.core.versions.ruby import _compare_gem_versions
from agent_bom.core.versions.validation import _looks_like_commit_sha, normalize_version

if TYPE_CHECKING:
    from packaging.version import Version


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


_PACKAGIST_ECOSYSTEMS = frozenset({"packagist", "composer", "php"})


_NUGET_ECOSYSTEMS = frozenset({"nuget"})


_RUBYGEMS_ECOSYSTEMS = frozenset({"rubygems", "gem", "gems"})


_ECOSYSTEM_COMPARATORS = {
    "deb": _compare_debian_versions,
    "rpm": _compare_rpm_versions,
    "apk": _compare_apk_versions,
    "go": _compare_go_versions,
    "maven": _compare_maven_versions,
    **dict.fromkeys(_PACKAGIST_ECOSYSTEMS - {"php"}, _compare_composer_versions),
    "php": _compare_php_versions,
    **dict.fromkeys(_NUGET_ECOSYSTEMS, _compare_nuget_versions),
    **dict.fromkeys(_RUBYGEMS_ECOSYSTEMS, _compare_gem_versions),
}


@lru_cache(maxsize=131072)
def _pep440_version(normalized: str) -> "Version":
    """Parse once per distinct string; ingest compares each release many times."""
    from packaging.version import Version

    return Version(normalized)


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

    comparator = _ECOSYSTEM_COMPARATORS.get(eco)
    if comparator is not None:
        return comparator(left, right)

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

    return _compare_packaging_versions(left, right, eco)


def _compare_packaging_versions(left: str, right: str, eco: str) -> int | None:
    """Preserve PEP 440 precedence and the explicit legacy suffix fallbacks."""
    try:
        left_version = _pep440_version(normalize_version(left, eco))
        right_version = _pep440_version(normalize_version(right, eco))
        return (left_version > right_version) - (left_version < right_version)
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
