"""Canonical php rules for ecosystem version comparison."""

from __future__ import annotations

import re

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


def _composer_patch_parts(version: str) -> list[str]:
    """Recognize Composer's patch alias before PHP's ordering comparison.

    Composer's VersionParser accepts patch, pl and p interchangeably. Native
    PHP does not recognize the word patch, so this normalization is restricted
    to Composer/Packagist and leaves the PHP comparator unchanged.
    See https://github.com/composer/semver/blob/main/src/VersionParser.php.
    """
    return ["pl" if part.lower() == "patch" else part for part in _php_canonicalize_version(version).split(".")]


def _compare_composer_versions(left: str, right: str) -> int:
    return _php_compare_slices(_composer_patch_parts(left), _composer_patch_parts(right))
