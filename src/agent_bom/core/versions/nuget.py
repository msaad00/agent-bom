"""Canonical nuget rules for ecosystem version comparison."""

from __future__ import annotations

import re

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
