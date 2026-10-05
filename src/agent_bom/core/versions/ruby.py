"""Canonical ruby rules for ecosystem version comparison."""

from __future__ import annotations

import re

_GEM_VERSION_RE = re.compile(r"^\s*(?:[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)?\s*$")


_GEM_SEGMENT_RE = re.compile(r"[0-9]+|[a-z]+", re.IGNORECASE)

# Artifact architecture/OS is not part of Gem::Version. Only recognize known
# native platform shapes here; arbitrary suffixes remain prerelease versions.
_NATIVE_GEM_PLATFORM = re.compile(
    r"^(?P<version>.+)-(?P<platform>(?:x86_64|x64|x86|i[3-6]86|arm64|aarch64|arm|armv[5-8]l|powerpc|ppc64le|s390x)"
    r"-(?:linux(?:-(?:gnu|musl)(?:eabihf)?)?|darwin(?:-\d+)?|mingw(?:32|-ucrt)|mswin(?:32|64)(?:_\d+)?))$"
)


def split_gem_artifact_version(version: str, platforms: list[str] | None = None) -> tuple[str, str | None]:
    """Separate a recognized native artifact platform, preserving prereleases."""
    for platform in platforms or []:
        if platform != "ruby" and version.endswith("-" + platform):
            return version[: -len(platform) - 1], platform
    match = _NATIVE_GEM_PLATFORM.fullmatch(version)
    if match and _gem_canonical_segments(match["version"]) is not None:
        return match["version"], match["platform"]
    return version, None


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
