"""Shared package ecosystem constants."""

from __future__ import annotations

SUPPORTED_PACKAGE_ECOSYSTEMS: tuple[str, ...] = (
    "npm",
    "pypi",
    "go",
    "cargo",
    "maven",
    "nuget",
    "rubygems",
    "composer",
    "swift",
    "pub",
    "hex",
    "conda",
    "deb",
    "apk",
    "rpm",
)

SUPPORTED_PACKAGE_ECOSYSTEM_SET = frozenset(SUPPORTED_PACKAGE_ECOSYSTEMS)
