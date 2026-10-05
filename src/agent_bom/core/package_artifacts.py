"""Normalize package artifact identity and derive advisory query names."""

from __future__ import annotations

from typing import Any, Protocol

from packageurl import PackageURL

from agent_bom.core.packages import normalize_package_name
from agent_bom.core.versions.ruby import split_gem_artifact_version


class PackageArtifact(Protocol):
    name: str
    version: str
    ecosystem: str
    purl: str | None
    source_package: str | None
    version_evidence: list[dict[str, Any]]


def normalize_artifact_version(package: PackageArtifact) -> None:
    """Keep Ruby artifact platforms out of advisory and package identity."""
    if package.ecosystem.lower() not in {"rubygems", "gem"}:
        return
    raw_version = package.version
    version, platform = split_gem_artifact_version(raw_version)
    if platform is None:
        return
    package.version = version
    package.version_evidence.append({"type": "artifact_platform", "raw_version": raw_version, "platform": platform})
    if package.purl:
        try:
            parsed = PackageURL.from_string(package.purl)
            if parsed.type == "gem" and parsed.version == raw_version:
                package.purl = parsed._replace(version=version).to_string()
        except ValueError:
            pass  # Preserve malformed input for the existing identity fallback.


def package_lookup_names(package: PackageArtifact) -> list[str]:
    """Candidate package names for vulnerability matching."""
    names: list[str] = []

    def add_name(candidate: str | None) -> None:
        candidate = (candidate or "").strip()
        if not candidate:
            return
        norm_candidate = normalize_package_name(candidate, package.ecosystem)
        if all(normalize_package_name(existing, package.ecosystem) != norm_candidate for existing in names):
            names.append(candidate)

    add_name(package.name)
    if package.ecosystem.lower() == "maven" and package.purl:
        try:
            parsed = PackageURL.from_string(package.purl)
        except Exception:
            parsed = None
        if parsed is not None and (parsed.type or "").lower() == "maven" and parsed.namespace and parsed.name:
            add_name(f"{parsed.namespace}:{parsed.name}")
    if package.source_package:
        source_name = package.source_package.strip()
        if source_name and normalize_package_name(source_name, package.ecosystem) != normalize_package_name(
            package.name, package.ecosystem
        ):
            add_name(source_name)
    return names
