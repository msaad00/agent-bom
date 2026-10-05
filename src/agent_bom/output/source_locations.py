"""Source-backed SARIF package locations without fabricated checkout files."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

from agent_bom.finding import Finding
from agent_bom.models import AIBOMReport, Package
from agent_bom.output.finding_views import package_ecosystem, package_name, package_version

SourceIndex = dict[tuple[str, str, str, str], list[tuple[str, int | None]]]


def _relative_uri(source: str, config_path: str) -> str | None:
    if not source or source.startswith("<"):
        return None
    path = Path(source)
    if not path.is_absolute():
        if ".." in path.parts or source.startswith(("~", "\\")) or ":" in source:
            return None
        return quote(path.as_posix(), safe="/")
    roots = [Path.cwd()]
    if config_path and not config_path.startswith("<"):
        config = Path(config_path)
        if config.is_dir():
            roots.append(config)
        elif config.is_file():
            roots.append(config.parent)
    for root in roots:
        try:
            relative = path.resolve().relative_to(root.resolve())
        except (ValueError, OSError):
            continue
        return quote(relative.as_posix(), safe="/")
    return None


def _package_sources(package: Package, config_path: str) -> list[tuple[str, int | None]]:
    locations = []
    for entry in package.version_evidence:
        path = entry.get("source_file") or entry.get("path")
        if not isinstance(path, str):
            continue
        uri = _relative_uri(path, config_path)
        if uri is not None:
            line = entry.get("line")
            locations.append((uri, line if type(line) is int and line > 0 else None))
    if not locations and config_path.startswith("self-scan://"):
        locations.append((config_path, None))
    return list(dict.fromkeys(locations))


def package_source_index(report: AIBOMReport) -> SourceIndex:
    """Index raw producer provenance before generic path redaction loses scope."""
    index: SourceIndex = defaultdict(list)
    for agent in report.agents:
        for server in agent.mcp_servers:
            for package in server.packages:
                key = (agent.name, package.ecosystem, package.name, package.version)
                index[key].extend(_package_sources(package, agent.config_path))
    for radius in report.blast_radii:
        package = radius.package
        for agent in radius.affected_agents:
            key = (agent.name, package.ecosystem, package.name, package.version)
            index[key].extend(_package_sources(package, agent.config_path))
    return index


def finding_package_location(finding: Finding, index: SourceIndex) -> tuple[str, int | None]:
    for agent in finding.affected_agents:
        key = (str(agent), package_ecosystem(finding), package_name(finding), package_version(finding))
        if index.get(key):
            return index[key][0]
    # Persisted redacted basenames cannot identify the original repository file.
    # The package identity is still useful and safe as a logical SARIF location.
    identity = finding.asset.identifier or ""
    if finding.asset.location and finding.asset.location.startswith("self-scan://"):
        return finding.asset.location, None
    if not identity.startswith("pkg:"):
        identity = f"package:{package_ecosystem(finding)}/{package_name(finding)}@{package_version(finding)}"
    return identity, None
