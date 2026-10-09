"""Wire an imported external report into a scan without double counting.

The parser (:mod:`agent_bom.parsers.external_scanners`) turns a report into
packages plus findings. This module attaches that evidence to the scan:

* external packages that match a natively inventoried package are folded onto
  the native package (one package, one vulnerability per id, both provenance
  labels kept) instead of becoming a second copy of the same package;
* name-only dependency results resolve against the native package declared in
  the same manifest; when that is impossible they become labelled unresolved
  findings rather than invented ``@0.0.0`` coordinates.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from agent_bom.finding_merge import merge_external_code_findings as merge_external_code_findings
from agent_bom.models import Agent, AgentType, MCPServer, Package, ServerSurface, TransportType, Vulnerability

if TYPE_CHECKING:
    from agent_bom.finding import Finding
    from agent_bom.parsers.external_scanners import ExternalScanImport


def build_external_agent(imported: "ExternalScanImport", report_path: str) -> Agent:
    """Return the synthetic agent that carries an external report's packages."""
    resource_name = PurePosixPath(str(report_path).replace("\\", "/")).stem or "external-scan"
    surface = ServerSurface.SBOM if imported.is_sbom else ServerSurface.EXTERNAL_SCAN
    server = MCPServer(
        name=resource_name,
        command="external-scan",
        args=[report_path],
        transport=TransportType.STDIO,
        packages=list(imported.packages),
        surface=surface,
    )
    return Agent(
        name=f"external-scan:{resource_name}",
        agent_type=AgentType.CUSTOM,
        config_path=report_path,
        source="external-scan",
        mcp_servers=[server],
    )


def _is_external_server(server: MCPServer) -> bool:
    return server.command == "external-scan"


def _manifest_files(pkg: Package) -> list[str]:
    files: list[str] = []
    for evidence in pkg.version_evidence or []:
        if isinstance(evidence, dict) and isinstance(evidence.get("source_file"), str) and evidence["source_file"]:
            files.append(evidence["source_file"].replace("\\", "/"))
    return files


def _same_manifest(native: Package, manifest: str) -> bool:
    manifest = manifest.replace("\\", "/").lstrip("./")
    for path in _manifest_files(native):
        if path == manifest or path.endswith("/" + manifest):
            return True
    return False


def merge_vulnerability(target: Package, incoming: Vulnerability) -> bool:
    """Merge one vulnerability into ``target``; return True when it was new.

    A vulnerability already present (by id or alias) keeps its record and gains
    the incoming provenance labels, so the same advisory is counted once.
    """
    from agent_bom.advisory_sources import merge_advisory_sources

    incoming_keys = {incoming.id, *incoming.aliases}
    for existing in target.vulnerabilities:
        if incoming_keys & {existing.id, *existing.aliases}:
            existing.advisory_sources = merge_advisory_sources(*existing.advisory_sources, *incoming.advisory_sources)
            return False
    target.vulnerabilities.append(incoming)
    return True


def _unresolved_finding(pkg: Package, vuln: Vulnerability, manifest: str) -> "Finding":
    from agent_bom.compliance_hub import apply_hub_classification
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType, stable_id

    tool_labels = [label for label in vuln.advisory_sources if label.startswith("external")]
    location = manifest or None
    title = f"{vuln.id}: {pkg.name} (version unresolved)"
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.EXTERNAL,
        asset=Asset(
            name=f"{pkg.name} in {manifest}" if manifest else pkg.name,
            asset_type="manifest_file" if manifest else "external",
            identifier=location or pkg.name,
            location=location,
        ),
        severity=vuln.severity.value,
        title=title,
        description=vuln.summary,
        cve_id=vuln.id,
        cwe_ids=list(vuln.cwe_ids),
        cvss_score=vuln.cvss_score,
        fixed_version=vuln.fixed_version,
        evidence={
            "package_resolution": "unresolved",
            "package_name": pkg.name,
            "ecosystem": pkg.ecosystem,
            "file": manifest or None,
            "reason": "external result named a package without a version and no native package matched it",
        },
        sources=tool_labels or ["external"],
        id=stable_id("external-unresolved", pkg.ecosystem, pkg.name, vuln.id, manifest),
    )
    return apply_hub_classification(finding)


def fold_external_packages(agents: list[Agent], *, findings: "list[Finding] | None" = None) -> list[str]:
    """Fold external-report packages onto matching native packages in place.

    Returns human-readable notices for dependency evidence that could not be
    resolved to a real package. When ``findings`` is given, each unresolved
    result is also appended there as a labelled EXTERNAL finding.
    """
    from agent_bom.package_utils import canonical_package_key, normalize_package_ecosystem, normalize_package_name

    native_by_key: dict[str, Package] = {}
    native_by_name: dict[tuple[str, str], list[Package]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            if _is_external_server(server):
                continue
            for pkg in server.packages:
                native_by_key.setdefault(canonical_package_key(pkg.name, pkg.version, pkg.ecosystem, pkg.purl), pkg)
                eco = normalize_package_ecosystem(pkg.ecosystem)
                native_by_name.setdefault((eco, normalize_package_name(pkg.name, eco)), []).append(pkg)

    notices: list[str] = []
    for agent in agents:
        for server in agent.mcp_servers:
            if not _is_external_server(server):
                continue
            kept: list[Package] = []
            for pkg in server.packages:
                if pkg.version:
                    native = native_by_key.get(canonical_package_key(pkg.name, pkg.version, pkg.ecosystem, pkg.purl))
                    if native is None:
                        kept.append(pkg)
                        continue
                    for vuln in pkg.vulnerabilities:
                        merge_vulnerability(native, vuln)
                    continue

                manifest = next(iter(_manifest_files(pkg)), "")
                eco = normalize_package_ecosystem(pkg.ecosystem)
                candidates = native_by_name.get((eco, normalize_package_name(pkg.name, eco)), [])
                if manifest:
                    candidates = [candidate for candidate in candidates if _same_manifest(candidate, manifest)]
                versions = {candidate.version for candidate in candidates if candidate.version}
                if len(candidates) >= 1 and len(versions) == 1:
                    for candidate in candidates:
                        for vuln in pkg.vulnerabilities:
                            merge_vulnerability(candidate, vuln)
                    continue
                ids = ", ".join(v.id for v in pkg.vulnerabilities)
                where = f" in {manifest}" if manifest else ""
                notices.append(
                    f"External report named {pkg.name}{where} without a version and no single native package matched it; "
                    f"kept {ids} as unresolved external finding(s) instead of guessing a version."
                )
                if findings is not None:
                    findings.extend(_unresolved_finding(pkg, vuln, manifest) for vuln in pkg.vulnerabilities)
            server.packages = kept
    return notices
