"""SPDX 2.2 / 2.3 output formats (JSON and tag-value).

Complements the SPDX 3.0 JSON-LD emitter in ``spdx_fmt.py``. Many downstream
tools (license scanners, procurement portals, government SBOM intake) still
consume SPDX 2.x. This module emits the classic document shape:

- one ``SPDXRef-DOCUMENT`` with ``creationInfo`` and ``documentNamespace``
- agents / MCP servers / packages as SPDX ``packages``
- ``relationships`` (DESCRIBES, CONTAINS, DEPENDS_ON)
- per-package ``checksums`` when the source provides integrity digests
- vulnerabilities surfaced as package ``annotations`` (SPDX 2.x has no native
  vulnerability object)
"""

from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent_bom.checksums import spdx2_checksums
from agent_bom.models import AIBOMReport

_SUPPORTED_VERSIONS = {"2.2", "2.3"}
_NOASSERTION = "NOASSERTION"
_NONE = "NONE"


def _validate_version(version: str) -> str:
    if version not in _SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported SPDX 2.x version: {version!r} (expected one of {sorted(_SUPPORTED_VERSIONS)})")
    return version


def _created_timestamp(report: AIBOMReport) -> str:
    generated = report.generated_at
    if generated.tzinfo:
        return generated.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return generated.strftime("%Y-%m-%dT%H:%M:%SZ")


def _license_field(value: str | None) -> str:
    value = (value or "").strip()
    return value or _NOASSERTION


def _vuln_annotations(pkg: Any, created: str) -> list[dict[str, str]]:
    """Encode each vulnerability as an SPDX annotation on the package."""
    annotations: list[dict[str, str]] = []
    for vuln in pkg.vulnerabilities:
        parts = [vuln.id]
        if getattr(vuln, "severity", None) is not None:
            parts.append(f"severity={vuln.severity.value}")
        if getattr(vuln, "cvss_score", None) is not None:
            parts.append(f"cvss={vuln.cvss_score}")
        if getattr(vuln, "fixed_version", None):
            parts.append(f"fixed-in={vuln.fixed_version}")
        if getattr(vuln, "is_kev", False):
            parts.append("cisa-kev=true")
        annotations.append(
            {
                "annotationType": "OTHER",
                "annotator": "Tool: agent-bom",
                "annotationDate": created,
                "comment": "agent-bom:vulnerability " + " ".join(parts),
            }
        )
    return annotations


def to_spdx2(report: AIBOMReport, version: str = "2.3") -> dict:
    """Build an SPDX 2.2/2.3 document dict from ``report``.

    ``version`` selects ``"2.2"`` or ``"2.3"`` (affects ``spdxVersion`` only;
    the emitted shape is compatible with both).
    """
    _validate_version(version)
    created = _created_timestamp(report)

    counter = [0]

    def _next_id(prefix: str) -> str:
        counter[0] += 1
        return f"SPDXRef-{prefix}-{counter[0]}"

    spdx_packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    document_id = "SPDXRef-DOCUMENT"
    described_ids: list[str] = []
    pkg_ref_map: dict[str, str] = {}

    def _add_relationship(from_id: str, rel_type: str, to_id: str) -> None:
        relationships.append(
            {
                "spdxElementId": from_id,
                "relationshipType": rel_type,
                "relatedSpdxElement": to_id,
            }
        )

    for agent in report.agents:
        agent_id = _next_id("Agent")
        spdx_packages.append(
            {
                "SPDXID": agent_id,
                "name": agent.name,
                "versionInfo": agent.version or _NOASSERTION,
                "downloadLocation": _NOASSERTION,
                "filesAnalyzed": False,
                "licenseConcluded": _NOASSERTION,
                "licenseDeclared": _NOASSERTION,
                "copyrightText": _NOASSERTION,
                "primaryPackagePurpose": "APPLICATION",
                "comment": f"AI Agent ({agent.agent_type.value})",
            }
        )
        described_ids.append(agent_id)

        for server in agent.mcp_servers:
            server_id = _next_id("MCPServer")
            server_pkg: dict[str, Any] = {
                "SPDXID": server_id,
                "name": server.name,
                "versionInfo": server.mcp_version or _NOASSERTION,
                "downloadLocation": _NOASSERTION,
                "filesAnalyzed": False,
                "licenseConcluded": _NOASSERTION,
                "licenseDeclared": _NOASSERTION,
                "copyrightText": _NOASSERTION,
                "primaryPackagePurpose": "APPLICATION",
                "comment": f"MCP Server ({server.transport.value})",
            }
            spdx_packages.append(server_pkg)
            _add_relationship(agent_id, "CONTAINS", server_id)

            for pkg in server.packages:
                pkg_key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if pkg_key not in pkg_ref_map:
                    pkg_id = _next_id("Package")
                    pkg_ref_map[pkg_key] = pkg_id

                    declared_license = _license_field(pkg.license_expression or pkg.license)
                    pkg_entry: dict[str, Any] = {
                        "SPDXID": pkg_id,
                        "name": pkg.name,
                        "versionInfo": pkg.version or _NOASSERTION,
                        "downloadLocation": pkg.download_url or _NOASSERTION,
                        "filesAnalyzed": False,
                        "licenseConcluded": _NOASSERTION,
                        "licenseDeclared": declared_license,
                        "copyrightText": pkg.copyright_text or _NOASSERTION,
                        "primaryPackagePurpose": "LIBRARY",
                    }
                    if pkg.supplier:
                        pkg_entry["supplier"] = f"Organization: {pkg.supplier}"
                    if pkg.homepage:
                        pkg_entry["homepage"] = pkg.homepage
                    if pkg.description:
                        pkg_entry["summary"] = pkg.description[:300]
                    checksums = spdx2_checksums(pkg.checksums)
                    if checksums:
                        pkg_entry["checksums"] = checksums
                    if pkg.purl:
                        pkg_entry["externalRefs"] = [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": pkg.purl,
                            }
                        ]
                    annotations = _vuln_annotations(pkg, created)
                    if annotations:
                        pkg_entry["annotations"] = annotations
                    spdx_packages.append(pkg_entry)

                _add_relationship(server_id, "DEPENDS_ON", pkg_ref_map[pkg_key])

    for described_id in described_ids:
        _add_relationship(document_id, "DESCRIBES", described_id)

    namespace = f"https://agent-bom.dev/spdx/{report.scan_id or uuid4()}"
    document: dict[str, Any] = {
        "spdxVersion": f"SPDX-{version}",
        "dataLicense": "CC0-1.0",
        "SPDXID": document_id,
        "name": f"agent-bom-{report.generated_at.strftime('%Y%m%d-%H%M%S')}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: agent-bom-{report.tool_version}"],
        },
        "comment": (
            f"Security scan generated by agent-bom {report.tool_version}. "
            f"Covers {report.total_agents} agent(s), {report.total_servers} MCP server(s), "
            f"{report.total_packages} package(s), {report.total_vulnerabilities} vulnerability/ies."
        ),
        "packages": spdx_packages,
        "relationships": relationships,
        "documentDescribes": described_ids,
    }
    return document


def export_spdx2(report: AIBOMReport, output_path: str, version: str = "2.3") -> None:
    """Export report as an SPDX 2.x JSON file."""
    data = to_spdx2(report, version=version)
    Path(output_path).write_text(json.dumps(data, indent=2))


def to_spdx2_tagvalue(report: AIBOMReport, version: str = "2.3") -> str:
    """Render an SPDX 2.x document in tag-value (``.spdx``) format."""
    doc = to_spdx2(report, version=version)
    lines: list[str] = [
        f"SPDXVersion: {doc['spdxVersion']}",
        f"DataLicense: {doc['dataLicense']}",
        f"SPDXID: {doc['SPDXID']}",
        f"DocumentName: {doc['name']}",
        f"DocumentNamespace: {doc['documentNamespace']}",
        f"Created: {doc['creationInfo']['created']}",
    ]
    for creator in doc["creationInfo"]["creators"]:
        lines.append(f"Creator: {creator}")
    lines.append("")

    for pkg in doc["packages"]:
        lines.append(f"PackageName: {pkg['name']}")
        lines.append(f"SPDXID: {pkg['SPDXID']}")
        lines.append(f"PackageVersion: {pkg.get('versionInfo', _NOASSERTION)}")
        lines.append(f"PackageDownloadLocation: {pkg.get('downloadLocation', _NOASSERTION)}")
        lines.append(f"FilesAnalyzed: {'true' if pkg.get('filesAnalyzed') else 'false'}")
        if pkg.get("supplier"):
            lines.append(f"PackageSupplier: {pkg['supplier']}")
        lines.append(f"PackageLicenseConcluded: {pkg.get('licenseConcluded', _NOASSERTION)}")
        lines.append(f"PackageLicenseDeclared: {pkg.get('licenseDeclared', _NOASSERTION)}")
        lines.append(f"PackageCopyrightText: {pkg.get('copyrightText', _NOASSERTION)}")
        for checksum in pkg.get("checksums", []):
            lines.append(f"PackageChecksum: {checksum['algorithm']}: {checksum['checksumValue']}")
        for ext in pkg.get("externalRefs", []):
            lines.append(
                f"ExternalRef: {ext['referenceCategory']} {ext['referenceType']} {ext['referenceLocator']}"
            )
        for annotation in pkg.get("annotations", []):
            lines.append(f"PackageComment: {annotation['comment']}")
        lines.append("")

    for rel in doc["relationships"]:
        lines.append(f"Relationship: {rel['spdxElementId']} {rel['relationshipType']} {rel['relatedSpdxElement']}")

    return "\n".join(lines) + "\n"


def export_spdx2_tagvalue(report: AIBOMReport, output_path: str, version: str = "2.3") -> None:
    """Export report as an SPDX 2.x tag-value file."""
    Path(output_path).write_text(to_spdx2_tagvalue(report, version=version))
