"""SPDX 3.0 (JSON-LD) output format."""

from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import Any

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.models import AIBOMReport


def to_spdx(report: AIBOMReport) -> dict:
    """Build an SPDX 3.0 (JSON-LD) dict from report.

    Follows the SPDX 3.0 AI BOM profile where applicable:
    - Each agent becomes an /AI element
    - Each package becomes a /Package element
    - Vulnerabilities become /security/VulnAssessmentRelationship elements
    - Dependency edges become DEPENDS_ON relationships
    """
    spdx_id_counter = [0]

    def _next_id(prefix: str = "SPDXRef") -> str:
        spdx_id_counter[0] += 1
        return f"{prefix}-{spdx_id_counter[0]}"

    elements: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    document_id = _next_id("SPDXRef-DOCUMENT")

    creation_info = {
        "specVersion": "3.0.0",
        "created": report.generated_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if report.generated_at.tzinfo
        else report.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ") + "Z",
        "createdBy": [
            {
                "type": "Tool",
                "name": f"agent-bom {report.tool_version}",
                "externalIdentifier": [
                    {
                        "type": "PackageURL",
                        "identifier": f"pkg:pypi/agent-bom@{report.tool_version}",
                    }
                ],
            }
        ],
    }

    pkg_ref_map: dict[str, str] = {}

    for agent in report.agents:
        agent_id = _next_id("SPDXRef-Agent")

        agent_element: dict[str, Any] = {
            "type": "SOFTWARE_PACKAGE",
            "spdxId": agent_id,
            "name": agent.name,
            "primaryPurpose": "APPLICATION",
            "description": f"AI Agent ({agent.agent_type.value})",
            "annotation": [
                {
                    "type": "Annotation",
                    "annotationType": "OTHER",
                    "subject": agent_id,
                    "statement": f"agent-bom:ai-agent-type={agent.agent_type.value}",
                }
            ],
        }
        if agent.config_path:
            agent_element["comment"] = f"config_path: {agent.config_path}, status: {agent.status.value}"
        if agent.source:
            agent_element["originatedBy"] = agent.source
        elements.append(agent_element)

        for server in agent.mcp_servers:
            server_id = _next_id("SPDXRef-MCPServer")

            server_desc = f"MCP Server ({server.transport.value})"
            if server.tools:
                server_desc += f" — {len(server.tools)} tool(s): {', '.join(t.name for t in server.tools[:10])}"
                if len(server.tools) > 10:
                    server_desc += f" (+{len(server.tools) - 10} more)"
            server_element: dict[str, Any] = {
                "type": "SOFTWARE_PACKAGE",
                "spdxId": server_id,
                "name": server.name,
                "primaryPurpose": "APPLICATION",
                "description": server_desc,
            }
            if server.mcp_version:
                server_element["versionInfo"] = server.mcp_version
            # Export MCP tool capabilities as annotations
            if server.tools:
                server_element["annotation"] = [
                    {
                        "type": "Annotation",
                        "annotationType": "OTHER",
                        "subject": server_id,
                        "statement": f"agent-bom:mcp-tool={tool.name}" + (f": {tool.description[:120]}" if tool.description else ""),
                    }
                    for tool in server.tools
                ]
            elements.append(server_element)

            relationships.append(
                {
                    "type": "Relationship",
                    "spdxId": _next_id("SPDXRef-Rel"),
                    "relationshipType": "CONTAINS",
                    "from": agent_id,
                    "to": [server_id],
                }
            )

            for pkg in server.packages:
                pkg_key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if pkg_key not in pkg_ref_map:
                    pkg_id = _next_id("SPDXRef-Pkg")
                    pkg_ref_map[pkg_key] = pkg_id

                    pkg_element: dict[str, object] = {
                        "type": "SOFTWARE_PACKAGE",
                        "spdxId": pkg_id,
                        "name": pkg.name,
                        "versionInfo": pkg.version,
                        "primaryPurpose": "LIBRARY",
                    }
                    version_provenance = package_version_provenance(pkg)
                    pkg_element["annotation"] = [
                        {
                            "type": "Annotation",
                            "annotationType": "OTHER",
                            "subject": pkg_id,
                            "statement": f"agent-bom:version-provenance-source={version_provenance.get('version_source', 'unknown')}",
                        },
                        {
                            "type": "Annotation",
                            "annotationType": "OTHER",
                            "subject": pkg_id,
                            "statement": f"agent-bom:version-provenance-confidence={version_provenance.get('confidence', 'unknown')}",
                        },
                    ]
                    if pkg.purl:
                        pkg_element["externalIdentifier"] = [{"type": "PackageURL", "identifier": pkg.purl}]
                    if pkg.license_expression or pkg.license:
                        pkg_element["declaredLicense"] = pkg.license_expression or pkg.license
                    if pkg.supplier:
                        pkg_element["supplier"] = pkg.supplier
                    if pkg.description:
                        pkg_element["description"] = pkg.description[:300]
                    if pkg.homepage:
                        pkg_element["homepage"] = pkg.homepage
                    if pkg.download_url:
                        pkg_element["downloadLocation"] = pkg.download_url
                    if pkg.copyright_text:
                        pkg_element["copyrightText"] = pkg.copyright_text
                    elements.append(pkg_element)

                pkg_id = pkg_ref_map[pkg_key]
                relationships.append(
                    {
                        "type": "Relationship",
                        "spdxId": _next_id("SPDXRef-Rel"),
                        "relationshipType": "DEPENDS_ON",
                        "from": server_id,
                        "to": [pkg_id],
                    }
                )

                for vuln in pkg.vulnerabilities:
                    vuln_element_id = _next_id("SPDXRef-Vuln")
                    vuln_element: dict[str, object] = {
                        "type": "security/Vulnerability",
                        "spdxId": vuln_element_id,
                        "name": vuln.id,
                        "description": vuln.summary or "",
                        "externalIdentifier": [{"type": "cve", "identifier": vuln.id}] if vuln.id.startswith("CVE-") else [],
                    }
                    if vuln.cvss_score is not None:
                        vuln_element["assessedElement"] = pkg_id
                        vuln_element["score"] = {
                            "method": "CVSS_3",
                            "score": vuln.cvss_score,
                            "severity": vuln.severity.value,
                        }
                    elements.append(vuln_element)

                    assessment_id = _next_id("SPDXRef-VulnAssessment")
                    assessment = {
                        "type": "security/VulnAssessmentRelationship",
                        "spdxId": assessment_id,
                        "relationshipType": "AFFECTS",
                        "from": vuln_element_id,
                        "to": [pkg_id],
                        "severity": vuln.severity.value,
                    }
                    if vuln.fixed_version:
                        assessment["remediation"] = f"Upgrade to {vuln.fixed_version}"
                    if vuln.is_kev:
                        assessment["comment"] = "CISA KEV: actively exploited in the wild"
                    relationships.append(assessment)

    return {
        "spdxVersion": "SPDX-3.0",
        "dataLicense": "CC0-1.0",
        "SPDXID": document_id,
        "name": f"agent-bom-{report.generated_at.strftime('%Y%m%d-%H%M%S')}",
        "creationInfo": creation_info,
        "elements": elements,
        "relationships": relationships,
        "comment": (
            f"Security scan generated by agent-bom {report.tool_version}. "
            f"Covers {report.total_agents} agent(s), {report.total_servers} MCP server(s), "
            f"{report.total_packages} package(s), {report.total_vulnerabilities} vulnerability/ies."
        ),
    }


def export_spdx(report: AIBOMReport, output_path: str) -> None:
    """Export report as SPDX 3.0 JSON-LD file."""
    data = to_spdx(report)
    Path(output_path).write_text(json.dumps(data, indent=2))
