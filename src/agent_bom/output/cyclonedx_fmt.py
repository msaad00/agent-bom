"""CycloneDX 1.6 SBOM output format."""

from __future__ import annotations

import json
import re
from pathlib import Path
from uuid import uuid4

from agent_bom.models import AIBOMReport


def _sanitize_bom_ref(raw: str) -> str:
    """Sanitize a CycloneDX bom-ref to contain only valid characters.

    CycloneDX 1.6 bom-ref should match ``^[a-zA-Z0-9._-]+$``.
    Replace invalid characters (``@``, ``/``, spaces, etc.) with ``-``.
    """
    return re.sub(r"[^a-zA-Z0-9._-]", "-", raw)


def to_cyclonedx(report: AIBOMReport) -> dict:
    """Build CycloneDX 1.6 dict from report."""
    components = []
    vulnerabilities_cdx = []
    dependencies = []

    comp_id = 0
    bom_ref_map = {}

    for agent in report.agents:
        agent_ref = _sanitize_bom_ref(f"agent-{agent.name}")
        agent_deps = []

        components.append(
            {
                "type": "application",
                "bom-ref": agent_ref,
                "name": agent.name,
                "version": agent.version or "unknown",
                "description": f"AI Agent ({agent.agent_type.value})",
                "properties": [
                    {"name": "agent-bom:type", "value": "ai-agent"},
                    {"name": "agent-bom:config-path", "value": agent.config_path},
                    {"name": "agent-bom:status", "value": agent.status.value},
                ],
            }
        )

        for server in agent.mcp_servers:
            server_ref = _sanitize_bom_ref(f"mcp-server-{server.name}-{comp_id}")
            comp_id += 1
            server_deps = []

            server_props = [
                {"name": "agent-bom:type", "value": "mcp-server"},
                {"name": "agent-bom:command", "value": server.command},
                {"name": "agent-bom:transport", "value": server.transport.value},
            ]
            if server.has_credentials:
                server_props.append({"name": "agent-bom:has-credentials", "value": "true"})
            if server.tools:
                server_props.append({"name": "agent-bom:tool-count", "value": str(len(server.tools))})
                # Export each tool as a property for SBOM consumers
                for tool in server.tools:
                    tool_val = tool.name
                    if tool.description:
                        tool_val = f"{tool.name}: {tool.description[:120]}"
                    server_props.append({"name": "agent-bom:mcp-tool", "value": tool_val})

            server_component: dict = {
                "type": "application",
                "bom-ref": server_ref,
                "name": server.name,
                "description": f"MCP Server ({server.transport.value})",
                "properties": server_props,
            }
            # Add MCP tool capabilities as services (CycloneDX 1.6 services array)
            if server.tools:
                server_component["services"] = [
                    {
                        "name": tool.name,
                        "description": tool.description or "",
                    }
                    for tool in server.tools
                ]
            components.append(server_component)
            agent_deps.append(server_ref)

            for pkg in server.packages:
                pkg_ref = _sanitize_bom_ref(f"pkg-{pkg.ecosystem}-{pkg.name}-{pkg.version}-{comp_id}")
                comp_id += 1

                pkg_properties = [
                    {"name": "agent-bom:ecosystem", "value": pkg.ecosystem},
                    {"name": "agent-bom:is-direct", "value": str(pkg.is_direct).lower()},
                    {"name": "agent-bom:dependency-depth", "value": str(pkg.dependency_depth)},
                    {"name": "agent-bom:resolved-from-registry", "value": str(pkg.resolved_from_registry).lower()},
                    {"name": "agent-bom:version-source", "value": pkg.version_source},
                ]
                if pkg.parent_package:
                    pkg_properties.append({"name": "agent-bom:parent-package", "value": pkg.parent_package})
                if pkg.scorecard_score is not None:
                    pkg_properties.append({"name": "agent-bom:scorecard-score", "value": str(pkg.scorecard_score)})

                pkg_component: dict = {
                    "type": "library",
                    "bom-ref": pkg_ref,
                    "name": pkg.name,
                    "version": pkg.version,
                    "purl": pkg.purl,
                    "properties": pkg_properties,
                }
                if pkg.license_expression or pkg.license:
                    lic_val = pkg.license_expression or pkg.license or ""
                    # CycloneDX 1.6: compound expressions (AND/OR/WITH) use
                    # "expression" at the licenses array level, not "license.id".
                    # Single SPDX IDs use "license.id".
                    if any(op in lic_val for op in (" AND ", " OR ", " WITH ")):
                        pkg_component["licenses"] = [{"expression": lic_val}]
                    else:
                        pkg_component["licenses"] = [{"license": {"id": lic_val}}]
                if pkg.supplier:
                    pkg_component["supplier"] = {"name": pkg.supplier}
                if pkg.author:
                    pkg_component["author"] = pkg.author
                if pkg.description:
                    pkg_component["description"] = pkg.description
                if pkg.copyright_text:
                    pkg_component["copyright"] = pkg.copyright_text
                ext_refs = []
                if pkg.homepage:
                    ext_refs.append({"type": "website", "url": pkg.homepage})
                if pkg.repository_url:
                    ext_refs.append({"type": "vcs", "url": pkg.repository_url})
                if pkg.download_url:
                    ext_refs.append({"type": "distribution", "url": pkg.download_url})
                if ext_refs:
                    pkg_component["externalReferences"] = ext_refs
                components.append(pkg_component)
                server_deps.append(pkg_ref)
                bom_ref_map[f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"] = pkg_ref

                for vuln in pkg.vulnerabilities:
                    ratings: list[dict[str, object]] = []
                    if vuln.cvss_score:
                        ratings.append(
                            {
                                "score": vuln.cvss_score,
                                "severity": vuln.severity.value,
                                "method": "CVSSv3",
                            }
                        )
                    else:
                        ratings.append(
                            {
                                "severity": vuln.severity.value,
                            }
                        )
                    vuln_entry: dict[str, object] = {
                        "id": vuln.id,
                        "description": vuln.summary or f"See {vuln.id} for details",
                        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.id}"},
                        "ratings": ratings,
                        "affects": [{"ref": pkg_ref}],
                    }
                    if vuln.fixed_version:
                        vuln_entry["recommendation"] = f"Upgrade to {vuln.fixed_version}"
                    if vuln.vex_status:
                        _cdx_state_map = {
                            "affected": "exploitable",
                            "not_affected": "not_affected",
                            "fixed": "resolved",
                            "under_investigation": "in_triage",
                        }
                        analysis_dict: dict[str, str] = {
                            "state": _cdx_state_map.get(vuln.vex_status, "in_triage"),
                        }
                        if vuln.vex_justification:
                            analysis_dict["justification"] = vuln.vex_justification
                        vuln_entry["analysis"] = analysis_dict
                    vulnerabilities_cdx.append(vuln_entry)

            dependencies.append({"ref": server_ref, "dependsOn": server_deps})
        dependencies.append({"ref": agent_ref, "dependsOn": agent_deps})

    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{report.scan_id}" if report.scan_id else f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.generated_at.isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "agent-bom",
                        "version": report.tool_version,
                        "description": "Security scanner for AI infrastructure — from agent to runtime",
                    }
                ]
            },
            "properties": [
                {"name": "agent-bom:total-agents", "value": str(report.total_agents)},
                {"name": "agent-bom:total-mcp-servers", "value": str(report.total_servers)},
                {"name": "agent-bom:total-vulnerabilities", "value": str(report.total_vulnerabilities)},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }

    if vulnerabilities_cdx:
        cdx["vulnerabilities"] = vulnerabilities_cdx

    return cdx


def export_cyclonedx(report: AIBOMReport, output_path: str) -> None:
    """Export report as CycloneDX 1.6 JSON file."""
    cdx = to_cyclonedx(report)
    Path(output_path).write_text(json.dumps(cdx, indent=2))
