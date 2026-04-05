"""JSON report output format."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.compliance_utils import effective_blast_radius_tags
from agent_bom.models import AIBOMReport, BlastRadius, Severity


def _severity_state(severity: Severity) -> str:
    """Stable severity-state label for structured consumers."""
    return "pending" if severity == Severity.UNKNOWN else "scored"


def _severity_label(severity: Severity) -> str:
    """Human-friendly label that distinguishes advisory-only findings."""
    return "advisory" if severity == Severity.UNKNOWN else severity.value


def _risk_narrative(item: dict) -> str:
    """Build plain-text risk narrative for a remediation item."""
    vuln_id = item["vulns"][0] if item["vulns"] else "this vulnerability"
    agents = ", ".join(item["agents"][:3]) or "affected agents"
    creds = ", ".join(item["creds"][:3])
    tools = ", ".join(item["tools"][:3])

    parts = [f"If not remediated, an attacker exploiting {vuln_id}"]
    if creds:
        parts.append(f"can exfiltrate {creds}")
    parts.append(f"via {agents}")
    if tools:
        parts.append(f"through {tools}")
    return " ".join(parts) + "."


def _build_remediation_json(report: AIBOMReport) -> list[dict]:
    """Build JSON-serializable remediation plan with named assets and percentages."""
    from agent_bom.output import build_remediation_plan

    plan = build_remediation_plan(report.blast_radii)
    total_agents = report.total_agents or 1

    all_creds: set[str] = set()
    all_tools: set[str] = set()
    for br in report.blast_radii:
        all_creds.update(br.exposed_credentials)
        all_tools.update(t.name for t in br.exposed_tools)
    total_creds = len(all_creds) or 1
    total_tools = len(all_tools) or 1

    result = []
    for item in plan:
        n_agents = len(item["agents"])
        n_creds = len(item["creds"])
        n_tools = len(item["tools"])
        result.append(
            {
                "package": item["package"],
                "ecosystem": item["ecosystem"],
                "current_version": item["current"],
                "fixed_version": item["fix"],
                "severity": item["max_severity"].value,
                "is_kev": item["has_kev"],
                "impact_score": item["impact"],
                "priority": item["priority"],
                "action": item["action"],
                "reason": item.get("reason"),
                "command": item.get("command"),
                "verify_command": item.get("verify_command"),
                "vulnerabilities": item["vulns"],
                "affected_agents": item["agents"],
                "agents_pct": round(n_agents / total_agents * 100),
                "exposed_credentials": item["creds"],
                "credentials_pct": round(n_creds / total_creds * 100) if n_creds else 0,
                "reachable_tools": item["tools"],
                "tools_pct": round(n_tools / total_tools * 100) if n_tools else 0,
                "owasp_tags": item["owasp"],
                "atlas_tags": item["atlas"],
                "nist_ai_rmf_tags": item["nist"],
                "owasp_mcp_tags": item["owasp_mcp"],
                "owasp_agentic_tags": item["owasp_agentic"],
                "eu_ai_act_tags": item["eu_ai_act"],
                "nist_csf_tags": item["nist_csf"],
                "iso_27001_tags": item["iso_27001"],
                "soc2_tags": item["soc2"],
                "cis_tags": item["cis"],
                "references": item.get("references", []),
                "risk_narrative": _risk_narrative(item),
            }
        )
    return result


def _build_framework_summary(blast_radii: list[BlastRadius]) -> dict:
    """Aggregate OWASP + ATLAS tag coverage across all blast radius findings."""
    from collections import Counter

    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.cis_controls import CIS_CONTROLS
    from agent_bom.eu_ai_act import EU_AI_ACT
    from agent_bom.iso_27001 import ISO_27001
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.nist_csf import NIST_CSF
    from agent_bom.owasp import OWASP_LLM_TOP10
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10
    from agent_bom.soc2 import SOC2_TSC

    owasp_counts: Counter[str] = Counter()
    atlas_counts: Counter[str] = Counter()
    nist_counts: Counter[str] = Counter()
    owasp_mcp_counts: Counter[str] = Counter()
    owasp_agentic_counts: Counter[str] = Counter()
    eu_ai_act_counts: Counter[str] = Counter()
    nist_csf_counts: Counter[str] = Counter()
    iso_27001_counts: Counter[str] = Counter()
    soc2_counts: Counter[str] = Counter()
    cis_counts: Counter[str] = Counter()
    for br in blast_radii:
        tags = effective_blast_radius_tags(br)
        for tag in tags["owasp_tags"]:
            owasp_counts[tag] += 1
        for tag in tags["atlas_tags"]:
            atlas_counts[tag] += 1
        for tag in tags["nist_ai_rmf_tags"]:
            nist_counts[tag] += 1
        for tag in tags["owasp_mcp_tags"]:
            owasp_mcp_counts[tag] += 1
        for tag in tags["owasp_agentic_tags"]:
            owasp_agentic_counts[tag] += 1
        for tag in tags["eu_ai_act_tags"]:
            eu_ai_act_counts[tag] += 1
        for tag in tags["nist_csf_tags"]:
            nist_csf_counts[tag] += 1
        for tag in tags["iso_27001_tags"]:
            iso_27001_counts[tag] += 1
        for tag in tags["soc2_tags"]:
            soc2_counts[tag] += 1
        for tag in tags["cis_tags"]:
            cis_counts[tag] += 1

    return {
        "owasp_llm_top10": [
            {
                "code": code,
                "name": OWASP_LLM_TOP10[code],
                "findings": owasp_counts.get(code, 0),
                "triggered": code in owasp_counts,
            }
            for code in sorted(OWASP_LLM_TOP10.keys())
        ],
        "mitre_atlas": [
            {
                "technique_id": tid,
                "name": ATLAS_TECHNIQUES[tid],
                "findings": atlas_counts.get(tid, 0),
                "triggered": tid in atlas_counts,
            }
            for tid in sorted(ATLAS_TECHNIQUES.keys())
        ],
        "nist_ai_rmf": [
            {
                "subcategory_id": sid,
                "name": NIST_AI_RMF[sid],
                "findings": nist_counts.get(sid, 0),
                "triggered": sid in nist_counts,
            }
            for sid in sorted(NIST_AI_RMF.keys())
        ],
        "owasp_mcp_top10": [
            {
                "code": code,
                "name": OWASP_MCP_TOP10[code],
                "findings": owasp_mcp_counts.get(code, 0),
                "triggered": code in owasp_mcp_counts,
            }
            for code in sorted(OWASP_MCP_TOP10.keys())
        ],
        "owasp_agentic_top10": [
            {
                "code": code,
                "name": OWASP_AGENTIC_TOP10[code],
                "findings": owasp_agentic_counts.get(code, 0),
                "triggered": code in owasp_agentic_counts,
            }
            for code in sorted(OWASP_AGENTIC_TOP10.keys())
        ],
        "eu_ai_act": [
            {
                "code": code,
                "name": EU_AI_ACT[code],
                "findings": eu_ai_act_counts.get(code, 0),
                "triggered": code in eu_ai_act_counts,
            }
            for code in sorted(EU_AI_ACT.keys())
        ],
        "nist_csf": [
            {
                "code": code,
                "name": NIST_CSF[code],
                "findings": nist_csf_counts.get(code, 0),
                "triggered": code in nist_csf_counts,
            }
            for code in sorted(NIST_CSF.keys())
        ],
        "iso_27001": [
            {
                "code": code,
                "name": ISO_27001[code],
                "findings": iso_27001_counts.get(code, 0),
                "triggered": code in iso_27001_counts,
            }
            for code in sorted(ISO_27001.keys())
        ],
        "soc2_tsc": [
            {
                "code": code,
                "name": SOC2_TSC[code],
                "findings": soc2_counts.get(code, 0),
                "triggered": code in soc2_counts,
            }
            for code in sorted(SOC2_TSC.keys())
        ],
        "cis_controls": [
            {
                "code": code,
                "name": CIS_CONTROLS[code],
                "findings": cis_counts.get(code, 0),
                "triggered": code in cis_counts,
            }
            for code in sorted(CIS_CONTROLS.keys())
        ],
        "total_owasp_triggered": sum(1 for c in owasp_counts if owasp_counts[c] > 0),
        "total_atlas_triggered": sum(1 for c in atlas_counts if atlas_counts[c] > 0),
        "total_nist_triggered": sum(1 for c in nist_counts if nist_counts[c] > 0),
        "total_owasp_mcp_triggered": sum(1 for c in owasp_mcp_counts if owasp_mcp_counts[c] > 0),
        "total_owasp_agentic_triggered": sum(1 for c in owasp_agentic_counts if owasp_agentic_counts[c] > 0),
        "total_eu_ai_act_triggered": sum(1 for c in eu_ai_act_counts if eu_ai_act_counts[c] > 0),
        "total_nist_csf_triggered": sum(1 for c in nist_csf_counts if nist_csf_counts[c] > 0),
        "total_iso_27001_triggered": sum(1 for c in iso_27001_counts if iso_27001_counts[c] > 0),
        "total_soc2_triggered": sum(1 for c in soc2_counts if soc2_counts[c] > 0),
        "total_cis_triggered": sum(1 for c in cis_counts if cis_counts[c] > 0),
    }


def _build_inventory_snapshot(report: AIBOMReport) -> dict:
    """Build a deterministic inventory snapshot for diffing and BOM operations."""
    agents: list[dict] = []
    servers: dict[str, dict] = {}
    tools: dict[str, dict] = {}
    resources: dict[str, dict] = {}
    packages: dict[str, dict] = {}
    relationships: list[dict] = []

    for agent in report.agents:
        server_ids: list[str] = []
        agents.append(
            {
                "id": agent.stable_id,
                "name": agent.name,
                "type": agent.agent_type.value,
                "status": agent.status.value,
                "config_path": agent.config_path,
                "server_ids": server_ids,
            }
        )

        for server in agent.mcp_servers:
            server_ids.append(server.stable_id)
            if server.stable_id not in servers:
                servers[server.stable_id] = {
                    "id": server.stable_id,
                    "name": server.name,
                    "surface": server.surface.value,
                    "fingerprint": server.fingerprint,
                    "auth_mode": server.auth_mode,
                    "transport": server.transport.value,
                    "command": server.command,
                    "url": server.url,
                    "tool_ids": [],
                    "resource_ids": [],
                    "package_ids": [],
                }
            relationships.append({"from": agent.stable_id, "to": server.stable_id, "type": "uses"})

            for tool in server.tools:
                if tool.stable_id not in tools:
                    tools[tool.stable_id] = {
                        "id": tool.stable_id,
                        "name": tool.name,
                        "fingerprint": tool.fingerprint,
                        "description": tool.description,
                        "schema_findings": tool.schema_findings,
                        "risk_score": tool.risk_score,
                    }
                if tool.stable_id not in servers[server.stable_id]["tool_ids"]:
                    servers[server.stable_id]["tool_ids"].append(tool.stable_id)
                relationships.append({"from": server.stable_id, "to": tool.stable_id, "type": "exposes_tool"})

            for resource in server.resources:
                if resource.stable_id not in resources:
                    resources[resource.stable_id] = {
                        "id": resource.stable_id,
                        "uri": resource.uri,
                        "name": resource.name,
                        "fingerprint": resource.fingerprint,
                        "mime_type": resource.mime_type,
                        "content_findings": resource.content_findings,
                        "risk_score": resource.risk_score,
                    }
                if resource.stable_id not in servers[server.stable_id]["resource_ids"]:
                    servers[server.stable_id]["resource_ids"].append(resource.stable_id)
                relationships.append({"from": server.stable_id, "to": resource.stable_id, "type": "exposes_resource"})

            for pkg in server.packages:
                if pkg.stable_id not in packages:
                    packages[pkg.stable_id] = {
                        "id": pkg.stable_id,
                        "name": pkg.name,
                        "version": pkg.version,
                        "ecosystem": pkg.ecosystem,
                        "purl": pkg.purl,
                        "source_package": pkg.source_package,
                        "distro_name": pkg.distro_name,
                        "distro_version": pkg.distro_version,
                        "vulnerability_count": len(pkg.vulnerabilities),
                    }
                if pkg.stable_id not in servers[server.stable_id]["package_ids"]:
                    servers[server.stable_id]["package_ids"].append(pkg.stable_id)
                relationships.append({"from": server.stable_id, "to": pkg.stable_id, "type": "depends_on"})

    return {
        "summary": {
            "agents": len(agents),
            "servers": len(servers),
            "tools": len(tools),
            "resources": len(resources),
            "packages": len(packages),
            "relationships": len(relationships),
        },
        "agents": agents,
        "servers": sorted(servers.values(), key=lambda x: x["id"]),
        "tools": sorted(tools.values(), key=lambda x: x["id"]),
        "resources": sorted(resources.values(), key=lambda x: x["id"]),
        "packages": sorted(packages.values(), key=lambda x: x["id"]),
        "relationships": relationships,
    }


def _build_mcp_runtime_diff(report: AIBOMReport) -> dict | None:
    """Compare configured servers against observed/runtime evidence."""
    introspection_results = {
        item.get("server_name"): item for item in (report.introspection_data or {}).get("results", []) if item.get("server_name")
    }
    runtime_used: dict[str, set[str]] = {}
    for finding in (report.runtime_correlation or {}).get("correlated_findings", []):
        server_name = finding.get("server_name")
        tool_name = finding.get("tool_name")
        if server_name and tool_name:
            runtime_used.setdefault(server_name, set()).add(tool_name)

    if not introspection_results and not runtime_used:
        return None

    server_diffs: list[dict] = []
    for agent in report.agents:
        for server in agent.mcp_servers:
            if not server.is_mcp_surface:
                continue
            intro = introspection_results.get(server.name, {})
            observed_tools = {tool.name for tool in server.tools}
            used_tools = sorted(runtime_used.get(server.name, set()))
            server_diffs.append(
                {
                    "agent_name": agent.name,
                    "agent_stable_id": agent.stable_id,
                    "server_name": server.name,
                    "server_stable_id": server.stable_id,
                    "transport": server.transport.value,
                    "auth_mode": intro.get("auth_mode", server.auth_mode),
                    "configured_fingerprint": intro.get("configured_fingerprint", server.fingerprint),
                    "runtime_fingerprint": intro.get("runtime_fingerprint"),
                    "configured_tool_count": intro.get("configured_tool_count", len(server.tools)),
                    "observed_tool_count": intro.get("tool_count", len(server.tools)),
                    "configured_resource_count": intro.get("configured_resource_count", len(server.resources)),
                    "observed_resource_count": intro.get("resource_count", len(server.resources)),
                    "tools_added": intro.get("tools_added", []),
                    "tools_removed": intro.get("tools_removed", []),
                    "resources_added": intro.get("resources_added", []),
                    "resources_removed": intro.get("resources_removed", []),
                    "capability_risk_score": intro.get("capability_risk_score", 0.0),
                    "capability_risk_level": intro.get("capability_risk_level", "low"),
                    "capability_counts": intro.get("capability_counts", {}),
                    "capability_tools": intro.get("capability_tools", {}),
                    "dangerous_combinations": intro.get("dangerous_combinations", []),
                    "risk_justification": intro.get("risk_justification", ""),
                    "tool_risk_profiles": intro.get("tool_risk_profiles", []),
                    "tool_schema_findings": intro.get(
                        "tool_schema_findings",
                        sorted({finding for tool in server.tools for finding in tool.schema_findings}),
                    ),
                    "resource_findings": intro.get(
                        "resource_findings",
                        sorted({finding for resource in server.resources for finding in resource.content_findings}),
                    ),
                    "max_tool_risk_score": max(
                        [item.get("risk_score", 0) for item in intro.get("tool_risk_profiles", [])]
                        or [tool.risk_score for tool in server.tools]
                        or [0]
                    ),
                    "max_resource_risk_score": max((resource.risk_score for resource in server.resources), default=0),
                    "runtime_used_tools": used_tools,
                    "observed_not_used_tools": sorted(observed_tools - set(used_tools)),
                    "configured_vs_observed_changed": bool(
                        intro.get("has_drift")
                        or intro.get("configured_fingerprint")
                        and intro.get("runtime_fingerprint")
                        and intro.get("configured_fingerprint") != intro.get("runtime_fingerprint")
                    ),
                    "observed_vs_runtime_gap": bool(observed_tools - set(used_tools)),
                    "has_runtime_usage": bool(used_tools),
                }
            )

    return {
        "summary": {
            "servers_with_introspection": sum(1 for diff in server_diffs if diff["runtime_fingerprint"]),
            "servers_changed": sum(1 for diff in server_diffs if diff["configured_vs_observed_changed"]),
            "servers_with_runtime_usage": sum(1 for diff in server_diffs if diff["has_runtime_usage"]),
            "runtime_used_tools": sum(len(diff["runtime_used_tools"]) for diff in server_diffs),
        },
        "servers": server_diffs,
    }


def to_json(report: AIBOMReport) -> dict:
    """Convert report to JSON-serializable dict."""
    inventory_snapshot = _build_inventory_snapshot(report)
    mcp_runtime_diff = _build_mcp_runtime_diff(report)
    from agent_bom.scorecard import summarize_scorecard_coverage

    all_packages = [pkg for agent in report.agents for server in agent.mcp_servers for pkg in server.packages]
    result = {
        "document_type": "AI-BOM",
        "spec_version": "1.0",
        "scan_id": report.scan_id,
        "ai_bom_version": report.tool_version,
        "generated_at": report.generated_at.isoformat(),
        "scan_sources": report.scan_sources,
        "has_mcp_context": report.has_mcp_context,
        "has_agent_context": report.has_agent_context,
        "ai_bom_entities": {
            "schema_version": "1.0",
            **inventory_snapshot,
        },
        "summary": {
            "total_agents": report.total_agents,
            "total_mcp_servers": report.total_servers,
            "total_packages": report.total_packages,
            "total_vulnerabilities": report.total_vulnerabilities,
            "critical_findings": len(report.critical_vulns),
        },
        "inventory_snapshot": inventory_snapshot,
        "agents": [
            {
                "name": agent.name,
                "stable_id": agent.stable_id,
                "type": agent.agent_type.value,
                "config_path": agent.config_path,
                "source": agent.source,
                "status": agent.status.value,
                "automation_settings": agent.automation_settings,
                "mcp_servers": [
                    {
                        "name": server.name,
                        "stable_id": server.stable_id,
                        "surface": server.surface.value,
                        "fingerprint": server.fingerprint,
                        "command": server.command,
                        "args": server.args,
                        "transport": server.transport.value,
                        "url": server.url,
                        "auth_mode": server.auth_mode,
                        "mcp_version": server.mcp_version,
                        "has_credentials": server.has_credentials,
                        "credential_env_vars": server.credential_names,
                        "security_blocked": server.security_blocked,
                        "security_warnings": server.security_warnings,
                        "tools": [
                            {
                                "name": t.name,
                                "stable_id": t.stable_id,
                                "fingerprint": t.fingerprint,
                                "description": t.description,
                                "schema_findings": t.schema_findings,
                                "risk_score": t.risk_score,
                            }
                            for t in server.tools
                        ],
                        "resources": [
                            {
                                "uri": r.uri,
                                "stable_id": r.stable_id,
                                "fingerprint": r.fingerprint,
                                "name": r.name,
                                "description": r.description,
                                "mime_type": r.mime_type,
                                "content_findings": r.content_findings,
                                "risk_score": r.risk_score,
                            }
                            for r in server.resources
                        ],
                        "packages": [
                            {
                                "name": pkg.name,
                                "stable_id": pkg.stable_id,
                                "version": pkg.version,
                                "ecosystem": pkg.ecosystem,
                                "purl": pkg.purl,
                                "source_package": pkg.source_package,
                                "distro_name": pkg.distro_name,
                                "distro_version": pkg.distro_version,
                                "is_direct": pkg.is_direct,
                                "parent_package": pkg.parent_package,
                                "dependency_depth": pkg.dependency_depth,
                                "resolved_from_registry": pkg.resolved_from_registry,
                                "version_source": pkg.version_source,
                                "registry_version": pkg.registry_version,
                                "license": pkg.license,
                                "license_expression": pkg.license_expression,
                                "supplier": pkg.supplier,
                                "author": pkg.author,
                                "description": pkg.description,
                                "homepage": pkg.homepage,
                                "repository_url": pkg.repository_url,
                                "download_url": pkg.download_url,
                                "copyright_text": pkg.copyright_text,
                                "deps_dev_resolved": pkg.deps_dev_resolved,
                                "scorecard_score": pkg.scorecard_score,
                                "scorecard_checks": pkg.scorecard_checks or None,
                                "scorecard_repo": pkg.scorecard_repo,
                                "scorecard_lookup_state": pkg.scorecard_lookup_state,
                                "scorecard_lookup_reason": pkg.scorecard_lookup_reason,
                                "vulnerability_count": len(pkg.vulnerabilities),
                                "vulnerabilities": [
                                    {
                                        "id": v.id,
                                        "summary": v.summary,
                                        "severity": v.severity.value,
                                        "severity_label": _severity_label(v.severity),
                                        "severity_state": _severity_state(v.severity),
                                        "severity_source": v.severity_source,
                                        "confidence": v.confidence,
                                        "cvss_score": v.cvss_score,
                                        "epss_score": v.epss_score,
                                        "epss_percentile": v.epss_percentile,
                                        "is_kev": v.is_kev,
                                        "kev_date_added": v.kev_date_added,
                                        "kev_due_date": v.kev_due_date,
                                        "published_at": v.published_at,
                                        "modified_at": v.modified_at,
                                        "aliases": v.aliases,
                                        "exploitability": v.exploitability,
                                        "cwe_ids": v.cwe_ids,
                                        "fixed_version": v.fixed_version,
                                        "references": v.references,
                                        "nvd_published": v.nvd_published,
                                        "nvd_modified": v.nvd_modified,
                                        "nvd_status": v.nvd_status,
                                        "vex_status": v.vex_status,
                                        "vex_justification": v.vex_justification,
                                        "compliance_tags": v.compliance_tags,
                                    }
                                    for v in pkg.vulnerabilities
                                ],
                            }
                            for pkg in server.packages
                        ],
                        "permission_profile": (
                            {
                                "runs_as_root": server.permission_profile.runs_as_root,
                                "container_privileged": server.permission_profile.container_privileged,
                                "privilege_level": server.permission_profile.privilege_level,
                                "tool_permissions": server.permission_profile.tool_permissions,
                                "capabilities": server.permission_profile.capabilities,
                                "network_access": server.permission_profile.network_access,
                                "filesystem_write": server.permission_profile.filesystem_write,
                                "shell_access": server.permission_profile.shell_access,
                            }
                            if server.permission_profile
                            else None
                        ),
                    }
                    for server in agent.mcp_servers
                ],
            }
            for agent in report.agents
        ],
        "blast_radius": [
            {
                **({"package_name": br.package.name, "package_version": br.package.version, "package_stable_id": br.package.stable_id}),
                **effective_blast_radius_tags(br),
                "risk_score": br.risk_score,
                "reachability": br.reachability,
                "actionable": br.is_actionable,
                "vulnerability_id": br.vulnerability.id,
                "severity": br.vulnerability.severity.value,
                "severity_label": _severity_label(br.vulnerability.severity),
                "severity_state": _severity_state(br.vulnerability.severity),
                "cvss_score": br.vulnerability.cvss_score,
                "epss_score": br.vulnerability.epss_score,
                "is_kev": br.vulnerability.is_kev,
                "published_at": br.vulnerability.published_at,
                "modified_at": br.vulnerability.modified_at,
                "nvd_status": br.vulnerability.nvd_status,
                "compliance_tags": br.vulnerability.compliance_tags,
                "package": f"{br.package.name}@{br.package.version}",
                "ecosystem": br.package.ecosystem,
                "is_malicious": br.package.is_malicious,
                "malicious_reason": br.package.malicious_reason,
                "scorecard_score": br.package.scorecard_score,
                "scorecard_repo": br.package.scorecard_repo,
                "scorecard_lookup_state": br.package.scorecard_lookup_state,
                "affected_agents": [a.name for a in br.affected_agents],
                "affected_servers": [s.name for s in br.affected_servers],
                "exposed_credentials": br.exposed_credentials,
                "exposed_tools": [t.name for t in br.exposed_tools],
                "impact_category": getattr(br, "impact_category", "code-execution"),
                "all_server_credentials": getattr(br, "all_server_credentials", []),
                "attack_vector_summary": getattr(br, "attack_vector_summary", None),
                "fixed_version": br.vulnerability.fixed_version,
                "vendor_severity": getattr(br.vulnerability, "vendor_severity", None),
                "cvss_severity": getattr(br.vulnerability, "cvss_severity", None),
                "ai_risk_context": br.ai_risk_context,
                "ai_summary": br.ai_summary,
                "hop_depth": getattr(br, "hop_depth", 1),
                "delegation_chain": getattr(br, "delegation_chain", []),
                "transitive_agents": getattr(br, "transitive_agents", []),
                "transitive_credentials": getattr(br, "transitive_credentials", []),
                "transitive_risk_score": getattr(br, "transitive_risk_score", 0.0),
            }
            for br in report.blast_radii
        ],
        "threat_framework_summary": _build_framework_summary(report.blast_radii),
        "scorecard_summary": summarize_scorecard_coverage(all_packages).to_dict(),
        "remediation_plan": _build_remediation_json(report),
    }

    # AI enrichment fields (only when present)
    if report.executive_summary:
        result["executive_summary"] = report.executive_summary
    if report.ai_threat_chains:
        result["ai_threat_chains"] = report.ai_threat_chains
    if report.mcp_config_analysis:
        result["mcp_config_analysis"] = report.mcp_config_analysis

    # Skill security audit (only when skill files were scanned)
    if report.skill_audit_data:
        result["skill_audit"] = report.skill_audit_data

    # Trust assessment (only when skill files were scanned)
    if report.trust_assessment_data:
        result["trust_assessment"] = report.trust_assessment_data

    if report.prompt_scan_data:
        result["prompt_scan"] = report.prompt_scan_data

    if report.model_files:
        result["model_files"] = report.model_files

    if report.model_manifests:
        result["model_manifests"] = report.model_manifests

    if report.model_provenance:
        result["model_provenance"] = report.model_provenance

    if report.model_hash_verification_data:
        result["model_hash_verification"] = report.model_hash_verification_data

    if report.model_supply_chain_data:
        result["model_supply_chain"] = report.model_supply_chain_data

    if report.enforcement_data:
        result["enforcement"] = report.enforcement_data

    if report.context_graph_data:
        result["context_graph"] = report.context_graph_data

    if report.license_report:
        result["license_report"] = report.license_report

    if report.vex_data:
        result["vex"] = report.vex_data

    if report.toxic_combinations:
        result["toxic_combinations"] = report.toxic_combinations

    if report.prioritized_findings:
        result["prioritized_findings"] = report.prioritized_findings

    if report.sast_data:
        result["sast"] = report.sast_data

    if report.iac_findings_data:
        result["iac_findings"] = report.iac_findings_data

    if report.cis_benchmark_data:
        result["cis_benchmark"] = report.cis_benchmark_data

    if report.snowflake_cis_benchmark_data:
        result["snowflake_cis_benchmark"] = report.snowflake_cis_benchmark_data

    if report.azure_cis_benchmark_data:
        result["azure_cis_benchmark"] = report.azure_cis_benchmark_data

    if report.gcp_cis_benchmark_data:
        result["gcp_cis_benchmark"] = report.gcp_cis_benchmark_data

    if report.databricks_cis_benchmark_data:
        result["databricks_cis_benchmark"] = report.databricks_cis_benchmark_data

    if report.aisvs_benchmark_data:
        result["aisvs_benchmark"] = report.aisvs_benchmark_data

    if report.runtime_correlation:
        result["runtime_correlation"] = report.runtime_correlation
    if report.scan_performance_data:
        result["scan_performance"] = report.scan_performance_data
    if report.runtime_session_graph:
        result["runtime_session_graph"] = report.runtime_session_graph
    if mcp_runtime_diff:
        result["mcp_runtime_diff"] = mcp_runtime_diff

    # Training pipeline lineage + dataset cards
    if report.training_pipelines:
        result["training_pipelines"] = report.training_pipelines
    if report.dataset_cards:
        result["dataset_cards"] = report.dataset_cards
    if report.serving_configs:
        result["serving_configs"] = report.serving_configs
    if report.browser_extensions:
        result["browser_extensions"] = report.browser_extensions
    if report.ai_inventory_data:
        result["ai_inventory"] = report.ai_inventory_data
    if report.project_inventory_data:
        result["project_inventory"] = report.project_inventory_data
    if report.introspection_data:
        result["introspection"] = report.introspection_data
    if report.health_check_data:
        result["health_check"] = report.health_check_data

    if report.vector_db_scan_data:
        result["vector_db_scan"] = report.vector_db_scan_data
    if report.gpu_infra_data:
        result["gpu_infra"] = report.gpu_infra_data

    # Posture scorecard
    from agent_bom.posture import (
        compute_credential_risk_ranking,
        compute_incident_correlation,
        compute_posture_scorecard,
    )

    scorecard = compute_posture_scorecard(report)
    result["posture_scorecard"] = scorecard.to_dict()
    result["credential_risk_ranking"] = compute_credential_risk_ranking(report)
    result["incident_correlation"] = compute_incident_correlation(report)

    return result


def export_json(report: AIBOMReport, output_path: str) -> None:
    """Export report as JSON file."""
    data = to_json(report)
    Path(output_path).write_text(json.dumps(data, indent=2))
