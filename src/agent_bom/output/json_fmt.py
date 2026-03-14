"""JSON report output format."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.models import AIBOMReport, BlastRadius


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
        for tag in br.owasp_tags:
            owasp_counts[tag] += 1
        for tag in br.atlas_tags:
            atlas_counts[tag] += 1
        for tag in br.nist_ai_rmf_tags:
            nist_counts[tag] += 1
        for tag in br.owasp_mcp_tags:
            owasp_mcp_counts[tag] += 1
        for tag in br.owasp_agentic_tags:
            owasp_agentic_counts[tag] += 1
        for tag in br.eu_ai_act_tags:
            eu_ai_act_counts[tag] += 1
        for tag in br.nist_csf_tags:
            nist_csf_counts[tag] += 1
        for tag in br.iso_27001_tags:
            iso_27001_counts[tag] += 1
        for tag in br.soc2_tags:
            soc2_counts[tag] += 1
        for tag in br.cis_tags:
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


def to_json(report: AIBOMReport) -> dict:
    """Convert report to JSON-serializable dict."""
    result = {
        "document_type": "AI-BOM",
        "spec_version": "1.0",
        "ai_bom_version": report.tool_version,
        "generated_at": report.generated_at.isoformat(),
        "scan_sources": report.scan_sources,
        "has_mcp_context": report.has_mcp_context,
        "has_agent_context": report.has_agent_context,
        "summary": {
            "total_agents": report.total_agents,
            "total_mcp_servers": report.total_servers,
            "total_packages": report.total_packages,
            "total_vulnerabilities": report.total_vulnerabilities,
            "critical_findings": len(report.critical_vulns),
        },
        "agents": [
            {
                "name": agent.name,
                "type": agent.agent_type.value,
                "config_path": agent.config_path,
                "source": agent.source,
                "status": agent.status.value,
                "mcp_servers": [
                    {
                        "name": server.name,
                        "command": server.command,
                        "args": server.args,
                        "transport": server.transport.value,
                        "url": server.url,
                        "mcp_version": server.mcp_version,
                        "has_credentials": server.has_credentials,
                        "credential_env_vars": server.credential_names,
                        "security_blocked": server.security_blocked,
                        "security_warnings": server.security_warnings,
                        "tools": [{"name": t.name, "description": t.description} for t in server.tools],
                        "packages": [
                            {
                                "name": pkg.name,
                                "version": pkg.version,
                                "ecosystem": pkg.ecosystem,
                                "purl": pkg.purl,
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
                                "vulnerabilities": [
                                    {
                                        "id": v.id,
                                        "summary": v.summary,
                                        "severity": v.severity.value,
                                        "cvss_score": v.cvss_score,
                                        "epss_score": v.epss_score,
                                        "epss_percentile": v.epss_percentile,
                                        "is_kev": v.is_kev,
                                        "kev_date_added": v.kev_date_added,
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
                "risk_score": br.risk_score,
                "vulnerability_id": br.vulnerability.id,
                "severity": br.vulnerability.severity.value,
                "cvss_score": br.vulnerability.cvss_score,
                "epss_score": br.vulnerability.epss_score,
                "is_kev": br.vulnerability.is_kev,
                "nvd_status": br.vulnerability.nvd_status,
                "compliance_tags": br.vulnerability.compliance_tags,
                "package": f"{br.package.name}@{br.package.version}",
                "ecosystem": br.package.ecosystem,
                "is_malicious": br.package.is_malicious,
                "malicious_reason": br.package.malicious_reason,
                "scorecard_score": br.package.scorecard_score,
                "affected_agents": [a.name for a in br.affected_agents],
                "affected_servers": [s.name for s in br.affected_servers],
                "exposed_credentials": br.exposed_credentials,
                "exposed_tools": [t.name for t in br.exposed_tools],
                "fixed_version": br.vulnerability.fixed_version,
                "vendor_severity": getattr(br.vulnerability, "vendor_severity", None),
                "cvss_severity": getattr(br.vulnerability, "cvss_severity", None),
                "ai_risk_context": br.ai_risk_context,
                "ai_summary": br.ai_summary,
                "owasp_tags": br.owasp_tags,
                "atlas_tags": br.atlas_tags,
                "attack_tags": getattr(br, "attack_tags", []),
                "nist_ai_rmf_tags": br.nist_ai_rmf_tags,
                "owasp_mcp_tags": br.owasp_mcp_tags,
                "owasp_agentic_tags": br.owasp_agentic_tags,
                "eu_ai_act_tags": br.eu_ai_act_tags,
                "nist_csf_tags": br.nist_csf_tags,
                "iso_27001_tags": br.iso_27001_tags,
                "soc2_tags": br.soc2_tags,
                "cis_tags": br.cis_tags,
                "hop_depth": getattr(br, "hop_depth", 1),
                "delegation_chain": getattr(br, "delegation_chain", []),
                "transitive_agents": getattr(br, "transitive_agents", []),
                "transitive_credentials": getattr(br, "transitive_credentials", []),
                "transitive_risk_score": getattr(br, "transitive_risk_score", 0.0),
            }
            for br in report.blast_radii
        ],
        "threat_framework_summary": _build_framework_summary(report.blast_radii),
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

    if report.model_provenance:
        result["model_provenance"] = report.model_provenance

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
