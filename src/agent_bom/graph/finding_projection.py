"""Static scan and toxic-combination findings projected without unrelated report data."""

from __future__ import annotations

from pathlib import PurePath
from typing import Any

from agent_bom.graph.build_indexes import BuildIndexes
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode, stable_node_id
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text


def project_secret_findings(graph: UnifiedGraph, findings: Any) -> None:
    """Project canonical secret/PII findings without copying matched material.

    Finding IDs identify report occurrences, not globally shared credentials.
    No stable/canonical attribute is assigned: correlation must keep these
    observations snapshot-scoped until exact cross-scan ownership is known.
    The repository overlay supplies recorded finding-to-file relationships.
    """
    if not isinstance(findings, list):
        return
    for row in findings:
        if not isinstance(row, dict) or row.get("source") != "SECRET_SCAN":
            continue
        finding_type = row.get("finding_type")
        finding_id = row.get("id")
        if finding_type not in {"PII_EXPOSURE", "CREDENTIAL_EXPOSURE"} or not isinstance(finding_id, str) or not finding_id:
            continue
        raw_evidence, raw_asset = row.get("evidence"), row.get("asset")
        evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
        asset = raw_asset if isinstance(raw_asset, dict) else {}
        path = evidence.get("file") or asset.get("location") or ""
        attributes = {
            "finding_id": finding_id,
            "finding_type": finding_type,
            "finding_source": "SECRET_SCAN",
            "file_path": sanitize_text(path, max_len=500) if isinstance(path, str) else "",
            "line": evidence.get("line") if isinstance(evidence.get("line"), int) else None,
        }
        graph.add_node(
            UnifiedNode(
                id=f"misconfig:secret_scan:{finding_id}",
                entity_type=EntityType.MISCONFIGURATION,
                label=sanitize_text(str(row.get("title") or finding_type), max_len=500),
                severity=str(row.get("severity") or "medium").lower(),
                attributes=attributes,
                data_sources=["secret-scan"],
            )
        )


def project_sast(graph: UnifiedGraph, sast_data: dict[str, Any] | None) -> None:
    if sast_data:
        for finding in sast_data.get("findings", []):
            rule_id = finding.get("rule_id", "unknown")
            finding_path = finding.get("file_path") or finding.get("path", "")
            finding_line = finding.get("start_line") or finding.get("line", 0)
            cwe_ids = list(finding.get("cwe_ids", []))
            owasp_ids = list(finding.get("owasp_ids", []))
            sast_id = f"misconfig:sast:{rule_id}:{finding_path}:{finding_line}"
            graph.add_node(
                UnifiedNode(
                    id=sast_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=finding.get("message", rule_id or "SAST finding"),
                    severity=finding.get("severity", "medium").lower(),
                    attributes={
                        "rule_id": rule_id,
                        "path": finding_path,
                        "file_path": finding_path,
                        "line": finding_line,
                        "start_line": finding.get("start_line", finding_line),
                        "end_line": finding.get("end_line", finding_line),
                        "cwe_ids": cwe_ids,
                        "owasp_ids": owasp_ids,
                        "rule_url": finding.get("rule_url", ""),
                    },
                    compliance_tags=sorted(set(cwe_ids + owasp_ids)),
                    data_sources=["sast"],
                )
            )


def project_iac(graph: UnifiedGraph, iac_data: dict[str, Any] | None) -> None:
    if iac_data:
        for finding in iac_data.get("findings", []):
            rule_id = finding.get("rule_id", "unknown")
            finding_path = finding.get("file_path", "") or "unknown"
            finding_line = finding.get("line_number", 0) or 0
            category = str(finding.get("category", "iac") or "iac").lower()
            compliance = list(finding.get("compliance", []))
            attack_techniques = list(finding.get("attack_techniques", []))
            remediation = finding.get("remediation", "")
            iac_id = f"misconfig:iac:{rule_id}:{finding_path}:{finding_line}"
            target_id = f"iac_target:{category}:{finding_path}"

            graph.add_node(
                UnifiedNode(
                    id=iac_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=finding.get("title", rule_id or "IaC finding"),
                    severity=finding.get("severity", "medium").lower(),
                    attributes={
                        "rule_id": rule_id,
                        "file_path": finding_path,
                        "line_number": finding_line,
                        "category": category,
                        "message": finding.get("message", ""),
                        "remediation": remediation,
                    },
                    compliance_tags=sorted(set(compliance + attack_techniques)),
                    data_sources=sorted(set(["iac", category])),
                )
            )
            graph.add_node(
                UnifiedNode(
                    id=target_id,
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=finding_path,
                    attributes={
                        "file_path": finding_path,
                        "category": category,
                        "target_type": "iac_file",
                    },
                    data_sources=sorted(set(["iac", category])),
                )
            )
            graph.add_edge(
                UnifiedEdge(
                    source=iac_id,
                    target=target_id,
                    relationship=RelationshipType.AFFECTS,
                )
            )


def project_skill_audit(graph: UnifiedGraph, skill_audit: dict[str, Any] | None, indexes: BuildIndexes) -> None:
    if skill_audit:
        for index, finding in enumerate(skill_audit.get("findings", []), start=1):
            category = str(finding.get("category", "skill_audit") or "skill_audit").lower()
            package_name = str(finding.get("package", "") or "").strip()
            server_name = str(finding.get("server", "") or "").strip()
            source_file = str(finding.get("source_file", "") or "").strip()
            finding_id = f"misconfig:skill_audit:{category}:{index}"
            graph.add_node(
                UnifiedNode(
                    id=finding_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=str(finding.get("title", "") or category or "Skill audit finding"),
                    severity=str(finding.get("severity", "medium") or "medium").lower(),
                    attributes={
                        "category": category,
                        "detail": finding.get("detail", ""),
                        "source_file": source_file,
                        "package": package_name,
                        "server": server_name,
                        "recommendation": finding.get("recommendation", ""),
                        "context": finding.get("context", ""),
                        "ai_analysis": finding.get("ai_analysis"),
                        "ai_adjusted_severity": finding.get("ai_adjusted_severity"),
                    },
                    compliance_tags=[f"skill_audit:{category}"],
                    data_sources=["skill-audit"],
                )
            )
            for target_id in _resolve_skill_audit_target_ids(
                finding,
                package_name_to_ids=indexes.package_name_to_ids,
                server_name_to_ids=indexes.server_name_to_ids,
                agent_name_to_ids=indexes.agent_name_to_ids,
                agent_config_path_to_id=indexes.agent_config_path_to_id,
            ):
                graph.add_edge(
                    UnifiedEdge(
                        source=finding_id,
                        target=target_id,
                        relationship=RelationshipType.AFFECTS,
                    )
                )


def project_toxic_combinations(graph: UnifiedGraph, toxic_data: list[dict[str, Any]] | dict[str, Any] | None) -> None:
    if toxic_data:
        for combo in toxic_data if isinstance(toxic_data, list) else toxic_data.get("combinations", []):
            components = combo.get("components", []) if isinstance(combo.get("components", []), list) else []
            component_vulns = [
                str(component.get("id", "")).strip()
                for component in components
                if str(component.get("type", "")).lower() in {"cve", "vulnerability"} and str(component.get("id", "")).strip()
            ]
            combo_vulns = combo.get("vulnerability_ids", combo.get("vulns", component_vulns))
            if not isinstance(combo_vulns, list):
                combo_vulns = [combo_vulns]
            combo_vulns = [str(vuln_id).strip() for vuln_id in combo_vulns if str(vuln_id).strip()]
            combo_label = combo.get("label") or combo.get("title") or combo.get("name") or combo.get("pattern") or "toxic_combo"
            combo_key = combo.get("id") or combo.get("name") or combo.get("label")
            if not combo_key:
                combo_key = stable_node_id("toxic-combination", str(combo.get("pattern", "")), str(combo_label))[:12]
            toxic_node_id = f"toxic:{combo_key}"
            graph.add_node(
                UnifiedNode(
                    id=toxic_node_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=combo_label,
                    severity=str(combo.get("severity", "") or ""),
                    risk_score=float(combo.get("risk_score", 0) or 0),
                    attributes={
                        "combo": combo_key,
                        "pattern": combo.get("pattern", ""),
                        "title": combo.get("title", combo_label),
                        "description": combo.get("description", ""),
                        "components": components,
                        "remediation": combo.get("remediation", ""),
                        "risk_score": combo.get("risk_score", 0),
                        "vulnerability_ids": combo_vulns,
                    },
                    data_sources=["toxic-combinations"],
                )
            )
            for vuln_id in combo_vulns:
                vuln_node_id = f"vuln:{vuln_id}"
                if graph.has_node(vuln_node_id):
                    graph.add_edge(
                        UnifiedEdge(
                            source=vuln_node_id,
                            target=toxic_node_id,
                            relationship=RelationshipType.TRIGGERS,
                            evidence={
                                "combo": combo_key,
                                "pattern": combo.get("pattern", ""),
                                "title": combo.get("title", combo_label),
                                "risk": combo.get("risk_score", 0),
                                "remediation": combo.get("remediation", ""),
                            },
                        )
                    )


def _resolve_skill_audit_target_ids(
    finding: dict[str, Any],
    *,
    package_name_to_ids: dict[str, list[str]],
    server_name_to_ids: dict[str, list[str]],
    agent_name_to_ids: dict[str, list[str]],
    agent_config_path_to_id: dict[str, str],
) -> list[str]:
    """Resolve graph target IDs for a serialized skill-audit finding."""
    target_ids: set[str] = set()

    package_name = str(finding.get("package", "") or "").strip()
    if package_name:
        target_ids.update(package_name_to_ids.get(package_name, []))

    server_name = str(finding.get("server", "") or "").strip()
    if server_name:
        target_ids.update(server_name_to_ids.get(server_name, []))

    source_file = str(finding.get("source_file", "") or "").strip()
    if source_file:
        if source_file in agent_config_path_to_id:
            target_ids.add(agent_config_path_to_id[source_file])
        elif source_file == PurePath(source_file).name:
            # Legacy basename-only evidence may identify an owner only when the
            # name has one match. A qualified source must never cross scopes by
            # dropping its directory, even when its exact path is unknown.
            candidates = {
                agent_id for config_path, agent_id in agent_config_path_to_id.items() if source_file == PurePath(config_path).name
            }
            if len(candidates) == 1:
                target_ids.update(candidates)

    if not target_ids and not source_file:
        # One display-name bucket can still contain distinct agent occurrences.
        candidates = {agent_id for agent_ids in agent_name_to_ids.values() for agent_id in agent_ids}
        if len(candidates) == 1:
            target_ids.update(candidates)

    return sorted(target_ids)
