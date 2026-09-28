"""Vulnerability and shared-server projection over bounded per-build indexes."""

from typing import Any

from agent_bom.canonical_ids import canonical_graph_node_id, source_ids
from agent_bom.core.severity import SEVERITY_RISK_SCORE
from agent_bom.graph.build_indexes import BuildIndexes
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.package_projection import (
    _add_exploitable_via_edges,
    _blast_radius_package_evidence,
    _collect_compliance_tags,
    _package_node_id_from_parts,
    _resolve_affected_package_ids,
    _resolve_affected_server_ids,
)
from agent_bom.graph.types import EntityType, RelationshipType


def project_package_exploits(graph: UnifiedGraph, indexes: BuildIndexes, data_source_tag: str) -> None:
    for vuln_node_id, srv_id, pkg_id, package_evidence, severity in indexes.pending_exploitable_edges:
        _add_exploitable_via_edges(
            graph,
            server_to_tool_ids=indexes.server_to_tool_ids,
            vuln_node_id=vuln_node_id,
            server_id=srv_id,
            package_id=pkg_id,
            evidence=package_evidence,
            severity=severity,
            data_source=data_source_tag,
        )


def _add_blast_node(
    graph: UnifiedGraph, br_dict: dict[str, Any], vuln_node_id: str, vuln_id_str: str, severity: str, data_source_tag: str
) -> None:
    graph.add_node(
        UnifiedNode(
            id=vuln_node_id,
            entity_type=EntityType.VULNERABILITY,
            label=vuln_id_str,
            severity=severity,
            risk_score=br_dict.get("risk_score", 0),
            attributes={
                "canonical_id": canonical_graph_node_id(EntityType.VULNERABILITY.value, vuln_node_id),
                "source_ids": source_ids(vulnerability_id=vuln_id_str),
                "vulnerability_id": vuln_id_str,
                **(
                    {"finding_id": str(br_dict["finding_id"]).strip()}
                    if isinstance(br_dict.get("finding_id"), str) and str(br_dict.get("finding_id") or "").strip()
                    else {}
                ),
                "cvss_score": br_dict.get("cvss_score"),
                "cvss_vector": br_dict.get("cvss_vector"),
                "attack_vector": br_dict.get("attack_vector"),
                "attack_complexity": br_dict.get("attack_complexity"),
                "privileges_required": br_dict.get("privileges_required"),
                "user_interaction": br_dict.get("user_interaction"),
                "network_exploitable": br_dict.get("network_exploitable", False),
                "epss_score": br_dict.get("epss_score"),
                "is_kev": br_dict.get("is_kev", False),
                "fixed_version": br_dict.get("fixed_version"),
                "impact_category": br_dict.get("impact_category", ""),
                "reachability": br_dict.get("reachability", ""),
                "reachability_basis": list(br_dict.get("reachability_basis") or []),
                "graph_reachable": br_dict.get("graph_reachable"),
                "symbol_reachability": br_dict.get("symbol_reachability"),
                "symbol_reachability_reason": br_dict.get("symbol_reachability_reason"),
                "runtime_dependency_chain": list(br_dict.get("runtime_dependency_chain") or []),
                "dependency_reachable": br_dict.get("dependency_reachable"),
            },
            compliance_tags=_collect_compliance_tags(br_dict),
            data_sources=[data_source_tag],
        )
    )


def project_blast_radius(graph: UnifiedGraph, blast_data: list[dict[str, Any]], indexes: BuildIndexes, data_source_tag: str) -> None:
    for br_dict in blast_data:
        vuln_id_str = br_dict.get("vulnerability_id", "")
        if not vuln_id_str:
            continue
        severity = br_dict.get("severity", "").lower()
        pkg_name = br_dict.get("package_name", br_dict.get("package", "").split("@")[0])
        pkg_version = br_dict.get("package_version", "")
        ecosystem = br_dict.get("ecosystem", "")

        # Add/merge vuln node (add_node unions compliance_tags if node exists)
        vuln_node_id = f"vuln:{vuln_id_str}"
        _add_blast_node(graph, br_dict, vuln_node_id, vuln_id_str, severity, data_source_tag)

        # Link package → vulnerability
        if pkg_name:
            pkg_id = _package_node_id_from_parts(pkg_name, pkg_version, ecosystem, br_dict.get("package_purl") or br_dict.get("purl"))
            if graph.has_node(pkg_id):
                graph.add_edge(
                    UnifiedEdge(
                        source=pkg_id,
                        target=vuln_node_id,
                        relationship=RelationshipType.VULNERABLE_TO,
                        weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
                        evidence=_blast_radius_package_evidence(br_dict, data_source_tag),
                    )
                )

        # Link affected servers → vulnerability using indexed lookups instead
        # of an agent×server cross-product scan.
        affected_server_ids = _resolve_affected_server_ids(
            br_dict,
            pkg_name=pkg_name,
            pkg_version=pkg_version,
            ecosystem=ecosystem,
            pkg_key_to_servers=indexes.pkg_key_to_servers,
            server_name_to_agent_servers=indexes.server_name_to_agent_servers,
            agent_to_server_ids=indexes.agent_to_server_ids,
        )
        for srv_id in affected_server_ids:
            graph.add_edge(
                UnifiedEdge(
                    source=srv_id,
                    target=vuln_node_id,
                    relationship=RelationshipType.VULNERABLE_TO,
                    weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
                    evidence=_blast_radius_package_evidence(br_dict, data_source_tag),
                )
            )

        for srv_id in affected_server_ids:
            pkg_ids = _resolve_affected_package_ids(
                br_dict,
                server_id=srv_id,
                pkg_name=pkg_name,
                pkg_version=pkg_version,
                ecosystem=ecosystem,
                package_id_to_servers=indexes.package_id_to_servers,
            )
            for pkg_id in pkg_ids:
                _add_exploitable_via_edges(
                    graph,
                    server_to_tool_ids=indexes.server_to_tool_ids,
                    vuln_node_id=vuln_node_id,
                    server_id=srv_id,
                    package_id=pkg_id,
                    evidence=_blast_radius_package_evidence(br_dict, data_source_tag),
                    severity=severity,
                    data_source=data_source_tag,
                )


def project_shared_servers(graph: UnifiedGraph, indexes: BuildIndexes) -> None:
    for srv_name, agent_names in indexes.server_to_agents.items():
        unique = sorted(set(agent_names))
        if len(unique) >= 2:
            for i, a1 in enumerate(unique):
                for a2 in unique[i + 1 :]:
                    graph.add_edge(
                        UnifiedEdge(
                            source=a1,
                            target=a2,
                            relationship=RelationshipType.SHARES_SERVER,
                            direction="bidirectional",
                            weight=3.0,
                            evidence={"server": srv_name},
                        )
                    )


def enrich_blast_radius(graph: UnifiedGraph, blast_data: list[dict[str, Any]]) -> None:
    for br_dict in blast_data:
        vuln_id_str = br_dict.get("vulnerability_id", "")
        vuln_node = graph.get_node(f"vuln:{vuln_id_str}") if vuln_id_str else None
        if vuln_node:
            vuln_node.attributes["affected_agent_count"] = len(br_dict.get("affected_agents", []))
            vuln_node.attributes["affected_server_count"] = len(br_dict.get("affected_servers", []))
            vuln_node.attributes["exposed_credential_count"] = len(br_dict.get("exposed_credentials", []))
            vuln_node.attributes["exposed_tool_count"] = len(br_dict.get("exposed_tools", []))
            vuln_node.attributes["reachability"] = br_dict.get("reachability", "")
            vuln_node.attributes["reachability_basis"] = list(br_dict.get("reachability_basis") or [])
            vuln_node.attributes["graph_reachable"] = br_dict.get("graph_reachable")
            vuln_node.attributes["symbol_reachability"] = br_dict.get("symbol_reachability")
            vuln_node.attributes["symbol_reachability_reason"] = br_dict.get("symbol_reachability_reason")
            vuln_node.attributes["runtime_dependency_chain"] = list(br_dict.get("runtime_dependency_chain") or [])
            vuln_node.attributes["dependency_reachable"] = br_dict.get("dependency_reachable")
            vuln_node.attributes["actionable"] = br_dict.get("actionable", False)
