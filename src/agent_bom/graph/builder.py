"""Unified graph builder from serialized AIBOM report data.

This ingests the JSON contract emitted by ``output.json_fmt.to_json()``
and builds the core inventory, finding, runtime, and compliance entities
used for current-state views, traversal, attack paths, and temporal diffs.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Mapping
from pathlib import PurePath
from typing import Any

from agent_bom.api.tracing import get_tracer
from agent_bom.asset_provenance import package_version_provenance, sanitize_discovery_provenance
from agent_bom.canonical_ids import canonical_agent_id, canonical_graph_node_id, source_ids
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode, stable_node_id
from agent_bom.graph.severity import SEVERITY_RISK_SCORE
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.package_utils import canonical_package_key, normalize_package_name
from agent_bom.risk_analyzer import ToolCapability, classify_tool
from agent_bom.runtime.incident_feedback import (
    RuntimeIncidentRecord,
    incident_attribute,
    iter_observed_targets,
    load_incident_records,
    merge_records,
)
from agent_bom.security import sanitize_security_warnings, sanitize_sensitive_payload, sanitize_text, sanitize_url

try:
    from agent_bom.constants import is_credential_key as _is_credential_key
except ImportError:  # pragma: no cover

    def _is_credential_key(name: str) -> bool:
        low = name.lower()
        return any(p in low for p in ("key", "token", "secret", "password", "auth"))


_GRAPH_TRACER = get_tracer("agent_bom.graph")
_logger = logging.getLogger(__name__)


def build_unified_graph_from_report(
    report_json: dict[str, Any],
    *,
    scan_id: str = "",
    tenant_id: str = "",
) -> UnifiedGraph:
    """Build a UnifiedGraph from the persisted AIBOM report JSON contract.

    Args:
        report_json: The dict produced by ``output.json_fmt.to_json(report)``.
        scan_id: Scan identifier (defaults to report's scan_id).
        tenant_id: Multi-tenant isolation key.

    Returns:
        A fully populated :class:`UnifiedGraph`.
    """
    span = _GRAPH_TRACER.start_span("graph.build_unified_graph_from_report") if _GRAPH_TRACER else None
    sid = scan_id or report_json.get("scan_id", "")
    graph = UnifiedGraph(scan_id=sid, tenant_id=tenant_id)

    agents_data = report_json.get("agents", [])
    blast_data = report_json.get("blast_radius", report_json.get("blast_radii", []))
    scan_sources = report_json.get("scan_sources", [])
    data_source_tag = scan_sources[0] if scan_sources else "mcp-scan"

    # Track shared resources for lateral movement edges
    server_to_agents: dict[str, list[str]] = defaultdict(list)
    cred_to_agents: dict[str, list[str]] = defaultdict(list)
    # Track server/package indexes for vuln edges
    pkg_key_to_servers: dict[str, list[str]] = defaultdict(list)
    package_name_to_ids: dict[str, list[str]] = defaultdict(list)
    server_name_to_ids: dict[str, list[str]] = defaultdict(list)
    agent_name_to_ids: dict[str, list[str]] = defaultdict(list)
    server_name_to_agent_servers: dict[str, dict[str, str]] = defaultdict(dict)
    agent_to_server_ids: dict[str, set[str]] = defaultdict(set)
    agent_config_path_to_id: dict[str, str] = {}
    server_to_tool_ids: dict[str, list[str]] = defaultdict(list)
    package_id_to_servers: dict[str, list[str]] = defaultdict(list)
    pending_exploitable_edges: list[tuple[str, str, str, dict[str, Any], str]] = []

    # ── Agents → Servers → Packages → Tools → Credentials ───────────
    for agent_dict in agents_data:
        agent_name = agent_dict.get("name", "unknown")
        agent_scope = _agent_identity_scope(agent_dict)
        agent_id = _agent_node_id(agent_name, agent_scope)
        agent_node_key = agent_id.removeprefix("agent:")
        agent_type = agent_dict.get("type", agent_dict.get("agent_type", ""))
        provider_name = str(agent_dict.get("source") or "local").strip() or "local"
        provider_id = f"provider:{provider_name}"
        agent_metadata = agent_dict.get("metadata", {})
        if not isinstance(agent_metadata, dict):
            agent_metadata = {}
        agent_discovery_provenance = sanitize_discovery_provenance(agent_dict.get("discovery_provenance"))

        graph.add_node(
            UnifiedNode(
                id=provider_id,
                entity_type=EntityType.PROVIDER,
                label=provider_name,
                attributes={
                    "provider": provider_name,
                    "canonical_id": canonical_graph_node_id(EntityType.PROVIDER.value, provider_id),
                },
                data_sources=[data_source_tag],
            )
        )

        graph.add_node(
            UnifiedNode(
                id=agent_id,
                entity_type=EntityType.AGENT,
                label=agent_name,
                first_seen=str(agent_dict.get("discovered_at") or ""),
                last_seen=str(agent_dict.get("last_seen") or agent_dict.get("discovered_at") or ""),
                attributes={
                    "agent_type": agent_type,
                    "canonical_id": agent_dict.get("canonical_id")
                    or (
                        canonical_agent_id(agent_type, agent_name, source_id=agent_scope)
                        if agent_scope
                        else agent_dict.get("stable_id") or canonical_agent_id(agent_type, agent_name)
                    ),
                    "source_ids": source_ids(source_id=agent_scope, stable_id=agent_dict.get("stable_id")),
                    "status": agent_dict.get("status", ""),
                    "stable_id": agent_dict.get("stable_id", ""),
                    "config_path": agent_dict.get("config_path", ""),
                    "source": provider_name,
                    "source_id": agent_scope,
                    "enrollment_name": agent_dict.get("enrollment_name", ""),
                    "owner": agent_dict.get("owner", ""),
                    "environment": agent_dict.get("environment", ""),
                    "mdm_provider": agent_dict.get("mdm_provider", ""),
                    "tags": agent_dict.get("tags", []),
                    "discovered_at": agent_dict.get("discovered_at"),
                    "last_seen": agent_dict.get("last_seen"),
                    "server_count": len(agent_dict.get("mcp_servers", [])),
                    "discovery_provenance": agent_discovery_provenance,
                    "cloud_origin": agent_metadata.get("cloud_origin"),
                    "cloud_state": agent_metadata.get("cloud_state"),
                    "cloud_scope": agent_metadata.get("cloud_scope"),
                    "cloud_principal": agent_metadata.get("cloud_principal"),
                },
                dimensions=NodeDimensions(agent_type=agent_type),
                data_sources=[data_source_tag],
            )
        )
        agent_name_to_ids[agent_name].append(agent_id)
        config_path = str(agent_dict.get("config_path", "") or "").strip()
        if config_path:
            agent_config_path_to_id[config_path] = agent_id
        graph.add_edge(
            UnifiedEdge(
                source=provider_id,
                target=agent_id,
                relationship=RelationshipType.HOSTS,
            )
        )
        _add_agent_cloud_lineage(
            graph,
            agent_id=agent_id,
            agent_dict=agent_dict,
            agent_metadata=agent_metadata,
            data_source=data_source_tag,
        )

        for srv_dict in agent_dict.get("mcp_servers", []):
            srv_name = srv_dict.get("name", "unknown")
            srv_id = f"server:{agent_node_key}:{srv_name}"
            surface = srv_dict.get("surface", "mcp-server")

            graph.add_node(
                UnifiedNode(
                    id=srv_id,
                    entity_type=EntityType.SERVER,
                    label=srv_name,
                    attributes={
                        "command": sanitize_text(srv_dict.get("command", "")),
                        "transport": srv_dict.get("transport", ""),
                        "url": sanitize_url(str(srv_dict.get("url") or "")) or "",
                        "auth_mode": srv_dict.get("auth_mode", ""),
                        "mcp_version": srv_dict.get("mcp_version", ""),
                        "has_credentials": srv_dict.get("has_credentials", False),
                        "security_blocked": srv_dict.get("security_blocked", False),
                        "security_warnings": sanitize_security_warnings(list(srv_dict.get("security_warnings", []) or [])),
                        "security_intelligence": [
                            sanitize_security_intelligence_entry(item)
                            for item in (srv_dict.get("security_intelligence", []) or [])
                            if isinstance(item, dict)
                        ],
                        "security_intelligence_count": len(srv_dict.get("security_intelligence", []) or []),
                        "agent": agent_name,
                        "canonical_id": srv_dict.get("canonical_id")
                        or srv_dict.get("stable_id")
                        or canonical_graph_node_id(EntityType.SERVER.value, srv_id),
                        "source_ids": source_ids(stable_id=srv_dict.get("stable_id"), registry_id=srv_dict.get("registry_id")),
                        "stable_id": srv_dict.get("stable_id", ""),
                        "fingerprint": srv_dict.get("fingerprint", ""),
                    },
                    dimensions=NodeDimensions(surface=surface),
                    data_sources=[data_source_tag],
                )
            )
            server_name_to_ids[srv_name].append(srv_id)
            graph.add_edge(
                UnifiedEdge(
                    source=agent_id,
                    target=srv_id,
                    relationship=RelationshipType.USES,
                )
            )
            server_to_agents[srv_name].append(agent_id)
            server_name_to_agent_servers[srv_name][agent_id] = srv_id
            agent_to_server_ids[agent_name].add(srv_id)
            if agent_scope:
                agent_to_server_ids[agent_scope].add(srv_id)
                agent_to_server_ids[f"{agent_scope}:{agent_name}"].add(srv_id)

            # ── Packages ──
            for pkg_dict in srv_dict.get("packages", []):
                pkg_name = pkg_dict.get("name", "unknown")
                pkg_version = pkg_dict.get("version", "")
                ecosystem = pkg_dict.get("ecosystem", "")
                pkg_id = _package_node_id(pkg_dict)
                package_evidence = _package_evidence(pkg_dict, data_source_tag)
                package_discovery_provenance = sanitize_discovery_provenance(pkg_dict.get("discovery_provenance"))
                package_version_provenance = _package_version_provenance_from_dict(pkg_dict)

                graph.add_node(
                    UnifiedNode(
                        id=pkg_id,
                        entity_type=EntityType.PACKAGE,
                        label=f"{pkg_name}@{pkg_version}" if pkg_version else pkg_name,
                        attributes={
                            "version": pkg_version,
                            "ecosystem": ecosystem,
                            "purl": pkg_dict.get("purl", ""),
                            "canonical_id": pkg_dict.get("canonical_id")
                            or pkg_dict.get("stable_id")
                            or canonical_graph_node_id(EntityType.PACKAGE.value, pkg_id),
                            "source_ids": source_ids(stable_id=pkg_dict.get("stable_id"), purl=pkg_dict.get("purl")),
                            "is_direct": pkg_dict.get("is_direct", True),
                            "parent_package": pkg_dict.get("parent_package", ""),
                            "dependency_depth": pkg_dict.get("dependency_depth", 0),
                            "license": pkg_dict.get("license", ""),
                            "scorecard_score": pkg_dict.get("scorecard_score"),
                            "is_malicious": pkg_dict.get("is_malicious", False),
                            "stable_id": pkg_dict.get("stable_id", ""),
                            "discovery_provenance": package_discovery_provenance,
                            "version_provenance": package_version_provenance,
                        },
                        dimensions=NodeDimensions(ecosystem=ecosystem),
                        data_sources=[data_source_tag],
                    )
                )
                package_name_to_ids[pkg_name].append(pkg_id)
                normalized_pkg_name = normalize_package_name(pkg_name, ecosystem)
                if normalized_pkg_name != pkg_name:
                    package_name_to_ids[normalized_pkg_name].append(pkg_id)
                graph.add_edge(
                    UnifiedEdge(
                        source=srv_id,
                        target=pkg_id,
                        relationship=RelationshipType.DEPENDS_ON,
                        evidence=package_evidence,
                    )
                )
                package_id_to_servers[pkg_id].append(srv_id)
                pkg_key = _package_graph_key(pkg_name, pkg_version, ecosystem, pkg_dict.get("purl"))
                pkg_key_to_servers[pkg_key].append(srv_id)

                # ── Package-level vulnerabilities ──
                for vuln_dict in pkg_dict.get("vulnerabilities", []):
                    vuln_node_id = _add_vuln_node(graph, vuln_dict, pkg_id, data_source_tag, package_evidence)
                    if vuln_node_id:
                        pending_exploitable_edges.append(
                            (
                                vuln_node_id,
                                srv_id,
                                pkg_id,
                                package_evidence,
                                str(vuln_dict.get("severity", "") or "").lower(),
                            )
                        )

            # ── Tools ──
            tool_ids: list[str] = []
            for tool_dict in srv_dict.get("tools", []):
                tool_name = tool_dict.get("name", "unknown")
                tool_id = f"tool:{srv_id}:{tool_name}"
                tool_ids.append(tool_id)
                capabilities, capability_source = _tool_capabilities(tool_dict)
                graph.add_node(
                    UnifiedNode(
                        id=tool_id,
                        entity_type=EntityType.TOOL,
                        label=tool_name,
                        attributes={
                            "description": tool_dict.get("description", ""),
                            "canonical_id": tool_dict.get("canonical_id")
                            or tool_dict.get("stable_id")
                            or canonical_graph_node_id(EntityType.TOOL.value, tool_id),
                            "source_ids": source_ids(stable_id=tool_dict.get("stable_id")),
                            "stable_id": tool_dict.get("stable_id", ""),
                            "fingerprint": tool_dict.get("fingerprint", ""),
                            "risk_score": tool_dict.get("risk_score", 0),
                            "schema_findings": tool_dict.get("schema_findings", []),
                            "schema_rule_findings": tool_dict.get("schema_rule_findings", []),
                            "declared_capabilities": tool_dict.get("declared_capabilities", []),
                            "capabilities": capabilities,
                            "capability_source": capability_source,
                            "server": srv_id,
                            "agent": agent_name,
                        },
                        data_sources=[data_source_tag],
                    )
                )
                server_to_tool_ids[srv_id].append(tool_id)
                graph.add_edge(
                    UnifiedEdge(
                        source=srv_id,
                        target=tool_id,
                        relationship=RelationshipType.PROVIDES_TOOL,
                    )
                )

            # ── Credentials (from env keys) ──
            env_keys = srv_dict.get("credential_env_vars", [])
            if not env_keys:
                env_dict = srv_dict.get("env", {})
                if isinstance(env_dict, dict):
                    env_keys = [k for k in env_dict if _is_credential_key(k)]
            for env_key in env_keys:
                cred_id = f"cred:{env_key}"
                graph.add_node(
                    UnifiedNode(
                        id=cred_id,
                        entity_type=EntityType.CREDENTIAL,
                        label=env_key,
                        attributes={
                            "canonical_id": canonical_graph_node_id(EntityType.CREDENTIAL.value, cred_id),
                            "source_ids": source_ids(env_key=env_key),
                            "servers": [srv_id],
                        },
                        data_sources=[data_source_tag],
                    )
                )
                graph.add_edge(
                    UnifiedEdge(
                        source=srv_id,
                        target=cred_id,
                        relationship=RelationshipType.EXPOSES_CRED,
                        weight=2.0,
                    )
                )
                cred_to_agents[env_key].append(agent_id)
                for tool_id in tool_ids:
                    graph.add_edge(
                        UnifiedEdge(
                            source=cred_id,
                            target=tool_id,
                            relationship=RelationshipType.REACHES_TOOL,
                            evidence={
                                "source": data_source_tag,
                                "server": srv_id,
                                "credential_env_var": env_key,
                                "mapping_method": "server_scope_conservative",
                                "confidence": "medium",
                            },
                        )
                    )

    for vuln_node_id, srv_id, pkg_id, package_evidence, severity in pending_exploitable_edges:
        _add_exploitable_via_edges(
            graph,
            server_to_tool_ids=server_to_tool_ids,
            vuln_node_id=vuln_node_id,
            server_id=srv_id,
            package_id=pkg_id,
            evidence=package_evidence,
            severity=severity,
            data_source=data_source_tag,
        )

    # ── Blast radius vulnerabilities ─────────────────────────────────
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
                },
                compliance_tags=_collect_compliance_tags(br_dict),
                data_sources=[data_source_tag],
            )
        )

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
            pkg_key_to_servers=pkg_key_to_servers,
            server_name_to_agent_servers=server_name_to_agent_servers,
            agent_to_server_ids=agent_to_server_ids,
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
                package_id_to_servers=package_id_to_servers,
            )
            for pkg_id in pkg_ids:
                _add_exploitable_via_edges(
                    graph,
                    server_to_tool_ids=server_to_tool_ids,
                    vuln_node_id=vuln_node_id,
                    server_id=srv_id,
                    package_id=pkg_id,
                    evidence=_blast_radius_package_evidence(br_dict, data_source_tag),
                    severity=severity,
                    data_source=data_source_tag,
                )

    # ── Shared server edges (agent ↔ agent) ──────────────────────────
    for srv_name, agent_names in server_to_agents.items():
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

    # ── Shared credential edges (agent ↔ agent) ─────────────────────
    for cred_name, agent_names in cred_to_agents.items():
        unique = sorted(set(agent_names))
        if len(unique) >= 2:
            for i, a1 in enumerate(unique):
                for a2 in unique[i + 1 :]:
                    graph.add_edge(
                        UnifiedEdge(
                            source=a1,
                            target=a2,
                            relationship=RelationshipType.SHARES_CRED,
                            direction="bidirectional",
                            weight=4.0,
                            evidence={"credential": cred_name},
                        )
                    )

    # ── Model provenance ─────────────────────────────────────────────
    for model_dict in report_json.get("model_provenance", []):
        model_name = model_dict.get("model_name", model_dict.get("name", "unknown"))
        model_id = f"model:{model_name}"
        graph.add_node(
            UnifiedNode(
                id=model_id,
                entity_type=EntityType.MODEL,
                label=model_name,
                attributes={
                    "framework": model_dict.get("framework", ""),
                    "source": model_dict.get("source", ""),
                    "hash": model_dict.get("hash", ""),
                    "verified": model_dict.get("verified", False),
                },
                data_sources=["model-provenance"],
            )
        )

    # ── Dataset cards ────────────────────────────────────────────────
    dataset_cards = report_json.get("dataset_cards")
    if isinstance(dataset_cards, dict):
        for dataset_dict in dataset_cards.get("datasets", []):
            dataset_name = dataset_dict.get("name") or dataset_dict.get("source_file") or "unknown-dataset"
            graph.add_node(
                UnifiedNode(
                    id=f"dataset:{dataset_name}",
                    entity_type=EntityType.DATASET,
                    label=dataset_name,
                    attributes={
                        "description": dataset_dict.get("description", ""),
                        "license": dataset_dict.get("license", ""),
                        "source_url": dataset_dict.get("source_url", ""),
                        "version": dataset_dict.get("version", ""),
                        "features": dataset_dict.get("features", []),
                        "splits": dataset_dict.get("splits", {}),
                        "size_bytes": dataset_dict.get("size_bytes", 0),
                        "source_file": dataset_dict.get("source_file", ""),
                        "languages": dataset_dict.get("languages", []),
                        "task_categories": dataset_dict.get("task_categories", []),
                        "security_flags": dataset_dict.get("security_flags", []),
                    },
                    compliance_tags=_flatten_compliance_tags(dataset_dict.get("compliance_tags")),
                    data_sources=["dataset-cards"],
                )
            )

    # ── Serving configs / containers ────────────────────────────────
    for serving_dict in report_json.get("serving_configs", []):
        container_image = serving_dict.get("container_image", "")
        if not container_image:
            continue
        container_id = f"container:{container_image}"
        graph.add_node(
            UnifiedNode(
                id=container_id,
                entity_type=EntityType.CONTAINER,
                label=serving_dict.get("name") or container_image,
                attributes={
                    "container_image": container_image,
                    "framework": serving_dict.get("framework", ""),
                    "source_file": serving_dict.get("source_file", ""),
                    "model_uri": serving_dict.get("model_uri", ""),
                    "endpoint_url": serving_dict.get("endpoint_url", ""),
                    "security_flags": serving_dict.get("security_flags", []),
                },
                dimensions=NodeDimensions(surface="container"),
                data_sources=["training-pipeline"],
            )
        )
        model_id = _resolve_model_id(graph, serving_dict.get("model_uri", ""))
        if model_id:
            graph.add_edge(
                UnifiedEdge(
                    source=container_id,
                    target=model_id,
                    relationship=RelationshipType.SERVES_MODEL,
                )
            )

    # ── CIS benchmark misconfigurations ──────────────────────────────
    for section_key, legacy_key, default_cloud_provider in (
        ("cis_benchmark", "cis_benchmark_data", "aws"),
        ("snowflake_cis_benchmark", "snowflake_cis_benchmark_data", "snowflake"),
        ("azure_cis_benchmark", "azure_cis_benchmark_data", "azure"),
        ("gcp_cis_benchmark", "gcp_cis_benchmark_data", "gcp"),
        ("databricks_cis_benchmark", "databricks_cis_benchmark_data", "databricks"),
    ):
        cis_data = report_json.get(section_key) or report_json.get(legacy_key)
        if not cis_data:
            continue
        cloud_provider = (
            _clean_graph_part(cis_data.get("provider")) or _clean_graph_part(cis_data.get("cloud_provider")) or default_cloud_provider
        )
        checks = cis_data.get("checks", [])
        cloud_account_id = _clean_graph_part(
            cis_data.get("subscription_id") or cis_data.get("account_id") or cis_data.get("aws_account_id") or cis_data.get("project_id")
        )
        for check in checks:
            if str(check.get("status", "")).upper() != "FAIL":
                continue
            check_id = check.get("check_id", "unknown")
            misconfig_id = f"misconfig:{section_key}:{check_id}"
            resource_ids = list(check.get("resource_ids", []))
            graph.add_node(
                UnifiedNode(
                    id=misconfig_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=check.get("title", check_id),
                    severity=check.get("severity", "medium").lower(),
                    attributes={
                        "check_id": check_id,
                        "cis_section": check.get("cis_section", ""),
                        "evidence": check.get("evidence", ""),
                        "recommendation": check.get("recommendation", ""),
                        "resource_ids": resource_ids,
                        "cloud_provider": cloud_provider,
                        "network_exposure": list(check.get("network_exposure", [])),
                    },
                    compliance_tags=[f"CIS-{check_id}"],
                    data_sources=[section_key],
                    dimensions=NodeDimensions(cloud_provider=cloud_provider),
                )
            )
            for resource_id in sorted(set(resource_ids)):
                resource_node_id = f"cloud_resource:{cloud_provider or 'generic'}:{resource_id}"
                graph.add_node(
                    UnifiedNode(
                        id=resource_node_id,
                        entity_type=EntityType.CLOUD_RESOURCE,
                        label=resource_id,
                        attributes={
                            "resource_id": resource_id,
                            "cloud_provider": cloud_provider,
                            "source_section": section_key,
                        },
                        data_sources=[section_key],
                        dimensions=NodeDimensions(cloud_provider=cloud_provider),
                    )
                )
                graph.add_edge(
                    UnifiedEdge(
                        source=misconfig_id,
                        target=resource_node_id,
                        relationship=RelationshipType.AFFECTS,
                    )
                )

            # Subscription/tenant-scoped controls (Defender plans, Activity
            # Log alerts, Network Watcher, security contacts) carry no
            # ``resource_ids``. Anchor them to the cloud account node so they
            # are reachable by blast-radius / attack-path analysis instead of
            # floating as orphan nodes that never surface to the user.
            if not resource_ids and cloud_provider and cloud_account_id:
                account_node_id = _identity_node_id(EntityType.ACCOUNT, cloud_provider, cloud_account_id)
                graph.add_node(
                    UnifiedNode(
                        id=account_node_id,
                        entity_type=EntityType.ACCOUNT,
                        label=cloud_account_id,
                        attributes={"account_id": cloud_account_id, "cloud_provider": cloud_provider},
                        data_sources=[section_key],
                        dimensions=NodeDimensions(cloud_provider=cloud_provider),
                    )
                )
                graph.add_edge(
                    UnifiedEdge(
                        source=misconfig_id,
                        target=account_node_id,
                        relationship=RelationshipType.AFFECTS,
                    )
                )

    # ── SAST findings as misconfiguration nodes ──────────────────────
    sast_data = report_json.get("sast") or report_json.get("sast_data")
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

    # ── IaC findings as misconfiguration nodes ───────────────────────
    iac_data = report_json.get("iac_findings") or report_json.get("iac_findings_data")
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

    # ── Skill-audit findings as misconfiguration nodes ──────────────
    skill_audit = report_json.get("skill_audit")
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
                package_name_to_ids=package_name_to_ids,
                server_name_to_ids=server_name_to_ids,
                agent_name_to_ids=agent_name_to_ids,
                agent_config_path_to_id=agent_config_path_to_id,
            ):
                graph.add_edge(
                    UnifiedEdge(
                        source=finding_id,
                        target=target_id,
                        relationship=RelationshipType.AFFECTS,
                    )
                )

    # ── Framework-native static topology (CrewAI / LangGraph / AutoGen) ──
    ai_inventory = report_json.get("ai_inventory", {})
    if isinstance(ai_inventory, dict):
        _add_framework_topology(graph, ai_inventory.get("framework_agents", []), data_source_tag)

    # ── Cross-environment correlation (#1892 Phase 1: AWS Bedrock) ──
    _add_cross_env_correlation(graph, agents_data, data_source_tag)

    # ── Runtime session graph (dynamic edges) ──────────────────────
    runtime_graph = report_json.get("runtime_session_graph")
    if runtime_graph:
        for edge_dict in runtime_graph.get("edges", []):
            rel_str = edge_dict.get("interaction_type", edge_dict.get("relation", ""))
            rel_map = {
                "tool_call": RelationshipType.INVOKED,
                "invoked": RelationshipType.INVOKED,
                "resource_access": RelationshipType.ACCESSED,
                "accessed": RelationshipType.ACCESSED,
                "delegation": RelationshipType.DELEGATED_TO,
                "delegated_to": RelationshipType.DELEGATED_TO,
            }
            rel = rel_map.get(rel_str.lower())
            if not rel:
                continue
            src = edge_dict.get("source_node_id", edge_dict.get("source", ""))
            tgt = edge_dict.get("target_node_id", edge_dict.get("target", ""))
            if src and tgt:
                graph.add_edge(
                    UnifiedEdge(
                        source=src,
                        target=tgt,
                        relationship=rel,
                        evidence={
                            "timestamp": edge_dict.get("timestamp", ""),
                            "tool_capability": edge_dict.get("tool_capability", ""),
                            "risk_score": edge_dict.get("risk_score", 0),
                            "data_source": "runtime-proxy",
                        },
                    )
                )

    # ── Agentic identity graph projections (runtime audit slices) ─────
    _add_agentic_identity_graph_projections(graph, report_json, data_source_tag, tenant_id)

    # ── Runtime → graph feedback (observed-reach from the runtime relay) ──
    # The feedback direction of the agentic moat: incidents the runtime engine
    # observed (credential reach, lateral movement, kill-switch) are projected
    # onto agent nodes so this scan reflects OBSERVED behavior, not just static
    # reachability. Default-off — absent records is a pure no-op.
    _add_runtime_incident_feedback(graph, report_json, agent_name_to_ids, data_source_tag)

    # ── Toxic combinations as TRIGGERS edges ─────────────────────────
    toxic_data = report_json.get("toxic_combinations")
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

    # ── Enrich vulnerability nodes with blast radius stats ───────────
    for br_dict in blast_data:
        vuln_id_str = br_dict.get("vulnerability_id", "")
        vuln_node = graph.get_node(f"vuln:{vuln_id_str}") if vuln_id_str else None
        if vuln_node:
            vuln_node.attributes["affected_agent_count"] = len(br_dict.get("affected_agents", []))
            vuln_node.attributes["affected_server_count"] = len(br_dict.get("affected_servers", []))
            vuln_node.attributes["exposed_credential_count"] = len(br_dict.get("exposed_credentials", []))
            vuln_node.attributes["exposed_tool_count"] = len(br_dict.get("exposed_tools", []))
            vuln_node.attributes["reachability"] = br_dict.get("reachability", "")
            vuln_node.attributes["actionable"] = br_dict.get("actionable", False)

    # ── General cloud-asset inventory (estate-wide, opt-in) ──────────
    # Promote estate-wide cloud assets (AWS S3/EC2/IAM, Azure storage/VM/NSG/
    # managed-identity, GCP GCS/compute/firewall/service-account) into the graph
    # so a resource with no CIS/IaC finding still becomes a node the CNAPP /
    # effective-permissions overlays below can consume. Runs before those
    # overlays so they see the inventory. Accepts one payload or a list of
    # per-provider payloads.
    for inventory_payload in _iter_cloud_inventories(report_json.get("cloud_inventory")):
        _add_cloud_inventory(graph, inventory_payload, data_source_tag)
        _add_cloud_role_assignments(graph, inventory_payload, data_source_tag)
        # GCP estate roll-up backbone (org → folders → projects), carried on the
        # GCP inventory payload. Promoted after the inventory so project nodes the
        # CONTAINS tree references already exist to stitch onto.
        _add_gcp_organization(graph, inventory_payload.get("gcp_organization"), data_source_tag)

    _add_aws_organization(graph, report_json.get("aws_organization"), data_source_tag)
    _add_snowflake_object_graph(graph, report_json.get("snowflake_object_graph"), data_source_tag)
    _add_snowflake_exfil(graph, report_json.get("snowflake_exfil_graph"), data_source_tag)
    _add_snowflake_identity(
        graph,
        report_json.get("snowflake_login_anomalies"),
        report_json.get("snowflake_auth_posture"),
        data_source_tag,
    )
    _add_snowflake_services(graph, report_json.get("snowflake_services"), data_source_tag)
    # Snowflake estate roll-up backbone (organization → accounts). Carried on the
    # services payload under ``organization``; promoted after the services layer so
    # the account node(s) the CONTAINS tree references already exist to stitch onto.
    _sf_services_payload = report_json.get("snowflake_services")
    _add_snowflake_organization(
        graph,
        _sf_services_payload.get("organization") if isinstance(_sf_services_payload, dict) else None,
        data_source_tag,
    )
    _add_snowflake_pipeline(graph, report_json.get("snowflake_pipeline"), data_source_tag)
    _add_snowflake_integrations(graph, report_json.get("snowflake_integrations"), data_source_tag)
    _add_snowflake_external_data(graph, report_json.get("snowflake_external_data"), data_source_tag)
    _add_snowflake_governance(graph, report_json.get("snowflake_governance"), data_source_tag)
    _add_snowflake_activity(graph, report_json.get("snowflake_activity"), data_source_tag)

    # ── Cloud audit-trail behavioral edges (opt-in, read-only) ───────────
    # Observed-reach edges derived from each cloud's native audit trail
    # (CloudTrail / Activity Log / Cloud Audit Logs). The reader already
    # aggregated raw events into (principal, resource, action) descriptors;
    # no raw log lines are present in the report. Accepts one payload or a
    # per-provider list. A no-op unless an operator opted in to ingestion.
    _audit_payload = report_json.get("cloud_audit_trail")
    if isinstance(_audit_payload, list):
        for _provider_audit in _audit_payload:
            _add_cloud_audit_behavioral(graph, _provider_audit, data_source_tag)
    else:
        _add_cloud_audit_behavioral(graph, _audit_payload, data_source_tag)

    # ── Discovered non-human identities (IdP service accounts, gated) ────
    # Project NHIs enumerated by the identity connectors (Okta service apps /
    # API tokens, Entra service principals / app registrations) into the graph
    # as managed_identity nodes. Runs before the effective-permissions overlay
    # so those principals feed assume/permission resolution. Gated upstream:
    # the report only carries an "identity_discovery" block when an operator ran
    # discovery, so this is a no-op on ordinary scans.
    try:
        from agent_bom.graph.nhi_overlay import apply_nhi_overlay_from_report

        apply_nhi_overlay_from_report(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("NHI discovery overlay failed", exc_info=True)

    # Cloud-CNAPP enrichment: derive internet exposure, data stores, and toxic
    # (exposed + vulnerable) chains from the CIS/IaC findings now in the graph.
    try:
        from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay

        apply_cnapp_overlay(graph)
    except Exception:  # noqa: BLE001
        _logger.warning("CNAPP overlay failed", exc_info=True)

    # Effective permissions: resolve assume/trust chains into HAS_PERMISSION
    # edges and flag privilege-escalation paths. Runs after CNAPP so escalation
    # to internet-exposed resources is scored higher.
    try:
        from agent_bom.graph.effective_permissions import apply_effective_permissions

        apply_effective_permissions(graph)
    except Exception:  # noqa: BLE001
        _logger.warning("effective-permissions overlay failed", exc_info=True)

    # NHI governance: usage-based right-sizing, dormant/orphaned detection, and a
    # 0-100 per-identity risk score, written back onto the managed_identity nodes.
    # Runs after effective-permissions + CNAPP so it sees HAS_PERMISSION edges,
    # escalation flags, and internet-exposure markers. No-op when no NHIs exist.
    try:
        from agent_bom.graph.nhi_governance import apply_nhi_governance

        apply_nhi_governance(graph)
    except Exception:  # noqa: BLE001
        _logger.warning("NHI governance overlay failed", exc_info=True)

    # A2A auth posture: flag agent/identity nodes named by weak inter-agent
    # auth findings (shared tokens, missing mutual auth, over-broad delegation,
    # unverified actor tokens). Reference-only; no-op when no A2A findings exist.
    try:
        from agent_bom.a2a_auth_posture import annotate_graph_a2a_auth_from_report

        annotate_graph_a2a_auth_from_report(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("A2A auth posture overlay failed", exc_info=True)

    # MCP server + agent→MCP auth posture: flag MCP-server nodes named by weak
    # MCP-auth findings (unauthenticated network server, weak transport, static
    # credentials, agent→MCP gap). Reference-only; no-op when no MCP-auth
    # findings exist.
    try:
        from agent_bom.mcp_auth_posture import annotate_graph_mcp_auth_from_report

        annotate_graph_mcp_auth_from_report(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("MCP auth posture overlay failed", exc_info=True)

    # Multi-hop attack-path fusion: now that both the CNAPP exposure overlay and
    # the effective-permissions overlay have enriched the single graph, walk true
    # end-to-end kill-chains (internet entry → vuln/credential/permission/
    # escalation → crown-jewel data store) and materialise them as first-class
    # attack paths. Runs last so it sees every flag/edge the overlays wrote.
    try:
        from agent_bom.graph.attack_path_fusion import apply_attack_path_fusion

        apply_attack_path_fusion(graph)
    except Exception:  # noqa: BLE001
        _logger.warning("attack-path fusion failed", exc_info=True)

    # Cost (FinOps) fusion: attach LLM spend to agent/resource nodes, roll it up
    # the CONTAINS hierarchy, and flag nodes that are BOTH high-cost AND
    # high-risk. Runs LAST so it sees every exposure/toxic/critical flag the
    # overlays above wrote. Cost is optional: this no-ops byte-identically when
    # the report carries no ``llm_cost_records`` block.
    try:
        _apply_cost_overlay(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("cost overlay failed", exc_info=True)

    # ASPM (Application Security Posture Management) correlation: organise the
    # AppSec findings already in the graph AROUND the application they belong to
    # — derive APPLICATION roots from finding source paths, attach findings via
    # BELONGS_TO, roll up per-app risk, dedupe duplicate CVE/rule across sources,
    # and flag reachability from existing attack-path data. Runs LAST so it sees
    # every attack-path / exposure signal the overlays above wrote. No scanners,
    # no network: a pure correlation layer that no-ops byte-identically when the
    # report carries no ``findings`` block.
    try:
        _apply_aspm_overlay(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("ASPM overlay failed", exc_info=True)

    try:
        _apply_runtime_evidence_overlay(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("runtime evidence overlay failed", exc_info=True)

    # Repository folder/file structure: materialise the directory tree, manifest
    # files, file → dependency → vuln paths, and file → finding paths from the
    # project inventory + file-scoped findings already in the report, so a code
    # / repo scan visualises its folder layout the way the cloud graph
    # visualises the cloud hierarchy. Runs after the inventory + ASPM overlays so
    # the project servers, packages, and misconfiguration nodes it stitches onto
    # already exist. No-op (graph byte-identical) when no project inventory and
    # no file-scoped findings are present.
    try:
        _apply_repo_structure_overlay(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("repo-structure overlay failed", exc_info=True)

    if span is not None:
        span.set_attribute("agent_bom.graph.scan_id", sid)
        span.set_attribute("agent_bom.graph.tenant_id", tenant_id or "default")
        span.set_attribute("agent_bom.graph.agent_count", len(agents_data))
        span.set_attribute("agent_bom.graph.blast_radius_count", len(blast_data))
        span.set_attribute("agent_bom.graph.node_count", len(graph.nodes))
        span.set_attribute("agent_bom.graph.edge_count", len(graph.edges))
        span.end()
    return graph


def _apply_cost_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Fuse LLM cost into the graph from cost records carried on the report.

    Reads the optional ``llm_cost_records`` block (a list of priced cost-record
    dicts the caller loaded from the cost store — never fetched here) and hands
    it to :func:`agent_bom.graph.cost_overlay.apply_cost_overlay`. Gated to a
    clean no-op when the block is absent or empty, so an ordinary scan (no cost
    data) leaves the graph byte-identical. Mirrors how ``cnapp_overlay`` /
    ``governance_overlay`` are invoked above.
    """
    raw = report_json.get("llm_cost_records")
    if not isinstance(raw, list) or not raw:
        return
    records = [r for r in raw if isinstance(r, dict)]
    if not records:
        return
    from datetime import datetime, timezone

    from agent_bom.graph.cost_overlay import apply_cost_overlay

    apply_cost_overlay(graph, records, datetime.now(timezone.utc))


def _apply_aspm_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Correlate AppSec findings around applications from the report's findings.

    Reads the optional unified ``findings`` block (a list of ``Finding.to_dict()``
    dicts the report already carries) and hands it to
    :func:`agent_bom.graph.aspm_overlay.apply_aspm_overlay`, which derives
    APPLICATION roots, attaches each finding via ``BELONGS_TO``, rolls up per-app
    risk, dedupes duplicate CVE/rule across sources, and flags reachability from
    existing attack-path data. Gated to a clean no-op when the block is absent or
    empty, so a scan with no findings leaves the graph byte-identical. Mirrors how
    ``_apply_cost_overlay`` is invoked above.
    """
    raw = report_json.get("findings")
    if not isinstance(raw, list) or not raw:
        return
    from datetime import datetime, timezone

    from agent_bom.graph.aspm_overlay import apply_aspm_overlay

    apply_aspm_overlay(graph, dict(report_json), datetime.now(timezone.utc))


def _apply_runtime_evidence_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    from agent_bom.graph.evidence_overlay import apply_runtime_evidence_overlay

    apply_runtime_evidence_overlay(graph, report_json)


def _apply_repo_structure_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Materialise the repository folder/file structure into the graph.

    Reads the optional ``project_inventory`` block (the directory tree + per-
    directory manifest / lockfile / declaration files the project scanner already
    emits) and hands it to
    :func:`agent_bom.graph.repo_structure_overlay.apply_repo_structure_overlay`,
    which builds ``DIRECTORY`` nodes with ``CONTAINS`` edges, attaches manifest
    ``CONFIG_FILE`` nodes, links each manifest to the direct packages it declares
    (file → package → vuln), and places file-scoped findings under their folder
    (finding → file). Gated to a clean no-op when neither a project inventory nor
    a file-scoped finding is present, so an unrelated scan leaves the graph
    byte-identical. Mirrors how ``_apply_aspm_overlay`` is invoked above.
    """
    has_inventory = isinstance(report_json.get("project_inventory"), Mapping)
    if not has_inventory and not any(node.entity_type == EntityType.MISCONFIGURATION for node in graph.nodes.values()):
        return
    from datetime import datetime, timezone

    from agent_bom.graph.repo_structure_overlay import apply_repo_structure_overlay

    apply_repo_structure_overlay(graph, dict(report_json), datetime.now(timezone.utc))


def _iter_agentic_identity_graph_projections(report_json: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return runtime identity graph projections embedded in report JSON."""
    candidates: list[Any] = [
        report_json.get("agentic_identity_graph"),
        report_json.get("agentic_identity_graphs"),
    ]
    runtime_graph = report_json.get("runtime_session_graph")
    if isinstance(runtime_graph, Mapping):
        candidates.extend(
            [
                runtime_graph.get("agentic_identity_graph"),
                runtime_graph.get("agentic_identity_graphs"),
            ]
        )

    for event in _mapping_list(report_json.get("audit_events")):
        candidates.append(event.get("agentic_identity_graph"))
        details = event.get("details")
        if isinstance(details, Mapping):
            candidates.extend(
                [
                    details.get("agentic_identity_graph"),
                    details.get("agentic_identity_graphs"),
                ]
            )

    projections: list[Mapping[str, Any]] = []
    seen: set[int] = set()
    for candidate in candidates:
        for projection in _mapping_list(candidate):
            if projection.get("schema_version") != "agentic_identity_graph.v1":
                continue
            marker = id(projection)
            if marker in seen:
                continue
            seen.add(marker)
            projections.append(projection)
    return projections


def _add_agentic_identity_graph_projections(
    graph: UnifiedGraph,
    report_json: Mapping[str, Any],
    data_source_tag: str,
    tenant_id: str,
) -> None:
    """Ingest sanitized runtime identity projections into the canonical graph."""
    for projection in _iter_agentic_identity_graph_projections(report_json):
        schema_version = sanitize_text(projection.get("schema_version", "agentic_identity_graph.v1"), max_len=80)
        projection_source = sanitize_text(projection.get("source", "runtime-identity"), max_len=160)
        node_ids: set[str] = set()
        for node_dict in _mapping_list(projection.get("nodes")):
            node_id = sanitize_text(node_dict.get("id", ""), max_len=260)
            if not node_id:
                continue
            entity_type = _runtime_identity_entity_type(node_dict.get("entity_type"))
            if entity_type is None:
                continue
            node_ids.add(node_id)
            graph.add_node(
                UnifiedNode(
                    id=node_id,
                    entity_type=entity_type,
                    label=sanitize_text(node_dict.get("label", node_id), max_len=180) or node_id,
                    attributes=_runtime_identity_node_attributes(node_dict, schema_version, projection_source),
                    data_sources=[data_source_tag, "runtime-identity"],
                    dimensions=NodeDimensions(surface="runtime"),
                )
            )

        for edge_dict in _mapping_list(projection.get("edges")):
            source = sanitize_text(edge_dict.get("source", ""), max_len=260)
            target = sanitize_text(edge_dict.get("target", ""), max_len=260)
            if not source or not target:
                continue
            if source not in node_ids and not graph.has_node(source):
                continue
            if target not in node_ids and not graph.has_node(target):
                continue
            relationship = _runtime_identity_relationship(edge_dict.get("relationship"))
            if relationship is None:
                continue
            evidence = _runtime_identity_evidence(
                edge_dict.get("evidence"),
                schema_version=schema_version,
                projection_source=projection_source,
                tenant_id=tenant_id,
            )
            graph.add_edge(
                UnifiedEdge(
                    source=source,
                    target=target,
                    relationship=relationship,
                    confidence=0.9,
                    evidence=evidence,
                    provenance={
                        "source": projection_source,
                        "schema_version": schema_version,
                    },
                )
            )


# Which observed-reach relationship each incident kind projects.
_FEEDBACK_RELATIONSHIP: dict[str, RelationshipType] = {
    "reached_credential": RelationshipType.USED_CREDENTIAL,
    "lateral_movement": RelationshipType.ACCESSED,
    "kill_switch": RelationshipType.ACCESSED,
}


def _iter_runtime_incident_records(report_json: Mapping[str, Any]) -> list[RuntimeIncidentRecord]:
    """Collect runtime incident-feedback records for this scan.

    Two sources, both optional and default-off:

    * ``runtime_incident_feedback``: an inline list of record dicts in the
      report (e.g. carried alongside a runtime audit slice).
    * ``runtime_incident_feedback_path``: a path to a JSONL file the runtime
      relay appended to during the prior window.

    Absent both ⇒ empty list ⇒ the graph build is byte-identical to today.
    """
    records: list[RuntimeIncidentRecord] = []
    for raw in _mapping_list(report_json.get("runtime_incident_feedback")):
        record = RuntimeIncidentRecord.from_dict(raw)
        if record is not None:
            records.append(record)
    path = report_json.get("runtime_incident_feedback_path")
    if isinstance(path, str) and path.strip():
        records.extend(load_incident_records(path))
    return records


def _resolve_feedback_agent_ids(
    agent_id: str,
    agent_name_to_ids: Mapping[str, list[str]],
) -> list[str]:
    """Map a runtime incident's ``agent_id`` onto existing graph agent node ids.

    Matches by agent name first (the common case). When the runtime id does not
    name a discovered agent, falls back to the deterministic ``agent:<name>`` id
    so the observed-reach is still recorded against a stable node.
    """
    name = str(agent_id or "").strip()
    if name and name in agent_name_to_ids and agent_name_to_ids[name]:
        return list(agent_name_to_ids[name])
    return [_agent_node_id(name or "unknown")]


def _add_runtime_incident_feedback(
    graph: UnifiedGraph,
    report_json: Mapping[str, Any],
    agent_name_to_ids: Mapping[str, list[str]],
    data_source_tag: str,
) -> None:
    """Project runtime-observed incidents onto the unified graph (feedback dir).

    For each record:

    * Mark the matched agent node with the ``observed_*`` attribute for the
      incident kind (e.g. ``observed_reached_credential=True``) plus an
      aggregate ``runtime_feedback`` summary — toxic-combo / reachability
      evaluators then account for observed behavior, not just static reach.
    * Draw an observed-reach edge (``USED_CREDENTIAL`` / ``ACCESSED``) from the
      agent to each observed node id, or to a synthetic observed-tool node for
      label-only reaches. Every node/edge is tagged ``source="runtime-feedback"``.
    """
    records = _iter_runtime_incident_records(report_json)
    if not records:
        return

    for agent_id, agent_records in merge_records(records).items():
        node_ids = _resolve_feedback_agent_ids(agent_id, agent_name_to_ids)
        for node_id in node_ids:
            _project_agent_feedback(graph, node_id, agent_records, data_source_tag)


def _project_agent_feedback(
    graph: UnifiedGraph,
    agent_node_id: str,
    records: list[RuntimeIncidentRecord],
    data_source_tag: str,
) -> None:
    """Mark one agent node + draw observed-reach edges for its incidents."""
    observed_attrs: dict[str, Any] = {}
    kinds: set[str] = set()
    severities: set[str] = set()
    total = 0
    for record in records:
        attr = incident_attribute(record.kind)
        if attr is None:
            continue
        observed_attrs[attr] = True
        kinds.add(record.kind)
        severities.add(record.severity)
        total += max(1, record.count)

    if not kinds:
        return

    observed_attrs["runtime_feedback"] = {
        "source": "runtime-feedback",
        "incident_kinds": sorted(kinds),
        "incident_count": total,
        "severities": sorted(severities),
    }

    # add_node merges attributes onto the existing agent node (if any); when the
    # observed agent was not otherwise discovered this scan, this materializes a
    # minimal agent node so the observed-reach is never silently dropped.
    graph.add_node(
        UnifiedNode(
            id=agent_node_id,
            entity_type=EntityType.AGENT,
            label=agent_node_id.removeprefix("agent:"),
            attributes=observed_attrs,
            data_sources=[data_source_tag, "runtime-feedback"],
        )
    )

    for record in records:
        relationship = _FEEDBACK_RELATIONSHIP.get(record.kind, RelationshipType.ACCESSED)
        for target, is_node_id in iter_observed_targets(record):
            target_id = target if is_node_id else f"tool:observed:{_clean_graph_part(target) or 'unknown'}"
            if not is_node_id:
                graph.add_node(
                    UnifiedNode(
                        id=target_id,
                        entity_type=EntityType.TOOL,
                        label=target,
                        attributes={"source": "runtime-feedback", "observed": True},
                        data_sources=[data_source_tag, "runtime-feedback"],
                    )
                )
            elif target_id not in graph.nodes:
                # Reference to a node not present this scan — skip the dangling edge.
                continue
            _add_rel_edge(
                graph,
                agent_node_id,
                target_id,
                relationship,
                {
                    "source": "runtime-feedback",
                    "incident_kind": record.kind,
                    "severity": record.severity,
                    "observed_at": record.observed_at,
                    "count": max(1, record.count),
                },
            )


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _runtime_identity_entity_type(value: Any) -> EntityType | None:
    try:
        return EntityType(str(value))
    except ValueError:
        return None


def _runtime_identity_relationship(value: Any) -> RelationshipType | None:
    try:
        return RelationshipType(str(value))
    except ValueError:
        return None


def _runtime_identity_node_attributes(
    node_dict: Mapping[str, Any],
    schema_version: str,
    projection_source: str,
) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "agentic_identity_graph_schema": schema_version,
        "runtime_graph_source": projection_source,
    }
    raw_attrs = node_dict.get("attributes")
    if isinstance(raw_attrs, Mapping):
        sanitized_attrs = sanitize_sensitive_payload(dict(raw_attrs))
        if isinstance(sanitized_attrs, dict):
            attributes.update(sanitized_attrs)
    source_ref = node_dict.get("source_ref")
    if isinstance(source_ref, Mapping):
        sanitized_ref = sanitize_sensitive_payload(dict(source_ref))
        if isinstance(sanitized_ref, dict):
            attributes["source_ref"] = sanitized_ref
    return attributes


def _runtime_identity_evidence(
    evidence: Any,
    *,
    schema_version: str,
    projection_source: str,
    tenant_id: str,
) -> dict[str, Any]:
    sanitized = sanitize_sensitive_payload(dict(evidence)) if isinstance(evidence, Mapping) else {}
    safe_evidence = sanitized if isinstance(sanitized, dict) else {}
    safe_evidence.setdefault("source", projection_source)
    safe_evidence["schema_version"] = schema_version
    safe_evidence["data_source"] = "runtime-identity"
    if tenant_id:
        safe_evidence.setdefault("tenant_id", sanitize_text(tenant_id, max_len=200))
    return safe_evidence


def _tool_capabilities(tool_dict: dict[str, Any]) -> tuple[list[str], str]:
    """Return normalized tool capability facets and their evidence source."""
    declared_values = tool_dict.get("capabilities") or tool_dict.get("declared_capabilities") or []
    if isinstance(declared_values, list):
        declared = sorted(
            {
                capability.value
                for raw in declared_values
                if isinstance(raw, str) and (capability := _normalize_tool_capability(raw)) is not None
            }
        )
        if declared:
            return declared, "declared"

    capabilities = {capability.value for capability in classify_tool(str(tool_dict.get("name", "")), str(tool_dict.get("description", "")))}
    schema_findings = tool_dict.get("schema_findings", [])
    if isinstance(schema_findings, list):
        for finding in schema_findings:
            low = str(finding).lower()
            if "network-egress" in low or "url" in low:
                capabilities.add(ToolCapability.NETWORK.value)
            if "shell-execution" in low or "command" in low:
                capabilities.add(ToolCapability.EXECUTE.value)
            if "filesystem" in low or "path" in low:
                capabilities.add(ToolCapability.READ.value)
    return sorted(capabilities), "classified"


def _normalize_tool_capability(value: str) -> ToolCapability | None:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "readonly": "read",
        "read_only": "read",
        "destructive": "delete",
        "exec": "execute",
        "execution": "execute",
        "network_egress": "network",
        "egress": "network",
        "credential": "auth",
        "credentials": "auth",
        "administrative": "admin",
    }
    normalized = aliases.get(normalized, normalized)
    try:
        return ToolCapability(normalized)
    except ValueError:
        return None


def _resolve_affected_package_ids(
    br_dict: dict[str, Any],
    *,
    server_id: str,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    package_id_to_servers: dict[str, list[str]],
) -> list[str]:
    """Return package nodes on a specific server that can safely drive capability-impact edges."""
    if not pkg_name:
        return []
    pkg_id = _package_node_id_from_parts(pkg_name, pkg_version, ecosystem, br_dict.get("package_purl") or br_dict.get("purl"))
    if server_id not in package_id_to_servers.get(pkg_id, []):
        return []
    evidence = _blast_radius_package_evidence(br_dict, "")
    if not _has_mappable_package_version(evidence):
        return []
    return [pkg_id]


def _add_exploitable_via_edges(
    graph: UnifiedGraph,
    *,
    server_to_tool_ids: dict[str, list[str]],
    vuln_node_id: str,
    server_id: str,
    package_id: str,
    evidence: dict[str, Any],
    severity: str,
    data_source: str,
) -> None:
    """Link a vulnerability to impacted tool capabilities with conservative evidence.

    The graph usually knows that an MCP server depends on a vulnerable package
    and exposes tools, but not the exact function-level package-to-tool call
    stack. These edges therefore carry a conservative mapping method instead
    of pretending to prove exact exploit reachability.
    """
    if not _has_mappable_package_version(evidence):
        return
    for tool_id in server_to_tool_ids.get(server_id, []):
        tool = graph.get_node(tool_id)
        if tool is None:
            continue
        capabilities = [str(cap) for cap in tool.attributes.get("capabilities", []) if str(cap)]
        if not capabilities:
            continue
        graph.add_edge(
            UnifiedEdge(
                source=vuln_node_id,
                target=tool_id,
                relationship=RelationshipType.EXPLOITABLE_VIA,
                weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
                evidence={
                    "source": data_source,
                    "server": server_id,
                    "package_node": package_id,
                    "package": evidence.get("package") or evidence.get("package_name", ""),
                    "version": evidence.get("version") or evidence.get("package_version", ""),
                    "ecosystem": evidence.get("ecosystem", ""),
                    "purl": evidence.get("purl", ""),
                    "mapping_method": "server_scope_conservative",
                    "confidence": "medium",
                    "capabilities": capabilities,
                    "capability_source": tool.attributes.get("capability_source", ""),
                    "discovery_provenance": evidence.get("discovery_provenance", {}),
                },
            )
        )


def _has_mappable_package_version(evidence: dict[str, Any]) -> bool:
    version = str(evidence.get("version") or evidence.get("package_version") or "").strip().lower()
    return bool(version and version not in {"unknown", "latest", "*", "main", "master"})


def _add_vuln_node(
    graph: UnifiedGraph,
    vuln_dict: dict[str, Any],
    pkg_id: str,
    data_source: str,
    package_evidence: dict[str, Any] | None = None,
) -> str | None:
    """Add a vulnerability node and link it to its package."""
    vuln_id_str = vuln_dict.get("id", "")
    if not vuln_id_str:
        return None
    severity = vuln_dict.get("severity", "").lower()
    vuln_node_id = f"vuln:{vuln_id_str}"

    graph.add_node(
        UnifiedNode(
            id=vuln_node_id,
            entity_type=EntityType.VULNERABILITY,
            label=vuln_id_str,
            severity=severity,
            attributes={
                "canonical_id": canonical_graph_node_id(EntityType.VULNERABILITY.value, vuln_node_id),
                "source_ids": source_ids(vulnerability_id=vuln_id_str),
                "cvss_score": vuln_dict.get("cvss_score"),
                "cvss_vector": vuln_dict.get("cvss_vector"),
                "attack_vector": vuln_dict.get("attack_vector"),
                "attack_complexity": vuln_dict.get("attack_complexity"),
                "privileges_required": vuln_dict.get("privileges_required"),
                "user_interaction": vuln_dict.get("user_interaction"),
                "network_exploitable": vuln_dict.get("network_exploitable", False),
                "epss_score": vuln_dict.get("epss_score"),
                "is_kev": vuln_dict.get("is_kev", False),
                "fixed_version": vuln_dict.get("fixed_version"),
                "cwe_ids": vuln_dict.get("cwe_ids", []),
            },
            data_sources=[data_source],
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=pkg_id,
            target=vuln_node_id,
            relationship=RelationshipType.VULNERABLE_TO,
            weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
            evidence=package_evidence or {"source": data_source},
        )
    )
    return vuln_node_id


def _normalize_server_name(raw: Any) -> str:
    """Return a comparable server name from string or object payloads."""
    if isinstance(raw, dict):
        return str(raw.get("name", "")).strip()
    name = getattr(raw, "name", raw)
    return str(name).strip()


def _resolve_affected_server_ids(
    br_dict: dict[str, Any],
    *,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    pkg_key_to_servers: dict[str, list[str]],
    server_name_to_agent_servers: dict[str, dict[str, str]],
    agent_to_server_ids: dict[str, set[str]],
) -> list[str]:
    """Resolve the concrete server node IDs touched by a blast-radius finding.

    Preference order:
    1. package-host servers from the inventory graph
    2. explicit affected server names
    3. explicit affected agent names

    Each additional hint narrows the candidate set instead of creating a
    synthetic agent×server cross-product.
    """
    candidate_ids: set[str] = set()
    if pkg_name:
        pkg_key = _package_graph_key(pkg_name, pkg_version, ecosystem, br_dict.get("package_purl") or br_dict.get("purl"))
        candidate_ids.update(pkg_key_to_servers.get(pkg_key, []))

    server_names = {name for name in (_normalize_server_name(server) for server in br_dict.get("affected_servers", [])) if name}
    if server_names:
        named_ids: set[str] = set()
        for server_name in server_names:
            named_ids.update(server_name_to_agent_servers.get(server_name, {}).values())
        narrowed = (candidate_ids & named_ids) if candidate_ids else named_ids
        candidate_ids = narrowed

    agent_names = {str(agent).strip() for agent in br_dict.get("affected_agents", []) if str(agent).strip()}
    if agent_names:
        agent_ids: set[str] = set()
        for agent_name in agent_names:
            agent_ids.update(agent_to_server_ids.get(agent_name, set()))
        narrowed = (candidate_ids & agent_ids) if candidate_ids else agent_ids
        candidate_ids = narrowed

    return sorted(candidate_ids)


def _package_graph_key(name: str, version: str, ecosystem: str, purl: str | None = None) -> str:
    return canonical_package_key(name, version, ecosystem, purl)


def _package_node_id(pkg_dict: dict[str, Any]) -> str:
    return _package_node_id_from_parts(
        str(pkg_dict.get("name", "unknown") or "unknown"),
        str(pkg_dict.get("version", "") or ""),
        str(pkg_dict.get("ecosystem", "") or ""),
        pkg_dict.get("purl"),
    )


def _package_node_id_from_parts(name: str, version: str, ecosystem: str, purl: str | None = None) -> str:
    return f"pkg:{_package_graph_key(name, version, ecosystem, purl)}"


def _package_evidence(pkg_dict: dict[str, Any], data_source_tag: str) -> dict[str, Any]:
    """Build bounded provenance evidence for package graph edges."""
    occurrences = pkg_dict.get("occurrences", [])
    if not isinstance(occurrences, list):
        occurrences = []
    normalized_occurrences: list[dict[str, Any]] = []
    for occurrence in occurrences[:10]:
        if not isinstance(occurrence, dict):
            continue
        item = {
            key: occurrence.get(key)
            for key in (
                "layer_index",
                "layer_id",
                "layer_path",
                "package_path",
                "created_by",
                "dockerfile_instruction",
                "source_file",
                "line",
                "parser",
            )
            if occurrence.get(key) not in (None, "")
        }
        if item:
            normalized_occurrences.append(item)

    evidence = {
        "source": data_source_tag,
        "package": pkg_dict.get("name", ""),
        "version": pkg_dict.get("version", ""),
        "ecosystem": pkg_dict.get("ecosystem", ""),
        "purl": pkg_dict.get("purl", ""),
        "stable_id": pkg_dict.get("stable_id", ""),
        "source_package": pkg_dict.get("source_package", ""),
        "version_source": pkg_dict.get("version_source", ""),
        "discovery_provenance": sanitize_discovery_provenance(pkg_dict.get("discovery_provenance")),
        "version_provenance": _package_version_provenance_from_dict(pkg_dict),
        "occurrence_count": pkg_dict.get("occurrence_count", len(occurrences)),
        "occurrences": normalized_occurrences,
    }
    introduced = pkg_dict.get("introduced_in_layer")
    if isinstance(introduced, dict):
        evidence["introduced_in_layer"] = {
            key: introduced.get(key)
            for key in ("layer_index", "layer_id", "layer_path", "package_path", "created_by", "dockerfile_instruction")
            if introduced.get(key) not in (None, "")
        }
    return {key: value for key, value in evidence.items() if value not in (None, "", [])}


def _package_version_provenance_from_dict(pkg_dict: dict[str, Any]) -> dict[str, Any]:
    explicit = pkg_dict.get("version_provenance")
    if isinstance(explicit, dict):
        return package_version_provenance(
            {
                "name": pkg_dict.get("name"),
                "version": pkg_dict.get("version"),
                "version_source": pkg_dict.get("version_source"),
                "resolved_from_registry": pkg_dict.get("resolved_from_registry", False),
                "discovery_provenance": {"version_provenance": explicit},
            }
        )
    return package_version_provenance(
        {
            "name": pkg_dict.get("name"),
            "version": pkg_dict.get("version"),
            "version_source": pkg_dict.get("version_source"),
            "resolved_from_registry": pkg_dict.get("resolved_from_registry", False),
            "declared_version": pkg_dict.get("declared_version"),
            "resolved_version": pkg_dict.get("resolved_version"),
            "version_confidence": pkg_dict.get("version_confidence"),
            "version_resolved_at": pkg_dict.get("version_resolved_at"),
            "version_evidence": pkg_dict.get("version_evidence") or pkg_dict.get("occurrences") or [],
            "version_conflicts": pkg_dict.get("version_conflicts") or [],
            "floating_reference": pkg_dict.get("floating_reference", False),
            "floating_reference_reason": pkg_dict.get("floating_reference_reason"),
            "registry_version": pkg_dict.get("registry_version"),
        }
    )


def _blast_radius_package_evidence(br_dict: dict[str, Any], data_source_tag: str) -> dict[str, Any]:
    evidence = {
        "source": data_source_tag,
        "package": br_dict.get("package", ""),
        "package_name": br_dict.get("package_name", ""),
        "package_version": br_dict.get("package_version", ""),
        "package_stable_id": br_dict.get("package_stable_id", ""),
        "purl": br_dict.get("package_purl") or br_dict.get("purl", ""),
        "reachability": br_dict.get("reachability", ""),
    }
    return {key: value for key, value in evidence.items() if value not in (None, "", [])}


def _collect_compliance_tags(br_dict: dict[str, Any]) -> list[str]:
    """Collect all compliance tags from a blast radius dict."""
    tags: list[str] = []
    for key in (
        "owasp_tags",
        "atlas_tags",
        "attack_tags",
        "nist_ai_rmf_tags",
        "owasp_mcp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
    ):
        tags.extend(br_dict.get(key, []))
    return sorted(set(tags))


_PRINCIPAL_TYPE_TO_ENTITY: dict[str, EntityType] = {
    "account": EntityType.ACCOUNT,
    "aws-account": EntityType.ACCOUNT,
    "cloud-account": EntityType.ACCOUNT,
    "federated": EntityType.FEDERATED_IDENTITY,
    "federated-identity": EntityType.FEDERATED_IDENTITY,
    "federated-user": EntityType.FEDERATED_IDENTITY,
    "group": EntityType.GROUP,
    "iam-role": EntityType.ROLE,
    "managed-identity": EntityType.MANAGED_IDENTITY,
    "oidc": EntityType.FEDERATED_IDENTITY,
    "policy": EntityType.POLICY,
    "role": EntityType.ROLE,
    "saml": EntityType.FEDERATED_IDENTITY,
    "service-account": EntityType.SERVICE_ACCOUNT,
    "service-principal": EntityType.SERVICE_PRINCIPAL,
    "serviceprincipal": EntityType.SERVICE_PRINCIPAL,
    "user": EntityType.USER,
}

_IDENTITY_NODE_PREFIX: dict[EntityType, str] = {
    EntityType.ORG: "org",
    EntityType.ACCOUNT: "account",
    EntityType.USER: "user",
    EntityType.GROUP: "group",
    EntityType.ROLE: "role",
    EntityType.POLICY: "policy",
    EntityType.SERVICE_ACCOUNT: "service_account",
    EntityType.SERVICE_PRINCIPAL: "service_principal",
    EntityType.MANAGED_IDENTITY: "managed_identity",
    EntityType.FEDERATED_IDENTITY: "federated_identity",
}


def _identity_entity_type(raw_type: Any) -> EntityType:
    principal_type = _clean_graph_part(raw_type).lower().replace("_", "-").replace(" ", "-")
    return _PRINCIPAL_TYPE_TO_ENTITY.get(principal_type, EntityType.SERVICE_ACCOUNT)


def _identity_node_id(entity_type: EntityType, provider: str, identity_id: str) -> str:
    prefix = _IDENTITY_NODE_PREFIX.get(entity_type, "identity")
    return f"{prefix}:{provider}:{identity_id}"


def _first_cloud_scope_value(scope: dict[str, Any], *keys: str) -> tuple[str, str]:
    for key in keys:
        value = _clean_graph_part(scope.get(key))
        if value:
            return key, value
    return "", ""


def _policy_entries(principal: dict[str, Any]) -> list[dict[str, str]]:
    raw_policies = principal.get("policies") or principal.get("attached_policies") or principal.get("policy_ids") or []
    if isinstance(raw_policies, (str, bytes)):
        raw_policies = [raw_policies]
    if not isinstance(raw_policies, list):
        return []

    policies: list[dict[str, str]] = []
    for raw_policy in raw_policies:
        privilege_level = "unknown"
        if isinstance(raw_policy, dict):
            policy_id = _clean_graph_part(raw_policy.get("policy_id")) or _clean_graph_part(raw_policy.get("arn"))
            policy_name = _clean_graph_part(raw_policy.get("policy_name")) or _clean_graph_part(raw_policy.get("name")) or policy_id
            privilege_level = str(raw_policy.get("privilege_level") or "unknown")
        else:
            policy_id = _clean_graph_part(raw_policy)
            policy_name = policy_id
        if policy_id:
            policies.append({"id": policy_id, "name": policy_name or policy_id, "privilege_level": privilege_level})
    return policies


def _trust_entries(principal: dict[str, Any]) -> list[dict[str, str]]:
    raw_trusts = principal.get("trust_principals") or []
    if isinstance(raw_trusts, dict):
        raw_trusts = [raw_trusts]
    if not isinstance(raw_trusts, list):
        return []

    trusts: list[dict[str, str]] = []
    for raw_trust in raw_trusts:
        if not isinstance(raw_trust, dict):
            continue
        principal_id = _clean_graph_part(raw_trust.get("principal_id")) or _clean_graph_part(raw_trust.get("arn"))
        if not principal_id:
            continue
        trusts.append(
            {
                "id": principal_id,
                "name": _clean_graph_part(raw_trust.get("principal_name")) or principal_id,
                "type": _clean_graph_part(raw_trust.get("principal_type")) or "federated-identity",
                "relationship": _clean_graph_part(raw_trust.get("relationship")) or "trusts",
                "source_field": _clean_graph_part(raw_trust.get("source_field")),
            }
        )
    return trusts


def _prepare_cloud_payload(payload: Any, data_source: str, *tags: str) -> tuple[str, list[str]] | None:
    """Shared guard for the cloud ``_add_*`` layers.

    Returns ``None`` when *payload* is not a status-ok dict (the universal no-op
    guard), otherwise ``(account, data_sources)`` where ``account`` is the
    cleaned ``account`` field and ``data_sources`` is the sorted, blank-stripped
    union of *data_source* and *tags*.
    """
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return None
    account = _clean_graph_part(payload.get("account"))
    data_sources = sorted({data_source, *tags} - {""})
    return account, data_sources


def _add_identity_node(
    graph: UnifiedGraph,
    entity_type: EntityType,
    identity_id: str,
    provider: str,
    data_sources: list[str],
    *,
    label: str | None = None,
    surface: str = "identity",
    **attrs: Any,
) -> str:
    """Add an identity-surface node (account/role/user/OU/...) and return its id.

    Mirrors the repeated cloud identity-node construction: id from
    ``_identity_node_id``, ``surface`` dimensions on *provider* (default
    ``"identity"``), and the caller's attributes verbatim. The ``cloud_provider``
    attribute is passed as a keyword like any other (it is *not* derived from
    *provider*) so call sites stay byte-identical.
    """
    node_id = _identity_node_id(entity_type, provider, identity_id)
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=entity_type,
            label=label if label is not None else identity_id,
            attributes=attrs,
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface=surface),
        )
    )
    return node_id


def _add_rel_edge(
    graph: UnifiedGraph,
    source_id: str,
    target_id: str,
    relationship: RelationshipType,
    evidence: dict[str, Any] | None = None,
) -> None:
    """Add a relationship edge; thin wrapper over ``graph.add_edge(UnifiedEdge(...))``.

    ``evidence=None`` is normalized to ``{}`` to match the ``UnifiedEdge``
    default, so routed call sites stay byte-identical.
    """
    graph.add_edge(
        UnifiedEdge(
            source=source_id,
            target=target_id,
            relationship=relationship,
            evidence=evidence if evidence is not None else {},
        )
    )


def _add_agent_cloud_lineage(
    graph: UnifiedGraph,
    *,
    agent_id: str,
    agent_dict: dict[str, Any],
    agent_metadata: dict[str, Any],
    data_source: str,
) -> None:
    """Promote normalized cloud-origin metadata into explicit lineage nodes.

    Cloud providers already normalize runtime identity into ``agent.metadata``.
    The graph should carry that as inventory too, otherwise cloud-discovered
    agents remain disconnected from provider/runtime assets.
    """
    origin = agent_metadata.get("cloud_origin")
    if not isinstance(origin, dict):
        return

    # Cloud sources are conventionally named `<provider>-<service>` (e.g.
    # "aws-bedrock", "azure-openai", "gcp-vertex-ai") so we can recover the
    # service name from the agent's `source` field when `cloud_origin` lacks
    # it. This mirrors the secondary fallback chain that `provider` already
    # uses and avoids the literal "unknown-service" placeholder leaking into
    # the graph just because one cloud discoverer forgot to populate the
    # service slot.
    raw_source = str(agent_dict.get("source") or "").strip()
    source_service_fallback = raw_source.split("-", 1)[1] if "-" in raw_source else ""

    provider = _clean_graph_part(origin.get("provider")) or _clean_graph_part(raw_source) or "cloud"
    service = _clean_graph_part(origin.get("service")) or _clean_graph_part(source_service_fallback) or "unknown-service"
    resource_type = _clean_graph_part(origin.get("resource_type")) or "resource"
    resource_id = _clean_graph_part(origin.get("resource_id")) or _clean_graph_part(origin.get("resource_name"))
    if not resource_id:
        return

    resource_name = _clean_graph_part(origin.get("resource_name")) or resource_id
    location = _clean_graph_part(origin.get("location"))
    cloud_provider_id = f"provider:{provider}"
    resource_node_id = f"cloud_resource:{provider}:{service}:{resource_type}:{resource_id}"
    data_sources = sorted({data_source, str(agent_dict.get("source") or "").strip(), f"cloud:{provider}"} - {""})
    scope = origin.get("scope", {})
    if not isinstance(scope, dict):
        scope = {}
    org_key, org_id = _first_cloud_scope_value(scope, "org_id", "organization_id", "management_group_id")
    account_key, account_id = _first_cloud_scope_value(
        scope,
        "account_id",
        "aws_account_id",
        "subscription_id",
        "project_id",
        "tenant_id",
    )
    account_id = account_id or _clean_graph_part(origin.get("account_id")) or _clean_graph_part(origin.get("subscription_id"))
    org_node_id = _identity_node_id(EntityType.ORG, provider, org_id) if org_id else ""
    account_node_id = _identity_node_id(EntityType.ACCOUNT, provider, account_id) if account_id else ""

    graph.add_node(
        UnifiedNode(
            id=cloud_provider_id,
            entity_type=EntityType.PROVIDER,
            label=provider,
            attributes={"provider": provider, "source": "cloud_origin"},
            data_sources=data_sources,
        )
    )
    graph.add_node(
        UnifiedNode(
            id=resource_node_id,
            entity_type=EntityType.CLOUD_RESOURCE,
            label=resource_name,
            attributes={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
                "cloud_provider": provider,
                "cloud_service": service,
                "location": location,
                "scope": origin.get("scope", {}),
                "network": origin.get("network", {}),
                "cloud_origin": origin,
                "cloud_state": agent_metadata.get("cloud_state"),
                "cloud_scope": agent_metadata.get("cloud_scope"),
                "cloud_timestamps": agent_metadata.get("cloud_timestamps"),
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface=service),
        )
    )
    if org_node_id:
        _add_identity_node(
            graph,
            EntityType.ORG,
            org_id,
            provider,
            data_sources,
            label=org_id,
            org_id=org_id,
            scope_key=org_key,
            cloud_provider=provider,
            cloud_origin=origin,
        )
        _add_rel_edge(
            graph,
            cloud_provider_id,
            org_node_id,
            RelationshipType.HOSTS,
            {"source": "cloud_origin", "provider": provider, "scope_key": org_key},
        )
    if account_node_id:
        _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account_id,
            provider,
            data_sources,
            label=account_id,
            account_id=account_id,
            scope_key=account_key or "account_id",
            cloud_provider=provider,
            cloud_origin=origin,
        )
        _add_rel_edge(
            graph,
            cloud_provider_id,
            account_node_id,
            RelationshipType.HOSTS,
            {"source": "cloud_origin", "provider": provider, "scope_key": account_key or "account_id"},
        )
        if org_node_id:
            _add_rel_edge(
                graph,
                account_node_id,
                org_node_id,
                RelationshipType.PART_OF,
                {"source": "cloud_origin", "provider": provider, "scope_key": org_key},
            )
        _add_rel_edge(
            graph,
            account_node_id,
            resource_node_id,
            RelationshipType.HOSTS,
            {"source": "cloud_origin", "provider": provider, "scope_key": account_key or "account_id"},
        )
        _add_rel_edge(
            graph,
            account_node_id,
            resource_node_id,
            RelationshipType.CONTAINS,
            {"source": "cloud_origin", "provider": provider, "scope_key": account_key or "account_id"},
        )
    _add_rel_edge(
        graph,
        cloud_provider_id,
        resource_node_id,
        RelationshipType.HOSTS,
        {"source": "cloud_origin", "provider": provider, "service": service},
    )
    _add_rel_edge(
        graph,
        resource_node_id,
        agent_id,
        RelationshipType.HOSTS,
        {"source": "cloud_origin", "resource_id": resource_id},
    )

    principal = agent_metadata.get("cloud_principal")
    if not isinstance(principal, dict):
        return
    principal_id = _clean_graph_part(principal.get("principal_id")) or _clean_graph_part(principal.get("principal_name"))
    if not principal_id:
        return
    principal_name = _clean_graph_part(principal.get("principal_name")) or principal_id
    principal_type = principal.get("principal_type", "")
    principal_entity_type = _identity_entity_type(principal_type)
    principal_node_id = _add_identity_node(
        graph,
        principal_entity_type,
        principal_id,
        provider,
        data_sources,
        label=principal_name,
        principal_id=principal_id,
        principal_name=principal_name,
        principal_type=principal_type,
        tenant_id=principal.get("tenant_id", ""),
        source_field=principal.get("source_field", ""),
        cloud_provider=provider,
        cloud_service=service,
        cloud_principal=principal,
    )
    if account_node_id:
        _add_rel_edge(
            graph,
            principal_node_id,
            account_node_id,
            RelationshipType.MEMBER_OF,
            {"source": "cloud_principal", "principal_type": principal_type},
        )
    _add_rel_edge(
        graph,
        principal_node_id,
        resource_node_id,
        RelationshipType.MANAGES,
        {"source": "cloud_principal", "principal_type": principal_type},
    )
    _add_rel_edge(
        graph,
        principal_node_id,
        resource_node_id,
        RelationshipType.CAN_ACCESS,
        {"source": "cloud_principal", "principal_type": principal_type},
    )
    for policy in _policy_entries(principal):
        policy_node_id = _add_identity_node(
            graph,
            EntityType.POLICY,
            policy["id"],
            provider,
            data_sources,
            label=policy["name"],
            policy_id=policy["id"],
            policy_name=policy["name"],
            privilege_level=policy.get("privilege_level", "unknown"),
            cloud_provider=provider,
        )
        _add_rel_edge(
            graph,
            principal_node_id,
            policy_node_id,
            RelationshipType.ATTACHED,
            {"source": "cloud_principal", "principal_type": principal_type},
        )
    for trust in _trust_entries(principal):
        trust_entity_type = _identity_entity_type(trust["type"])
        trust_node_id = _add_identity_node(
            graph,
            trust_entity_type,
            trust["id"],
            provider,
            data_sources,
            label=trust["name"],
            principal_id=trust["id"],
            principal_name=trust["name"],
            principal_type=trust["type"],
            cloud_provider=provider,
        )
        relationship = (
            RelationshipType.CROSS_ACCOUNT_TRUST
            if trust["relationship"] == RelationshipType.CROSS_ACCOUNT_TRUST.value
            else RelationshipType.TRUSTS
        )
        _add_rel_edge(
            graph,
            principal_node_id,
            trust_node_id,
            relationship,
            {
                "source": "cloud_principal_trust",
                "principal_type": principal_type,
                "trusted_principal_type": trust["type"],
                "source_field": trust["source_field"],
            },
        )
    # Direct principal → agent edge so single-hop "which principals can
    # reach this agent?" queries don't have to traverse the intermediate
    # cloud_resource node. The intermediate edges (principal → resource,
    # resource → agent) above stay so the lineage is fully reconstructable.
    # `via` records that the relationship is mediated by a cloud_resource
    # so consumers can distinguish direct ownership from cloud-mediated
    # operation when they need to.
    _add_rel_edge(
        graph,
        principal_node_id,
        agent_id,
        RelationshipType.MANAGES,
        {
            "source": "cloud_principal",
            "principal_type": principal_type,
            "via": resource_node_id,
        },
    )


def _iter_cloud_inventories(raw: Any) -> list[dict[str, Any]]:
    """Yield each cloud-inventory payload from a single dict or a list.

    The ``cloud_inventory`` report section may carry one provider's payload
    (AWS, the original shape) or a list of per-provider payloads (AWS + Azure +
    GCP). Non-dict entries are ignored.
    """
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _normalize_cloud_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Map a per-provider inventory payload onto the canonical builder shape.

    AWS payloads already use the canonical keys (``buckets`` / ``instances`` /
    ``security_groups`` / ``roles`` / ``users``). Azure and GCP payloads carry
    provider-native keys (``storage_accounts`` / ``firewalls`` /
    ``managed_identities`` / ``service_accounts`` …); this translates them into
    the same lists, tagging each resource with ``_service`` / ``_kind`` /
    ``_label`` / ``_resource_type`` so node IDs and the CNAPP data-store keyword
    match stay provider-accurate. Unknown providers pass through untouched.
    """
    provider = _clean_graph_part(inventory.get("provider")).lower()
    if provider == "azure":
        return _normalize_azure_inventory(inventory)
    if provider == "gcp":
        return _normalize_gcp_inventory(inventory)
    return inventory


def _normalize_azure_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Translate an Azure inventory payload into the canonical builder shape."""
    buckets: list[dict[str, Any]] = []
    for account in inventory.get("storage_accounts", []) or []:
        if not isinstance(account, dict):
            continue
        buckets.append(
            {
                **account,
                "_service": "storage",
                "_kind": "azure-storage-account",
                # "storage account" is a CNAPP data-store keyword.
                "_label": "storage account",
            }
        )
    groups: list[dict[str, Any]] = []
    for nsg in inventory.get("security_groups", []) or []:
        if not isinstance(nsg, dict):
            continue
        groups.append({**nsg, "_service": "network", "_kind": "azure-nsg", "_resource_type": "network-security-group"})
    instances: list[dict[str, Any]] = []
    for vm in inventory.get("instances", []) or []:
        if not isinstance(vm, dict):
            continue
        instances.append({**vm, "_service": "compute", "_kind": "azure-vm", "_label": "vm"})
    principals = [p for p in inventory.get("managed_identities", []) or [] if isinstance(p, dict)]
    principals.extend(p for p in inventory.get("service_principals", []) or [] if isinstance(p, dict))
    identity_groups = [g for g in inventory.get("entra_groups", []) or [] if isinstance(g, dict)]
    return {
        **inventory,
        "buckets": buckets,
        "security_groups": groups,
        "instances": instances,
        "roles": [],
        "users": principals,
        "groups": identity_groups,
    }


def _normalize_gcp_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Translate a GCP inventory payload into the canonical builder shape."""
    buckets: list[dict[str, Any]] = []
    for bucket in inventory.get("buckets", []) or []:
        if not isinstance(bucket, dict):
            continue
        # "bucket" is already a CNAPP data-store keyword; keep gcs service tag.
        buckets.append({**bucket, "_service": "gcs", "_kind": "gcs-bucket", "_label": "gcs bucket"})
    groups: list[dict[str, Any]] = []
    for firewall in inventory.get("firewalls", []) or []:
        if not isinstance(firewall, dict):
            continue
        groups.append({**firewall, "_service": "compute", "_kind": "gcp-firewall", "_resource_type": "firewall"})
    instances: list[dict[str, Any]] = []
    for instance in inventory.get("instances", []) or []:
        if not isinstance(instance, dict):
            continue
        instances.append({**instance, "_service": "compute", "_kind": "gce-instance", "_label": "gce"})
    principals = [p for p in inventory.get("service_accounts", []) or [] if isinstance(p, dict)]
    identity_groups = [g for g in inventory.get("groups", []) or [] if isinstance(g, dict)]
    return {
        **inventory,
        "buckets": buckets,
        "security_groups": groups,
        "instances": instances,
        "roles": [],
        "users": principals,
        "groups": identity_groups,
    }


def _add_snowflake_object_graph(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake tables/views + their lineage into the graph.

    Each table/view becomes a ``DATA_STORE`` node owned by the Snowflake
    account; ``OBJECT_DEPENDENCIES`` become ``DEPENDS_ON`` edges (the referencing
    object depends on the referenced one — e.g. a view on its base table). This
    is the data-lineage layer: blast-radius and exfil analysis can walk from a
    table to everything derived from it. Never raises; a missing/empty payload
    is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-objects")
    if prepared is None:
        return
    account, data_sources = prepared

    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            "snowflake",
            data_sources,
            label=account or "snowflake",
            account_id=account,
            cloud_provider="snowflake",
            source="snowflake-objects",
        )

    def _obj_node_id(fqn: str) -> str:
        return f"data_store:snowflake:{fqn}"

    seen: set[str] = set()

    def _ensure_object(fqn: str, *, object_type: str = "object", attributes: dict[str, Any] | None = None) -> str:
        node_id = _obj_node_id(fqn)
        if node_id in seen:
            return node_id
        seen.add(node_id)
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.DATA_STORE,
                label=f"{object_type}: {fqn}",
                attributes={
                    "fqn": fqn,
                    "object_type": object_type,
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    **(attributes or {}),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        if account_node_id:
            _add_rel_edge(graph, account_node_id, node_id, RelationshipType.OWNS, {"source": "snowflake-objects"})
        return node_id

    for obj in payload.get("objects", []) or []:
        if not isinstance(obj, dict):
            continue
        fqn = _clean_graph_part(obj.get("fqn"))
        if not fqn:
            continue
        _ensure_object(
            fqn,
            object_type=str(obj.get("object_type") or "object"),
            attributes={
                "database": obj.get("database"),
                "schema": obj.get("schema"),
                "row_count": obj.get("row_count"),
                "bytes": obj.get("bytes"),
            },
        )

    for dep in payload.get("dependencies", []) or []:
        if not isinstance(dep, dict):
            continue
        referencing = _clean_graph_part(dep.get("referencing_fqn"))
        referenced = _clean_graph_part(dep.get("referenced_fqn"))
        if not referencing or not referenced:
            continue
        # Dependency endpoints may not be in the objects list (e.g. SNOWFLAKE
        # system objects) — create thin nodes so the lineage edge still lands.
        src = _ensure_object(referencing, object_type=str(dep.get("referencing_domain") or "object").lower())
        tgt = _ensure_object(referenced, object_type=str(dep.get("referenced_domain") or "object").lower())
        _add_rel_edge(
            graph,
            src,
            tgt,
            RelationshipType.DEPENDS_ON,
            {"source": "snowflake-objects", "dependency_type": dep.get("dependency_type", "")},
        )

    # ── Roles + users (CIEM access layer) ──────────────────────────────
    seen_roles: set[str] = set()

    def _ensure_role(name: str) -> str:
        node_id = f"role:snowflake:{name}"
        if node_id not in seen_roles:
            seen_roles.add(node_id)
            _add_identity_node(
                graph,
                EntityType.ROLE,
                name,
                "snowflake",
                data_sources,
                label=f"role: {name}",
                role_name=name,
                cloud_provider="snowflake",
                source="snowflake-objects",
            )
        return node_id

    # Object-level grants: role HAS_PERMISSION on the object (data store).
    for grant in payload.get("grants", []) or []:
        if not isinstance(grant, dict):
            continue
        role = _clean_graph_part(grant.get("role"))
        object_fqn = _clean_graph_part(grant.get("object_fqn"))
        if not role or not object_fqn:
            continue
        _add_rel_edge(
            graph,
            _ensure_role(role),
            _ensure_object(object_fqn, object_type=str(grant.get("object_type") or "object").lower()),
            RelationshipType.HAS_PERMISSION,
            {"source": "snowflake-objects", "privilege": grant.get("privilege", "")},
        )

    # Users. ``role_memberships`` carry user→role grants; the live SHOW overlay
    # also emits role→role memberships ({role, parent}) and a top-level
    # ``users`` list (freshly-created users that have no membership yet).
    seen_users: set[str] = set()

    def _ensure_user(user_name: str, **extra: Any) -> str:
        node_id = f"user:snowflake:{user_name}"
        if node_id not in seen_users:
            seen_users.add(node_id)
            _add_identity_node(
                graph,
                EntityType.USER,
                user_name,
                "snowflake",
                data_sources,
                label=f"user: {user_name}",
                user_name=user_name,
                cloud_provider="snowflake",
                source="snowflake-objects",
                **{k: v for k, v in extra.items() if v not in (None, "")},
            )
        return node_id

    # Standalone users (no membership row yet) so new accounts graph instantly.
    for usr in payload.get("users", []) or []:
        if not isinstance(usr, dict):
            continue
        user_name = _clean_graph_part(usr.get("name"))
        if not user_name:
            continue
        _ensure_user(
            user_name,
            default_role=_clean_graph_part(usr.get("default_role")) or None,
            disabled=usr.get("disabled"),
        )

    for membership in payload.get("role_memberships", []) or []:
        if not isinstance(membership, dict):
            continue
        role = _clean_graph_part(membership.get("role"))
        if not role:
            continue
        parent = _clean_graph_part(membership.get("parent"))
        is_role_member = str(membership.get("member_type") or "").lower() == "role" or bool(parent)
        if is_role_member:
            # Role → role: the child role is a MEMBER_OF the parent and inherits
            # (ASSUMES) its privileges, so privilege chains traverse end-to-end.
            if not parent:
                continue
            child_id = _ensure_role(role)
            parent_id = _ensure_role(parent)
            _add_rel_edge(graph, child_id, parent_id, RelationshipType.MEMBER_OF, {"source": "snowflake-objects"})
            _add_rel_edge(graph, child_id, parent_id, RelationshipType.ASSUMES, {"source": "snowflake-objects"})
            continue
        # User → role: the user is a MEMBER_OF and ASSUMES the role's privileges.
        user_name = _clean_graph_part(membership.get("user"))
        if not user_name:
            continue
        user_node_id = _ensure_user(user_name)
        role_id = _ensure_role(role)
        _add_rel_edge(graph, user_node_id, role_id, RelationshipType.MEMBER_OF, {"source": "snowflake-objects"})
        _add_rel_edge(graph, user_node_id, role_id, RelationshipType.ASSUMES, {"source": "snowflake-objects"})


_EXFIL_STAGE_SERVICE = {"aws": "s3", "azure": "blob", "gcp": "gcs"}


def _add_snowflake_services(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake compute + the database/schema containment tree into the graph.

    Completes the object catalog beyond tables/views:

    * **Warehouses** → ``CLOUD_RESOURCE`` (compute) owned by the account.
    * **Databases** → ``DATA_STORE`` container owned by the account.
    * **Schemas** → ``DATA_STORE`` container; the database ``CONTAINS`` the schema.
    * Existing table/view nodes (``data_store:snowflake:DB.SCHEMA.OBJ`` from the
      object graph) are linked under their schema via ``CONTAINS``, so the graph
      renders a navigable DB → schema → table tree instead of a flat owned-by-account list.

    Never raises; missing/empty/non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-services")
    if prepared is None:
        return
    account, data_sources = prepared
    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            "snowflake",
            data_sources,
            label=account or "snowflake",
            account_id=account,
            cloud_provider="snowflake",
            source="snowflake-services",
        )

    def _own(node: UnifiedNode) -> str:
        graph.add_node(node)
        if account_node_id:
            _add_rel_edge(graph, account_node_id, node.id, RelationshipType.OWNS, {"source": "snowflake-services"})
        return node.id

    for wh in payload.get("warehouses", []) or []:
        if not isinstance(wh, dict):
            continue
        name = _clean_graph_part(wh.get("name"))
        if not name:
            continue
        _own(
            UnifiedNode(
                id=f"cloud_resource:snowflake:warehouse:{name}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"warehouse: {name}",
                attributes={
                    "resource_name": name,
                    "resource_type": "warehouse",
                    "resource_kind": "snowflake-warehouse",
                    "cloud_provider": "snowflake",
                    "size": wh.get("size"),
                    "state": wh.get("state"),
                    "auto_suspend": wh.get("auto_suspend"),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="compute"),
            )
        )

    # Database + schema containers, keyed by fqn so table nodes can attach.
    schema_node_by_fqn: dict[str, str] = {}
    db_node_by_name: dict[str, str] = {}
    for db in payload.get("databases", []) or []:
        if not isinstance(db, dict):
            continue
        name = _clean_graph_part(db.get("name"))
        if not name:
            continue
        db_id = _own(
            UnifiedNode(
                id=f"data_store:snowflake:db:{name}",
                entity_type=EntityType.DATA_STORE,
                label=f"database: {name}",
                attributes={
                    "database_name": name,
                    "object_type": "database",
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "is_container": True,
                    "retention_time": db.get("retention_time"),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        db_node_by_name[name] = db_id

    for sch in payload.get("schemas", []) or []:
        if not isinstance(sch, dict):
            continue
        fqn = _clean_graph_part(sch.get("fqn"))
        db_name = _clean_graph_part(sch.get("database_name"))
        if not fqn or not db_name:
            continue
        sch_id = f"data_store:snowflake:schema:{fqn}"
        graph.add_node(
            UnifiedNode(
                id=sch_id,
                entity_type=EntityType.DATA_STORE,
                label=f"schema: {fqn}",
                attributes={
                    "fqn": fqn,
                    "object_type": "schema",
                    "database": db_name,
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "is_container": True,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        schema_node_by_fqn[fqn] = sch_id
        # database CONTAINS schema
        parent_db_id = db_node_by_name.get(db_name)
        if parent_db_id:
            _add_rel_edge(graph, parent_db_id, sch_id, RelationshipType.CONTAINS, {"source": "snowflake-services"})

    # Link existing object-graph table/view nodes under their schema (schema CONTAINS object).
    if schema_node_by_fqn:
        for node in list(graph.nodes.values()):
            if node.entity_type != EntityType.DATA_STORE:
                continue
            obj_fqn = str(node.attributes.get("fqn") or "")
            # Only DB.SCHEMA.OBJECT (3-part) table/view nodes, not the containers themselves.
            if node.attributes.get("is_container") or obj_fqn.count(".") != 2:
                continue
            parent_schema = obj_fqn.rsplit(".", 1)[0]
            parent_sch_id = schema_node_by_fqn.get(parent_schema)
            if parent_sch_id:
                _add_rel_edge(graph, parent_sch_id, node.id, RelationshipType.CONTAINS, {"source": "snowflake-services"})


def _add_snowflake_organization(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote the Snowflake Organization → Accounts roll-up into the graph.

    The Snowflake analogue of :func:`_add_aws_organization` and
    :func:`_add_gcp_organization`: multiple Snowflake accounts roll up under a
    parent ``ORG`` node via ``CONTAINS`` so the estate is traversable top-down.

    The account nodes reuse the same ``account:snowflake:<locator>`` id that
    :func:`_add_snowflake_services` (and the rest of the Snowflake graph) emits, so
    the org backbone stitches onto any already-inventoried account graph rather
    than creating a parallel island. When org data is absent or non-ok the call is
    a no-op and the account stays the root — single-account behavior is unchanged.

    Never raises; a non-ok / non-dict payload is a no-op.
    """
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return
    accounts = payload.get("accounts") or []
    if not accounts:
        return
    data_sources = sorted({data_source, "snowflake-organizations"} - {""})
    org_name = _clean_graph_part(payload.get("org_name")) or "organization"
    org_node_id = f"org:snowflake:{org_name}"
    graph.add_node(
        UnifiedNode(
            id=org_node_id,
            entity_type=EntityType.ORG,
            label=f"Snowflake org: {org_name}",
            attributes={
                "org_name": org_name,
                "cloud_provider": "snowflake",
                "account_count": len([a for a in accounts if isinstance(a, dict)]),
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
        )
    )

    for member in accounts:
        if not isinstance(member, dict):
            continue
        locator = _clean_graph_part(member.get("locator"))
        if not locator:
            continue
        account_node = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            locator,
            "snowflake",
            data_sources,
            label=_clean_graph_part(member.get("name")) or locator,
            account_id=locator,
            cloud_provider="snowflake",
            account_name=_clean_graph_part(member.get("name")),
            region=_clean_graph_part(member.get("region")),
            edition=_clean_graph_part(member.get("edition")),
            source="snowflake-organizations",
        )
        _add_rel_edge(graph, org_node_id, account_node, RelationshipType.CONTAINS, {"source": "snowflake-organizations"})


_SF_EXTERNAL_BUCKET_SERVICE = {"aws": "s3", "azure": "blob", "gcp": "gcs"}


def _add_snowflake_external_data(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake open-table-format + external data into the graph.

    * **Iceberg tables** → ``DATA_STORE``; when the base location is a cloud
      bucket, ``EXPOSED_TO`` that bucket node (same id a cloud scan emits — the
      cross-cloud stitch), so off-account Iceberg data is traversable.
    * **External tables** → ``DATA_STORE``; ``DEPENDS_ON`` the stage they read
      from (which the exfil layer links onward to the bucket).

    Never raises; a non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-external-data")
    if prepared is None:
        return
    account, data_sources = prepared
    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            "snowflake",
            data_sources,
            label=account or "snowflake",
            account_id=account,
            cloud_provider="snowflake",
            source="snowflake-external-data",
        )

    def _own_data_store(node_id: str, label: str, attrs: dict[str, Any]) -> str:
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.DATA_STORE,
                label=label,
                attributes={"cloud_provider": "snowflake", "is_data_store": True, **attrs},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        if account_node_id:
            _add_rel_edge(graph, account_node_id, node_id, RelationshipType.OWNS, {"source": "snowflake-external-data"})
        return node_id

    for tbl in payload.get("iceberg_tables", []) or []:
        if not isinstance(tbl, dict):
            continue
        fqn = _clean_graph_part(tbl.get("fqn")) or _clean_graph_part(tbl.get("name"))
        if not fqn:
            continue
        node_id = _own_data_store(
            f"data_store:snowflake:iceberg:{fqn}",
            f"iceberg table: {fqn}",
            {
                "fqn": fqn,
                "object_type": "iceberg_table",
                "table_format": "iceberg",
                "catalog": tbl.get("catalog"),
                "catalog_source": tbl.get("catalog_source"),
                "base_location": tbl.get("base_location"),
            },
        )
        cloud = _clean_graph_part(tbl.get("cloud_provider"))
        bucket = _clean_graph_part(tbl.get("bucket"))
        if cloud and bucket:
            service = _SF_EXTERNAL_BUCKET_SERVICE.get(cloud, "storage")
            bucket_id = f"cloud_resource:{cloud}:{service}:bucket:{bucket}"
            if bucket_id not in graph.nodes:
                graph.add_node(
                    UnifiedNode(
                        id=bucket_id,
                        entity_type=EntityType.CLOUD_RESOURCE,
                        label=f"bucket: {bucket}",
                        attributes={
                            "resource_name": bucket,
                            "resource_type": "bucket",
                            "resource_kind": f"{service}-bucket",
                            "cloud_provider": cloud,
                            "cloud_service": service,
                        },
                        data_sources=data_sources,
                        dimensions=NodeDimensions(cloud_provider=cloud, surface=service),
                    )
                )
            _add_rel_edge(
                graph,
                node_id,
                bucket_id,
                RelationshipType.EXPOSED_TO,
                {"source": "snowflake-external-data", "channel": "iceberg-base-location"},
            )

    for tbl in payload.get("external_tables", []) or []:
        if not isinstance(tbl, dict):
            continue
        fqn = _clean_graph_part(tbl.get("fqn")) or _clean_graph_part(tbl.get("name"))
        if not fqn:
            continue
        node_id = _own_data_store(
            f"data_store:snowflake:external_table:{fqn}",
            f"external table: {fqn}",
            {"fqn": fqn, "object_type": "external_table", "location": tbl.get("location")},
        )
        stage = _clean_graph_part(tbl.get("stage"))
        if stage:
            stage_name = stage.split(".")[-1]
            stage_id = f"cloud_resource:snowflake:stage:{stage_name}"
            if stage_id not in graph.nodes:
                graph.add_node(
                    UnifiedNode(
                        id=stage_id,
                        entity_type=EntityType.CLOUD_RESOURCE,
                        label=f"external stage: {stage_name}",
                        attributes={"cloud_provider": "snowflake", "resource_type": "external-stage"},
                        data_sources=data_sources,
                        dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
                    )
                )
            _add_rel_edge(
                graph,
                node_id,
                stage_id,
                RelationshipType.DEPENDS_ON,
                {"source": "snowflake-external-data", "via": "external-table-stage"},
            )


def _add_snowflake_integrations(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake account integrations into the graph (external-trust layer).

    Each integration is the account's connection to the outside world. They
    become ``CLOUD_RESOURCE`` nodes owned by the account, carrying the category
    (STORAGE / API / EXTERNAL_ACCESS / SECURITY / NOTIFICATION / CATALOG) and an
    ``internet_exposed`` flag for the egress-bearing kinds, so blast-radius and
    the visual surface the account's outbound/federation surface. Never raises;
    a non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-integrations")
    if prepared is None:
        return
    account, data_sources = prepared
    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            "snowflake",
            data_sources,
            label=account or "snowflake",
            account_id=account,
            cloud_provider="snowflake",
            source="snowflake-integrations",
        )

    egress_categories = {"STORAGE", "API", "EXTERNAL_ACCESS", "NOTIFICATION", "CATALOG"}
    for integ in payload.get("integrations", []) or []:
        if not isinstance(integ, dict):
            continue
        name = _clean_graph_part(integ.get("name"))
        if not name:
            continue
        category = str(integ.get("category", "") or "").upper()
        node_id = f"cloud_resource:snowflake:integration:{name}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"integration: {name}",
                attributes={
                    "resource_name": name,
                    "resource_type": "integration",
                    "resource_kind": "snowflake-integration",
                    "cloud_provider": "snowflake",
                    "integration_type": integ.get("type"),
                    "integration_category": category,
                    "enabled": bool(integ.get("enabled")),
                    "internet_exposed": bool(integ.get("enabled")) and category in egress_categories,
                    "external_access": category == "EXTERNAL_ACCESS",
                    "identity_federation": category == "SECURITY",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="network"),
            )
        )
        if account_node_id:
            _add_rel_edge(graph, account_node_id, node_id, RelationshipType.OWNS, {"source": "snowflake-integrations"})


def _add_snowflake_pipeline(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake data-pipeline + automation objects into the graph.

    * **Tasks** → ``CLOUD_RESOURCE`` (automation); ``DEPENDS_ON`` the warehouse
      it runs on, ``ASSUMES`` the owner role (privilege surface).
    * **Streams** → ``DATA_STORE``; ``DEPENDS_ON`` the source table it tracks.
    * **Pipes** → ``CLOUD_RESOURCE`` (ingestion); ``DEPENDS_ON`` the stage it
      reads from — which the exfil layer links onward to the actual cloud bucket,
      so the ingress path is traversable end to end.

    Endpoints (warehouse/table/stage) may already exist from other layers; a thin
    node is created only when absent. Never raises; non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-pipeline")
    if prepared is None:
        return
    account, data_sources = prepared
    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            "snowflake",
            data_sources,
            label=account or "snowflake",
            account_id=account,
            cloud_provider="snowflake",
            source="snowflake-pipeline",
        )

    def _own(node: UnifiedNode) -> str:
        graph.add_node(node)
        if account_node_id:
            _add_rel_edge(graph, account_node_id, node.id, RelationshipType.OWNS, {"source": "snowflake-pipeline"})
        return node.id

    def _thin(node_id: str, entity_type: EntityType, label: str, surface: str) -> None:
        if node_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=node_id,
                    entity_type=entity_type,
                    label=label,
                    attributes={"cloud_provider": "snowflake"},
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider="snowflake", surface=surface),
                )
            )

    for task in payload.get("tasks", []) or []:
        if not isinstance(task, dict):
            continue
        fqn = _clean_graph_part(task.get("fqn")) or _clean_graph_part(task.get("name"))
        if not fqn:
            continue
        task_id = _own(
            UnifiedNode(
                id=f"cloud_resource:snowflake:task:{fqn}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"task: {fqn}",
                attributes={
                    "resource_name": fqn,
                    "resource_type": "task",
                    "resource_kind": "snowflake-task",
                    "cloud_provider": "snowflake",
                    "schedule": task.get("schedule"),
                    "state": task.get("state"),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="compute"),
            )
        )
        warehouse = _clean_graph_part(task.get("warehouse"))
        if warehouse:
            wh_id = f"cloud_resource:snowflake:warehouse:{warehouse}"
            _thin(wh_id, EntityType.CLOUD_RESOURCE, f"warehouse: {warehouse}", "compute")
            _add_rel_edge(graph, task_id, wh_id, RelationshipType.DEPENDS_ON, {"source": "snowflake-pipeline", "via": "warehouse"})
        owner = _clean_graph_part(task.get("owner"))
        if owner:
            role_id = f"role:snowflake:{owner}"
            _thin(role_id, EntityType.ROLE, f"role: {owner}", "identity")
            _add_rel_edge(graph, task_id, role_id, RelationshipType.ASSUMES, {"source": "snowflake-pipeline", "runs_as": owner})

    for stream in payload.get("streams", []) or []:
        if not isinstance(stream, dict):
            continue
        fqn = _clean_graph_part(stream.get("fqn")) or _clean_graph_part(stream.get("name"))
        if not fqn:
            continue
        stream_id = _own(
            UnifiedNode(
                id=f"data_store:snowflake:stream:{fqn}",
                entity_type=EntityType.DATA_STORE,
                label=f"stream: {fqn}",
                attributes={
                    "fqn": fqn,
                    "object_type": "stream",
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "stale": bool(stream.get("stale")),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        source = _clean_graph_part(stream.get("source_fqn"))
        if source:
            src_id = f"data_store:snowflake:{source}"
            _thin(src_id, EntityType.DATA_STORE, f"object: {source}", "data")
            _add_rel_edge(graph, stream_id, src_id, RelationshipType.DEPENDS_ON, {"source": "snowflake-pipeline", "via": "cdc-source"})

    for pipe in payload.get("pipes", []) or []:
        if not isinstance(pipe, dict):
            continue
        fqn = _clean_graph_part(pipe.get("fqn")) or _clean_graph_part(pipe.get("name"))
        if not fqn:
            continue
        pipe_id = _own(
            UnifiedNode(
                id=f"cloud_resource:snowflake:pipe:{fqn}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"pipe: {fqn}",
                attributes={
                    "resource_name": fqn,
                    "resource_type": "pipe",
                    "resource_kind": "snowflake-pipe",
                    "cloud_provider": "snowflake",
                    "auto_ingest": bool(pipe.get("auto_ingest")),
                    "integration": pipe.get("integration"),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        stage = _clean_graph_part(pipe.get("stage"))
        if stage:
            stage_name = stage.split(".")[-1]
            stage_id = f"cloud_resource:snowflake:stage:{stage_name}"
            _thin(stage_id, EntityType.CLOUD_RESOURCE, f"external stage: {stage_name}", "data")
            _add_rel_edge(graph, pipe_id, stage_id, RelationshipType.DEPENDS_ON, {"source": "snowflake-pipeline", "via": "ingest-stage"})


def _add_snowflake_identity(graph: UnifiedGraph, login_payload: Any, auth_payload: Any, data_source: str) -> None:
    """Enrich Snowflake user nodes with identity-threat + auth-posture signal.

    Closes the gap where login-anomaly detection and auth-posture inventory
    reached JSON but never the graph, so a flagged/weak identity was invisible
    to the visual and blast-radius. For each affected user this merges threat +
    posture attributes onto the existing ``user:snowflake:<name>`` node (a thin
    node is created when the user appears only in the threat feed), tags the
    relevant **MITRE ATT&CK** technique, and raises node severity. Never raises;
    missing/empty/non-ok payloads are a no-op.

    Technique mapping:
      * impossible travel / high distinct-IP → ``T1078`` (Valid Accounts)
      * failed-login burst → ``T1110`` (Brute Force)
      * password user without MFA → ``T1078`` (Valid Accounts)
    """
    login_ok = isinstance(login_payload, dict) and login_payload.get("status") == "ok"
    auth_ok = isinstance(auth_payload, dict) and auth_payload.get("status") == "ok"
    if not login_ok and not auth_ok:
        return

    data_sources = sorted({data_source, "snowflake-identity"} - {""})

    def _user_node_id(name: str) -> str:
        return f"user:snowflake:{name}"

    def _enrich(name: str, attrs: dict[str, Any], *, severity: str | None, mitre: list[str]) -> None:
        name = _clean_graph_part(name)
        if not name:
            return
        node = UnifiedNode(
            id=_user_node_id(name),
            entity_type=EntityType.USER,
            label=f"user: {name}",
            severity=severity or "",
            attributes={"user_name": name, "cloud_provider": "snowflake", **attrs},
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
            compliance_tags=sorted(set(mitre)),
        )
        graph.add_node(node)  # merges onto an existing user node (attrs/tags/severity union)

    if login_ok:
        rapid_by_user = {
            _clean_graph_part(it.get("user")): int(it.get("rapid_switches", 0) or 0)
            for it in login_payload.get("impossible_travel", []) or []
            if isinstance(it, dict)
        }
        failed_by_user = {
            _clean_graph_part(b.get("user")): int(b.get("failed", 0) or 0)
            for b in login_payload.get("failed_bursts", []) or []
            if isinstance(b, dict)
        }
        for u in login_payload.get("per_user", []) or []:
            if not isinstance(u, dict):
                continue
            name = _clean_graph_part(u.get("user"))
            if not name:
                continue
            impossible = name in rapid_by_user
            failed = failed_by_user.get(name, int(u.get("failed", 0) or 0))
            distinct_ips = int(u.get("distinct_ips", 0) or 0)
            mitre: list[str] = []
            sev = None
            if impossible:
                mitre.append("T1078")  # Valid Accounts
                sev = "high"
            if failed_by_user.get(name):
                mitre.append("T1110")  # Brute Force
                sev = sev or "medium"
            _enrich(
                name,
                {
                    "impossible_travel": impossible,
                    "rapid_ip_switches": rapid_by_user.get(name, 0),
                    "distinct_login_ips": distinct_ips,
                    "failed_logins": failed,
                    "identity_threat": bool(mitre),
                },
                severity=sev,
                mitre=mitre,
            )

    if auth_ok:
        account_np = bool(auth_payload.get("account_network_policy"))
        for u in auth_payload.get("users", []) or []:
            if not isinstance(u, dict):
                continue
            name = _clean_graph_part(u.get("name"))
            if not name:
                continue
            auth_methods = list(u.get("auth_methods") or [])
            has_mfa = bool(u.get("has_mfa"))
            disabled = bool(u.get("disabled"))
            user_type = str(u.get("user_type", "") or "").upper()
            weak = not disabled and "password" in auth_methods and not has_mfa and user_type in ("PERSON", "UNKNOWN", "")
            _enrich(
                name,
                {
                    "auth_methods": auth_methods,
                    "has_mfa": has_mfa,
                    "disabled": disabled,
                    "user_type": user_type or "unknown",
                    "account_network_policy": account_np,
                    "weak_auth": weak,
                },
                severity="high" if weak else None,
                mitre=["T1078"] if weak else [],  # Valid Accounts (weak credential control)
            )


def _add_snowflake_exfil(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake egress surfaces into the graph (exfil layer).

    Three node/edge families that model how data leaves the account:

    - **Outbound shares** → ``DATA_STORE`` for the shared database, ``EXPOSED_TO``
      each consumer ``ACCOUNT`` (a Marketplace listing reaches an open consumer
      set, modeled as a single internet-reachable consumer).
    - **External stages** → ``CLOUD_RESOURCE`` stage node, ``EXPOSED_TO`` the
      destination bucket. The bucket id matches the scheme an AWS/Azure/GCP scan
      emits (``cloud_resource:{cloud}:{service}:bucket:{name}``), so when both a
      cloud scan and this Snowflake scan run, the edge **stitches the two clouds'
      graphs together** rather than landing on a thin node.
    - **Sensitive objects** → ``DATA_STORE`` carrying a ``sensitivity`` attribute
      and ``is_protected`` (masking/row-access coverage).

    Never raises; a missing/empty/non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-exfil")
    if prepared is None:
        return
    account, data_sources = prepared
    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            "snowflake",
            data_sources,
            label=account or "snowflake",
            account_id=account,
            cloud_provider="snowflake",
            source="snowflake-exfil",
        )

    def _owned(node: UnifiedNode) -> str:
        graph.add_node(node)
        if account_node_id:
            _add_rel_edge(graph, account_node_id, node.id, RelationshipType.OWNS, {"source": "snowflake-exfil"})
        return node.id

    # ── Outbound shares → consumer accounts ────────────────────────────
    for share in payload.get("outbound_shares", []) or []:
        if not isinstance(share, dict):
            continue
        share_name = _clean_graph_part(share.get("share_name"))
        if not share_name:
            continue
        db = _clean_graph_part(share.get("database_name"))
        is_marketplace = bool(share.get("is_marketplace"))
        share_id = _owned(
            UnifiedNode(
                id=f"data_store:snowflake:share:{share_name}",
                entity_type=EntityType.DATA_STORE,
                label=f"outbound share: {share_name}",
                attributes={
                    "share_name": share_name,
                    "database": db,
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "is_outbound_share": True,
                    "is_marketplace": is_marketplace,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        consumers = list(share.get("consumers") or [])
        if is_marketplace and not consumers:
            consumers = ["public-marketplace"]
        for consumer in consumers:
            consumer = _clean_graph_part(consumer)
            if not consumer:
                continue
            consumer_id = _add_identity_node(
                graph,
                EntityType.ACCOUNT,
                consumer,
                "snowflake",
                data_sources,
                label=f"consumer account: {consumer}",
                account_id=consumer,
                cloud_provider="snowflake",
                is_external_consumer=True,
                internet_exposed=consumer == "public-marketplace",
            )
            _add_rel_edge(
                graph,
                share_id,
                consumer_id,
                RelationshipType.EXPOSED_TO,
                {"source": "snowflake-exfil", "channel": "data-share", "marketplace": is_marketplace},
            )

    # ── External stages → destination buckets (cross-cloud stitch) ─────
    for stage in payload.get("external_stages", []) or []:
        if not isinstance(stage, dict):
            continue
        stage_name = _clean_graph_part(stage.get("stage_name"))
        bucket = _clean_graph_part(stage.get("bucket"))
        cloud = _clean_graph_part(stage.get("cloud_provider"))
        if not stage_name or not bucket or not cloud:
            continue
        stage_id = _owned(
            UnifiedNode(
                id=f"cloud_resource:snowflake:stage:{stage_name}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"external stage: {stage_name}",
                attributes={
                    "resource_name": stage_name,
                    "resource_type": "external-stage",
                    "resource_kind": "snowflake-external-stage",
                    "cloud_provider": "snowflake",
                    "destination_cloud": cloud,
                    "destination_bucket": bucket,
                    "url": _clean_graph_part(stage.get("url")),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        service = _EXFIL_STAGE_SERVICE.get(cloud, "storage")
        bucket_node_id = f"cloud_resource:{cloud}:{service}:bucket:{bucket}"
        if bucket_node_id not in graph.nodes:
            # Thin destination node — a cloud scan, if also run, owns the rich one.
            graph.add_node(
                UnifiedNode(
                    id=bucket_node_id,
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=f"bucket: {bucket}",
                    attributes={
                        "resource_name": bucket,
                        "resource_type": "bucket",
                        "resource_kind": f"{service}-bucket",
                        "cloud_provider": cloud,
                        "cloud_service": service,
                    },
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider=cloud, surface=service),
                )
            )
        _add_rel_edge(
            graph,
            stage_id,
            bucket_node_id,
            RelationshipType.EXPOSED_TO,
            {"source": "snowflake-exfil", "channel": "external-stage", "destination_cloud": cloud},
        )

    # ── Sensitive objects → DATA_STORE with sensitivity ────────────────
    for obj in payload.get("sensitive_objects", []) or []:
        if not isinstance(obj, dict):
            continue
        fqn = _clean_graph_part(obj.get("fqn"))
        if not fqn:
            continue
        _owned(
            UnifiedNode(
                id=f"data_store:snowflake:{fqn}",
                entity_type=EntityType.DATA_STORE,
                label=f"sensitive: {fqn}",
                attributes={
                    "fqn": fqn,
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    "sensitivity": _clean_graph_part(obj.get("sensitivity")) or "sensitive",
                    "tagged_columns": obj.get("tagged_columns"),
                    "is_protected": bool(obj.get("is_protected")),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )


def _add_snowflake_governance(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake governance telemetry into the graph (CIEM read-access layer).

    De-duplicated against ``_add_snowflake_object_graph`` (grants + role
    memberships) and ``_add_snowflake_exfil`` (sensitivity tags): only the
    non-redundant value is wired here.

    - **ACCESS_HISTORY** → for each ``(user, object)`` pair, a ``USER`` node
      ``ACCESSED`` the object's ``DATA_STORE`` node. The data-store id matches the
      scheme the object/exfil layers emit (``data_store:snowflake:{fqn}``), so the
      edge lands on the existing object node rather than a duplicate. Records are
      collapsed per ``(user, object, write?)`` so a year of reads becomes a handful
      of edges, not thousands.
    - **CORTEX_AGENT_USAGE_HISTORY** → one ``AGENT`` node per distinct agent name,
      ``OWNS``-attached to the account, carrying aggregate telemetry (calls, tokens,
      credits) as attributes — not one node per call.
    - **Derived findings** are converged into the unified findings stream by
      ``GraphIndices.to_findings`` (``_snowflake_governance_findings``), not into
      nodes, so ``--fail-on-severity`` sees them.

    Never raises; a missing/empty/non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-governance")
    if prepared is None:
        return
    account, data_sources = prepared

    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            "snowflake",
            data_sources,
            label=account or "snowflake",
            account_id=account,
            cloud_provider="snowflake",
            source="snowflake-governance",
        )

    # ── ACCESS_HISTORY: user ACCESSED data store (collapsed per user+object) ──
    seen_users: set[str] = set()
    seen_access: set[tuple[str, str, bool]] = set()

    def _ensure_user(name: str) -> str:
        node_id = f"user:snowflake:{name}"
        if node_id not in seen_users:
            seen_users.add(node_id)
            _add_identity_node(
                graph,
                EntityType.USER,
                name,
                "snowflake",
                data_sources,
                label=f"user: {name}",
                user_name=name,
                cloud_provider="snowflake",
                source="snowflake-governance",
            )
        return node_id

    for rec in payload.get("access_records", []) or []:
        if not isinstance(rec, dict):
            continue
        user_name = _clean_graph_part(rec.get("user_name"))
        object_name = _clean_graph_part(rec.get("object_name"))
        if not user_name or not object_name:
            continue
        is_write = bool(rec.get("is_write"))
        key = (user_name, object_name, is_write)
        if key in seen_access:
            continue
        seen_access.add(key)
        object_node_id = f"data_store:snowflake:{object_name}"
        if object_node_id not in graph.nodes:
            # Thin object node — the object/exfil layers, if also run, own the
            # rich one (same id → merges, no duplicate).
            graph.add_node(
                UnifiedNode(
                    id=object_node_id,
                    entity_type=EntityType.DATA_STORE,
                    label=f"{_clean_graph_part(rec.get('object_type')) or 'object'}: {object_name}",
                    attributes={
                        "fqn": object_name,
                        "object_type": _clean_graph_part(rec.get("object_type")) or "object",
                        "cloud_provider": "snowflake",
                        "is_data_store": True,
                    },
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
                )
            )
            if account_node_id:
                _add_rel_edge(graph, account_node_id, object_node_id, RelationshipType.OWNS, {"source": "snowflake-governance"})
        _add_rel_edge(
            graph,
            _ensure_user(user_name),
            object_node_id,
            RelationshipType.ACCESSED,
            {
                "source": "snowflake-governance",
                "operation": _clean_graph_part(rec.get("operation")),
                "is_write": is_write,
                "role_name": _clean_graph_part(rec.get("role_name")),
            },
        )

    # ── CORTEX_AGENT_USAGE_HISTORY: one AGENT node per name, aggregated ──────
    agent_aggregate: dict[str, dict[str, Any]] = {}
    for rec in payload.get("agent_usage", []) or []:
        if not isinstance(rec, dict):
            continue
        agent_name = _clean_graph_part(rec.get("agent_name"))
        if not agent_name:
            continue
        agg = agent_aggregate.setdefault(
            agent_name,
            {"calls": 0, "total_tokens": 0, "credits_used": 0.0, "tool_calls": 0, "models": set(), "users": set()},
        )
        agg["calls"] += 1
        agg["total_tokens"] += int(rec.get("total_tokens") or 0)
        agg["credits_used"] += float(rec.get("credits_used") or 0.0)
        agg["tool_calls"] += int(rec.get("tool_calls") or 0)
        model = _clean_graph_part(rec.get("model_name"))
        if model:
            agg["models"].add(model)
        user = _clean_graph_part(rec.get("user_name"))
        if user:
            agg["users"].add(user)

    for agent_name, agg in agent_aggregate.items():
        agent_node_id = f"agent:snowflake:{agent_name}"
        graph.add_node(
            UnifiedNode(
                id=agent_node_id,
                entity_type=EntityType.AGENT,
                label=f"cortex agent: {agent_name}",
                attributes={
                    "agent_name": agent_name,
                    "cloud_provider": "snowflake",
                    "source": "cortex-agent-usage",
                    "call_count": agg["calls"],
                    "total_tokens": agg["total_tokens"],
                    "credits_used": round(agg["credits_used"], 4),
                    "tool_calls": agg["tool_calls"],
                    "models": sorted(agg["models"]),
                    "distinct_users": len(agg["users"]),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
            )
        )
        if account_node_id:
            _add_rel_edge(graph, account_node_id, agent_node_id, RelationshipType.OWNS, {"source": "snowflake-governance"})


def _add_cloud_audit_behavioral(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote cloud audit-trail behavioral signal into observed-reach edges.

    Mirrors the Snowflake ACCESS_HISTORY → ``ACCESSED`` layer
    (:func:`_add_snowflake_governance`) for AWS CloudTrail / Azure Activity Log /
    GCP Cloud Audit Logs. The reader
    (:mod:`agent_bom.cloud.audit_trail`) has already collapsed raw events into
    ``(principal, resource, action)`` aggregates carrying ``count`` and
    ``last_seen`` — **no raw log lines reach this function**.

    For each aggregate a ``principal`` node draws an observed-behavior edge to the
    ``resource`` node:

    * ``relationship == "invoked"`` → :data:`RelationshipType.INVOKED`
      (a management/write action *taken*).
    * otherwise → :data:`RelationshipType.ACCESSED` (a resource *reached*).

    The edge carries ``observed_at`` (``last_seen``), the action, outcome
    summary, and the observation ``count`` so attack-path/reachability can reason
    about *who actually reached what*, not just who *can*. The principal and
    resource node ids are scheme-stable so repeated runs of the same events
    produce the same nodes/edges. Never raises; a non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "cloud-audit-trail")
    if prepared is None:
        return
    account, data_sources = prepared
    provider = _clean_graph_part(payload.get("provider")) or "cloud"

    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            provider,
            data_sources,
            label=account or provider,
            account_id=account,
            cloud_provider=provider,
            source="cloud-audit-trail",
        )

    seen_principals: set[str] = set()

    def _ensure_principal(name: str) -> str:
        node_id = _identity_node_id(EntityType.USER, provider, name)
        if node_id not in seen_principals:
            seen_principals.add(node_id)
            _add_identity_node(
                graph,
                EntityType.USER,
                name,
                provider,
                data_sources,
                label=f"principal: {name}",
                user_name=name,
                cloud_provider=provider,
                source="cloud-audit-trail",
            )
            if account_node_id:
                _add_rel_edge(
                    graph,
                    account_node_id,
                    node_id,
                    RelationshipType.OWNS,
                    {"source": "cloud-audit-trail"},
                )
        return node_id

    for rec in payload.get("behavioral_edges", []) or []:
        if not isinstance(rec, dict):
            continue
        principal = _clean_graph_part(rec.get("principal"))
        resource = _clean_graph_part(rec.get("resource"))
        action = _clean_graph_part(rec.get("action"))
        if not principal or not resource or not action:
            continue
        relationship = RelationshipType.INVOKED if _clean_graph_part(rec.get("relationship")) == "invoked" else RelationshipType.ACCESSED
        resource_node_id = f"cloud_resource:{provider}:audit:resource:{resource}"
        if resource_node_id not in graph.nodes:
            # Thin resource node — a full cloud inventory scan, if also run, owns
            # the rich one (a different id scheme, so no collision/duplicate).
            graph.add_node(
                UnifiedNode(
                    id=resource_node_id,
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=f"resource: {resource}",
                    attributes={
                        "resource_name": resource,
                        "resource_kind": "audit-observed-resource",
                        "cloud_provider": provider,
                        "is_sensitive_resource": bool(rec.get("is_sensitive_resource")),
                    },
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider=provider, surface="cloud"),
                )
            )
            if account_node_id:
                _add_rel_edge(
                    graph,
                    account_node_id,
                    resource_node_id,
                    RelationshipType.OWNS,
                    {"source": "cloud-audit-trail"},
                )
        _add_rel_edge(
            graph,
            _ensure_principal(principal),
            resource_node_id,
            relationship,
            {
                "source": "cloud-audit-trail",
                "observed": True,
                "action": action,
                "observed_at": _clean_graph_part(rec.get("last_seen")),
                "observation_count": int(rec.get("count") or 0),
                "failure_count": int(rec.get("failure_count") or 0),
                "is_sensitive_resource": bool(rec.get("is_sensitive_resource")),
            },
        )


def _add_snowflake_activity(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Summarize the Snowflake activity timeline onto the account node.

    QUERY_HISTORY can carry a year of rows; exploding them into per-query nodes
    would bury the graph (the data-store-scale lesson). Instead this attaches a
    compact ``activity_summary`` to the account node — total/agent query counts,
    distinct users, and a capped sample of notable agent-pattern statements — and
    creates **no per-query nodes**. Never raises; non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-activity")
    if prepared is None:
        return
    account, data_sources = prepared
    if not account:
        return

    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    query_history = payload.get("query_history") or []

    distinct_users: set[str] = set()
    notable: list[dict[str, str]] = []
    notable_cap = 25
    for q in query_history:
        if not isinstance(q, dict):
            continue
        user = _clean_graph_part(q.get("user_name"))
        if user:
            distinct_users.add(user)
        if q.get("is_agent_query") and len(notable) < notable_cap:
            notable.append(
                {
                    "query_id": _clean_graph_part(q.get("query_id")),
                    "user_name": user,
                    "agent_pattern": _clean_graph_part(q.get("agent_pattern")),
                    "query_type": _clean_graph_part(q.get("query_type")),
                    "start_time": _clean_graph_part(q.get("start_time")),
                }
            )

    activity_summary = {
        "total_queries": int(summary.get("total_queries") or 0),
        "agent_queries": int(summary.get("agent_queries") or 0),
        "observability_events": int(summary.get("observability_events") or 0),
        "unique_agents": int(summary.get("unique_agents") or 0),
        "tool_calls": int(summary.get("tool_calls") or 0),
        "distinct_users": len(distinct_users),
        "notable_agent_statements": notable,
    }

    # Merge onto the account node (add_node unions attributes by id).
    _add_identity_node(
        graph,
        EntityType.ACCOUNT,
        account,
        "snowflake",
        data_sources,
        label=account or "snowflake",
        account_id=account,
        cloud_provider="snowflake",
        source="snowflake-activity",
        activity_summary=activity_summary,
    )


_RBAC_PRINCIPAL_ENTITY = {
    "serviceprincipal": EntityType.SERVICE_PRINCIPAL,
    "service_principal": EntityType.SERVICE_PRINCIPAL,
    "user": EntityType.USER,
    "group": EntityType.GROUP,
    "managedidentity": EntityType.MANAGED_IDENTITY,
    "managed_identity": EntityType.MANAGED_IDENTITY,
}
# Roles that grant broad / privileged access — flagged on the edge for risk.
_RBAC_PRIVILEGED_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
    "key vault administrator",
    "storage blob data owner",
}


def _add_aws_organization(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote the AWS Organization (org → OUs → accounts → SCPs) into the graph.

    The multi-account estate as a navigable ``CONTAINS`` hierarchy: org → OU →
    account, with SCPs ``GOVERNS``-linked to the OUs/accounts they bound. Account
    nodes use the same ``account:aws:<id>`` id a per-account scan emits, so the
    org structure and any inventoried account graph stitch together. Scales to
    thousands of accounts. Never raises; non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "aws-organizations")
    if prepared is None:
        return
    _, data_sources = prepared
    org_id = _clean_graph_part(payload.get("org_id"))
    org_node_id = f"org:aws:{org_id}" if org_id else "org:aws:organization"
    graph.add_node(
        UnifiedNode(
            id=org_node_id,
            entity_type=EntityType.ORG,
            label=f"AWS org: {org_id or 'organization'}",
            attributes={
                "org_id": org_id,
                "cloud_provider": "aws",
                "master_account_id": _clean_graph_part(payload.get("master_account_id")),
                "feature_set": _clean_graph_part(payload.get("feature_set")),
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider="aws", surface="identity"),
        )
    )

    def _ou_node_id(ou_id: str) -> str:
        return f"org:aws:ou:{ou_id}"

    for ou in payload.get("organizational_units", []) or []:
        if not isinstance(ou, dict):
            continue
        ou_id = _clean_graph_part(ou.get("id"))
        if not ou_id:
            continue
        node_id = _ou_node_id(ou_id)
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.ORG,
                label=f"{'root' if ou.get('is_root') else 'OU'}: {_clean_graph_part(ou.get('name')) or ou_id}",
                attributes={"ou_id": ou_id, "is_root": bool(ou.get("is_root")), "cloud_provider": "aws"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="aws", surface="identity"),
            )
        )
        parent = _clean_graph_part(ou.get("parent_id"))
        parent_node = _ou_node_id(parent) if parent else org_node_id
        _add_rel_edge(graph, parent_node, node_id, RelationshipType.CONTAINS, {"source": "aws-organizations"})

    for acct in payload.get("accounts", []) or []:
        if not isinstance(acct, dict):
            continue
        acct_id = _clean_graph_part(acct.get("id"))
        if not acct_id:
            continue
        acct_node = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            acct_id,
            "aws",
            data_sources,
            label=f"account: {_clean_graph_part(acct.get('name')) or acct_id}",
            account_id=acct_id,
            cloud_provider="aws",
            account_name=_clean_graph_part(acct.get("name")),
            account_status=_clean_graph_part(acct.get("status")),
        )
        ou_id = _clean_graph_part(acct.get("ou_id"))
        parent_node = _ou_node_id(ou_id) if ou_id else org_node_id
        _add_rel_edge(graph, parent_node, acct_node, RelationshipType.CONTAINS, {"source": "aws-organizations"})

    for scp in payload.get("scps", []) or []:
        if not isinstance(scp, dict):
            continue
        scp_id = _clean_graph_part(scp.get("id"))
        if not scp_id:
            continue
        scp_node = f"policy:aws:scp:{scp_id}"
        graph.add_node(
            UnifiedNode(
                id=scp_node,
                entity_type=EntityType.POLICY,
                label=f"SCP: {_clean_graph_part(scp.get('name')) or scp_id}",
                attributes={"scp_id": scp_id, "aws_managed": bool(scp.get("aws_managed")), "cloud_provider": "aws"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="aws", surface="identity"),
            )
        )
        _add_rel_edge(graph, org_node_id, scp_node, RelationshipType.OWNS, {"source": "aws-organizations"})
        for target in scp.get("targets", []) or []:
            target = _clean_graph_part(target)
            if not target:
                continue
            # A target is an OU id, the root id, or a 12-digit account id.
            tgt_node = _identity_node_id(EntityType.ACCOUNT, "aws", target) if target.isdigit() else _ou_node_id(target)
            if tgt_node in graph.nodes:
                _add_rel_edge(graph, scp_node, tgt_node, RelationshipType.GOVERNS, {"source": "aws-organizations"})


def _add_gcp_organization(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote the GCP Organization (org → folders → projects) into the graph.

    The GCP analogue of :func:`_add_aws_organization` and the Azure
    management-group hierarchy: the estate as a navigable ``CONTAINS`` roll-up
    backbone — org → folder → project(ACCOUNT) → resources — with org/folder IAM
    bindings attached as ``HAS_PERMISSION`` edges (privilege classified, inherited
    DOWN to every child project) and org-policy constraints as ``GOVERNS`` edges.

    Project nodes use the same ``account:gcp:<project_id>`` id a per-project
    inventory emits, so the org structure and any inventoried project graph stitch
    together. Scales to the org/folder project budget. Never raises; a non-ok
    payload is a no-op.
    """
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return
    data_sources = sorted({data_source, "gcp-organizations"} - {""})
    org_id = _clean_graph_part(payload.get("org_id"))
    org_node_id = f"org:gcp:{org_id}" if org_id else "org:gcp:organization"
    graph.add_node(
        UnifiedNode(
            id=org_node_id,
            entity_type=EntityType.ORG,
            label=f"GCP org: {_clean_graph_part(payload.get('org_name')) or org_id or 'organization'}",
            attributes={
                "org_id": org_id,
                "org_name": _clean_graph_part(payload.get("org_name")),
                "cloud_provider": "gcp",
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider="gcp", surface="identity"),
        )
    )

    def _folder_node_id(folder_id: str) -> str:
        # folder_id is the resource name "folders/123"; keep it stable + readable.
        return f"org:gcp:folder:{folder_id.rsplit('/', 1)[-1]}"

    # Folders (the FOLDER tier of the CONTAINS tree). A folder's parent is the org
    # or another folder; map both to their node ids.
    folder_ids = {_clean_graph_part(f.get("id")) for f in (payload.get("folders") or []) if isinstance(f, dict)}
    for folder in payload.get("folders", []) or []:
        if not isinstance(folder, dict):
            continue
        folder_id = _clean_graph_part(folder.get("id"))
        if not folder_id:
            continue
        node_id = _folder_node_id(folder_id)
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.ORG,
                label=f"folder: {_clean_graph_part(folder.get('name')) or folder_id}",
                attributes={"folder_id": folder_id, "cloud_provider": "gcp"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="gcp", surface="identity"),
            )
        )
        parent = _clean_graph_part(folder.get("parent_id"))
        parent_node = _folder_node_id(parent) if parent in folder_ids else org_node_id
        _add_rel_edge(graph, parent_node, node_id, RelationshipType.CONTAINS, {"source": "gcp-organizations"})

    # Projects (the ACCOUNT tier). Same node id a per-project scan emits so the
    # org tree and inventoried project graphs stitch together.
    for project in payload.get("projects", []) or []:
        if not isinstance(project, dict):
            continue
        project_id = _clean_graph_part(project.get("id"))
        if not project_id:
            continue
        project_node = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            project_id,
            "gcp",
            data_sources,
            label=f"project: {_clean_graph_part(project.get('name')) or project_id}",
            account_id=project_id,
            cloud_provider="gcp",
            account_name=_clean_graph_part(project.get("name")),
            project_number=_clean_graph_part(project.get("number")),
        )
        parent = _clean_graph_part(project.get("parent_id"))
        parent_node = _folder_node_id(parent) if parent in folder_ids else org_node_id
        _add_rel_edge(graph, parent_node, project_node, RelationshipType.CONTAINS, {"source": "gcp-organizations"})

    # Org/folder IAM bindings → HAS_PERMISSION from each member to the scope node
    # (these grant DOWN to every child project — inherited permissions).
    _GCP_PRINCIPAL_ENTITY = {  # noqa: N806 — local constant lookup
        "serviceaccount": EntityType.SERVICE_ACCOUNT,
        "user": EntityType.USER,
        "group": EntityType.USER,
    }
    for binding in payload.get("iam_bindings", []) or []:
        if not isinstance(binding, dict):
            continue
        role = _clean_graph_part(binding.get("role"))
        scope_id = _clean_graph_part(binding.get("scope_id"))
        if not role or not scope_id:
            continue
        scope_level = str(binding.get("scope_level", "") or "").lower()
        scope_node = org_node_id if scope_level == "organization" else _folder_node_id(scope_id)
        if scope_node not in graph.nodes:
            continue
        privilege = str(binding.get("privilege_level", "") or "unknown")
        for member in binding.get("members", []) or []:
            member = str(member or "").strip()
            if not member:
                continue
            prefix, _, identity = member.partition(":")
            identity = (identity or member).strip().lower()
            if not identity:
                continue
            entity = _GCP_PRINCIPAL_ENTITY.get(prefix.strip().lower().replace("-", "").replace("_", ""), EntityType.USER)
            principal_node = _add_identity_node(
                graph,
                entity,
                identity,
                "gcp",
                data_sources,
                label=f"{prefix or 'principal'}: {identity}",
                principal_id=identity,
                cloud_provider="gcp",
            )
            graph.add_edge(
                UnifiedEdge(
                    source=principal_node,
                    target=scope_node,
                    relationship=RelationshipType.HAS_PERMISSION,
                    evidence={
                        "source": "gcp-organizations",
                        "role": role,
                        "scope": scope_id,
                        "scope_level": scope_level,
                        "privilege_level": privilege,
                        "privileged": privilege == "admin",
                        "inherited": True,
                    },
                )
            )

    # Org-policy constraints → GOVERNS the scope they apply to (the AWS-SCP analogue).
    for policy in payload.get("org_policies", []) or []:
        if not isinstance(policy, dict):
            continue
        constraint = _clean_graph_part(policy.get("constraint")) or _clean_graph_part(policy.get("id"))
        scope_id = _clean_graph_part(policy.get("scope_id"))
        if not constraint or not scope_id:
            continue
        policy_node = f"policy:gcp:orgpolicy:{constraint}"
        graph.add_node(
            UnifiedNode(
                id=policy_node,
                entity_type=EntityType.POLICY,
                label=f"org policy: {constraint}",
                attributes={"constraint": constraint, "cloud_provider": "gcp"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="gcp", surface="identity"),
            )
        )
        _add_rel_edge(graph, org_node_id, policy_node, RelationshipType.OWNS, {"source": "gcp-organizations"})
        scope_is_org = scope_id.startswith("organizations/")
        scope_node = org_node_id if scope_is_org else _folder_node_id(scope_id)
        if scope_node in graph.nodes:
            _add_rel_edge(graph, policy_node, scope_node, RelationshipType.GOVERNS, {"source": "gcp-organizations"})


def _add_cloud_role_assignments(graph: UnifiedGraph, inventory: Any, data_source: str) -> None:
    """Turn cloud RBAC role assignments into ``HAS_PERMISSION`` edges.

    Each assignment links a principal (by its directory object id) to a scope —
    the subscription/account, a resource group, or a specific resource — via a
    role. Principal and scope nodes are created when absent (so the CIEM graph is
    complete even for principals not in the resource inventory), and merged onto
    existing nodes when present. Resource scopes are matched to inventoried
    resource nodes by their ARM ``resource_id``. Privileged roles mark the edge.
    Never raises; missing/empty data is a no-op.
    """
    if not isinstance(inventory, dict):
        return
    assignments = inventory.get("role_assignments") or []
    if not assignments:
        return
    provider = _clean_graph_part(inventory.get("provider")) or "azure"
    account_id = _clean_graph_part(inventory.get("account_id") or inventory.get("subscription_id"))
    data_sources = sorted({data_source, "cloud-rbac"} - {""})
    account_node_id = _identity_node_id(EntityType.ACCOUNT, provider, account_id) if account_id else ""

    # Index inventoried resource nodes by their ARM resource_id for scope match.
    resource_by_arm: dict[str, str] = {}
    for node in graph.nodes.values():
        if node.entity_type == EntityType.CLOUD_RESOURCE:
            arm = _clean_graph_part(node.attributes.get("resource_id"))
            if arm:
                resource_by_arm[arm.lower()] = node.id

    # Index group → member principals from the MEMBER_OF edges the inventory pass
    # already added (it runs before this one). A role granted to a group reaches
    # every member, so a group-scoped assignment is expanded to its members.
    group_members: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.relationship == RelationshipType.MEMBER_OF:
            target = graph.nodes.get(edge.target)
            if target is not None and target.entity_type == EntityType.GROUP:
                group_members[edge.target].append(edge.source)

    def _scope_target(scope: str) -> str:
        s = scope.rstrip("/")
        low = s.lower()
        # Exact resource match against inventory.
        if low in resource_by_arm:
            return resource_by_arm[low]
        # Subscription scope → account node.
        if account_node_id and low == f"/subscriptions/{account_id}".lower():
            return account_node_id
        # Resource-group scope → a resource-group node.
        if "/resourcegroups/" in low and "/providers/" not in low:
            rg = s.rsplit("/", 1)[-1]
            rg_id = f"cloud_resource:{provider}:resource_group:{rg}"
            if rg_id not in graph.nodes:
                graph.add_node(
                    UnifiedNode(
                        id=rg_id,
                        entity_type=EntityType.CLOUD_RESOURCE,
                        label=f"resource group: {rg}",
                        attributes={"resource_name": rg, "resource_type": "resource_group", "cloud_provider": provider, "resource_id": s},
                        data_sources=data_sources,
                        dimensions=NodeDimensions(cloud_provider=provider),
                    )
                )
            return rg_id
        # A specific resource not in inventory → thin resource node.
        thin_id = f"cloud_resource:{provider}:scope:{low}"
        if thin_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=thin_id,
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=s.rsplit("/", 1)[-1] or s,
                    attributes={"resource_id": s, "cloud_provider": provider},
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider=provider),
                )
            )
        return thin_id

    # Group by (principal, scope) so a principal with several roles on the same
    # scope yields ONE edge carrying all roles — edge dedup would otherwise drop
    # all but the first role (seen live: an SP with 3 roles on one storage account).
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for ra in assignments:
        if not isinstance(ra, dict):
            continue
        principal_id = _clean_graph_part(ra.get("principal_id"))
        scope = _clean_graph_part(ra.get("scope"))
        if not principal_id or not scope:
            continue
        ptype = str(ra.get("principal_type", "") or "").lower().replace("-", "").replace("_", "")
        key = (principal_id, scope.rstrip("/"))
        entry = grouped.setdefault(key, {"principal_type": ptype, "roles": []})
        role_name = _clean_graph_part(ra.get("role_name"))
        if role_name and role_name not in entry["roles"]:
            entry["roles"].append(role_name)

    for (principal_id, scope), entry in grouped.items():
        ptype = entry["principal_type"]
        entity = _RBAC_PRINCIPAL_ENTITY.get(ptype, EntityType.SERVICE_PRINCIPAL)
        principal_node_id = _identity_node_id(entity, provider, principal_id)
        graph.add_node(
            UnifiedNode(
                id=principal_node_id,
                entity_type=entity,
                label=f"{ptype or 'principal'}: {principal_id[:8]}",
                attributes={"principal_id": principal_id, "principal_type": ptype, "cloud_provider": provider},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        roles = entry["roles"]
        scope_target = _scope_target(scope)
        privileged = any(r.lower() in _RBAC_PRIVILEGED_ROLES for r in roles)
        graph.add_edge(
            UnifiedEdge(
                source=principal_node_id,
                target=scope_target,
                relationship=RelationshipType.HAS_PERMISSION,
                evidence={
                    "source": "cloud-rbac",
                    "roles": roles,
                    "role": roles[0] if roles else "",
                    "privileged": privileged,
                    "scope": scope,
                },
            )
        )
        # A role granted to a group reaches every member: expand the assignment to
        # each member principal so group-granted RBAC access is not invisible.
        if entity == EntityType.GROUP:
            for member_node_id in group_members.get(principal_node_id, []):
                graph.add_edge(
                    UnifiedEdge(
                        source=member_node_id,
                        target=scope_target,
                        relationship=RelationshipType.HAS_PERMISSION,
                        evidence={
                            "source": "cloud-rbac",
                            "roles": roles,
                            "role": roles[0] if roles else "",
                            "privileged": privileged,
                            "scope": scope,
                            "via_group": principal_id,
                        },
                    )
                )


def _gcp_firewall_applies(firewall_attrs: dict[str, Any], instance: dict[str, Any]) -> bool:
    """Return whether a permissive GCP firewall rule reaches *instance*.

    A rule applies when it is on the instance's network AND its target scope
    covers the instance. The target scope is: target tags (instance must carry
    one) OR target service accounts (instance must run as one). An EMPTY target
    set means the rule applies to ALL instances on its network — the GCP default.
    A blank firewall network also matches (the rule scope is the whole project).
    """
    fw_network = _clean_graph_part(firewall_attrs.get("fw_network"))
    inst_network = _clean_graph_part(instance.get("network"))
    if fw_network and inst_network and fw_network != inst_network:
        return False

    target_tags = {str(t).strip() for t in (firewall_attrs.get("fw_target_tags") or []) if str(t).strip()}
    target_sas = {str(s).strip() for s in (firewall_attrs.get("fw_target_service_accounts") or []) if str(s).strip()}
    if not target_tags and not target_sas:
        # No targets → the rule applies to every instance on the network.
        return True
    instance_tags = {str(t).strip() for t in (instance.get("network_tags") or []) if str(t).strip()}
    if target_tags and instance_tags & target_tags:
        return True
    instance_sas = {str(s).strip() for s in (instance.get("service_accounts") or []) if str(s).strip()}
    if target_sas and instance_sas & target_sas:
        return True
    return False


def _apply_gcp_firewall_exposure(
    graph: UnifiedGraph,
    sg_node_by_id: dict[str, str],
    instance_nodes: list[tuple[str, dict[str, Any]]],
) -> None:
    """Mark GCP instances internet-exposed when a permissive firewall reaches them.

    For each instance with an external IP, find every internet-facing
    (``internet_exposed``) firewall node that applies to it (network + target
    tags/SA match). Set ``internet_exposed=True`` on the instance node — which the
    CNAPP overlay preserves — and add an ``EXPOSED_TO`` edge from the firewall to
    the instance, mirroring how an AWS security group exposes an EC2 instance.
    """
    firewall_nodes = [(graph.nodes.get(node_id), node_id) for node_id in sg_node_by_id.values()]
    permissive = [(node, node_id) for node, node_id in firewall_nodes if node is not None and node.attributes.get("internet_exposed")]
    if not permissive:
        return
    for inst_node_id, instance in instance_nodes:
        inst_node = graph.nodes.get(inst_node_id)
        if inst_node is None:
            continue
        # Only an instance with an external/public IP can be reached from the
        # internet; a permissive rule on a no-public-IP instance is not exposure.
        if not _clean_graph_part(instance.get("public_ip")):
            continue
        for fw_node, fw_node_id in permissive:
            if not _gcp_firewall_applies(fw_node.attributes, instance):
                continue
            inst_node.attributes["internet_exposed"] = True
            graph.add_edge(
                UnifiedEdge(
                    source=fw_node_id,
                    target=inst_node_id,
                    relationship=RelationshipType.EXPOSED_TO,
                    weight=6.0,
                    evidence={"source": "cloud-inventory", "reason": "permissive_firewall_external_ip"},
                )
            )


def _add_cloud_inventory(graph: UnifiedGraph, inventory: Any, data_source: str) -> None:
    """Promote estate-wide cloud inventory into first-class graph nodes.

    Consumes the payload produced by
    :func:`agent_bom.cloud.aws_inventory.discover_inventory` (stored under
    ``report_json["cloud_inventory"]``) and emits:

    - S3 buckets   → ``CLOUD_RESOURCE`` carrying ``resource_kind="s3-bucket"`` and
      a data-store-signalling label, so the CNAPP overlay attaches a
      ``DATA_STORE`` companion (via ``STORES``) and ``EXPOSED_TO`` when public —
      the path the DSPM tiers consume.
    - EC2 instances + security groups → ``CLOUD_RESOURCE``; an instance is linked
      ``EXPOSED_TO`` an internet-facing security group, and the group carries the
      structured ``network_exposure`` the CNAPP overlay reads.
    - IAM roles / users → identity principal nodes with attached ``POLICY`` nodes
      (``ATTACHED``) and trust principals (``TRUSTS`` / ``CROSS_ACCOUNT_TRUST``),
      plus ``CAN_ACCESS`` edges to the account's resources, so the
      effective-permissions overlay resolves ``HAS_PERMISSION``.

    Inventory is opt-in upstream; a missing / empty / non-ok payload is a no-op.
    Never raises into the builder.
    """
    if not isinstance(inventory, dict) or inventory.get("status") != "ok":
        return
    # The provider translation below rebuilds an AWS-shaped dict and drops the
    # data/secret/registry/network collections; keep the original to ingest them
    # through the normalized resource model.
    original_inventory = inventory
    inventory = _normalize_cloud_inventory(inventory)
    provider = _clean_graph_part(inventory.get("provider")) or "aws"
    account_id = _clean_graph_part(inventory.get("account_id"))
    region = _clean_graph_part(inventory.get("region"))
    data_sources = sorted({data_source, f"cloud-inventory:{provider}"} - {""})

    provider_node_id = f"provider:{provider}"
    graph.add_node(
        UnifiedNode(
            id=provider_node_id,
            entity_type=EntityType.PROVIDER,
            label=provider,
            attributes={"provider": provider, "source": "cloud-inventory"},
            data_sources=data_sources,
        )
    )
    account_node_id = ""
    if account_id:
        account_node_id = _identity_node_id(EntityType.ACCOUNT, provider, account_id)
        graph.add_node(
            UnifiedNode(
                id=account_node_id,
                entity_type=EntityType.ACCOUNT,
                label=account_id,
                attributes={"account_id": account_id, "cloud_provider": provider, "source": "cloud-inventory"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )

    resource_ids: list[str] = []

    # ── Agentless side-scan targets → workload disk CLOUD_RESOURCE ──
    for target in inventory.get("side_scan_targets", []) or []:
        if not isinstance(target, dict):
            continue
        target_id_raw = target.get("target_id") or target.get("id") or target.get("name")
        target_id = _clean_graph_part(target_id_raw)
        if not target_id:
            continue
        target_provider = _clean_graph_part(target.get("provider")) or provider
        target_type = _clean_graph_part(target.get("target_type")) or "disk"
        target_location = _clean_graph_part(target.get("location")) or region
        node_id = f"cloud_resource:{target_provider}:cwpp:{target_type}:{target_id}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{target_type}: {target.get('name') or target_id}",
                attributes={
                    "resource_id": target_id_raw,
                    "resource_name": _clean_graph_part(target.get("name")) or target_id,
                    "resource_type": "workload_disk",
                    "resource_kind": target_type,
                    "cloud_provider": target_provider,
                    "cloud_service": "cwpp-side-scan",
                    "location": target_location,
                    "account_id": target.get("account_id") or account_id,
                    "side_scan_status": _clean_graph_part(target.get("status")) or "eligible",
                    "side_scan_execution": _clean_graph_part(target.get("execution")) or "not_started",
                    "side_scan_requires_snapshot_role": bool(target.get("requires_snapshot_role", True)),
                    "size_gb": target.get("size_gb"),
                    "encryption": _clean_graph_part(target.get("encryption")) or "unknown",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=target_provider, surface="cwpp"),
            )
        )
        resource_ids.append(node_id)
        if account_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=account_node_id,
                    target=node_id,
                    relationship=RelationshipType.OWNS,
                    evidence={"source": "cloud-inventory", "reason": "side_scan_target"},
                )
            )

    # ── S3 buckets → CLOUD_RESOURCE (CNAPP makes the DATA_STORE companion) ──
    for bucket in inventory.get("buckets", []) or []:
        if not isinstance(bucket, dict):
            continue
        name = _clean_graph_part(bucket.get("name"))
        if not name:
            continue
        bucket_service = _clean_graph_part(bucket.get("_service")) or "s3"
        bucket_kind = _clean_graph_part(bucket.get("_kind")) or "s3-bucket"
        bucket_label = _clean_graph_part(bucket.get("_label")) or "s3 bucket"
        node_id = f"cloud_resource:{provider}:{bucket_service}:bucket:{name}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                # Label carries a data-store keyword ("bucket"/"storage account")
                # so the CNAPP overlay's data-store match fires and builds the
                # DATA_STORE companion.
                label=f"{bucket_label}: {name}",
                attributes={
                    "resource_id": bucket.get("arn") or bucket.get("id") or name,
                    "resource_name": name,
                    "resource_type": "bucket",
                    "resource_kind": bucket_kind,
                    "cloud_provider": provider,
                    "cloud_service": bucket_service,
                    "location": _clean_graph_part(bucket.get("location")) or region,
                    "internet_exposed": bool(bucket.get("publicly_accessible")),
                    "tags": bucket.get("tags", {}),
                    "account_id": account_id,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="s3"),
            )
        )
        resource_ids.append(node_id)
        if account_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=account_node_id, target=node_id, relationship=RelationshipType.OWNS, evidence={"source": "cloud-inventory"}
                )
            )

    # ── EC2 security groups → CLOUD_RESOURCE (carry structured exposure) ──
    sg_node_by_id: dict[str, str] = {}
    for group in inventory.get("security_groups", []) or []:
        if not isinstance(group, dict):
            continue
        group_id = _clean_graph_part(group.get("group_id"))
        if not group_id:
            continue
        sg_service = _clean_graph_part(group.get("_service")) or "ec2"
        sg_kind = _clean_graph_part(group.get("_kind")) or "ec2-security-group"
        sg_resource_type = _clean_graph_part(group.get("_resource_type")) or "security-group"
        node_id = f"cloud_resource:{provider}:{sg_service}:{sg_resource_type}:{group_id}"
        sg_node_by_id[group_id] = node_id
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{sg_resource_type}: {group.get('name') or group_id}",
                attributes={
                    "resource_id": group_id,
                    "resource_name": _clean_graph_part(group.get("name")) or group_id,
                    "resource_type": sg_resource_type,
                    "resource_kind": sg_kind,
                    "cloud_provider": provider,
                    "cloud_service": sg_service,
                    "location": region,
                    "vpc_id": _clean_graph_part(group.get("vpc_id")),
                    "internet_exposed": bool(group.get("internet_exposed")),
                    "network_exposure": list(group.get("network_exposure", []) or []),
                    # GCP firewall scoping (empty on AWS); the instance-matching
                    # pass below reads these to know which instances a rule covers.
                    "fw_network": _clean_graph_part(group.get("network")),
                    "fw_target_tags": list(group.get("target_tags", []) or []),
                    "fw_target_service_accounts": list(group.get("target_service_accounts", []) or []),
                    "fw_source_ranges": list(group.get("source_ranges", []) or []),
                    "account_id": account_id,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="ec2"),
            )
        )
        resource_ids.append(node_id)

    # ── EC2 instances → CLOUD_RESOURCE (linked to their security groups) ──
    # Track (node_id, raw-instance) so the GCP firewall-matching pass can mark
    # exposure by network + target tags/SA (GCP has no per-instance SG-id list).
    instance_nodes: list[tuple[str, dict[str, Any]]] = []
    internet_facing_lbs: list[tuple[str, str]] = []
    for instance in inventory.get("instances", []) or []:
        if not isinstance(instance, dict):
            continue
        instance_id = _clean_graph_part(instance.get("instance_id"))
        if not instance_id:
            continue
        inst_service = _clean_graph_part(instance.get("_service")) or "ec2"
        inst_kind = _clean_graph_part(instance.get("_kind")) or "ec2-instance"
        inst_label = _clean_graph_part(instance.get("_label")) or "ec2"
        node_id = f"cloud_resource:{provider}:{inst_service}:instance:{instance_id}"
        public_ip = _clean_graph_part(instance.get("public_ip"))
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{inst_label}: {instance.get('name') or instance_id}",
                attributes={
                    "resource_id": instance_id,
                    "resource_name": _clean_graph_part(instance.get("name")) or instance_id,
                    "resource_type": "instance",
                    "resource_kind": inst_kind,
                    "cloud_provider": provider,
                    "cloud_service": inst_service,
                    "location": _clean_graph_part(instance.get("region")) or region,
                    "instance_type": _clean_graph_part(instance.get("instance_type")),
                    "image_id": _clean_graph_part(instance.get("image_id")),
                    "state": _clean_graph_part(instance.get("state")),
                    "vpc_id": _clean_graph_part(instance.get("vpc_id")),
                    "public_ip": public_ip,
                    "private_ip": _clean_graph_part(instance.get("private_ip")),
                    "iam_instance_profile": _clean_graph_part(instance.get("iam_instance_profile")),
                    "security_group_ids": list(instance.get("security_group_ids", []) or []),
                    # GCP instance scoping (empty on AWS); the GCP firewall-matching
                    # pass below reads these to decide which permissive rules apply.
                    "network": _clean_graph_part(instance.get("network")),
                    "network_tags": list(instance.get("network_tags", []) or []),
                    "service_accounts": list(instance.get("service_accounts", []) or []),
                    "account_id": account_id,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="ec2"),
            )
        )
        resource_ids.append(node_id)
        instance_nodes.append((node_id, instance))
        for sg_id in instance.get("security_group_ids", []) or []:
            sg_node_id = sg_node_by_id.get(_clean_graph_part(sg_id))
            if not sg_node_id:
                continue
            graph.add_edge(
                UnifiedEdge(
                    source=node_id, target=sg_node_id, relationship=RelationshipType.PART_OF, evidence={"source": "cloud-inventory"}
                )
            )
            # An internet-facing security group exposes the instances in it.
            sg_node = graph.nodes.get(sg_node_id)
            if sg_node is not None and sg_node.attributes.get("internet_exposed"):
                graph.add_edge(
                    UnifiedEdge(
                        source=sg_node_id,
                        target=node_id,
                        relationship=RelationshipType.EXPOSED_TO,
                        weight=6.0,
                        evidence={"source": "cloud-inventory", "reason": "internet_facing_security_group"},
                    )
                )

        # A user-assigned managed identity is assumed by the VM: the identity's
        # permissions become the VM's blast radius. ASSUMES from the VM node to
        # each managed-identity node (those nodes are added by the principal pass
        # below; edges may reference them ahead of creation).
        for mi_arm_id in instance.get("user_assigned_identity_ids", []) or []:
            mi_clean = _clean_graph_part(mi_arm_id)
            if not mi_clean:
                continue
            mi_node_id = _identity_node_id(EntityType.MANAGED_IDENTITY, provider, mi_clean)
            graph.add_edge(
                UnifiedEdge(
                    source=node_id,
                    target=mi_node_id,
                    relationship=RelationshipType.ASSUMES,
                    weight=5.0,
                    evidence={"source": "cloud-inventory", "reason": "vm_user_assigned_identity"},
                )
            )

    # ── GCP compute exposure: match permissive firewalls to instances ──────
    # GCP firewalls apply by network + target tags / target service accounts,
    # not by a per-instance security-group id list (the AWS path above). Mirror
    # AWS's EC2-exposure model: an instance with an external IP that a permissive
    # (0.0.0.0/0) ingress rule reaches is marked internet_exposed with an
    # EXPOSED_TO edge from the firewall — making it a first-class attack-path entry.
    if provider == "gcp":
        _apply_gcp_firewall_exposure(graph, sg_node_by_id, instance_nodes)

    instance_node_by_id: dict[str, str] = {}
    for inst_node_id, instance in instance_nodes:
        iid = _clean_graph_part(instance.get("instance_id")) or _clean_graph_part(instance.get("id"))
        if iid:
            instance_node_by_id[iid] = inst_node_id

    # ── AWS data + compute services (RDS / DynamoDB / Lambda / EKS) ──────
    # (key, service, resource_type, kind, label, is_data_store)
    for coll_key, svc, rtype, kind, label, is_data in (
        ("rds_instances", "rds", "database", "rds-instance", "rds database", True),
        ("dynamodb_tables", "dynamodb", "database", "dynamodb-table", "dynamodb table", True),
        ("lambda_functions", "lambda", "function", "lambda-function", "lambda function", False),
        ("eks_clusters", "eks", "container_cluster", "eks-cluster", "eks cluster", False),
        ("elb_load_balancers", "elbv2", "load_balancer", "elb-load-balancer", "load balancer", False),
        ("vpcs", "ec2", "virtual_network", "vpc", "vpc", False),
        ("kms_keys", "kms", "key", "kms-key", "kms key", False),
        ("secrets", "secretsmanager", "secret", "secretsmanager-secret", "secret", False),
        ("cloudfront_distributions", "cloudfront", "cdn", "cloudfront-distribution", "cdn distribution", False),
        ("ecr_repositories", "ecr", "container_registry", "ecr-repository", "container registry", False),
        ("redshift_clusters", "redshift", "data_warehouse", "redshift-cluster", "redshift warehouse", True),
        ("messaging", "messaging", "messaging", "aws-messaging", "messaging", False),
    ):
        for item in inventory.get(coll_key, []) or []:
            if not isinstance(item, dict):
                continue
            name = _clean_graph_part(item.get("name"))
            if not name:
                continue
            node_id = f"cloud_resource:{provider}:{svc}:{rtype}:{name}"
            exposed = bool(item.get("publicly_accessible") or item.get("internet_exposed") or item.get("endpoint_public"))
            graph.add_node(
                UnifiedNode(
                    id=node_id,
                    entity_type=EntityType.DATA_STORE if is_data else EntityType.CLOUD_RESOURCE,
                    label=f"{label}: {name}",
                    attributes={
                        "resource_id": _clean_graph_part(item.get("arn")) or name,
                        "resource_name": name,
                        "resource_type": rtype,
                        "resource_kind": kind,
                        "cloud_provider": provider,
                        "cloud_service": svc,
                        "location": _clean_graph_part(item.get("location")) or region,
                        "internet_exposed": exposed,
                        "is_data_store": is_data,
                        "engine": _clean_graph_part(item.get("engine")),
                        "runtime": _clean_graph_part(item.get("runtime")),
                        "encrypted": bool(item.get("encrypted")),
                        "account_id": account_id,
                    },
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider=provider, surface=svc),
                )
            )
            resource_ids.append(node_id)
            if account_node_id:
                graph.add_edge(
                    UnifiedEdge(
                        source=account_node_id, target=node_id, relationship=RelationshipType.OWNS, evidence={"source": "cloud-inventory"}
                    )
                )
            if coll_key == "elb_load_balancers" and exposed:
                internet_facing_lbs.append((node_id, _clean_graph_part(item.get("vpc_id"))))

    # ── GCP estate breadth (GKE / Cloud Run / Functions / Cloud SQL / VPC /
    # disks / Pub/Sub) → CLOUD_RESOURCE or DATA_STORE, OWNS from the project. ──
    # Mirrors the AWS service loop above. Cloud SQL is a DATA_STORE so DSPM tiers
    # apply; a public-IP instance carries `internet_exposed` for CNAPP. The id key
    # (id_field) keeps a stable node id per resource (full self-link / uid).
    if provider == "gcp":
        for coll_key, svc, rtype, kind, label, is_data, id_field in (
            ("gke_clusters", "gke", "container_cluster", "gke-cluster", "gke cluster", False, "id"),
            ("cloud_run_services", "run", "function", "cloud-run-service", "cloud run service", False, "name"),
            ("cloud_functions", "cloudfunctions", "function", "cloud-function", "cloud function", False, "name"),
            ("cloud_sql_instances", "cloudsql", "database", "cloud-sql-instance", "cloud sql database", True, "name"),
            ("vpc_networks", "compute", "virtual_network", "vpc-network", "vpc network", False, "name"),
            ("disks", "compute", "storage", "persistent-disk", "persistent disk", False, "name"),
            ("pubsub_topics", "pubsub", "messaging", "pubsub-topic", "pubsub topic", False, "name"),
        ):
            for item in inventory.get(coll_key, []) or []:
                if not isinstance(item, dict):
                    continue
                name = _clean_graph_part(item.get("name"))
                if not name:
                    continue
                id_key = _clean_graph_part(item.get(id_field)) or name
                node_id = f"cloud_resource:gcp:{svc}:{rtype}:{id_key}"
                exposed = bool(item.get("publicly_accessible") or item.get("internet_exposed"))
                graph.add_node(
                    UnifiedNode(
                        id=node_id,
                        entity_type=EntityType.DATA_STORE if is_data else EntityType.CLOUD_RESOURCE,
                        label=f"{label}: {name}",
                        attributes={
                            "resource_id": _clean_graph_part(item.get("id")) or name,
                            "resource_name": name,
                            "resource_type": rtype,
                            "resource_kind": kind,
                            "cloud_provider": "gcp",
                            "cloud_service": svc,
                            "location": _clean_graph_part(item.get("location")) or region,
                            "internet_exposed": exposed,
                            "is_data_store": is_data,
                            "engine": _clean_graph_part(item.get("database_version")),
                            "encrypted": bool(item.get("encrypted")),
                            "account_id": account_id,
                        },
                        data_sources=data_sources,
                        dimensions=NodeDimensions(cloud_provider="gcp", surface=svc),
                    )
                )
                resource_ids.append(node_id)
                if account_node_id:
                    graph.add_edge(
                        UnifiedEdge(
                            source=account_node_id,
                            target=node_id,
                            relationship=RelationshipType.OWNS,
                            evidence={"source": "cloud-inventory"},
                        )
                    )

    # ── Data / secret / registry / network resources (normalized model) ──
    _add_normalized_cloud_resources(
        graph,
        original_inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )

    # ── Network edge: WAF, API gateways, ENIs/NICs, subnets, NAT/IGW, IPs ──
    _add_network_edge_inventory(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
        sg_node_by_id=sg_node_by_id,
        instance_node_by_id=instance_node_by_id,
    )
    _link_internet_facing_load_balancers(graph, internet_facing_lbs, instance_nodes)

    # ── Management-group hierarchy (org → subscription CONTAINS tree) ──
    _add_management_group_hierarchy(graph, original_inventory, provider=provider, data_sources=data_sources)

    # ── IAM roles + users → identity principals (CAN_ACCESS resources) ──
    for principal in [*(inventory.get("roles", []) or []), *(inventory.get("users", []) or [])]:
        if isinstance(principal, dict):
            _add_inventory_principal(
                graph, principal, provider=provider, account_node_id=account_node_id, resource_ids=resource_ids, data_sources=data_sources
            )

    # ── IAM / Entra groups → GROUP nodes + MEMBER_OF edges from members ──
    # A group carries its members' shared access (its attached policies / bound
    # roles). Wiring the group as a principal with CAN_ACCESS, plus MEMBER_OF
    # edges from each member, lets the effective-permissions overlay attribute
    # group-granted access to the member — group-based access is one of the most
    # common privilege paths and was invisible before.
    for group in inventory.get("groups", []) or []:
        if isinstance(group, dict):
            _add_inventory_group(
                graph, group, provider=provider, account_node_id=account_node_id, resource_ids=resource_ids, data_sources=data_sources
            )


def _add_management_group_hierarchy(graph: UnifiedGraph, inventory: dict[str, Any], *, provider: str, data_sources: list[str]) -> None:
    """Build the management-group → subscription hierarchy as ORG nodes + CONTAINS edges.

    Management groups are the tenant tier above subscriptions. Each becomes an
    ``ORG`` node; its children (nested management groups and subscriptions) are
    linked with ``CONTAINS``, so the graph carries the multi-subscription
    hierarchy and blast-radius can reason across the whole tenant. Subscription
    account nodes are created here if a per-subscription scan hasn't already.
    """
    for mg in inventory.get("management_groups", []) or []:
        if not isinstance(mg, dict):
            continue
        name = _clean_graph_part(mg.get("name"))
        if not name:
            continue
        org_node_id = _identity_node_id(EntityType.ORG, provider, name)
        graph.add_node(
            UnifiedNode(
                id=org_node_id,
                entity_type=EntityType.ORG,
                label=_clean_graph_part(mg.get("display_name")) or name,
                attributes={
                    "management_group_id": _clean_graph_part(mg.get("id")),
                    "cloud_provider": provider,
                    "source": "cloud-inventory",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        for child in mg.get("children", []) or []:
            if not isinstance(child, dict):
                continue
            child_name = _clean_graph_part(child.get("name"))
            if not child_name:
                continue
            child_type = str(child.get("type") or "").lower()
            if "managementgroups" in child_type:
                # The child ORG node is created when its own entry is processed.
                child_node_id = _identity_node_id(EntityType.ORG, provider, child_name)
            elif "subscriptions" in child_type:
                child_node_id = _identity_node_id(EntityType.ACCOUNT, provider, child_name)
                graph.add_node(
                    UnifiedNode(
                        id=child_node_id,
                        entity_type=EntityType.ACCOUNT,
                        label=_clean_graph_part(child.get("display_name")) or child_name,
                        attributes={"account_id": child_name, "cloud_provider": provider, "source": "cloud-inventory"},
                        data_sources=data_sources,
                        dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
                    )
                )
            else:
                continue
            graph.add_edge(
                UnifiedEdge(
                    source=org_node_id,
                    target=child_node_id,
                    relationship=RelationshipType.CONTAINS,
                    evidence={"source": "cloud-inventory"},
                )
            )


def _add_normalized_cloud_resources(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    account_node_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
) -> None:
    """Promote normalized data / secret / registry / network resources into nodes.

    Covers the resource classes the AWS-shaped loops above do not: secret stores
    (Key Vault), container registries, databases, virtual networks, public IPs,
    and load balancers. Each becomes a ``CLOUD_RESOURCE`` owned by the account so
    it shows up in the environment graph and is reachable by blast-radius. Data
    stores and secret stores carry a data-store keyword in their label so the
    CNAPP/DSPM overlay can attach its companion; resources with a public IP or an
    internet-facing frontend are flagged ``internet_exposed`` for exposure
    analysis. Identity / EXPOSED_TO edges between these and compute/identity nodes
    are added by the overlays once richer relations are available.
    """
    from agent_bom.cloud.resource_model import CloudResourceType, normalize_cloud_inventory

    # normalized type -> (label keyword, graph surface, signals a data store)
    type_meta = {
        CloudResourceType.CONTAINER_CLUSTER: ("kubernetes cluster", "container", False),
        CloudResourceType.SECRET_STORE: ("key vault", "secret-store", True),
        CloudResourceType.CONTAINER_REGISTRY: ("container registry", "registry", False),
        CloudResourceType.DATABASE: ("database", "database", True),
        CloudResourceType.VIRTUAL_NETWORK: ("virtual network", "network", False),
        CloudResourceType.PUBLIC_IP: ("public ip", "network", False),
        CloudResourceType.LOAD_BALANCER: ("load balancer", "network", False),
        CloudResourceType.MESSAGING: ("messaging", "messaging", False),
        CloudResourceType.CACHE: ("redis cache", "cache", False),
        CloudResourceType.BLOCK_STORAGE: ("managed disk", "storage", True),
        CloudResourceType.SERVERLESS_FUNCTION: ("app service", "compute", False),
    }
    pip_node_by_arm_id: dict[str, str] = {}
    load_balancer_nodes: list[tuple[str, dict[str, Any]]] = []
    for res in normalize_cloud_inventory(inventory):
        meta = type_meta.get(res.resource_type)
        if meta is None:
            continue  # storage / compute / identity handled by the dedicated loops
        label_keyword, surface, is_data_store = meta
        name = _clean_graph_part(res.name)
        if not name:
            continue
        node_id = f"cloud_resource:{provider}:{res.resource_type.value}:{name}"
        raw = res.raw or {}
        internet_exposed = bool(raw.get("ip_address")) or bool(raw.get("internet_facing"))
        if res.resource_type is CloudResourceType.PUBLIC_IP and res.resource_id:
            pip_node_by_arm_id[res.resource_id] = node_id
        if res.resource_type is CloudResourceType.LOAD_BALANCER:
            load_balancer_nodes.append((node_id, raw))
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{label_keyword}: {name}",
                attributes={
                    "resource_id": res.resource_id or name,
                    "resource_name": name,
                    "resource_type": res.resource_type.value,
                    "resource_kind": res.native_type,
                    "cloud_provider": provider,
                    "location": res.region or region,
                    "internet_exposed": internet_exposed,
                    "is_data_store": is_data_store,
                    "tags": dict(res.tags),
                    "account_id": account_id,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface=surface),
            )
        )
        resource_ids.append(node_id)
        if account_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=account_node_id,
                    target=node_id,
                    relationship=RelationshipType.OWNS,
                    evidence={"source": "cloud-inventory"},
                )
            )

    # ── Internet exposure path: public IP → load balancer it fronts ──
    # The public IP is the internet entry point; the load balancer (and its
    # backends) sit behind it. EXPOSED_TO from the IP to the LB lets blast-radius
    # and attack-path analysis start at the internet edge.
    for lb_node_id, lb_raw in load_balancer_nodes:
        for pip_arm_id in lb_raw.get("public_ip_ids", []) or []:
            pip_node_id = pip_node_by_arm_id.get(pip_arm_id)
            if pip_node_id:
                graph.add_edge(
                    UnifiedEdge(
                        source=pip_node_id,
                        target=lb_node_id,
                        relationship=RelationshipType.EXPOSED_TO,
                        weight=6.0,
                        evidence={"source": "cloud-inventory", "reason": "public_ip_frontend"},
                    )
                )


# Generic network-edge collections promoted as CLOUD_RESOURCE inventory nodes.
# (payload key, cloud service, resource_type, resource_kind, label, id field)
# Load balancers are intentionally NOT here: AWS uses ``elb_load_balancers`` and
# Azure routes them through the normalized-resource path; only GCP's new
# ``load_balancers`` key is ingested here, gated to GCP below.
_NETWORK_EDGE_COLLECTIONS: tuple[tuple[str, str, str, str, str, str], ...] = (
    ("nat_gateways", "network", "nat_gateway", "nat-gateway", "nat gateway", "id"),
    ("internet_gateways", "network", "internet_gateway", "internet-gateway", "internet gateway", "id"),
    ("vpc_endpoints", "network", "vpc_endpoint", "vpc-endpoint", "vpc endpoint", "id"),
    ("route_tables", "network", "route_table", "route-table", "route table", "id"),
    ("network_acls", "network", "network_acl", "network-acl", "network acl", "id"),
)
_GCP_LB_COLLECTION: tuple[str, str, str, str, str, str] = (
    "load_balancers",
    "network",
    "load_balancer",
    "load-balancer",
    "load balancer",
    "id",
)


def _add_exposure_path_edge(
    graph: UnifiedGraph,
    *,
    source: str,
    target: str,
    reason: str,
    weight: float = 6.0,
) -> None:
    """Emit a provenance-tagged EXPOSED_TO edge when both endpoints exist."""
    if source not in graph.nodes or target not in graph.nodes or source == target:
        return
    for edge in graph.edges:
        if edge.source == source and edge.target == target and edge.relationship == RelationshipType.EXPOSED_TO:
            return
    graph.add_edge(
        UnifiedEdge(
            source=source,
            target=target,
            relationship=RelationshipType.EXPOSED_TO,
            weight=weight,
            evidence={"source": "cloud-inventory", "reason": reason},
        )
    )


def _instance_internet_reachable(graph: UnifiedGraph, inst_node_id: str, instance: dict[str, Any]) -> bool:
    node = graph.nodes.get(inst_node_id)
    if node is None:
        return False
    if node.attributes.get("internet_exposed") or _clean_graph_part(instance.get("public_ip")):
        return True
    return any(e.relationship == RelationshipType.EXPOSED_TO and e.target == inst_node_id for e in graph.edges)


def _link_internet_facing_load_balancers(
    graph: UnifiedGraph,
    load_balancers: list[tuple[str, str]],
    instance_nodes: list[tuple[str, dict[str, Any]]],
) -> None:
    """Link internet-facing LBs to reachable instances in the same VPC."""
    for lb_node_id, lb_vpc_id in load_balancers:
        lb_node = graph.nodes.get(lb_node_id)
        if lb_node is None or not lb_node.attributes.get("internet_exposed"):
            continue
        for inst_node_id, instance in instance_nodes:
            inst_vpc = _clean_graph_part(instance.get("vpc_id"))
            if lb_vpc_id and inst_vpc and inst_vpc != lb_vpc_id:
                continue
            if _instance_internet_reachable(graph, inst_node_id, instance):
                _add_exposure_path_edge(
                    graph,
                    source=lb_node_id,
                    target=inst_node_id,
                    reason="internet_facing_load_balancer",
                )


def _add_network_edge_inventory(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    account_node_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
    sg_node_by_id: dict[str, str],
    instance_node_by_id: dict[str, str],
) -> None:
    """Promote network-edge inventory into nodes + exposure-relevant edges.

    Emits, from the live inventory payload (all three clouds):

    - **API gateways** (AWS API Gateway, GCP API Gateway/Apigee, Azure API
      Management) → ``API_GATEWAY`` nodes in the API_GATEWAY semantic layer.
    - **WAF / Cloud Armor** web ACLs → ``CLOUD_RESOURCE`` nodes.
    - A ``PROTECTS`` edge from each WAF / API gateway to the resource it fronts,
      so the CNAPP overlay can refine the fronted resource's exposure verdict.
    - **Subnets** → ``CLOUD_RESOURCE``; a public subnet is ``internet_exposed``.
    - **ENIs / NICs** → ``CLOUD_RESOURCE`` wired ``PART_OF`` their instance,
      subnet, and security group(s) so the network path is traversable; an ENI
      carrying a public IP marks its instance internet-reachable and emits
      ``EXPOSED_TO`` the instance.
    - **Elastic/public IPs** → ``EXPOSED_TO`` the attached instance when known.
    - **Internet-facing API gateways** → ``EXPOSED_TO`` protected frontends.
    - NAT/internet gateways, route tables, network ACLs, VPC endpoints, load
      balancers, and IP addresses → ``CLOUD_RESOURCE`` inventory nodes.

    Never raises into the builder; missing/empty collections are a no-op.
    """
    # Index existing resource nodes by their native id/arn/name so a WAF / API
    # gateway's protected-target reference resolves to the real node.
    ref_to_node: dict[str, str] = {}
    for nid in resource_ids:
        node = graph.nodes.get(nid)
        if node is None:
            continue
        for key in ("resource_id", "resource_name"):
            ref = _clean_graph_part(node.attributes.get(key))
            if ref:
                ref_to_node.setdefault(ref, nid)

    def _emit_resource(*, node_id: str, service: str, rtype: str, kind: str, label: str, name: str, attrs: dict[str, Any]) -> None:
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{label}: {name}",
                attributes={
                    "resource_name": name,
                    "resource_type": rtype,
                    "resource_kind": kind,
                    "cloud_provider": provider,
                    "cloud_service": service,
                    "location": _clean_graph_part(attrs.get("location")) or region,
                    "account_id": account_id,
                    **attrs,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="network"),
            )
        )
        resource_ids.append(node_id)
        if account_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=account_node_id, target=node_id, relationship=RelationshipType.OWNS, evidence={"source": "cloud-inventory"}
                )
            )

    def _protect(source_node_id: str, targets: list[Any], reason: str) -> None:
        for target_ref in targets or []:
            ref = _clean_graph_part(target_ref)
            target_node_id = ref_to_node.get(ref)
            if not target_node_id:
                continue
            graph.add_edge(
                UnifiedEdge(
                    source=source_node_id,
                    target=target_node_id,
                    relationship=RelationshipType.PROTECTS,
                    weight=4.0,
                    evidence={"source": "cloud-inventory", "reason": reason},
                )
            )

    # ── Subnets (public subnet = internet-reachable) ──
    subnet_node_by_id: dict[str, str] = {}
    for sn in inventory.get("subnets", []) or []:
        if not isinstance(sn, dict):
            continue
        sn_id = _clean_graph_part(sn.get("id"))
        if not sn_id:
            continue
        node_id = f"cloud_resource:{provider}:network:subnet:{sn_id}"
        subnet_node_by_id[sn_id] = node_id
        _emit_resource(
            node_id=node_id,
            service="network",
            rtype="subnet",
            kind="subnet",
            label="subnet",
            name=_clean_graph_part(sn.get("name")) or sn_id,
            attrs={
                "resource_id": sn_id,
                "vpc_id": _clean_graph_part(sn.get("vpc_id")),
                "cidr": _clean_graph_part(sn.get("cidr")),
                "is_public": bool(sn.get("is_public")),
                "internet_exposed": bool(sn.get("is_public")),
            },
        )

    # ── Generic edge resources (NAT/IGW/route-table/NACL/VPCe + GCP LB) ──
    collections = list(_NETWORK_EDGE_COLLECTIONS)
    if provider == "gcp":
        collections.append(_GCP_LB_COLLECTION)
    for coll_key, svc, rtype, kind, label, id_field in collections:
        for item in inventory.get(coll_key, []) or []:
            if not isinstance(item, dict):
                continue
            ident = _clean_graph_part(item.get(id_field)) or _clean_graph_part(item.get("name"))
            if not ident:
                continue
            node_id = f"cloud_resource:{provider}:{svc}:{rtype}:{ident}"
            _emit_resource(
                node_id=node_id,
                service=svc,
                rtype=rtype,
                kind=kind,
                label=label,
                name=_clean_graph_part(item.get("name")) or ident,
                attrs={
                    "resource_id": ident,
                    "vpc_id": _clean_graph_part(item.get("vpc_id")),
                    "internet_exposed": bool(item.get("internet_exposed")),
                    "has_internet_route": bool(item.get("has_internet_route")),
                    "subnet_ids": list(item.get("subnet_ids", []) or []),
                    "network_exposure": list(item.get("network_exposure", []) or []),
                },
            )

    # ── IP addresses (Elastic/reserved/public) ──
    for ip in inventory.get("ip_addresses", []) or []:
        if not isinstance(ip, dict):
            continue
        address = _clean_graph_part(ip.get("address"))
        if not address:
            continue
        node_id = f"cloud_resource:{provider}:network:ip_address:{address}"
        _emit_resource(
            node_id=node_id,
            service="network",
            rtype="ip_address",
            kind="ip-address",
            label="ip address",
            name=address,
            attrs={
                "resource_id": address,
                "ip_kind": _clean_graph_part(ip.get("kind")),
                "attached_to": _clean_graph_part(ip.get("attached_to")),
                "internet_exposed": True,
            },
        )
        attached_instance = instance_node_by_id.get(_clean_graph_part(ip.get("attached_to")))
        if attached_instance:
            _add_exposure_path_edge(
                graph,
                source=node_id,
                target=attached_instance,
                reason="elastic_ip_attachment",
            )

    # ── ENIs / NICs → PART_OF instance + subnet + security group(s) ──
    for eni in inventory.get("network_interfaces", []) or []:
        if not isinstance(eni, dict):
            continue
        eni_id = _clean_graph_part(eni.get("id"))
        if not eni_id:
            continue
        node_id = f"cloud_resource:{provider}:network:network_interface:{eni_id}"
        public_ip = _clean_graph_part(eni.get("public_ip"))
        _emit_resource(
            node_id=node_id,
            service="network",
            rtype="network_interface",
            kind="network-interface",
            label="network interface",
            name=_clean_graph_part(eni.get("name")) or eni_id,
            attrs={
                "resource_id": eni_id,
                "vpc_id": _clean_graph_part(eni.get("vpc_id")),
                "subnet_id": _clean_graph_part(eni.get("subnet_id")),
                "private_ip": _clean_graph_part(eni.get("private_ip")),
                "public_ip": public_ip,
                "internet_exposed": bool(public_ip),
            },
        )
        instance_node_id = instance_node_by_id.get(_clean_graph_part(eni.get("instance_id")))
        if instance_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=node_id, target=instance_node_id, relationship=RelationshipType.PART_OF, evidence={"source": "cloud-inventory"}
                )
            )
            # A public IP on the ENI makes the attached instance internet-reachable.
            if public_ip:
                inst_node = graph.nodes.get(instance_node_id)
                if inst_node is not None:
                    inst_node.attributes["internet_exposed"] = True
                _add_exposure_path_edge(
                    graph,
                    source=node_id,
                    target=instance_node_id,
                    reason="eni_public_ip",
                )
        subnet_node_id = subnet_node_by_id.get(_clean_graph_part(eni.get("subnet_id")))
        if subnet_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=node_id, target=subnet_node_id, relationship=RelationshipType.PART_OF, evidence={"source": "cloud-inventory"}
                )
            )
        for sg_id in eni.get("security_group_ids", []) or []:
            sg_node_id = sg_node_by_id.get(_clean_graph_part(sg_id))
            if sg_node_id:
                graph.add_edge(
                    UnifiedEdge(
                        source=node_id, target=sg_node_id, relationship=RelationshipType.PART_OF, evidence={"source": "cloud-inventory"}
                    )
                )

    # ── WAF / Cloud Armor web ACLs → CLOUD_RESOURCE + PROTECTS ──
    for acl in inventory.get("web_acls", []) or []:
        if not isinstance(acl, dict):
            continue
        acl_id = _clean_graph_part(acl.get("id")) or _clean_graph_part(acl.get("arn")) or _clean_graph_part(acl.get("name"))
        if not acl_id:
            continue
        name = _clean_graph_part(acl.get("name")) or acl_id
        node_id = f"cloud_resource:{provider}:waf:web_acl:{acl_id}"
        _emit_resource(
            node_id=node_id,
            service="waf",
            rtype="waf",
            kind="web-acl",
            label="waf",
            name=name,
            attrs={"resource_id": _clean_graph_part(acl.get("arn")) or acl_id, "scope": _clean_graph_part(acl.get("scope"))},
        )
        _protect(node_id, acl.get("protected_targets", []), "waf_web_acl_association")
        waf_node = graph.nodes.get(node_id)
        if waf_node is not None:
            waf_node.attributes["internet_exposed"] = True
        for target_ref in acl.get("protected_targets", []) or []:
            ref = _clean_graph_part(target_ref)
            target_node_id = ref_to_node.get(ref)
            if target_node_id:
                _add_exposure_path_edge(
                    graph,
                    source=node_id,
                    target=target_node_id,
                    reason="waf_internet_entry",
                )

    # ── API gateways → API_GATEWAY nodes (+ Azure API Management) + PROTECTS ──
    api_gateway_items = list(inventory.get("api_gateways", []) or [])
    for apim in inventory.get("api_management", []) or []:
        if isinstance(apim, dict):
            api_gateway_items.append(
                {
                    "name": apim.get("name"),
                    "id": apim.get("id") or apim.get("name"),
                    "protocol": "apim",
                    "endpoint": apim.get("gateway_url") or apim.get("endpoint") or "",
                    "internet_exposed": True,
                    "stages": [],
                    "protected_targets": apim.get("protected_targets", []),
                    "location": apim.get("location"),
                }
            )
    for api in api_gateway_items:
        if not isinstance(api, dict):
            continue
        api_id = _clean_graph_part(api.get("id")) or _clean_graph_part(api.get("arn")) or _clean_graph_part(api.get("name"))
        if not api_id:
            continue
        name = _clean_graph_part(api.get("name")) or api_id
        node_id = f"api_gateway:{provider}:{api_id}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.API_GATEWAY,
                label=f"api gateway: {name}",
                attributes={
                    "resource_id": _clean_graph_part(api.get("arn")) or api_id,
                    "resource_name": name,
                    "resource_type": "api_gateway",
                    "cloud_provider": provider,
                    "protocol": _clean_graph_part(api.get("protocol")),
                    "endpoint": _clean_graph_part(api.get("endpoint")),
                    "stages": list(api.get("stages", []) or []),
                    "internet_exposed": bool(api.get("internet_exposed")),
                    "location": _clean_graph_part(api.get("location")) or region,
                    "account_id": account_id,
                    "semantic_layer": "api_gateway",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="api_gateway"),
            )
        )
        resource_ids.append(node_id)
        if account_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=account_node_id, target=node_id, relationship=RelationshipType.OWNS, evidence={"source": "cloud-inventory"}
                )
            )
        _protect(node_id, api.get("protected_targets", []), "api_gateway_frontend")
        if api.get("internet_exposed"):
            for target_ref in api.get("protected_targets", []) or []:
                ref = _clean_graph_part(target_ref)
                target_node_id = ref_to_node.get(ref)
                if target_node_id:
                    _add_exposure_path_edge(
                        graph,
                        source=node_id,
                        target=target_node_id,
                        reason="internet_facing_api_gateway",
                    )

    _wire_network_entry_exposure_paths(
        graph,
        inventory,
        provider=provider,
        subnet_node_by_id=subnet_node_by_id,
        instance_node_by_id=instance_node_by_id,
    )


def _wire_network_entry_exposure_paths(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    subnet_node_by_id: dict[str, str],
    instance_node_by_id: dict[str, str],
) -> None:
    """Link IGW / public subnet / permissive NACL nodes to reachable instances."""
    public_subnet_ids = {
        sn_id
        for sn in inventory.get("subnets", []) or []
        if isinstance(sn, dict)
        for sn_id in [_clean_graph_part(sn.get("id"))]
        if sn_id and sn.get("is_public")
    }
    igw_by_vpc: dict[str, str] = {}
    for igw in inventory.get("internet_gateways", []) or []:
        if not isinstance(igw, dict):
            continue
        kind = _clean_graph_part(igw.get("kind")) or "internet-gateway"
        if kind != "internet-gateway":
            continue
        ident = _clean_graph_part(igw.get("id"))
        vpc_id = _clean_graph_part(igw.get("vpc_id"))
        if not ident or not vpc_id:
            continue
        node_id = f"cloud_resource:{provider}:network:internet_gateway:{ident}"
        if node_id in graph.nodes:
            graph.nodes[node_id].attributes["internet_exposed"] = True
            igw_by_vpc[vpc_id] = node_id

    for vpc_id, igw_node in igw_by_vpc.items():
        for sn in inventory.get("subnets", []) or []:
            if not isinstance(sn, dict):
                continue
            sn_id = _clean_graph_part(sn.get("id"))
            if sn_id not in public_subnet_ids or _clean_graph_part(sn.get("vpc_id")) != vpc_id:
                continue
            sn_node = subnet_node_by_id.get(sn_id)
            if sn_node:
                _add_exposure_path_edge(
                    graph,
                    source=igw_node,
                    target=sn_node,
                    reason="internet_gateway_public_subnet",
                )

    for sn_id in public_subnet_ids:
        sn_node = subnet_node_by_id.get(sn_id)
        if not sn_node:
            continue
        for instance in inventory.get("instances", []) or []:
            if not isinstance(instance, dict):
                continue
            if _clean_graph_part(instance.get("subnet_id")) != sn_id:
                continue
            inst_node = instance_node_by_id.get(_clean_graph_part(instance.get("instance_id")))
            if inst_node:
                _add_exposure_path_edge(
                    graph,
                    source=sn_node,
                    target=inst_node,
                    reason="public_subnet_instance",
                )

    for nacl in inventory.get("network_acls", []) or []:
        if not isinstance(nacl, dict) or not nacl.get("internet_exposed"):
            continue
        ident = _clean_graph_part(nacl.get("id"))
        if not ident:
            continue
        nacl_node = f"cloud_resource:{provider}:network:network_acl:{ident}"
        if nacl_node not in graph.nodes:
            continue
        for sn_id in nacl.get("subnet_ids", []) or []:
            sn_clean = _clean_graph_part(sn_id)
            sn_node = subnet_node_by_id.get(sn_clean)
            if sn_node:
                _add_exposure_path_edge(
                    graph,
                    source=nacl_node,
                    target=sn_node,
                    reason="permissive_network_acl",
                )
            for instance in inventory.get("instances", []) or []:
                if not isinstance(instance, dict):
                    continue
                if _clean_graph_part(instance.get("subnet_id")) != sn_clean:
                    continue
                inst_node = instance_node_by_id.get(_clean_graph_part(instance.get("instance_id")))
                if inst_node:
                    _add_exposure_path_edge(
                        graph,
                        source=nacl_node,
                        target=inst_node,
                        reason="permissive_network_acl_instance",
                    )


def _add_inventory_principal(
    graph: UnifiedGraph,
    principal: dict[str, Any],
    *,
    provider: str,
    account_node_id: str,
    resource_ids: list[str],
    data_sources: list[str],
) -> None:
    """Emit one IAM role/user as an identity principal with policy + access edges."""
    principal_type = _clean_graph_part(principal.get("principal_type")) or "user"
    principal_id = _clean_graph_part(principal.get("arn")) or _clean_graph_part(principal.get("name"))
    principal_name = _clean_graph_part(principal.get("name")) or principal_id
    if not principal_id:
        return
    entity_type = _identity_entity_type(principal_type)
    principal_node_id = _identity_node_id(entity_type, provider, principal_id)
    graph.add_node(
        UnifiedNode(
            id=principal_node_id,
            entity_type=entity_type,
            label=principal_name,
            attributes={
                "principal_id": principal_id,
                "principal_name": principal_name,
                "principal_type": principal_type,
                "cloud_provider": provider,
                "privilege_level": _clean_graph_part(principal.get("privilege_level")) or "unknown",
                "iam_path": _clean_graph_part(principal.get("path")),
                "source": "cloud-inventory",
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
        )
    )
    if account_node_id:
        graph.add_edge(
            UnifiedEdge(
                source=principal_node_id,
                target=account_node_id,
                relationship=RelationshipType.MEMBER_OF,
                evidence={"source": "cloud-inventory", "principal_type": principal_type},
            )
        )

    # Attached policies (privilege already classified by the scanner).
    for policy in _policy_entries(principal):
        policy_node_id = _identity_node_id(EntityType.POLICY, provider, policy["id"])
        graph.add_node(
            UnifiedNode(
                id=policy_node_id,
                entity_type=EntityType.POLICY,
                label=policy["name"],
                attributes={
                    "policy_id": policy["id"],
                    "policy_name": policy["name"],
                    "privilege_level": policy.get("privilege_level", "unknown"),
                    "cloud_provider": provider,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=principal_node_id,
                target=policy_node_id,
                relationship=RelationshipType.ATTACHED,
                evidence={"source": "cloud-inventory", "principal_type": principal_type},
            )
        )

    # Trust principals from the AssumeRole policy document.
    for trust in _trust_entries(principal):
        trust_entity_type = _identity_entity_type(trust["type"])
        trust_node_id = _identity_node_id(trust_entity_type, provider, trust["id"])
        graph.add_node(
            UnifiedNode(
                id=trust_node_id,
                entity_type=trust_entity_type,
                label=trust["name"],
                attributes={
                    "principal_id": trust["id"],
                    "principal_name": trust["name"],
                    "principal_type": trust["type"],
                    "cloud_provider": provider,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        relationship = (
            RelationshipType.CROSS_ACCOUNT_TRUST
            if trust["relationship"] == RelationshipType.CROSS_ACCOUNT_TRUST.value
            else RelationshipType.TRUSTS
        )
        graph.add_edge(
            UnifiedEdge(
                source=principal_node_id,
                target=trust_node_id,
                relationship=relationship,
                evidence={
                    "source": "cloud-inventory",
                    "principal_type": principal_type,
                    "trusted_principal_type": trust["type"],
                    "source_field": trust["source_field"],
                },
            )
        )

    # Direct access to the account's inventoried resources. The effective-
    # permissions overlay turns CAN_ACCESS (+ assume/trust chains) into the
    # HAS_PERMISSION transitive closure; admin-privileged principals reach
    # every resource, others get a baseline same-account access edge.
    privilege = _clean_graph_part(principal.get("privilege_level")) or "unknown"
    if privilege in ("admin", "write"):
        for resource_id in resource_ids:
            graph.add_edge(
                UnifiedEdge(
                    source=principal_node_id,
                    target=resource_id,
                    relationship=RelationshipType.CAN_ACCESS,
                    evidence={"source": "cloud-inventory", "basis": f"{privilege}_privilege"},
                )
            )


def _add_inventory_group(
    graph: UnifiedGraph,
    group: dict[str, Any],
    *,
    provider: str,
    account_node_id: str,
    resource_ids: list[str],
    data_sources: list[str],
) -> None:
    """Emit one IAM/Entra group as a ``GROUP`` node with policies + membership.

    The group node carries its attached/bound policies (``ATTACHED``) and, when
    it is admin/write-privileged, a ``CAN_ACCESS`` edge to each inventoried
    resource — the same baseline the effective-permissions overlay applies to a
    user/role. ``MEMBER_OF`` edges run from each member principal to the group so
    the overlay attributes group-granted access to the member. Members are created
    as thin nodes when a per-principal scan has not already added them.
    """
    group_id = _clean_graph_part(group.get("arn")) or _clean_graph_part(group.get("name"))
    if not group_id:
        return
    group_name = _clean_graph_part(group.get("name")) or group_id
    group_node_id = _identity_node_id(EntityType.GROUP, provider, group_id)
    privilege = _clean_graph_part(group.get("privilege_level")) or "unknown"
    graph.add_node(
        UnifiedNode(
            id=group_node_id,
            entity_type=EntityType.GROUP,
            label=group_name,
            attributes={
                "principal_id": group_id,
                "principal_name": group_name,
                "principal_type": "group",
                "cloud_provider": provider,
                "privilege_level": privilege,
                "iam_path": _clean_graph_part(group.get("path")),
                "source": "cloud-inventory",
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
        )
    )
    if account_node_id:
        _add_rel_edge(
            graph, group_node_id, account_node_id, RelationshipType.MEMBER_OF, {"source": "cloud-inventory", "principal_type": "group"}
        )

    # Group-attached policies (privilege already classified by the scanner).
    for policy in _policy_entries(group):
        policy_node_id = _add_identity_node(
            graph,
            EntityType.POLICY,
            policy["id"],
            provider,
            data_sources,
            label=policy["name"],
            policy_id=policy["id"],
            policy_name=policy["name"],
            privilege_level=policy.get("privilege_level", "unknown"),
            cloud_provider=provider,
        )
        _add_rel_edge(
            graph, group_node_id, policy_node_id, RelationshipType.ATTACHED, {"source": "cloud-inventory", "principal_type": "group"}
        )

    # Admin/write group → baseline same-account CAN_ACCESS, so the overlay can
    # inherit it to members via MEMBER_OF (mirrors the user/role baseline).
    if privilege in ("admin", "write"):
        for resource_id in resource_ids:
            _add_rel_edge(
                graph,
                group_node_id,
                resource_id,
                RelationshipType.CAN_ACCESS,
                {"source": "cloud-inventory", "basis": f"{privilege}_privilege"},
            )

    # Members → MEMBER_OF the group. Each member may be a user / service principal
    # / nested group; create a thin node when the member was not separately
    # inventoried so the membership edge always lands on a real node.
    for member in group.get("members", []) or []:
        if not isinstance(member, dict):
            continue
        member_id = _clean_graph_part(member.get("id"))
        if not member_id:
            continue
        member_entity = _identity_entity_type(_clean_graph_part(member.get("type")) or "user")
        member_node_id = _identity_node_id(member_entity, provider, member_id)
        if member_node_id not in graph.nodes:
            _add_identity_node(
                graph,
                member_entity,
                member_id,
                provider,
                data_sources,
                label=_clean_graph_part(member.get("name")) or member_id,
                principal_id=member_id,
                principal_name=_clean_graph_part(member.get("name")) or member_id,
                principal_type=_clean_graph_part(member.get("type")) or "user",
                cloud_provider=provider,
                source="cloud-inventory",
            )
        _add_rel_edge(
            graph, member_node_id, group_node_id, RelationshipType.MEMBER_OF, {"source": "cloud-inventory", "membership": "group"}
        )


def _add_cross_env_correlation(
    graph: UnifiedGraph,
    agents_data: Any,
    data_source: str,
) -> None:
    """Emit local↔cloud correlation edges across all configured providers.

    The strict-bar matcher in :mod:`agent_bom.cross_env_correlation` decides
    whether each candidate qualifies for ``CORRELATES_WITH`` (HIGH-confidence
    triplet match) or only ``POSSIBLY_CORRELATES_WITH`` (single-signal). Both
    relationships carry the matched signals and rationale so reviewers can see
    why the platform drew the line.
    """
    from agent_bom.cross_env_correlation import (
        CorrelationConfidence,
        correlate_cross_environment,
    )

    if not isinstance(agents_data, list):
        return
    result = correlate_cross_environment(agents_data)
    if not result.matches:
        return

    for match in result.matches:
        local_id = f"agent:{match.local_agent_name}"
        cloud_id = f"agent:{match.cloud_agent_name}"
        # Only wire edges between agents we already added as nodes — the
        # matcher operates over the report payload but the graph may have
        # filtered some agents out earlier.
        if not graph.get_node(local_id) or not graph.get_node(cloud_id):
            continue
        relationship = (
            RelationshipType.CORRELATES_WITH
            if match.confidence is CorrelationConfidence.HIGH
            else RelationshipType.POSSIBLY_CORRELATES_WITH
        )
        graph.add_edge(
            UnifiedEdge(
                source=local_id,
                target=cloud_id,
                relationship=relationship,
                # Cross-env correlation is semantically symmetric ("local
                # agent X corresponds to cloud agent Y" reads the same in
                # either direction), so the edge must be traversable both
                # ways. Without `bidirectional`, a query "for this cloud
                # Bedrock/Azure/Vertex agent, which local agent talks to
                # it?" misses the edge on the forward adjacency index and
                # only finds it via reverse_adjacency — silently
                # inconsistent with how the graph treats peer relations
                # like SHARES_SERVER and SHARES_CRED.
                direction="bidirectional",
                evidence={
                    "data_source": data_source,
                    "confidence": match.confidence.value,
                    "matched_signals": list(match.matched_signals),
                    "cloud_provider": match.cloud_provider,
                    "cloud_service": match.cloud_service,
                    "cloud_account_id": match.cloud_account_id or "",
                    "cloud_region": match.cloud_region or "",
                    "cloud_model_id": match.cloud_model_id or "",
                    "rationale": match.rationale,
                },
            )
        )


def _add_framework_topology(graph: UnifiedGraph, framework_agents: Any, data_source: str) -> None:
    """Add static framework-native agent nodes and topology edges."""
    if not isinstance(framework_agents, list):
        return
    known_agent_ids: set[str] = set()
    for item in framework_agents:
        if not isinstance(item, dict):
            continue
        agent_id = str(item.get("stable_id") or "").strip()
        if not agent_id:
            continue
        known_agent_ids.add(agent_id)
        graph.add_node(
            UnifiedNode(
                id=agent_id,
                entity_type=EntityType.AGENT,
                label=str(item.get("name") or agent_id),
                attributes={
                    "agent_type": "framework-agent",
                    "framework": item.get("framework", ""),
                    "file_path": item.get("file_path", ""),
                    "line_number": item.get("line_number", 0),
                    "confidence": item.get("confidence", ""),
                    "model_refs": item.get("model_refs", []),
                    "credential_refs": item.get("credential_refs", []),
                    "capabilities": item.get("capabilities", []),
                    "dynamic_edges": item.get("dynamic_edges", False),
                },
                dimensions=NodeDimensions(agent_type="framework-agent", surface=str(item.get("framework", ""))),
                data_sources=[data_source, "source-ast"],
            )
        )

    for item in framework_agents:
        if not isinstance(item, dict):
            continue
        for edge in item.get("topology_edges", []):
            if not isinstance(edge, dict):
                continue
            source_id = str(edge.get("source_id") or "").strip()
            target_id = str(edge.get("target_id") or "").strip()
            if not source_id or not target_id:
                continue
            for node_id, node_name in ((source_id, edge.get("source_name")), (target_id, edge.get("target_name"))):
                if node_id in known_agent_ids or graph.has_node(node_id):
                    continue
                graph.add_node(
                    UnifiedNode(
                        id=node_id,
                        entity_type=EntityType.AGENT,
                        label=str(node_name or node_id),
                        attributes={
                            "agent_type": "framework-agent",
                            "framework": edge.get("framework", ""),
                            "synthetic_from_topology_edge": True,
                        },
                        dimensions=NodeDimensions(agent_type="framework-agent", surface=str(edge.get("framework", ""))),
                        data_sources=[data_source, "source-ast"],
                    )
                )
                known_agent_ids.add(node_id)
            try:
                relationship = RelationshipType(str(edge.get("relationship") or "delegated_to"))
            except ValueError:
                continue
            graph.add_edge(
                UnifiedEdge(
                    source=source_id,
                    target=target_id,
                    relationship=relationship,
                    evidence={
                        "source": "source-ast",
                        "framework": edge.get("framework", ""),
                        "file_path": edge.get("file_path", ""),
                        "line_number": edge.get("line_number", 0),
                        "confidence": edge.get("confidence", ""),
                        "evidence": edge.get("evidence", ""),
                    },
                )
            )


def _clean_graph_part(value: Any) -> str:
    return str(value or "").strip()


def _agent_identity_scope(agent_dict: dict[str, Any]) -> str:
    """Return the endpoint/source scope that disambiguates fleet agents."""
    for key in ("source_id", "endpoint_id", "device_id"):
        value = str(agent_dict.get(key) or "").strip()
        if value:
            return value
    metadata = agent_dict.get("metadata")
    if isinstance(metadata, dict):
        for key in ("source_id", "endpoint_id", "device_id"):
            value = str(metadata.get(key) or "").strip()
            if value:
                return value
    return ""


def _agent_node_id(agent_name: Any, source_id: str = "") -> str:
    """Build an agent graph ID without collapsing same-name fleet endpoints."""
    name = str(agent_name or "unknown").strip() or "unknown"
    source = _clean_graph_part(source_id).replace(":", "%3A")
    if source:
        return f"agent:{source}:{name}"
    return f"agent:{name}"


def _flatten_compliance_tags(raw: Any) -> list[str]:
    """Normalize arbitrary compliance-tag payloads into a simple list."""
    if not raw:
        return []
    if isinstance(raw, list):
        return sorted({str(tag) for tag in raw if tag})
    if isinstance(raw, dict):
        tags: set[str] = set()
        for value in raw.values():
            if isinstance(value, list):
                tags.update(str(tag) for tag in value if tag)
            elif value:
                tags.add(str(value))
        return sorted(tags)
    return [str(raw)]


def _resolve_model_id(graph: UnifiedGraph, model_uri: str) -> str:
    """Best-effort link from a serving config model URI to a known model node."""
    if not model_uri:
        return ""
    candidates = [part for part in model_uri.replace("://", "/").replace(":", "/").split("/") if part]
    for candidate in reversed(candidates):
        model_id = f"model:{candidate}"
        if graph.has_node(model_id):
            return model_id
    return ""


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
        source_name = PurePath(source_file).name
        for config_path, agent_id in agent_config_path_to_id.items():
            if source_name and source_name == PurePath(config_path).name:
                target_ids.add(agent_id)

    if not target_ids and len(agent_name_to_ids) == 1:
        only_agent_ids = next(iter(agent_name_to_ids.values()))
        target_ids.update(only_agent_ids)

    return sorted(target_ids)
