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
    for section_key, legacy_key, cloud_provider in (
        ("cis_benchmark", "cis_benchmark_data", ""),
        ("snowflake_cis_benchmark", "snowflake_cis_benchmark_data", "snowflake"),
        ("azure_cis_benchmark", "azure_cis_benchmark_data", "azure"),
        ("gcp_cis_benchmark", "gcp_cis_benchmark_data", "gcp"),
        ("databricks_cis_benchmark", "databricks_cis_benchmark_data", "databricks"),
    ):
        cis_data = report_json.get(section_key) or report_json.get(legacy_key)
        if not cis_data:
            continue
        checks = cis_data.get("checks", [])
        cloud_account_id = _clean_graph_part(cis_data.get("subscription_id") or cis_data.get("account_id"))
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

    _add_snowflake_object_graph(graph, report_json.get("snowflake_object_graph"), data_source_tag)
    _add_snowflake_exfil(graph, report_json.get("snowflake_exfil_graph"), data_source_tag)

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

    if span is not None:
        span.set_attribute("agent_bom.graph.scan_id", sid)
        span.set_attribute("agent_bom.graph.tenant_id", tenant_id or "default")
        span.set_attribute("agent_bom.graph.agent_count", len(agents_data))
        span.set_attribute("agent_bom.graph.blast_radius_count", len(blast_data))
        span.set_attribute("agent_bom.graph.node_count", len(graph.nodes))
        span.set_attribute("agent_bom.graph.edge_count", len(graph.edges))
        span.end()
    return graph


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
        if candidate_ids and named_ids and not narrowed:
            _logger.debug(
                "blast-radius narrow-by-server collapsed to empty: pkg=%s servers=%s candidates=%s",
                pkg_name,
                sorted(server_names),
                sorted(candidate_ids),
            )
        candidate_ids = narrowed

    agent_names = {str(agent).strip() for agent in br_dict.get("affected_agents", []) if str(agent).strip()}
    if agent_names:
        agent_ids: set[str] = set()
        for agent_name in agent_names:
            agent_ids.update(agent_to_server_ids.get(agent_name, set()))
        narrowed = (candidate_ids & agent_ids) if candidate_ids else agent_ids
        if candidate_ids and agent_ids and not narrowed:
            _logger.debug(
                "blast-radius narrow-by-agent collapsed to empty: pkg=%s agents=%s candidates=%s",
                pkg_name,
                sorted(agent_names),
                sorted(candidate_ids),
            )
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
        graph.add_node(
            UnifiedNode(
                id=org_node_id,
                entity_type=EntityType.ORG,
                label=org_id,
                attributes={
                    "org_id": org_id,
                    "scope_key": org_key,
                    "cloud_provider": provider,
                    "cloud_origin": origin,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=cloud_provider_id,
                target=org_node_id,
                relationship=RelationshipType.HOSTS,
                evidence={"source": "cloud_origin", "provider": provider, "scope_key": org_key},
            )
        )
    if account_node_id:
        graph.add_node(
            UnifiedNode(
                id=account_node_id,
                entity_type=EntityType.ACCOUNT,
                label=account_id,
                attributes={
                    "account_id": account_id,
                    "scope_key": account_key or "account_id",
                    "cloud_provider": provider,
                    "cloud_origin": origin,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=cloud_provider_id,
                target=account_node_id,
                relationship=RelationshipType.HOSTS,
                evidence={"source": "cloud_origin", "provider": provider, "scope_key": account_key or "account_id"},
            )
        )
        if org_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=account_node_id,
                    target=org_node_id,
                    relationship=RelationshipType.PART_OF,
                    evidence={"source": "cloud_origin", "provider": provider, "scope_key": org_key},
                )
            )
        graph.add_edge(
            UnifiedEdge(
                source=account_node_id,
                target=resource_node_id,
                relationship=RelationshipType.HOSTS,
                evidence={"source": "cloud_origin", "provider": provider, "scope_key": account_key or "account_id"},
            )
        )
    graph.add_edge(
        UnifiedEdge(
            source=cloud_provider_id,
            target=resource_node_id,
            relationship=RelationshipType.HOSTS,
            evidence={"source": "cloud_origin", "provider": provider, "service": service},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=resource_node_id,
            target=agent_id,
            relationship=RelationshipType.HOSTS,
            evidence={"source": "cloud_origin", "resource_id": resource_id},
        )
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
    principal_node_id = _identity_node_id(principal_entity_type, provider, principal_id)
    graph.add_node(
        UnifiedNode(
            id=principal_node_id,
            entity_type=principal_entity_type,
            label=principal_name,
            attributes={
                "principal_id": principal_id,
                "principal_name": principal_name,
                "principal_type": principal_type,
                "tenant_id": principal.get("tenant_id", ""),
                "source_field": principal.get("source_field", ""),
                "cloud_provider": provider,
                "cloud_service": service,
                "cloud_principal": principal,
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
                evidence={"source": "cloud_principal", "principal_type": principal_type},
            )
        )
    graph.add_edge(
        UnifiedEdge(
            source=principal_node_id,
            target=resource_node_id,
            relationship=RelationshipType.MANAGES,
            evidence={"source": "cloud_principal", "principal_type": principal_type},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=principal_node_id,
            target=resource_node_id,
            relationship=RelationshipType.CAN_ACCESS,
            evidence={"source": "cloud_principal", "principal_type": principal_type},
        )
    )
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
                evidence={"source": "cloud_principal", "principal_type": principal_type},
            )
        )
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
                    "source": "cloud_principal_trust",
                    "principal_type": principal_type,
                    "trusted_principal_type": trust["type"],
                    "source_field": trust["source_field"],
                },
            )
        )
    # Direct principal → agent edge so single-hop "which principals can
    # reach this agent?" queries don't have to traverse the intermediate
    # cloud_resource node. The intermediate edges (principal → resource,
    # resource → agent) above stay so the lineage is fully reconstructable.
    # `via` records that the relationship is mediated by a cloud_resource
    # so consumers can distinguish direct ownership from cloud-mediated
    # operation when they need to.
    graph.add_edge(
        UnifiedEdge(
            source=principal_node_id,
            target=agent_id,
            relationship=RelationshipType.MANAGES,
            evidence={
                "source": "cloud_principal",
                "principal_type": principal_type,
                "via": resource_node_id,
            },
        )
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
    return {
        **inventory,
        "buckets": buckets,
        "security_groups": groups,
        "instances": instances,
        "roles": [],
        "users": principals,
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
    return {
        **inventory,
        "buckets": buckets,
        "security_groups": groups,
        "instances": instances,
        "roles": [],
        "users": principals,
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
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return
    account = _clean_graph_part(payload.get("account"))
    data_sources = sorted({data_source, "snowflake-objects"} - {""})

    account_node_id = _identity_node_id(EntityType.ACCOUNT, "snowflake", account) if account else ""
    if account_node_id:
        graph.add_node(
            UnifiedNode(
                id=account_node_id,
                entity_type=EntityType.ACCOUNT,
                label=account or "snowflake",
                attributes={"account_id": account, "cloud_provider": "snowflake", "source": "snowflake-objects"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
            )
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
            graph.add_edge(
                UnifiedEdge(
                    source=account_node_id,
                    target=node_id,
                    relationship=RelationshipType.OWNS,
                    evidence={"source": "snowflake-objects"},
                )
            )
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
        graph.add_edge(
            UnifiedEdge(
                source=src,
                target=tgt,
                relationship=RelationshipType.DEPENDS_ON,
                evidence={"source": "snowflake-objects", "dependency_type": dep.get("dependency_type", "")},
            )
        )

    # ── Roles + users (CIEM access layer) ──────────────────────────────
    seen_roles: set[str] = set()

    def _ensure_role(name: str) -> str:
        node_id = f"role:snowflake:{name}"
        if node_id not in seen_roles:
            seen_roles.add(node_id)
            graph.add_node(
                UnifiedNode(
                    id=node_id,
                    entity_type=EntityType.ROLE,
                    label=f"role: {name}",
                    attributes={"role_name": name, "cloud_provider": "snowflake", "source": "snowflake-objects"},
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
                )
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
        graph.add_edge(
            UnifiedEdge(
                source=_ensure_role(role),
                target=_ensure_object(object_fqn, object_type=str(grant.get("object_type") or "object").lower()),
                relationship=RelationshipType.HAS_PERMISSION,
                evidence={"source": "snowflake-objects", "privilege": grant.get("privilege", "")},
            )
        )

    # User → role memberships: the user ASSUMES the role's privileges.
    seen_users: set[str] = set()
    for membership in payload.get("role_memberships", []) or []:
        if not isinstance(membership, dict):
            continue
        user_name = _clean_graph_part(membership.get("user"))
        role = _clean_graph_part(membership.get("role"))
        if not user_name or not role:
            continue
        user_node_id = f"user:snowflake:{user_name}"
        if user_node_id not in seen_users:
            seen_users.add(user_node_id)
            graph.add_node(
                UnifiedNode(
                    id=user_node_id,
                    entity_type=EntityType.USER,
                    label=f"user: {user_name}",
                    attributes={"user_name": user_name, "cloud_provider": "snowflake", "source": "snowflake-objects"},
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
                )
            )
        graph.add_edge(
            UnifiedEdge(
                source=user_node_id,
                target=_ensure_role(role),
                relationship=RelationshipType.ASSUMES,
                evidence={"source": "snowflake-objects"},
            )
        )


_EXFIL_STAGE_SERVICE = {"aws": "s3", "azure": "blob", "gcp": "gcs"}


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
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return
    account = _clean_graph_part(payload.get("account"))
    data_sources = sorted({data_source, "snowflake-exfil"} - {""})
    account_node_id = _identity_node_id(EntityType.ACCOUNT, "snowflake", account) if account else ""
    if account_node_id:
        graph.add_node(
            UnifiedNode(
                id=account_node_id,
                entity_type=EntityType.ACCOUNT,
                label=account or "snowflake",
                attributes={"account_id": account, "cloud_provider": "snowflake", "source": "snowflake-exfil"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
            )
        )

    def _owned(node: UnifiedNode) -> str:
        graph.add_node(node)
        if account_node_id:
            graph.add_edge(
                UnifiedEdge(
                    source=account_node_id,
                    target=node.id,
                    relationship=RelationshipType.OWNS,
                    evidence={"source": "snowflake-exfil"},
                )
            )
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
            consumer_id = _identity_node_id(EntityType.ACCOUNT, "snowflake", consumer)
            graph.add_node(
                UnifiedNode(
                    id=consumer_id,
                    entity_type=EntityType.ACCOUNT,
                    label=f"consumer account: {consumer}",
                    attributes={
                        "account_id": consumer,
                        "cloud_provider": "snowflake",
                        "is_external_consumer": True,
                        "internet_exposed": consumer == "public-marketplace",
                    },
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
                )
            )
            graph.add_edge(
                UnifiedEdge(
                    source=share_id,
                    target=consumer_id,
                    relationship=RelationshipType.EXPOSED_TO,
                    evidence={"source": "snowflake-exfil", "channel": "data-share", "marketplace": is_marketplace},
                )
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
        graph.add_edge(
            UnifiedEdge(
                source=stage_id,
                target=bucket_node_id,
                relationship=RelationshipType.EXPOSED_TO,
                evidence={"source": "snowflake-exfil", "channel": "external-stage", "destination_cloud": cloud},
            )
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
                    "account_id": account_id,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="ec2"),
            )
        )
        resource_ids.append(node_id)

    # ── EC2 instances → CLOUD_RESOURCE (linked to their security groups) ──
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
                    "account_id": account_id,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="ec2"),
            )
        )
        resource_ids.append(node_id)
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

    # ── Management-group hierarchy (org → subscription CONTAINS tree) ──
    _add_management_group_hierarchy(graph, original_inventory, provider=provider, data_sources=data_sources)

    # ── IAM roles + users → identity principals (CAN_ACCESS resources) ──
    for principal in [*(inventory.get("roles", []) or []), *(inventory.get("users", []) or [])]:
        if isinstance(principal, dict):
            _add_inventory_principal(
                graph, principal, provider=provider, account_node_id=account_node_id, resource_ids=resource_ids, data_sources=data_sources
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
