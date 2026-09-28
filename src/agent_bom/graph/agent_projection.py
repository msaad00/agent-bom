"""Agent/server inventory projection with per-build indexes and explicit lineage input."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from agent_bom.asset_provenance import sanitize_discovery_provenance
from agent_bom.canonical_ids import canonical_agent_id, canonical_graph_node_id, source_ids
from agent_bom.graph.build_indexes import BuildIndexes
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.credential_projection import project_credentials
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.package_projection import (
    _add_vuln_node,
    _package_evidence,
    _package_graph_key,
    _package_node_id,
    _package_version_provenance_from_dict,
    _tool_capabilities,
)
from agent_bom.graph.projection_support import (
    _agent_identity_scope,
    _agent_node_id,
    _is_repository_inventory,
    _is_sbom_import,
    _normalized_environment,
    _repository_manifest_directory,
)
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.package_utils import normalize_package_name
from agent_bom.security import sanitize_security_warnings, sanitize_text, sanitize_url


class CloudLineageProjection(Protocol):
    def __call__(
        self, graph: UnifiedGraph, *, agent_id: str, agent_dict: dict[str, Any], agent_metadata: dict[str, Any], data_source: str
    ) -> None: ...


@dataclass
class AgentScope:
    agent_dict: dict[str, Any]
    agent_metadata: dict[str, Any]
    agent_discovery_provenance: dict[str, Any] | None
    agent_name: str = ""
    agent_scope: str = ""
    sbom_import: bool = False
    repository_inventory: bool = False
    static_inventory: bool = False
    data_source_tag: str = ""
    inventory_type: EntityType = EntityType.SOURCE_FILE
    agent_id: str = ""
    agent_node_key: str = ""
    agent_type: str = ""
    provider_name: str = ""
    provider_id: str = ""
    agent_env: str = ""


def _scope(agent_dict: dict[str, Any], report_data_source: str) -> AgentScope:
    agent = AgentScope(agent_dict=agent_dict, agent_metadata={}, agent_discovery_provenance={})
    agent.agent_name = agent.agent_dict.get("name", "unknown")
    agent.agent_scope = _agent_identity_scope(agent.agent_dict)
    agent.sbom_import = _is_sbom_import(agent.agent_dict)
    agent.repository_inventory = _is_repository_inventory(agent.agent_dict)
    agent.static_inventory = agent.sbom_import or agent.repository_inventory
    agent.data_source_tag = str(agent.agent_dict["source"]) if agent.repository_inventory else report_data_source
    agent.inventory_type = EntityType.DIRECTORY if agent.repository_inventory else EntityType.SOURCE_FILE
    agent.agent_id = _agent_node_id(agent.agent_name, agent.agent_scope)
    if agent.sbom_import:
        agent.agent_id = f"source_file:sbom:{agent.agent_id.removeprefix('agent:')}"
    if agent.repository_inventory:
        agent.agent_id = f"directory:repository:{agent.agent_id.removeprefix('agent:')}"
    agent.agent_node_key = agent.agent_id.removeprefix("agent:")
    agent.agent_type = agent.agent_dict.get("type", agent.agent_dict.get("agent_type", ""))
    agent.provider_name = str(agent.agent_dict.get("source") or "local").strip() or "local"
    # Import wrappers share the legacy Agent/MCPServer serialization shape.
    # Static imports document packages; they do not establish running agents.
    if agent.sbom_import:
        agent.provider_name = "sbom"
    agent.provider_id = f"provider:{agent.provider_name}"
    agent.agent_metadata = agent.agent_dict.get("metadata", {})
    if not isinstance(agent.agent_metadata, dict):
        agent.agent_metadata = {}
    agent.agent_discovery_provenance = sanitize_discovery_provenance(agent.agent_dict.get("discovery_provenance"))
    agent.agent_env = _normalized_environment(agent.agent_dict.get("environment"))
    return agent


def _add_agent_node(graph: UnifiedGraph, agent: AgentScope) -> None:
    if not agent.static_inventory:
        graph.add_node(
            UnifiedNode(
                id=agent.provider_id,
                entity_type=EntityType.PROVIDER,
                label=agent.provider_name,
                attributes={
                    "provider": agent.provider_name,
                    "canonical_id": canonical_graph_node_id(EntityType.PROVIDER.value, agent.provider_id),
                },
                data_sources=[agent.data_source_tag],
            )
        )
    graph.add_node(
        UnifiedNode(
            id=agent.agent_id,
            entity_type=agent.inventory_type if agent.static_inventory else EntityType.AGENT,
            label=agent.agent_name.removeprefix("sbom:").removeprefix("project:").removeprefix("repo-deps:")
            if agent.static_inventory
            else agent.agent_name,
            first_seen=str(agent.agent_dict.get("discovered_at") or ""),
            last_seen=str(agent.agent_dict.get("last_seen") or agent.agent_dict.get("discovered_at") or ""),
            attributes={
                "agent_type": agent.agent_type,
                "canonical_id": (canonical_graph_node_id(agent.inventory_type.value, agent.agent_id) if agent.static_inventory else None)
                or agent.agent_dict.get("canonical_id")
                or (
                    canonical_agent_id(agent.agent_type, agent.agent_name, source_id=agent.agent_scope)
                    if agent.agent_scope
                    else agent.agent_dict.get("stable_id") or canonical_agent_id(agent.agent_type, agent.agent_name)
                ),
                "source_ids": source_ids(source_id=agent.agent_scope, stable_id=agent.agent_dict.get("stable_id")),
                "status": agent.agent_dict.get("status", ""),
                "stable_id": agent.agent_dict.get("stable_id", ""),
                "config_path": agent.agent_dict.get("config_path", ""),
                "source": agent.provider_name,
                "source_id": agent.agent_scope,
                "enrollment_name": agent.agent_dict.get("enrollment_name", ""),
                "owner": agent.agent_dict.get("owner", ""),
                "environment": agent.agent_env,
                "mdm_provider": agent.agent_dict.get("mdm_provider", ""),
                "tags": agent.agent_dict.get("tags", []),
                "discovered_at": agent.agent_dict.get("discovered_at"),
                "last_seen": agent.agent_dict.get("last_seen"),
                "server_count": len(agent.agent_dict.get("mcp_servers", [])),
                "discovery_provenance": agent.agent_discovery_provenance,
                "cloud_origin": agent.agent_metadata.get("cloud_origin"),
                "cloud_state": agent.agent_metadata.get("cloud_state"),
                "cloud_scope": agent.agent_metadata.get("cloud_scope"),
                "cloud_principal": agent.agent_metadata.get("cloud_principal"),
            },
            dimensions=NodeDimensions(
                agent_type="" if agent.static_inventory else agent.agent_type,
                surface="code" if agent.repository_inventory else "sbom" if agent.sbom_import else "",
                environment=agent.agent_env,
            ),
            data_sources=[agent.data_source_tag],
        )
    )


def _project_agent(graph: UnifiedGraph, agent: AgentScope, indexes: BuildIndexes, lineage: CloudLineageProjection) -> None:
    _add_agent_node(graph, agent)
    indexes.agent_name_to_ids[agent.agent_name].append(agent.agent_id)
    config_path = str(agent.agent_dict.get("config_path", "") or "").strip()
    if config_path:
        indexes.agent_config_path_to_id[config_path] = agent.agent_id
    if not agent.static_inventory:
        graph.add_edge(
            UnifiedEdge(
                source=agent.provider_id,
                target=agent.agent_id,
                relationship=RelationshipType.HOSTS,
            )
        )
    lineage(
        graph,
        agent_id=agent.agent_id,
        agent_dict=agent.agent_dict,
        agent_metadata=agent.agent_metadata,
        data_source=agent.data_source_tag,
    )
    for srv_dict in agent.agent_dict.get("mcp_servers", []):
        _project_server(graph, agent, srv_dict, indexes)


def _add_server_node(graph: UnifiedGraph, agent: AgentScope, srv_dict: Mapping[str, Any], srv_id: str, srv_name: str, surface: str) -> str:
    if agent.repository_inventory:
        srv_id = f"directory:manifest:{agent.agent_node_key}:{srv_name}"
        graph.add_node(
            UnifiedNode(
                id=srv_id,
                entity_type=EntityType.DIRECTORY,
                label=srv_name,
                attributes={
                    "source": agent.data_source_tag,
                    "inventory_role": "manifest_dependencies",
                    "manifest_directory": _repository_manifest_directory(agent.agent_dict, srv_dict),
                    "canonical_id": canonical_graph_node_id(EntityType.DIRECTORY.value, srv_id),
                    "environment": agent.agent_env,
                },
                dimensions=NodeDimensions(surface="code", environment=agent.agent_env),
                data_sources=[agent.data_source_tag],
            )
        )
        graph.add_edge(UnifiedEdge(source=agent.agent_id, target=srv_id, relationship=RelationshipType.CONTAINS))

    if not agent.static_inventory:
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
                    "agent": agent.agent_name,
                    "environment": agent.agent_env,
                    "canonical_id": srv_dict.get("canonical_id")
                    or srv_dict.get("stable_id")
                    or canonical_graph_node_id(EntityType.SERVER.value, srv_id),
                    "source_ids": source_ids(stable_id=srv_dict.get("stable_id"), registry_id=srv_dict.get("registry_id")),
                    "stable_id": srv_dict.get("stable_id", ""),
                    "fingerprint": srv_dict.get("fingerprint", ""),
                },
                dimensions=NodeDimensions(surface=surface, environment=agent.agent_env),
                data_sources=[agent.data_source_tag],
            )
        )
    return srv_id


def _project_server(graph: UnifiedGraph, agent: AgentScope, srv_dict: Mapping[str, Any], indexes: BuildIndexes) -> None:
    srv_name = srv_dict.get("name", "unknown")
    srv_id = agent.agent_id if agent.sbom_import else f"server:{agent.agent_node_key}:{srv_name}"
    surface = srv_dict.get("surface", "mcp-server")
    srv_id = _add_server_node(graph, agent, srv_dict, srv_id, srv_name, surface)
    indexes.server_name_to_ids[srv_name].append(srv_id)
    if not agent.static_inventory:
        graph.add_edge(
            UnifiedEdge(
                source=agent.agent_id,
                target=srv_id,
                relationship=RelationshipType.USES,
            )
        )
        indexes.server_to_agents[srv_name].append(agent.agent_id)
    indexes.server_name_to_agent_servers[srv_name][agent.agent_id] = srv_id
    indexes.agent_to_server_ids[agent.agent_name].add(srv_id)
    if agent.agent_scope:
        indexes.agent_to_server_ids[agent.agent_scope].add(srv_id)
        indexes.agent_to_server_ids[f"{agent.agent_scope}:{agent.agent_name}"].add(srv_id)
    _project_packages(graph, agent, srv_dict, srv_id, indexes)
    if agent.static_inventory:
        return
    tool_ids = _project_tools(graph, agent, srv_dict, srv_id, indexes)
    project_credentials(graph, srv_dict, srv_id, tool_ids, agent.data_source_tag)


def _project_packages(graph: UnifiedGraph, agent: AgentScope, srv_dict: Mapping[str, Any], srv_id: str, indexes: BuildIndexes) -> None:
    for pkg_dict in srv_dict.get("packages", []):
        pkg_name = pkg_dict.get("name", "unknown")
        pkg_version = pkg_dict.get("version", "")
        ecosystem = pkg_dict.get("ecosystem", "")
        pkg_id = _package_node_id(pkg_dict)
        package_evidence = _package_evidence(pkg_dict, agent.data_source_tag)
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
                    "environment": agent.agent_env,
                    "discovery_provenance": package_discovery_provenance,
                    "version_provenance": package_version_provenance,
                },
                dimensions=NodeDimensions(ecosystem=ecosystem, environment=agent.agent_env),
                data_sources=[agent.data_source_tag],
            )
        )
        indexes.package_name_to_ids[pkg_name].append(pkg_id)
        normalized_pkg_name = normalize_package_name(pkg_name, ecosystem)
        if normalized_pkg_name != pkg_name:
            indexes.package_name_to_ids[normalized_pkg_name].append(pkg_id)
        graph.add_edge(
            UnifiedEdge(
                source=srv_id,
                target=pkg_id,
                relationship=RelationshipType.CONTAINS if agent.sbom_import else RelationshipType.DEPENDS_ON,
                evidence=package_evidence,
            )
        )
        indexes.package_id_to_servers[pkg_id].append(srv_id)
        pkg_key = _package_graph_key(pkg_name, pkg_version, ecosystem, pkg_dict.get("purl"))
        indexes.pkg_key_to_servers[pkg_key].append(srv_id)

        # ── Package-level vulnerabilities ──
        for vuln_dict in pkg_dict.get("vulnerabilities", []):
            vuln_node_id = _add_vuln_node(graph, vuln_dict, pkg_id, agent.data_source_tag, package_evidence)
            if vuln_node_id:
                indexes.pending_exploitable_edges.append(
                    (
                        vuln_node_id,
                        srv_id,
                        pkg_id,
                        package_evidence,
                        str(vuln_dict.get("severity", "") or "").lower(),
                    )
                )


def _project_tools(graph: UnifiedGraph, agent: AgentScope, srv_dict: Mapping[str, Any], srv_id: str, indexes: BuildIndexes) -> list[str]:
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
                    "agent": agent.agent_name,
                },
                data_sources=[agent.data_source_tag],
            )
        )
        indexes.server_to_tool_ids[srv_id].append(tool_id)
        graph.add_edge(
            UnifiedEdge(
                source=srv_id,
                target=tool_id,
                relationship=RelationshipType.PROVIDES_TOOL,
            )
        )
    return tool_ids


def project_agents(graph: UnifiedGraph, agents: list[dict[str, Any]], data_source: str, lineage: CloudLineageProjection) -> BuildIndexes:
    indexes = BuildIndexes()
    for record in agents:
        _project_agent(graph, _scope(record, data_source), indexes, lineage)
    return indexes
