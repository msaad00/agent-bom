"""Package, advisory and conservative tool-impact report projections."""

from __future__ import annotations

from typing import Any

from agent_bom.asset_provenance import package_version_provenance, sanitize_discovery_provenance
from agent_bom.canonical_ids import canonical_graph_node_id, source_ids
from agent_bom.core.severity import SEVERITY_RISK_SCORE
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.package_utils import canonical_package_key
from agent_bom.risk_analyzer import ToolCapability, classify_tool
from agent_bom.security import sanitize_text


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
                "vulnerability_id": vuln_id_str,
                **(
                    {"finding_id": str(vuln_dict["finding_id"]).strip()}
                    if isinstance(vuln_dict.get("finding_id"), str) and str(vuln_dict.get("finding_id") or "").strip()
                    else {}
                ),
                "summary": sanitize_text(str(vuln_dict.get("summary") or ""), max_len=2_000),
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

    constrained = bool(candidate_ids)
    server_names = {name for name in (_normalize_server_name(server) for server in br_dict.get("affected_servers", [])) if name}
    if server_names:
        named_ids: set[str] = set()
        for server_name in server_names:
            named_ids.update(server_name_to_agent_servers.get(server_name, {}).values())
        narrowed = (candidate_ids & named_ids) if constrained else named_ids
        candidate_ids = narrowed
        constrained = True

    agent_names = {str(agent).strip() for agent in br_dict.get("affected_agents", []) if str(agent).strip()}
    if agent_names:
        agent_ids: set[str] = set()
        for agent_name in agent_names:
            agent_ids.update(agent_to_server_ids.get(agent_name, set()))
        narrowed = (candidate_ids & agent_ids) if constrained else agent_ids
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
