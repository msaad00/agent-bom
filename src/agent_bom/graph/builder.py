"""Unified graph builder from serialized AIBOM report data.

This ingests the JSON contract emitted by ``output.json_fmt.to_json()``
and builds the core inventory, finding, runtime, and compliance entities
used for current-state views, traversal, attack paths, and temporal diffs.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from agent_bom.api.tracing import get_tracer
from agent_bom.canonical_ids import canonical_graph_node_id
from agent_bom.cloud.aws_iam_evidence import EvidenceCompleteness, normalize_iam_policy_document
from agent_bom.cloud.normalization import coerce_bool_or_none, coerce_truthy
from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.agent_projection import project_agents
from agent_bom.graph.authorization_evidence import apply_authorization_evidence, has_authoritative_authorization_evidence
from agent_bom.graph.benchmark_projection import benchmark_inputs, project_benchmarks
from agent_bom.graph.blast_projection import enrich_blast_radius, project_blast_radius, project_package_exploits, project_shared_servers
from agent_bom.graph.build_analysis import GraphAnalysisPorts, apply_build_analysis
from agent_bom.graph.build_indexes import BuildIndexes
from agent_bom.graph.build_input import GraphBuildInput
from agent_bom.graph.cloud_rbac import add_cloud_role_assignments as _add_cloud_role_assignments
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge, merge_edge_evidence
from agent_bom.graph.finding_projection import _resolve_skill_audit_target_ids as _resolve_skill_audit_target_ids
from agent_bom.graph.finding_projection import project_iac, project_sast, project_skill_audit, project_toxic_combinations
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode, stable_node_id
from agent_bom.graph.package_projection import (
    _add_exploitable_via_edges as _add_exploitable_via_edges,
)
from agent_bom.graph.package_projection import (
    _add_vuln_node as _add_vuln_node,
)
from agent_bom.graph.package_projection import (
    _blast_radius_package_evidence as _blast_radius_package_evidence,
)
from agent_bom.graph.package_projection import (
    _collect_compliance_tags as _collect_compliance_tags,
)
from agent_bom.graph.package_projection import (
    _has_mappable_package_version as _has_mappable_package_version,
)
from agent_bom.graph.package_projection import (
    _normalize_server_name as _normalize_server_name,
)
from agent_bom.graph.package_projection import (
    _normalize_tool_capability as _normalize_tool_capability,
)
from agent_bom.graph.package_projection import (
    _package_evidence as _package_evidence,
)
from agent_bom.graph.package_projection import (
    _package_graph_key as _package_graph_key,
)
from agent_bom.graph.package_projection import (
    _package_node_id as _package_node_id,
)
from agent_bom.graph.package_projection import (
    _package_node_id_from_parts as _package_node_id_from_parts,
)
from agent_bom.graph.package_projection import (
    _package_version_provenance_from_dict as _package_version_provenance_from_dict,
)
from agent_bom.graph.package_projection import (
    _resolve_affected_package_ids as _resolve_affected_package_ids,
)
from agent_bom.graph.package_projection import (
    _resolve_affected_server_ids as _resolve_affected_server_ids,
)
from agent_bom.graph.package_projection import (
    _tool_capabilities as _tool_capabilities,
)
from agent_bom.graph.projection_support import (
    _add_rel_edge as _add_rel_edge,
)
from agent_bom.graph.projection_support import (
    _agent_identity_scope as _agent_identity_scope,
)
from agent_bom.graph.projection_support import (
    _agent_node_id as _agent_node_id,
)
from agent_bom.graph.projection_support import _is_repository_inventory as _is_repository_inventory
from agent_bom.graph.projection_support import _is_sbom_import as _is_sbom_import
from agent_bom.graph.projection_support import (
    _mapping_list as _mapping_list,
)
from agent_bom.graph.projection_support import _normalized_environment as _normalized_environment
from agent_bom.graph.projection_support import _repository_manifest_directory as _repository_manifest_directory
from agent_bom.graph.resource_aliases import (
    _build_cloud_resource_alias_index as _build_cloud_resource_alias_index,
)
from agent_bom.graph.resource_aliases import (
    _CloudResourceAliasIndex as _CloudResourceAliasIndex,
)
from agent_bom.graph.resource_aliases import (
    _resolve_cloud_resource_node_id as _resolve_cloud_resource_node_id,
)
from agent_bom.graph.resource_aliases import (
    _resource_tail as _resource_tail,
)
from agent_bom.graph.runtime_projection import (
    _add_agentic_identity_graph_projections as _add_agentic_identity_graph_projections,
)
from agent_bom.graph.runtime_projection import (
    _add_runtime_incident_feedback as _add_runtime_incident_feedback,
)
from agent_bom.graph.runtime_projection import (
    _iter_agentic_identity_graph_projections as _iter_agentic_identity_graph_projections,
)
from agent_bom.graph.runtime_projection import (
    _iter_runtime_incident_records as _iter_runtime_incident_records,
)
from agent_bom.graph.runtime_projection import (
    _project_agent_feedback as _project_agent_feedback,
)
from agent_bom.graph.runtime_projection import (
    _resolve_feedback_agent_ids as _resolve_feedback_agent_ids,
)
from agent_bom.graph.runtime_projection import (
    _runtime_identity_entity_type as _runtime_identity_entity_type,
)
from agent_bom.graph.runtime_projection import (
    _runtime_identity_evidence as _runtime_identity_evidence,
)
from agent_bom.graph.runtime_projection import (
    _runtime_identity_node_attributes as _runtime_identity_node_attributes,
)
from agent_bom.graph.runtime_projection import (
    _runtime_identity_relationship as _runtime_identity_relationship,
)
from agent_bom.graph.runtime_projection import project_runtime_session
from agent_bom.graph.training_projection import (
    _flatten_compliance_tags as _flatten_compliance_tags,
)
from agent_bom.graph.training_projection import (
    _model_node_id as _model_node_id,
)
from agent_bom.graph.training_projection import (
    _normalize_model_ref as _normalize_model_ref,
)
from agent_bom.graph.training_projection import (
    _resolve_model_id as _resolve_model_id,
)
from agent_bom.graph.training_projection import project_dataset_cards, project_model_provenance, project_serving_configs
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part
from agent_bom.security import sanitize_sensitive_payload, sanitize_text

_GRAPH_TRACER = get_tracer("agent_bom.graph")
_logger = logging.getLogger(__name__)


def build_unified_graph_from_report(
    report_json: dict[str, Any],
    *,
    scan_id: str = "",
    tenant_id: str = "",
    container: UnifiedGraph | None = None,
) -> UnifiedGraph:
    """Adapt the serialized report to graph evidence; the caller owns container lifetime."""
    return build_unified_graph(GraphBuildInput.from_report(report_json), scan_id=scan_id, tenant_id=tenant_id, container=container)


def build_unified_graph(
    inputs: GraphBuildInput,
    *,
    scan_id: str = "",
    tenant_id: str = "",
    container: UnifiedGraph | None = None,
) -> UnifiedGraph:
    """Project inventory, findings and topology before running final graph analysis.

    A supplied store-backed container retains the same stage order and bounded
    workspace behavior as the in-memory path. This function never closes it.
    """
    span = _GRAPH_TRACER.start_span("graph.build_unified_graph_from_report") if _GRAPH_TRACER else None
    sid = scan_id or inputs.scan_id
    graph = container if container is not None else UnifiedGraph(scan_id=sid, tenant_id=tenant_id)
    indexes = project_agents(graph, inputs.agents, inputs.data_source, _add_agent_cloud_lineage)
    project_package_exploits(graph, indexes, inputs.data_source)
    project_blast_radius(graph, inputs.blast_radius, indexes, inputs.data_source)
    project_shared_servers(graph, indexes)
    report = inputs.report_sections()
    inventories = _project_inventory_findings(graph, inputs, indexes, report)
    _project_runtime_topology(graph, inputs, indexes, report, tenant_id)
    project_toxic_combinations(graph, report.get("toxic_combinations"))
    enrich_blast_radius(graph, inputs.blast_radius)
    _project_cloud_authority(graph, inventories, report, inputs.data_source)
    apply_build_analysis(graph, report, _analysis_ports())
    if span is not None:
        span.set_attribute("agent_bom.graph.scan_id", sid)
        span.set_attribute("agent_bom.graph.tenant_id", tenant_id or "default")
        span.set_attribute("agent_bom.graph.agent_count", len(inputs.agents))
        span.set_attribute("agent_bom.graph.blast_radius_count", len(inputs.blast_radius))
        span.set_attribute("agent_bom.graph.node_count", len(graph.nodes))
        span.set_attribute("agent_bom.graph.edge_count", len(graph.edges))
        span.end()
    return graph


def _project_inventory_findings(
    graph: UnifiedGraph,
    inputs: GraphBuildInput,
    indexes: BuildIndexes,
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    project_model_provenance(graph, report.get("model_provenance", []))
    project_dataset_cards(graph, report.get("dataset_cards"))
    project_serving_configs(graph, report.get("serving_configs", []))
    # Native cloud assets precede benchmark references to avoid duplicate nodes.
    inventories = list(_iter_cloud_inventories(report.get("cloud_inventory")))
    for inventory in inventories:
        _add_cloud_inventory(graph, inventory, inputs.data_source)
    project_benchmarks(graph, benchmark_inputs(report))
    project_sast(graph, report.get("sast") or report.get("sast_data"))
    project_iac(graph, report.get("iac_findings") or report.get("iac_findings_data"))
    project_skill_audit(graph, report.get("skill_audit"), indexes)
    return inventories


def _project_runtime_topology(
    graph: UnifiedGraph,
    inputs: GraphBuildInput,
    indexes: BuildIndexes,
    report: dict[str, Any],
    tenant_id: str,
) -> None:
    ai_inventory = report.get("ai_inventory", {})
    if isinstance(ai_inventory, dict):
        _add_framework_topology(
            graph, ai_inventory.get("framework_agents", []), inputs.data_source, host_agent_id=_project_host_agent_id(graph, inputs.agents)
        )
        _add_ai_stack_frameworks(graph, ai_inventory, inputs.data_source)
    _add_cross_env_correlation(graph, inputs.agents, inputs.data_source)
    project_runtime_session(graph, report.get("runtime_session_graph"))
    _add_agentic_identity_graph_projections(graph, report, inputs.data_source, tenant_id)
    _add_runtime_incident_feedback(graph, report, indexes.agent_name_to_ids, inputs.data_source)


def _project_cloud_authority(
    graph: UnifiedGraph,
    inventories: list[dict[str, Any]],
    report: dict[str, Any],
    data_source: str,
) -> None:
    for inventory in inventories:
        _add_cloud_role_assignments(graph, inventory, data_source)
        apply_authorization_evidence(graph, inventory)
        _add_gcp_organization(
            graph,
            inventory.get("gcp_organization"),
            data_source,
            allow_heuristic_authorization=not has_authoritative_authorization_evidence(inventory),
        )
    _add_aws_organization(graph, report.get("aws_organization"), data_source)
    _add_cloud_org_architecture_findings(graph, report, data_source)
    _add_snowflake_source_lanes(graph, report, data_source)
    audit = report.get("cloud_audit_trail")
    if isinstance(audit, list):
        for provider_audit in audit:
            _add_cloud_audit_behavioral(graph, provider_audit, data_source)
    else:
        _add_cloud_audit_behavioral(graph, audit, data_source)


def _analysis_ports() -> GraphAnalysisPorts:
    return GraphAnalysisPorts(
        runtime_evidence=_apply_runtime_evidence_overlay,
        repo_structure=_apply_repo_structure_overlay,
        ast_tool=_apply_ast_tool_overlay,
        code_graph=_apply_code_graph_overlay,
        repo_trust=_apply_repo_trust_overlay,
        ci_graph=_apply_ci_graph_overlay,
        agent_reach_risk=_apply_agent_reach_risk,
        aspm=_apply_aspm_overlay,
        cost=_apply_cost_overlay,
    )


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


def _apply_agent_reach_risk(graph: UnifiedGraph) -> None:
    """Score each agent by the worst vulnerability in its dependency closure.

    Agents reaching no vulnerability stay unassessed rather than being claimed
    risk-free, because the closure only covers vulnerability evidence.

    Walks the inverse of the dependency-reach edges once, worst vulnerability
    first: a node already reached by a worse vulnerability bounds all of its
    ancestors, so every node is visited at most once.
    """
    from collections import deque

    from agent_bom.graph.dependency_reach import _REACH_EDGE_TYPES, _vulnerability_packages

    agent_ids = {node.id for node in graph.iter_nodes_by_type(EntityType.AGENT)}
    if not agent_ids:
        return
    vulns = sorted(
        (
            (node.risk_score, SEVERITY_RANK.get(node.severity.lower(), 0), node.id, node.severity, node.severity_id)
            for node in graph.iter_nodes_by_type(EntityType.VULNERABILITY)
            if node.risk_score > 0 or node.severity
        ),
        reverse=True,
    )
    visited: set[str] = set()
    for risk_score, _rank, vuln_id, severity, severity_id in vulns:
        queue = deque(pkg for pkg in _vulnerability_packages(graph, vuln_id) if pkg not in visited)
        visited.update(queue)
        while queue:
            current = queue.popleft()
            if current in agent_ids:
                agent = graph.get_node(current)
                if agent is not None and agent.risk_score <= risk_score:
                    agent.risk_score = risk_score
                    agent.severity = severity
                    agent.severity_id = severity_id
                    agent.mark_risk_assessed(basis="max_reachable_vulnerability_risk", scope="agent_dependency_closure_vulnerabilities")
            for edge in graph.reverse_adjacency.get(current, []):
                if edge.relationship in _REACH_EDGE_TYPES and edge.source not in visited:
                    visited.add(edge.source)
                    queue.append(edge.source)


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


def _apply_ast_tool_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Materialise source-defined tool and application entrypoints."""
    inventory = report_json.get("ai_inventory")
    if not isinstance(inventory, Mapping):
        return
    analysis = inventory.get("ast_analysis")
    if not isinstance(analysis, Mapping):
        return
    raw_tools = analysis.get("tools")
    raw_entrypoints = analysis.get("application_entrypoints")
    if not isinstance(raw_tools, list):
        raw_tools = []
    if not isinstance(raw_entrypoints, list):
        raw_entrypoints = []

    for raw in raw_tools:
        if not isinstance(raw, Mapping):
            continue
        tool_name = sanitize_text(raw.get("name", ""), max_len=200).strip()
        source_file = sanitize_text(raw.get("file", ""), max_len=500).strip().replace("\\", "/")
        while source_file.startswith("./"):
            source_file = source_file[2:]
        if not tool_name or not source_file:
            continue

        file_id = f"{EntityType.SOURCE_FILE.value}:{source_file}"
        if file_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=file_id,
                    entity_type=EntityType.SOURCE_FILE,
                    label=source_file.rsplit("/", 1)[-1],
                    attributes={
                        "path": source_file,
                        "evidence_tier": "static_scan",
                        "canonical_id": canonical_graph_node_id(EntityType.SOURCE_FILE.value, file_id),
                    },
                    data_sources=["ast_analysis"],
                    dimensions=NodeDimensions(surface="code"),
                )
            )

        tool_id = f"tool:source:{stable_node_id(source_file, tool_name)}"
        graph.add_node(
            UnifiedNode(
                id=tool_id,
                entity_type=EntityType.TOOL,
                label=tool_name,
                attributes={
                    "description": sanitize_text(raw.get("description", ""), max_len=1_000),
                    "source_file": source_file,
                    "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
                    "parameters": sanitize_sensitive_payload(raw.get("parameters", [])),
                    "handler": sanitize_text(raw.get("handler", ""), max_len=200),
                    "registration_kind": sanitize_text(raw.get("registration_kind", ""), max_len=100),
                    "framework": sanitize_text(raw.get("framework", ""), max_len=100),
                    "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                    "discovery_source": "ast_analysis",
                    "canonical_id": canonical_graph_node_id(EntityType.TOOL.value, tool_id),
                },
                data_sources=["ast_analysis"],
                dimensions=NodeDimensions(surface="code"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=file_id,
                target=tool_id,
                relationship=RelationshipType.DEFINES,
                evidence={
                    "source": "ast_analysis",
                    "line": raw.get("line"),
                    "registration_kind": sanitize_text(raw.get("registration_kind", ""), max_len=100),
                    "framework": sanitize_text(raw.get("framework", ""), max_len=100),
                    "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                },
            )
        )

    for raw in raw_entrypoints:
        if not isinstance(raw, Mapping):
            continue
        entry_name = sanitize_text(raw.get("name", ""), max_len=200).strip()
        handler = sanitize_text(raw.get("handler", ""), max_len=200).strip()
        source_file = sanitize_text(raw.get("file", ""), max_len=500).strip().replace("\\", "/")
        while source_file.startswith("./"):
            source_file = source_file[2:]
        if not entry_name or not handler or not source_file:
            continue

        file_id = f"{EntityType.SOURCE_FILE.value}:{source_file}"
        if file_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=file_id,
                    entity_type=EntityType.SOURCE_FILE,
                    label=source_file.rsplit("/", 1)[-1],
                    attributes={
                        "path": source_file,
                        "evidence_tier": "static_scan",
                        "canonical_id": canonical_graph_node_id(EntityType.SOURCE_FILE.value, file_id),
                    },
                    data_sources=["ast_analysis"],
                    dimensions=NodeDimensions(surface="code"),
                )
            )

        entry_id = f"application_entrypoint:source:{stable_node_id(source_file, entry_name, handler)}"
        graph.add_node(
            UnifiedNode(
                id=entry_id,
                entity_type=EntityType.CODE_MODULE,
                label=entry_name,
                attributes={
                    "node_kind": "application_entrypoint",
                    "handler": handler,
                    "entrypoint_kind": sanitize_text(raw.get("kind", ""), max_len=100),
                    "framework": sanitize_text(raw.get("framework", ""), max_len=100),
                    "language": sanitize_text(raw.get("language", ""), max_len=100),
                    "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                    "source_file": source_file,
                    "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
                    "discovery_source": "ast_analysis",
                    "canonical_id": canonical_graph_node_id(EntityType.CODE_MODULE.value, entry_id),
                },
                data_sources=["ast_analysis"],
                dimensions=NodeDimensions(surface="code"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=file_id,
                target=entry_id,
                relationship=RelationshipType.DEFINES,
                evidence={
                    "source": "ast_analysis",
                    "line": raw.get("line"),
                    "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                },
            )
        )


def _apply_code_graph_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Emit CODE_MODULE nodes from SOURCE_FILE evidence already on the graph."""
    if not any(node.entity_type == EntityType.SOURCE_FILE for node in graph.nodes.values()):
        return
    from datetime import datetime, timezone

    from agent_bom.graph.code_graph_overlay import apply_code_graph_overlay

    apply_code_graph_overlay(graph, dict(report_json), datetime.now(timezone.utc))


def _apply_repo_trust_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Stamp ``repo_trust`` metadata onto APPLICATION (+ root DIRECTORY when present)."""
    has_trust = isinstance(report_json.get("repo_trust"), Mapping) and bool(report_json.get("repo_trust"))
    inventory = report_json.get("project_inventory")
    has_nested = isinstance(inventory, Mapping) and isinstance(inventory.get("repo_trust"), Mapping) and bool(inventory.get("repo_trust"))
    if not has_trust and not has_nested:
        return
    from datetime import datetime, timezone

    from agent_bom.graph.repo_trust_overlay import apply_repo_trust_overlay

    apply_repo_trust_overlay(graph, dict(report_json), datetime.now(timezone.utc))


def _apply_ci_graph_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Emit CI_JOB topology from github-actions agents in the report."""
    agents = report_json.get("agents")
    if not isinstance(agents, list):
        return
    if not any(isinstance(agent, dict) and agent.get("source") == "github-actions" for agent in agents):
        return
    from datetime import datetime, timezone

    from agent_bom.graph.ci_graph_overlay import apply_ci_graph_overlay

    apply_ci_graph_overlay(graph, dict(report_json), datetime.now(timezone.utc))


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


def _identity_entity_type(raw_type: Any) -> EntityType:
    principal_type = _clean_graph_part(raw_type).lower().replace("_", "-").replace(" ", "-")
    return _PRINCIPAL_TYPE_TO_ENTITY.get(principal_type, EntityType.SERVICE_ACCOUNT)


def _first_cloud_scope_value(scope: dict[str, Any], *keys: str) -> tuple[str, str]:
    for key in keys:
        value = _clean_graph_part(scope.get(key))
        if value:
            return key, value
    return "", ""


def _policy_entries(principal: dict[str, Any]) -> list[dict[str, Any]]:
    raw_policies = principal.get("policies") or principal.get("attached_policies") or principal.get("policy_ids") or []
    if isinstance(raw_policies, (str, bytes)):
        raw_policies = [raw_policies]
    if not isinstance(raw_policies, list):
        return []

    policies: list[dict[str, Any]] = []
    for raw_policy in raw_policies:
        privilege_level = "unknown"
        document: Any = None
        if isinstance(raw_policy, dict):
            policy_id = _clean_graph_part(raw_policy.get("policy_id")) or _clean_graph_part(raw_policy.get("arn"))
            policy_name = _clean_graph_part(raw_policy.get("policy_name")) or _clean_graph_part(raw_policy.get("name")) or policy_id
            privilege_level = str(raw_policy.get("privilege_level") or "unknown")
            # Discovery may carry the raw IAM policy document (``policy_document``,
            # or the AWS API ``PolicyDocument``); pass it through so the POLICY node
            # can carry it and the effective-permissions overlay can evaluate it.
            document = raw_policy.get("policy_document")
            if document is None:
                document = raw_policy.get("PolicyDocument")
        else:
            policy_id = _clean_graph_part(raw_policy)
            policy_name = policy_id
        if policy_id:
            entry: dict[str, Any] = {"id": policy_id, "name": policy_name or policy_id, "privilege_level": privilege_level}
            if isinstance(document, dict) and document:
                entry["policy_document"] = document
            policies.append(entry)
    return policies


def _policy_document_attrs(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``{"policy_document": <doc>}`` for a parseable IAM policy, else ``{}``.

    The raw document is what the effective-permissions overlay expects on the
    POLICY node — it re-normalizes at evaluation time. We validate here with
    ``normalize_iam_policy_document`` and only attach documents that parse to at
    least one statement, so unparseable/empty payloads never bloat the graph.
    """
    document = policy.get("policy_document")
    if not isinstance(document, Mapping) or not document:
        return {}
    if normalize_iam_policy_document(document).completeness is EvidenceCompleteness.UNAVAILABLE:
        return {}
    return {"policy_document": dict(document)}


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


def _environment_from_tags(tags: object) -> str:
    """Promote common cloud tag keys onto the environment dimension."""
    if not isinstance(tags, dict):
        return ""
    for key in ("environment", "Environment", "env", "Env", "ENVIRONMENT"):
        if key in tags:
            return _normalized_environment(tags.get(key))
    return ""


def _resource_environment(item: object) -> str:
    """Return the environment a cloud resource is tagged/labelled with.

    ``environment`` is a first-class leg of the estate hierarchy
    (provider / account / region / environment) and is what
    :func:`agent_bom.graph.scope.select_observed_scope` and
    ``/v1/inventory?environment=`` key off. Every provider spells the key/value
    metadata that carries it differently: AWS and Azure use ``tags``, GCP uses
    ``labels``. Reading only ``tags`` made the environment drill-down return
    Azure's estate while silently dropping the identically-tagged AWS and GCP
    one.

    GCE ``network_tags`` is deliberately NOT consulted — those are firewall
    targeting labels (a bare list, no values), not resource metadata.
    """
    if not isinstance(item, dict):
        return ""
    return _environment_from_tags(item.get("tags")) or _environment_from_tags(item.get("labels"))


def _add_account_resource_hierarchy(
    graph: UnifiedGraph,
    account_node_id: str,
    resource_node_id: str,
    *,
    evidence: dict[str, Any] | None = None,
) -> None:
    """Link account → resource as both ``OWNS`` and ``CONTAINS``.

    Cloud inventory and Snowflake object layers historically emitted ``OWNS``
    only. Estate rollup special-cases that edge, but attack-path fusion and cost
    subtrees walk ``CONTAINS``. Dual-emit keeps ownership semantics while making
    the account hierarchy traversable for kill-chains — matching cloud-origin
    lineage which already emits ``CONTAINS``.
    """
    if not account_node_id or not resource_node_id:
        return
    payload = dict(evidence or {})
    _add_rel_edge(graph, account_node_id, resource_node_id, RelationshipType.OWNS, payload)
    contains_evidence = {**payload, "hierarchy": "account_contains_resource"}
    _add_rel_edge(graph, account_node_id, resource_node_id, RelationshipType.CONTAINS, contains_evidence)
    _stamp_owning_account(graph, account_node_id, resource_node_id)


def _stamp_owning_account(graph: UnifiedGraph, account_node_id: str, resource_node_id: str) -> None:
    """Copy the owning account's id onto a resource that lacks it.

    ``account_id`` is the attribute :func:`agent_bom.graph.scope.select_observed_scope`
    matches for ``kind="account"``, so a resource without it drops out of the
    org → account → resource drill-down even though the graph holds an explicit
    ``OWNS``/``CONTAINS`` edge proving the membership. The cloud-inventory loops
    set it inline; the Snowflake object/services/pipeline layers did not, which
    collapsed the Snowflake account view to the bare ACCOUNT node.

    Derived only from the persisted ownership edge just written — never guessed —
    and never overwrites an id the emitting lane already set.
    """
    account = graph.nodes.get(account_node_id)
    resource = graph.nodes.get(resource_node_id)
    if account is None or resource is None:
        return
    account_id = _clean_graph_part(account.attributes.get("account_id"))
    if not account_id or _clean_graph_part(resource.attributes.get("account_id")):
        return
    resource.attributes["account_id"] = account_id


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
            **_policy_document_attrs(policy),
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


def _recorded_exposure_attributes(record: Mapping[str, Any], *fields: str) -> dict[str, Any]:
    """Preserve provider flag inputs and keep absent/unknown observations nullable."""
    inputs = {name: record[name] for name in fields if name in record}
    values = [coerce_bool_or_none(value) for value in inputs.values()]
    exposed = True if True in values else False if values and all(value is False for value in values) else None
    return {
        "internet_exposed": exposed,
        "internet_exposure_evidence": {
            "source": "cloud-inventory",
            "basis": "recorded_attributes",
            "inputs": sanitize_sensitive_payload(inputs),
        },
    }


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


def _add_snowflake_source_lanes(graph: UnifiedGraph, report_json: dict[str, Any], data_source: str) -> None:
    """Stage account-local lanes before any same-name nodes can merge.

    Single-account reports retain their existing node IDs. Mixed or missing
    account scopes get separate local IDs; labels and FQNs are never account
    equivalence evidence. Original persisted snapshots are not rewritten.
    """
    lane_keys = (
        "snowflake_object_graph",
        "snowflake_exfil_graph",
        "snowflake_login_anomalies",
        "snowflake_auth_posture",
        "snowflake_services",
        "snowflake_pipeline",
        "snowflake_integrations",
        "snowflake_external_data",
        "snowflake_governance",
        "snowflake_activity",
    )
    scopes: dict[tuple[str, str], dict[str, Any]] = {}
    for key in lane_keys:
        payload = report_json.get(key)
        if not isinstance(payload, dict):
            continue
        organization = payload.get("organization") if key == "snowflake_services" else None
        # Organization collection has its own status; retain that independent
        # evidence even when the containing services inventory is unavailable.
        organization_ok = isinstance(organization, dict) and organization.get("status") == "ok"
        if payload.get("status") != "ok" and not organization_ok:
            continue
        account = _clean_graph_part(payload.get("account"))
        scope = ("account", account) if account else ("source", key)
        scopes.setdefault(scope, {})[key] = payload

    if not scopes:
        return
    from contextlib import nullcontext
    from copy import deepcopy

    from agent_bom.graph.store_backed import StoreBackedUnifiedGraph, open_store_backed_unified_graph

    store_backed = isinstance(graph, StoreBackedUnifiedGraph)
    for scope, lanes in scopes.items():
        stage_context = (
            open_store_backed_unified_graph(scan_id=graph.scan_id, tenant_id=graph.tenant_id, created_at=graph.created_at, backend="sqlite")
            if store_backed
            else nullcontext(UnifiedGraph(scan_id=graph.scan_id, tenant_id=graph.tenant_id, created_at=graph.created_at))
        )
        with stage_context as staged:
            _project_snowflake_lanes(staged, lanes, data_source)
            remap: dict[str, str] = {}
            account = scope[1] if scope[0] == "account" else ""
            for staged_node in staged.nodes.values():
                # Store-backed cached identities must retain their original key.
                # Clone only the current output node, never the whole graph.
                node = deepcopy(staged_node) if store_backed else staged_node
                original_id = node.id
                provider = _clean_graph_part(node.attributes.get("cloud_provider") or node.dimensions.cloud_provider)
                account_local = provider == "snowflake" and node.entity_type not in {EntityType.ACCOUNT, EntityType.ORG}
                if account_local:
                    node.attributes["snowflake_local_id"] = original_id
                    node.attributes["snowflake_scope_version"] = "account-lanes.v1"
                    if account:
                        node.attributes["account_id"] = account
                    existing = graph.nodes.get(original_id)
                    collides = existing is not None and (not account or _clean_graph_part(existing.attributes.get("account_id")) != account)
                    if len(scopes) > 1 or collides:
                        # Content framing and SHA-256 preserve case and separators;
                        # stable_node_id lowercases its inputs and is unsuitable for
                        # quoted Snowflake identifiers or unproven account aliases.
                        key = json.dumps([*scope, original_id], separators=(",", ":"))
                        suffix = hashlib.sha256(key.encode()).hexdigest()
                        node.id = f"{node.entity_type.value}:snowflake:scoped:{suffix}"
                        node.attributes["legacy_graph_id"] = original_id
                if store_backed:
                    # Persist the mapping in the private staging workspace so
                    # a large source does not retain an O(nodes) remap in RAM.
                    staged_node.attributes["_snowflake_projection_id"] = node.id
                else:
                    remap[original_id] = node.id
                graph.add_node(node)
            for edge in staged.edges:
                if store_backed:
                    edge.source = staged.nodes[edge.source].attributes["_snowflake_projection_id"]
                    edge.target = staged.nodes[edge.target].attributes["_snowflake_projection_id"]
                else:
                    edge.source = remap[edge.source]
                    edge.target = remap[edge.target]
                graph.add_edge(edge)
            graph.analysis_status.update(staged.analysis_status)


def _project_snowflake_lanes(graph: UnifiedGraph, report_json: dict[str, Any], data_source: str) -> None:
    """Project lanes sharing one explicitly recorded account (or one unknown source)."""
    _add_snowflake_object_graph(graph, report_json.get("snowflake_object_graph"), data_source)
    _add_snowflake_exfil(graph, report_json.get("snowflake_exfil_graph"), data_source)
    _add_snowflake_identity(
        graph,
        report_json.get("snowflake_login_anomalies"),
        report_json.get("snowflake_auth_posture"),
        data_source,
    )
    _add_snowflake_services(graph, report_json.get("snowflake_services"), data_source)
    _sf_services_payload = report_json.get("snowflake_services")
    _add_snowflake_organization(
        graph,
        _sf_services_payload.get("organization") if isinstance(_sf_services_payload, dict) else None,
        data_source,
    )
    _add_snowflake_pipeline(graph, report_json.get("snowflake_pipeline"), data_source)
    _add_snowflake_integrations(graph, report_json.get("snowflake_integrations"), data_source)
    _add_snowflake_external_data(graph, report_json.get("snowflake_external_data"), data_source)
    _add_snowflake_governance(graph, report_json.get("snowflake_governance"), data_source)
    _add_snowflake_activity(graph, report_json.get("snowflake_activity"), data_source)


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
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "snowflake-objects"},
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
            {
                "source": "snowflake-objects",
                "privilege": grant.get("privilege", ""),
                "grant_receipts": [
                    {
                        "source": "snowflake-objects",
                        "account": account or None,
                        "role": role,
                        "privilege": grant.get("privilege", ""),
                        "object_fqn": object_fqn,
                        "object_type": str(grant["object_type"]).lower() if grant.get("object_type") else None,
                    }
                ],
            },
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
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node.id,
                evidence={"source": "snowflake-services"},
            )
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
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "snowflake-external-data"},
            )
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

    Account-owned nodes retain category and enabled configuration for outbound
    connections and federation. SHOW INTEGRATIONS does not establish inbound
    internet reachability, effective authorization or successful data transfer.
    A non-ok payload is a no-op.
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
        category = str(integ.get("category", "") or "").strip().upper().replace(" ", "_")
        enabled = coerce_bool_or_none(integ.get("enabled"))
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
                    "enabled": enabled,
                    "internet_exposed": None,
                    "outbound_access_configured": enabled if category in egress_categories else None,
                    "integration_evidence": {
                        "source": "snowflake-integrations",
                        "basis": "recorded_configuration",
                        "network_direction": "outbound" if category in egress_categories else "not_assessed",
                        "access_outcome": "not_observed",
                        "inputs": sanitize_sensitive_payload({key: integ[key] for key in ("category", "type", "enabled") if key in integ}),
                        **(
                            {"enabled_observation": sanitize_sensitive_payload(integ["enabled_evidence"])}
                            if isinstance(integ.get("enabled_evidence"), dict)
                            else {}
                        ),
                    },
                    "external_access": category == "EXTERNAL_ACCESS",
                    "identity_federation": category == "SECURITY",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="network"),
            )
        )
        if account_node_id:
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "snowflake-integrations"},
            )


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
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node.id,
                evidence={"source": "snowflake-pipeline"},
            )
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
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node.id,
                evidence={"source": "snowflake-exfil"},
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
      collapsed per ``(user, object)`` with distinct query/action/role receipts.
      Historical observations do not establish current permission or row impact.
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
    access_records_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

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
        receipt: dict[str, Any] = {"source": "snowflake-governance", "account": account}
        for field_name in ("query_id", "user_name", "role_name", "query_start", "object_name", "object_type", "operation", "source_field"):
            receipt[field_name] = _clean_graph_part(rec.get(field_name))
        receipt["is_write"] = rec.get("is_write") if isinstance(rec.get("is_write"), bool) else None
        for field_name in ("columns", "base_objects"):
            values = rec.get(field_name)
            receipt[field_name] = sorted({value for value in values if isinstance(value, str)}) if isinstance(values, list) else []
        access_records_by_pair[(user_name, object_name)].append(receipt)
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
                _add_account_resource_hierarchy(
                    graph,
                    account_node_id,
                    object_node_id,
                    evidence={"source": "snowflake-governance"},
                )
    for (user_name, object_name), receipts in access_records_by_pair.items():
        evidence: dict[str, Any] = {
            "source": "snowflake-governance",
            "evidence_kind": "historical_access",
            "authorization_state": "not_evaluated",
            "data_impact_state": "unknown",
        }
        # Aggregate once per edge rather than repeatedly merging its growing
        # history. Keep whole records so different queries/roles cannot combine.
        merge_edge_evidence(evidence, {"access_receipts": receipts})
        _add_rel_edge(graph, _ensure_user(user_name), f"data_store:snowflake:{object_name}", RelationshipType.ACCESSED, evidence)

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
                _add_account_resource_hierarchy(
                    graph,
                    account_node_id,
                    resource_node_id,
                    evidence={"source": "cloud-audit-trail"},
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


def _add_cloud_org_architecture_findings(graph: UnifiedGraph, report_json: Mapping[str, Any], data_source: str) -> None:
    """Promote org-architecture findings (single-account / flat hierarchy) to MISCONFIGURATION nodes.

    Reads ``aws_organization.findings`` and nested ``cloud_inventory[].gcp_organization.findings``.
    Works even when status is ``not_in_org`` (hierarchy builder no-ops) so the architecture
    verdict still lands on the graph. Does not invent CIS tags.
    """
    payloads: list[tuple[str, dict[str, Any]]] = []
    aws_org = report_json.get("aws_organization")
    if isinstance(aws_org, dict):
        payloads.append(("aws", aws_org))

    inventory = report_json.get("cloud_inventory")
    inv_list = inventory if isinstance(inventory, list) else ([inventory] if isinstance(inventory, dict) else [])
    for entry in inv_list:
        if not isinstance(entry, dict):
            continue
        gcp_org = entry.get("gcp_organization")
        if isinstance(gcp_org, dict):
            payloads.append(("gcp", gcp_org))

    for provider, payload in payloads:
        findings = payload.get("findings")
        if not isinstance(findings, list):
            continue
        org_id = _clean_graph_part(payload.get("org_id"))
        if provider == "aws":
            target_id = f"org:aws:{org_id}" if org_id else "org:aws:standalone"
            target_label = f"AWS org: {org_id or 'standalone account'}"
        else:
            target_id = f"org:gcp:{org_id}" if org_id else "org:gcp:standalone"
            target_label = f"GCP org: {org_id or 'standalone project'}"

        # Ensure a target ORG node exists even for not_in_org (hierarchy layer skipped).
        if target_id not in graph.nodes:
            arch = payload.get("architecture") if isinstance(payload.get("architecture"), dict) else {}
            graph.add_node(
                UnifiedNode(
                    id=target_id,
                    entity_type=EntityType.ORG,
                    label=target_label,
                    attributes={
                        "org_id": org_id,
                        "cloud_provider": provider,
                        "status": _clean_graph_part(payload.get("status")),
                        **({"architecture": arch} if arch else {}),
                    },
                    data_sources=sorted({data_source, f"{provider}-organizations"} - {""}),
                    dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
                )
            )

        for raw in findings:
            if not isinstance(raw, dict):
                continue
            check_id = _clean_graph_part(raw.get("check_id")) or _clean_graph_part(raw.get("title"))
            if not check_id:
                continue
            misconfig_id = f"misconfig:cloud-org:{provider}:{check_id}"
            if misconfig_id in graph.nodes:
                continue
            graph.add_node(
                UnifiedNode(
                    id=misconfig_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=_clean_graph_part(raw.get("title")) or check_id,
                    severity=str(raw.get("severity") or "medium").lower(),
                    attributes={
                        "check_id": check_id,
                        "category": _clean_graph_part(raw.get("category")) or "estate_architecture",
                        "evidence": _clean_graph_part(raw.get("detail")),
                        "cloud_provider": provider,
                        "account_count": raw.get("account_count"),
                        "hierarchy_depth": raw.get("hierarchy_depth"),
                    },
                    compliance_tags=[f"CLOUD-ORG-{check_id}"],
                    data_sources=sorted({data_source, f"{provider}-organizations"} - {""}),
                    dimensions=NodeDimensions(cloud_provider=provider),
                )
            )
            graph.add_edge(
                UnifiedEdge(
                    source=misconfig_id,
                    target=target_id,
                    relationship=RelationshipType.AFFECTS,
                )
            )


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
                **({"architecture": payload.get("architecture")} if isinstance(payload.get("architecture"), dict) else {}),
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


def _add_gcp_organization(
    graph: UnifiedGraph,
    payload: Any,
    data_source: str,
    *,
    allow_heuristic_authorization: bool = True,
) -> None:
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
    for binding in (payload.get("iam_bindings", []) or []) if allow_heuristic_authorization else ():
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
    permissive = [
        (node, node_id) for node, node_id in firewall_nodes if node is not None and coerce_truthy(node.attributes.get("internet_exposed"))
    ]
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
    allow_heuristic_authorization = not has_authoritative_authorization_evidence(original_inventory)
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
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory", "reason": "side_scan_target"},
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
        bucket_tags = bucket.get("tags", {}) if isinstance(bucket.get("tags"), dict) else {}
        bucket_env = _resource_environment(bucket)
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
                    **_recorded_exposure_attributes(bucket, "publicly_accessible"),
                    "tags": bucket_tags,
                    "account_id": account_id,
                    "environment": bucket_env,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="s3", environment=bucket_env),
            )
        )
        resource_ids.append(node_id)
        # Redacted DSPM content-sampling evidence rides onto the resource node so
        # the CNAPP/DSPM overlay's ``content_classification`` reader promotes the
        # DATA_STORE companion to a sensitive crown jewel (parity with the DB path
        # below). Copied verbatim — it is already redacted (types/counts only).
        bucket_classification = bucket.get("content_classification")
        if isinstance(bucket_classification, dict):
            graph.nodes[node_id].attributes["content_classification"] = bucket_classification
        if account_node_id:
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory"},
            )

    # ── DSPM databases → CLOUD_RESOURCE (RDS/Postgres/warehouse content stores) ──
    # A ``dspm_databases`` record carries the redacted database content-scan
    # classification (``agent-bom.dspm.database_scan.v1``). Materialize each as a
    # data-store-labelled CLOUD_RESOURCE carrying the classification so the CNAPP
    # overlay attaches a DATA_STORE companion and, when publicly reachable, the
    # public→sensitive toxic-combination path fires — the same surface S3/GCS
    # content sampling feeds. Never raises into the builder.
    for db in original_inventory.get("dspm_databases", []) or []:
        if not isinstance(db, dict):
            continue
        db_name = _clean_graph_part(db.get("name"))
        if not db_name:
            continue
        db_classification = db.get("content_classification")
        db_attributes: dict[str, Any] = {
            "resource_id": db.get("id") or db.get("arn") or db_name,
            "resource_name": db_name,
            "resource_type": "database",
            "resource_kind": _clean_graph_part(db.get("engine")) or "database",
            "cloud_provider": provider,
            "cloud_service": "dspm-database",
            "location": _clean_graph_part(db.get("location")) or region,
            **_recorded_exposure_attributes(db, "publicly_accessible"),
            "is_data_store": True,
            "account_id": db.get("account_id") or account_id,
        }
        if isinstance(db_classification, dict):
            db_attributes["content_classification"] = db_classification
        node_id = f"cloud_resource:{provider}:database:{db_name}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                # Label carries the "database" data-store keyword so the CNAPP
                # overlay's data-store match fires and builds the companion.
                label=f"database: {db_name}",
                attributes=db_attributes,
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="dspm"),
            )
        )
        resource_ids.append(node_id)
        if account_node_id:
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory"},
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
        sg_env = _resource_environment(group)
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
                    **_recorded_exposure_attributes(group, "internet_exposed"),
                    "network_exposure": list(group.get("network_exposure", []) or []),
                    # GCP firewall scoping (empty on AWS); the instance-matching
                    # pass below reads these to know which instances a rule covers.
                    "fw_network": _clean_graph_part(group.get("network")),
                    "fw_target_tags": list(group.get("target_tags", []) or []),
                    "fw_target_service_accounts": list(group.get("target_service_accounts", []) or []),
                    "fw_source_ranges": list(group.get("source_ranges", []) or []),
                    "account_id": account_id,
                    "environment": sg_env,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="ec2", environment=sg_env),
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
        instance_env = _resource_environment(instance)
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
                    "environment": instance_env,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="ec2", environment=instance_env),
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
            if sg_node is not None and coerce_truthy(sg_node.attributes.get("internet_exposed")):
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
            exposure = _recorded_exposure_attributes(item, "publicly_accessible", "internet_exposed", "endpoint_public")
            item_env = _resource_environment(item)
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
                        **exposure,
                        "is_data_store": is_data,
                        "engine": _clean_graph_part(item.get("engine")),
                        "runtime": _clean_graph_part(item.get("runtime")),
                        "encrypted": bool(item.get("encrypted")),
                        "account_id": account_id,
                        "environment": item_env,
                    },
                    data_sources=data_sources,
                    dimensions=NodeDimensions(cloud_provider=provider, surface=svc, environment=item_env),
                )
            )
            resource_ids.append(node_id)
            if account_node_id:
                _add_account_resource_hierarchy(
                    graph,
                    account_node_id,
                    node_id,
                    evidence={"source": "cloud-inventory"},
                )
            if coll_key == "elb_load_balancers" and exposure["internet_exposed"] is True:
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
                exposure = _recorded_exposure_attributes(item, "publicly_accessible", "internet_exposed")
                item_env = _resource_environment(item)
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
                            **exposure,
                            "is_data_store": is_data,
                            "engine": _clean_graph_part(item.get("database_version")),
                            "encrypted": bool(item.get("encrypted")),
                            "account_id": account_id,
                            "environment": item_env,
                        },
                        data_sources=data_sources,
                        dimensions=NodeDimensions(cloud_provider="gcp", surface=svc, environment=item_env),
                    )
                )
                resource_ids.append(node_id)
                if account_node_id:
                    _add_account_resource_hierarchy(
                        graph,
                        account_node_id,
                        node_id,
                        evidence={"source": "cloud-inventory"},
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
                graph,
                principal,
                provider=provider,
                account_node_id=account_node_id,
                resource_ids=resource_ids,
                data_sources=data_sources,
                allow_heuristic_authorization=allow_heuristic_authorization,
            )

    _wire_instance_profile_roles(
        graph,
        inventory,
        provider=provider,
        instance_node_by_id=instance_node_by_id,
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
                graph,
                group,
                provider=provider,
                account_node_id=account_node_id,
                resource_ids=resource_ids,
                data_sources=data_sources,
                allow_heuristic_authorization=allow_heuristic_authorization,
            )


def _wire_instance_profile_roles(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    instance_node_by_id: dict[str, str],
) -> None:
    """Link EC2 instance profiles to IAM roles and mark lateral roles exposed."""
    role_by_name = {
        _clean_graph_part(role.get("name")): role
        for role in inventory.get("roles", []) or []
        if isinstance(role, dict) and _clean_graph_part(role.get("name"))
    }
    for instance in inventory.get("instances", []) or []:
        if not isinstance(instance, dict):
            continue
        inst_id = _clean_graph_part(instance.get("instance_id"))
        inst_node = instance_node_by_id.get(inst_id)
        if not inst_node:
            continue
        profile = _clean_graph_part(instance.get("iam_instance_profile"))
        if not profile:
            continue
        role_name = ""
        if ":role/" in profile:
            role_name = profile.rsplit(":role/", 1)[-1].split("/")[0]
        elif profile in role_by_name:
            role_name = profile
        role = role_by_name.get(role_name)
        if role is None:
            continue
        role_arn = _clean_graph_part(role.get("arn")) or role_name
        role_node_id = _identity_node_id(EntityType.ROLE, provider, role_arn)
        if role_node_id not in graph.nodes:
            continue
        graph.add_edge(
            UnifiedEdge(
                source=inst_node,
                target=role_node_id,
                relationship=RelationshipType.ASSUMES,
                evidence={"source": "cloud-inventory", "reason": "ec2_instance_profile"},
            )
        )
        if _instance_internet_reachable(graph, inst_node, instance):
            graph.nodes[role_node_id].attributes["internet_exposed"] = True


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
        exposure = _recorded_exposure_attributes(raw, "internet_facing")
        if res.resource_type is CloudResourceType.PUBLIC_IP and raw.get("ip_address"):
            exposure["internet_exposed"] = True
            exposure["internet_exposure_evidence"]["public_ip_address"] = sanitize_text(str(raw["ip_address"]))
        if res.resource_type is CloudResourceType.PUBLIC_IP and res.resource_id:
            pip_node_by_arm_id[res.resource_id] = node_id
        if res.resource_type is CloudResourceType.LOAD_BALANCER:
            load_balancer_nodes.append((node_id, raw))
        resource_tags = dict(res.tags) if getattr(res, "tags", None) else {}
        resource_env = _environment_from_tags(resource_tags) or _resource_environment(raw)
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
                    **exposure,
                    "is_data_store": is_data_store,
                    "tags": resource_tags,
                    "account_id": account_id,
                    "environment": resource_env,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface=surface, environment=resource_env),
            )
        )
        resource_ids.append(node_id)
        if account_node_id:
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory"},
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
    if coerce_truthy(node.attributes.get("internet_exposed")) or _clean_graph_part(instance.get("public_ip")):
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
        if lb_node is None or not coerce_truthy(lb_node.attributes.get("internet_exposed")):
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
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory"},
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
                "is_public": coerce_bool_or_none(sn.get("is_public")),
                **_recorded_exposure_attributes(sn, "is_public"),
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
                    **_recorded_exposure_attributes(item, "internet_exposed"),
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
                    **_recorded_exposure_attributes(api, "internet_exposed"),
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
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory"},
            )
        _protect(node_id, api.get("protected_targets", []), "api_gateway_frontend")
        if coerce_truthy(api.get("internet_exposed")):
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
        if sn_id and coerce_truthy(sn.get("is_public"))
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
        if not isinstance(nacl, dict) or not coerce_truthy(nacl.get("internet_exposed")):
            continue
        ident = _clean_graph_part(nacl.get("id"))
        if not ident:
            continue
        nacl_node = f"cloud_resource:{provider}:network:network_acl:{ident}"
        if nacl_node not in graph.nodes:
            continue
        for sn_id in nacl.get("subnet_ids", []) or []:
            sn_clean = _clean_graph_part(sn_id)
            # A permissive NACL only implies internet reachability when the
            # subnet is actually public (has an IGW route). A permissive NACL on
            # a private subnet is not internet exposure — skip it to avoid a
            # false EXPOSED_TO edge. Mirrors the IGW branch's public gate above.
            if sn_clean not in public_subnet_ids:
                continue
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


def _role_last_used_at(usage_evidence: Any) -> str | None:
    """Newest real last-accessed timestamp across role usage-evidence records.

    Threads bounded AWS Access Advisor / RoleLastUsed telemetry
    (:mod:`agent_bom.cloud.aws_iam_evidence`) onto the identity node so NHI
    governance dormancy uses a real last-used signal. Returns ``None`` when no
    record carries a timestamp — absent telemetry must never be turned into a
    false "never used" (fail-closed); the role then stays not-evaluated for
    dormancy rather than being fabricated as dormant.
    """
    if not isinstance(usage_evidence, Mapping):
        return None
    records = usage_evidence.get("records")
    if not isinstance(records, list):
        return None
    newest: str | None = None
    for record in records:
        if not isinstance(record, Mapping):
            continue
        raw = record.get("last_accessed_at")
        if not isinstance(raw, str) or not raw.strip():
            continue
        if newest is None or raw > newest:
            newest = raw
    return newest


def _add_inventory_principal(
    graph: UnifiedGraph,
    principal: dict[str, Any],
    *,
    provider: str,
    account_node_id: str,
    resource_ids: list[str],
    data_sources: list[str],
    allow_heuristic_authorization: bool = True,
) -> None:
    """Emit one IAM role/user as an identity principal with policy + access edges."""
    principal_type = _clean_graph_part(principal.get("principal_type")) or "user"
    principal_id = _clean_graph_part(principal.get("arn")) or _clean_graph_part(principal.get("name"))
    principal_name = _clean_graph_part(principal.get("name")) or principal_id
    if not principal_id:
        return
    entity_type = _identity_entity_type(principal_type)
    principal_node_id = _identity_node_id(entity_type, provider, principal_id)
    node_attributes: dict[str, Any] = {
        "principal_id": principal_id,
        "principal_name": principal_name,
        "principal_type": principal_type,
        "directory_principal_id": _clean_graph_part(principal.get("principal_id")),
        "principal_email": _clean_graph_part(principal.get("email")),
        "principal_resource_id": _clean_graph_part(principal.get("arn")),
        "cloud_provider": provider,
        "privilege_level": _clean_graph_part(principal.get("privilege_level")) or "unknown",
        "iam_path": _clean_graph_part(principal.get("path")),
        "source": "cloud-inventory",
    }
    # Thread collected role usage evidence so NHI governance dormancy uses a real
    # last-used signal. Only a real timestamp sets ``last_used_at`` — absent
    # telemetry leaves the field unset so dormancy stays fail-closed.
    usage_evidence = principal.get("usage_evidence")
    if isinstance(usage_evidence, Mapping):
        state = usage_evidence.get("state")
        if isinstance(state, str) and state.strip():
            node_attributes["usage_evidence_state"] = state
        last_used = _role_last_used_at(usage_evidence)
        if last_used:
            node_attributes["last_used_at"] = last_used
    graph.add_node(
        UnifiedNode(
            id=principal_node_id,
            entity_type=entity_type,
            label=principal_name,
            attributes=node_attributes,
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
                    **_policy_document_attrs(policy),
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

    # AWS Access-Advisor right-sizing evidence: each service the principal is
    # granted, carrying its last-used timestamp (or None = never used), as a
    # HAS_PERMISSION grant edge the CIEM over-privilege emitter reads.
    _add_access_advisor_grants(
        graph,
        principal,
        principal_node_id=principal_node_id,
        provider=provider,
        data_sources=data_sources,
    )

    # Direct access to the account's inventoried resources. The effective-
    # permissions overlay turns CAN_ACCESS (+ assume/trust chains) into the
    # HAS_PERMISSION transitive closure; admin-privileged principals reach
    # every resource, others get a baseline same-account access edge.
    privilege = _clean_graph_part(principal.get("privilege_level")) or "unknown"
    if allow_heuristic_authorization and privilege in ("admin", "write"):
        for resource_id in resource_ids:
            graph.add_edge(
                UnifiedEdge(
                    source=principal_node_id,
                    target=resource_id,
                    relationship=RelationshipType.CAN_ACCESS,
                    evidence={"source": "cloud-inventory", "basis": f"{privilege}_privilege"},
                )
            )


def _add_access_advisor_grants(
    graph: UnifiedGraph,
    principal: dict[str, Any],
    *,
    principal_node_id: str,
    provider: str,
    data_sources: list[str],
) -> None:
    """Bridge AWS Access-Advisor usage evidence into per-service grant edges.

    Emits one ``HAS_PERMISSION`` edge per granted service, carrying the service's
    Access-Advisor ``last_used_at`` (``None`` = never used) so the CIEM
    over-privilege emitter can right-size. Only emitted when Access Advisor
    returned complete evidence (``state == "available"``) — denied/pending/
    unavailable evidence yields no edges, so absence is never read as unused.
    """
    evidence = principal.get("usage_evidence")
    if not isinstance(evidence, dict) or str(evidence.get("state") or "") != "available":
        return
    records = evidence.get("records")
    if not isinstance(records, list):
        return
    for record in records:
        if not isinstance(record, dict) or str(record.get("state") or "") != "available":
            continue
        service = _clean_graph_part(record.get("service_namespace"))
        if not service:
            continue
        last_accessed = record.get("last_accessed_at")
        last_used = last_accessed if isinstance(last_accessed, str) and last_accessed.strip() else None
        service_node_id = _identity_node_id(EntityType.RESOURCE, provider, f"{principal_node_id}:{service}")
        graph.add_node(
            UnifiedNode(
                id=service_node_id,
                entity_type=EntityType.RESOURCE,
                label=service,
                attributes={
                    "cloud_provider": provider,
                    "cloud_service": service,
                    "kind": "iam_service_permission",
                    "source": "access-advisor",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=principal_node_id,
                target=service_node_id,
                relationship=RelationshipType.HAS_PERMISSION,
                evidence={
                    "source": "access-advisor",
                    "access_advisor": True,
                    "service_namespace": service,
                    "last_used_at": last_used,
                },
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
    allow_heuristic_authorization: bool = True,
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
                "principal_resource_id": _clean_graph_part(group.get("arn")),
                "directory_principal_id": _clean_graph_part(group.get("principal_id")),
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
            **_policy_document_attrs(policy),
        )
        _add_rel_edge(
            graph, group_node_id, policy_node_id, RelationshipType.ATTACHED, {"source": "cloud-inventory", "principal_type": "group"}
        )

    # Legacy privilege inference remains separate from authoritative grants.
    if allow_heuristic_authorization and privilege in ("admin", "write"):
        for resource_id in resource_ids:
            _add_rel_edge(
                graph,
                group_node_id,
                resource_id,
                RelationshipType.CAN_ACCESS,
                {"source": "cloud-inventory", "basis": f"{privilege}_privilege"},
            )

    # Preserve native member IDs even when only directory membership was collected.
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
                directory_principal_id=member_id,
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


def _project_host_agent_id(graph: UnifiedGraph, agents_data: Any) -> str | None:
    """The single project agent that owns this report's source-code inventory.

    Code-level framework constructs are evidence about that project agent, not
    additional agents. With zero or several project roots there is no single
    owner, so the constructs keep their own nodes.
    """
    if not isinstance(agents_data, list):
        return None
    hosts: list[str] = []
    for agent in agents_data:
        if not isinstance(agent, dict):
            continue
        metadata = agent.get("metadata")
        if not (isinstance(metadata, dict) and metadata.get("project_root")):
            continue
        node_id = _agent_node_id(agent.get("name"), _agent_identity_scope(agent))
        node = graph.nodes.get(node_id)
        if node is not None and node.entity_type == EntityType.AGENT:
            hosts.append(node_id)
    return hosts[0] if len(hosts) == 1 else None


def _add_framework_topology(
    graph: UnifiedGraph,
    framework_agents: Any,
    data_source: str,
    *,
    host_agent_id: str | None = None,
) -> None:
    """Add framework nodes, model nodes, framework-native agents, and topology edges.

    Frameworks (LangChain, LangGraph, CrewAI, …) are first-class BOM entities.
    Agents link via ``uses_framework``; model string refs become ``model`` nodes
    linked via ``serves_model``.

    With a ``host_agent_id`` (the project agent), a construct that takes no part
    in multi-agent delegation is folded into the host as ``code_agents``
    evidence; delegation participants remain distinct agents.
    """
    if not isinstance(framework_agents, list):
        return
    known_agent_ids: set[str] = set()
    topology_participants: set[str] = set()
    for item in framework_agents:
        if not isinstance(item, dict):
            continue
        for edge in item.get("topology_edges", []) or []:
            if isinstance(edge, dict):
                topology_participants.add(str(edge.get("source_id") or "").strip())
                topology_participants.add(str(edge.get("target_id") or "").strip())
    host = graph.nodes.get(host_agent_id) if host_agent_id else None
    folded: list[dict[str, Any]] = []
    framework_ids: dict[str, str] = {}

    def _framework_node_id(name: str) -> str:
        key = name.strip().lower() or "unknown"
        if key not in framework_ids:
            framework_ids[key] = stable_node_id(EntityType.FRAMEWORK.value, key)
        return framework_ids[key]

    def _ensure_framework(name: str, *, kind: str = "orchestration") -> str | None:
        label = str(name or "").strip()
        if not label:
            return None
        fid = _framework_node_id(label)
        if not graph.has_node(fid):
            graph.add_node(
                UnifiedNode(
                    id=fid,
                    entity_type=EntityType.FRAMEWORK,
                    label=label,
                    attributes={
                        "framework": label,
                        "framework_kind": kind,
                    },
                    dimensions=NodeDimensions(surface=label, agent_type="framework"),
                    data_sources=[data_source, "source-ast"],
                )
            )
        return fid

    def _ensure_model(ref: str) -> str | None:
        label = str(ref or "").strip()
        if not label:
            return None
        mid = _model_node_id(label)
        # add_node is create-or-merge: unconditionally add so a model discovered
        # by multiple sources (provenance + framework ref) unions its attributes
        # onto one node rather than being skipped when already present.
        graph.add_node(
            UnifiedNode(
                id=mid,
                entity_type=EntityType.MODEL,
                label=label,
                attributes={"model_ref": label, "source": "framework-agent"},
                dimensions=NodeDimensions(surface="model"),
                data_sources=[data_source, "source-ast"],
            )
        )
        return mid

    for item in framework_agents:
        if not isinstance(item, dict):
            continue
        agent_id = str(item.get("stable_id") or "").strip()
        if not agent_id:
            continue
        framework_name = str(item.get("framework") or "").strip()
        if host is not None and agent_id not in topology_participants:
            folded.append(
                {
                    "name": str(item.get("name") or agent_id),
                    "framework": framework_name,
                    "file_path": item.get("file_path", ""),
                    "line_number": item.get("line_number", 0),
                    "confidence": item.get("confidence", ""),
                    "capabilities": item.get("capabilities", []),
                }
            )
            agent_id = host.id
        else:
            known_agent_ids.add(agent_id)
            graph.add_node(
                UnifiedNode(
                    id=agent_id,
                    entity_type=EntityType.AGENT,
                    label=str(item.get("name") or agent_id),
                    attributes={
                        "agent_type": "framework-agent",
                        "framework": framework_name,
                        "file_path": item.get("file_path", ""),
                        "line_number": item.get("line_number", 0),
                        "confidence": item.get("confidence", ""),
                        "model_refs": item.get("model_refs", []),
                        "credential_refs": item.get("credential_refs", []),
                        "capabilities": item.get("capabilities", []),
                        "dynamic_edges": item.get("dynamic_edges", False),
                    },
                    dimensions=NodeDimensions(agent_type="framework-agent", surface=framework_name),
                    data_sources=[data_source, "source-ast"],
                )
            )
        fw_id = _ensure_framework(framework_name)
        if fw_id:
            graph.add_edge(
                UnifiedEdge(
                    source=agent_id,
                    target=fw_id,
                    relationship=RelationshipType.USES_FRAMEWORK,
                    evidence={"source": "source-ast", "framework": framework_name},
                )
            )
        for model_ref in item.get("model_refs", []) or []:
            mid = _ensure_model(str(model_ref))
            if mid:
                graph.add_edge(
                    UnifiedEdge(
                        source=agent_id,
                        target=mid,
                        relationship=RelationshipType.SERVES_MODEL,
                        evidence={"source": "source-ast", "model_ref": str(model_ref)},
                    )
                )

    if host is not None and folded:
        host.attributes["code_agents"] = folded
        host.data_sources = list(dict.fromkeys([*host.data_sources, "source-ast"]))

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
                edge_fw = str(edge.get("framework") or "").strip()
                graph.add_node(
                    UnifiedNode(
                        id=node_id,
                        entity_type=EntityType.AGENT,
                        label=str(node_name or node_id),
                        attributes={
                            "agent_type": "framework-agent",
                            "framework": edge_fw,
                            "synthetic_from_topology_edge": True,
                        },
                        dimensions=NodeDimensions(agent_type="framework-agent", surface=edge_fw),
                        data_sources=[data_source, "source-ast"],
                    )
                )
                known_agent_ids.add(node_id)
                fw_id = _ensure_framework(edge_fw)
                if fw_id:
                    graph.add_edge(
                        UnifiedEdge(
                            source=node_id,
                            target=fw_id,
                            relationship=RelationshipType.USES_FRAMEWORK,
                            evidence={"source": "source-ast", "framework": edge_fw},
                        )
                    )
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


def _add_ai_stack_frameworks(graph: UnifiedGraph, ai_inventory: Any, data_source: str) -> None:
    """Project SDK/observability imports as first-class framework nodes + package/model links."""
    if not isinstance(ai_inventory, dict):
        return
    components = ai_inventory.get("components")
    if not isinstance(components, list):
        return

    observability_fids: list[str] = []

    def _ensure_model(ref: str, *, source: str = "ai-inventory") -> str | None:
        label = str(ref or "").strip()
        if not label or label.upper() == "[REDACTED]":
            return None
        mid = _model_node_id(label)
        # add_node is create-or-merge: unconditionally add so a model discovered
        # by multiple sources unions its attributes onto one node.
        graph.add_node(
            UnifiedNode(
                id=mid,
                entity_type=EntityType.MODEL,
                label=label,
                attributes={"model_ref": label, "source": source},
                dimensions=NodeDimensions(surface="model"),
                data_sources=[data_source, "ai-inventory"],
            )
        )
        return mid

    for comp in components:
        if not isinstance(comp, dict):
            continue
        ctype = str(comp.get("type") or "").strip().lower()
        name = str(comp.get("name") or comp.get("package") or "").strip()
        if not name:
            continue

        if ctype in {"model_reference", "deprecated_model"}:
            _ensure_model(name, source=ctype)
            continue

        if ctype not in {"agent_framework", "observability"}:
            continue
        kind = "observability" if ctype == "observability" else "orchestration"
        fid = stable_node_id(EntityType.FRAMEWORK.value, name.lower())
        if kind == "observability" and fid not in observability_fids:
            observability_fids.append(fid)
        if not graph.has_node(fid):
            graph.add_node(
                UnifiedNode(
                    id=fid,
                    entity_type=EntityType.FRAMEWORK,
                    label=name,
                    attributes={
                        "framework": name,
                        "framework_kind": kind,
                        "package": comp.get("package", ""),
                        "ecosystem": comp.get("ecosystem", ""),
                        "language": comp.get("language", ""),
                        "is_shadow": bool(comp.get("is_shadow")),
                        "file": comp.get("file", ""),
                        "line": comp.get("line", 0),
                    },
                    dimensions=NodeDimensions(surface=name, agent_type=kind),
                    data_sources=[data_source, "ai-inventory"],
                )
            )
        package_name = str(comp.get("package") or "").strip()
        ecosystem = str(comp.get("ecosystem") or "pypi").strip() or "pypi"
        if package_name:
            pkg_id = stable_node_id(EntityType.PACKAGE.value, ecosystem, package_name, "latest")
            # Prefer an existing versioned package node if present.
            existing = [
                n
                for n in graph.nodes_by_type(EntityType.PACKAGE)
                if str(n.attributes.get("name") or n.label).lower() == package_name.lower()
            ]
            if existing:
                pkg_id = existing[0].id
            elif not graph.has_node(pkg_id):
                graph.add_node(
                    UnifiedNode(
                        id=pkg_id,
                        entity_type=EntityType.PACKAGE,
                        label=package_name,
                        attributes={
                            "name": package_name,
                            "ecosystem": ecosystem,
                            "version": "latest",
                            "from_ai_inventory": True,
                        },
                        data_sources=[data_source, "ai-inventory"],
                    )
                )
            graph.add_edge(
                UnifiedEdge(
                    source=fid,
                    target=pkg_id,
                    relationship=RelationshipType.DEPENDS_ON,
                    evidence={"source": "ai-inventory", "framework": name},
                )
            )

    for model_name in ai_inventory.get("unique_models") or []:
        _ensure_model(str(model_name))

    # Observability frameworks (Langfuse/LangSmith/OpenLLMetry-class) instrument
    # the agents detected in the same scan surface. Emit framework→agent
    # ``observes`` edges so the advertised relationship is actually produced.
    if observability_fids:
        agent_ids = [n.id for n in graph.nodes_by_type(EntityType.AGENT)]
        for fid in observability_fids:
            for agent_id in agent_ids:
                graph.add_edge(
                    UnifiedEdge(
                        source=fid,
                        target=agent_id,
                        relationship=RelationshipType.OBSERVES,
                        evidence={"source": "ai-inventory"},
                    )
                )


# Provider prefixes stripped when fingerprinting a model reference so that
# ``openai:gpt-4o``, ``openai/gpt-4o`` and ``gpt-4o`` collapse to one node.
