"""Unified graph builder from serialized AIBOM report data.

This ingests the JSON contract emitted by ``output.json_fmt.to_json()``
and builds the core inventory, finding, runtime, and compliance entities
used for current-state views, traversal, attack paths, and temporal diffs.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from typing import Any

from agent_bom.api.tracing import get_tracer
from agent_bom.canonical_ids import canonical_graph_node_id
from agent_bom.cloud.normalization import coerce_bool_or_none, coerce_truthy
from agent_bom.core.cloud_identity import cloud_resource_node_id
from agent_bom.graph.agent_projection import project_agents
from agent_bom.graph.authorization_evidence import apply_authorization_evidence, has_authoritative_authorization_evidence
from agent_bom.graph.benchmark_projection import benchmark_inputs, project_benchmarks
from agent_bom.graph.blast_projection import enrich_blast_radius, project_blast_radius, project_package_exploits, project_shared_servers
from agent_bom.graph.build_analysis import GraphAnalysisPorts, apply_build_analysis
from agent_bom.graph.build_indexes import BuildIndexes
from agent_bom.graph.build_input import GraphBuildInput
from agent_bom.graph.builder_cloud_inventory import (
    _add_management_group_hierarchy as _add_management_group_hierarchy,
)
from agent_bom.graph.builder_cloud_inventory import (
    _wire_instance_profile_roles as _wire_instance_profile_roles,
)
from agent_bom.graph.builder_cloud_principals import (
    _add_access_advisor_grants as _add_access_advisor_grants,
)
from agent_bom.graph.builder_cloud_principals import (
    _role_last_used_at as _role_last_used_at,
)
from agent_bom.graph.builder_frameworks import (
    _add_cross_env_correlation as _add_cross_env_correlation,
)
from agent_bom.graph.builder_frameworks import (
    _project_host_agent_id as _project_host_agent_id,
)
from agent_bom.graph.builder_network_edges import (
    _GCP_LB_COLLECTION as _GCP_LB_COLLECTION,
)
from agent_bom.graph.builder_network_edges import (
    _NETWORK_EDGE_COLLECTIONS as _NETWORK_EDGE_COLLECTIONS,
)
from agent_bom.graph.builder_network_exposure import (
    _add_exposure_path_edge as _add_exposure_path_edge,
)
from agent_bom.graph.builder_network_exposure import (
    _apply_gcp_firewall_exposure as _apply_gcp_firewall_exposure,
)
from agent_bom.graph.builder_network_exposure import (
    _gcp_firewall_applies as _gcp_firewall_applies,
)
from agent_bom.graph.builder_network_exposure import (
    _instance_internet_reachable as _instance_internet_reachable,
)
from agent_bom.graph.builder_network_exposure import (
    _link_internet_facing_load_balancers as _link_internet_facing_load_balancers,
)
from agent_bom.graph.builder_overlays import (
    _apply_agent_reach_risk as _apply_agent_reach_risk,
)
from agent_bom.graph.builder_overlays import (
    _apply_aspm_overlay as _apply_aspm_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_ci_graph_overlay as _apply_ci_graph_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_code_graph_overlay as _apply_code_graph_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_cost_overlay as _apply_cost_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_repo_structure_overlay as _apply_repo_structure_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_repo_trust_overlay as _apply_repo_trust_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_runtime_evidence_overlay as _apply_runtime_evidence_overlay,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _EXFIL_STAGE_SERVICE as _EXFIL_STAGE_SERVICE,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _SF_EXTERNAL_BUCKET_SERVICE as _SF_EXTERNAL_BUCKET_SERVICE,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_exfil as _add_snowflake_exfil,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_external_data as _add_snowflake_external_data,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_external_stages as _add_snowflake_external_stages,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_external_tables as _add_snowflake_external_tables,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_iceberg_tables as _add_snowflake_iceberg_tables,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_outbound_shares as _add_snowflake_outbound_shares,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_sensitive_objects as _add_snowflake_sensitive_objects,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_stage_bucket as _add_snowflake_stage_bucket,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _link_iceberg_bucket as _link_iceberg_bucket,
)
from agent_bom.graph.builder_snowflake_governance import (
    _add_cortex_agent_nodes as _add_cortex_agent_nodes,
)
from agent_bom.graph.builder_snowflake_governance import (
    _add_snowflake_access_edges as _add_snowflake_access_edges,
)
from agent_bom.graph.builder_snowflake_governance import (
    _add_snowflake_activity as _add_snowflake_activity,
)
from agent_bom.graph.builder_snowflake_governance import (
    _add_snowflake_governance as _add_snowflake_governance,
)
from agent_bom.graph.builder_snowflake_governance import (
    _aggregate_cortex_agent_usage as _aggregate_cortex_agent_usage,
)
from agent_bom.graph.builder_snowflake_governance import (
    _collect_snowflake_access as _collect_snowflake_access,
)
from agent_bom.graph.builder_snowflake_governance import (
    _snowflake_access_receipt as _snowflake_access_receipt,
)
from agent_bom.graph.builder_snowflake_lane import (
    _snowflake_data_store as _snowflake_data_store,
)
from agent_bom.graph.builder_snowflake_lane import (
    _snowflake_thin_node as _snowflake_thin_node,
)
from agent_bom.graph.builder_snowflake_lane import (
    _SnowflakeLane as _SnowflakeLane,
)
from agent_bom.graph.builder_snowflake_objects import (
    _add_snowflake_auth_posture as _add_snowflake_auth_posture,
)
from agent_bom.graph.builder_snowflake_objects import (
    _add_snowflake_identity as _add_snowflake_identity,
)
from agent_bom.graph.builder_snowflake_objects import (
    _add_snowflake_login_threats as _add_snowflake_login_threats,
)
from agent_bom.graph.builder_snowflake_objects import (
    _add_snowflake_object_graph as _add_snowflake_object_graph,
)
from agent_bom.graph.builder_snowflake_objects import (
    _enrich_snowflake_user as _enrich_snowflake_user,
)
from agent_bom.graph.builder_snowflake_objects import (
    _SnowflakeObjectGraph as _SnowflakeObjectGraph,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_databases as _add_snowflake_databases,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_integrations as _add_snowflake_integrations,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_organization as _add_snowflake_organization,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_pipeline as _add_snowflake_pipeline,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_pipes as _add_snowflake_pipes,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_schemas as _add_snowflake_schemas,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_services as _add_snowflake_services,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_streams as _add_snowflake_streams,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_tasks as _add_snowflake_tasks,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_warehouses as _add_snowflake_warehouses,
)
from agent_bom.graph.builder_snowflake_platform import (
    _link_snowflake_objects_to_schemas as _link_snowflake_objects_to_schemas,
)
from agent_bom.graph.cloud_compute_projection import project_instances, project_security_groups
from agent_bom.graph.cloud_context import (
    _add_account_resource_hierarchy as _add_account_resource_hierarchy,
)
from agent_bom.graph.cloud_context import (
    _add_identity_node as _add_identity_node,
)
from agent_bom.graph.cloud_context import (
    _environment_from_tags as _environment_from_tags,
)
from agent_bom.graph.cloud_context import (
    _first_cloud_scope_value as _first_cloud_scope_value,
)
from agent_bom.graph.cloud_context import (
    _identity_entity_type as _identity_entity_type,
)
from agent_bom.graph.cloud_context import (
    _iter_cloud_inventories as _iter_cloud_inventories,
)
from agent_bom.graph.cloud_context import (
    _normalize_azure_inventory as _normalize_azure_inventory,
)
from agent_bom.graph.cloud_context import (
    _normalize_cloud_inventory as _normalize_cloud_inventory,
)
from agent_bom.graph.cloud_context import (
    _normalize_gcp_inventory as _normalize_gcp_inventory,
)
from agent_bom.graph.cloud_context import (
    _policy_document_attrs as _policy_document_attrs,
)
from agent_bom.graph.cloud_context import (
    _policy_entries as _policy_entries,
)
from agent_bom.graph.cloud_context import (
    _prepare_cloud_payload as _prepare_cloud_payload,
)
from agent_bom.graph.cloud_context import (
    _recorded_exposure_attributes as _recorded_exposure_attributes,
)
from agent_bom.graph.cloud_context import (
    _resource_environment as _resource_environment,
)
from agent_bom.graph.cloud_context import (
    _stamp_owning_account as _stamp_owning_account,
)
from agent_bom.graph.cloud_context import (
    _trust_entries as _trust_entries,
)
from agent_bom.graph.cloud_context import cloud_inventory_sources
from agent_bom.graph.cloud_rbac import add_cloud_role_assignments as _add_cloud_role_assignments
from agent_bom.graph.cloud_service_projection import project_aws_services, project_gcp_services
from agent_bom.graph.cloud_storage_projection import project_buckets, project_databases, project_side_scan_targets
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.finding_projection import _resolve_skill_audit_target_ids as _resolve_skill_audit_target_ids
from agent_bom.graph.finding_projection import (
    project_iac,
    project_sast,
    project_secret_findings,
    project_skill_audit,
    project_toxic_combinations,
)
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
    project_secret_findings(graph, report.get("findings"))
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

    Missing / empty / non-ok inventory is a no-op; imported data retains its source tag.
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
    data_sources = cloud_inventory_sources(original_inventory, data_source, provider)

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

    project_side_scan_targets(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    project_buckets(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    project_databases(
        graph,
        original_inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    sg_node_by_id = project_security_groups(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    instance_nodes = project_instances(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
        sg_node_by_id=sg_node_by_id,
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

    internet_facing_lbs = project_aws_services(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    project_gcp_services(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
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
        node_id = cloud_resource_node_id(provider, res.resource_type.value, res.raw or {}, res.account or account_id, region)
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
