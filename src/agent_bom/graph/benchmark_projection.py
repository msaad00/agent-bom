"""Benchmark findings anchored to native cloud resource or account identity."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.resource_aliases import _build_cloud_resource_alias_index, _CloudResourceAliasIndex, _resolve_cloud_resource_node_id
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


@dataclass(frozen=True)
class BenchmarkInput:
    section_key: str
    cis_data: Mapping[str, Any]
    default_cloud_provider: str


def benchmark_inputs(report_json: Mapping[str, Any]) -> list[BenchmarkInput]:
    result = []
    for section_key, legacy_key, default_cloud_provider in (
        ("cis_benchmark", "cis_benchmark_data", "aws"),
        ("snowflake_cis_benchmark", "snowflake_cis_benchmark_data", "snowflake"),
        ("azure_cis_benchmark", "azure_cis_benchmark_data", "azure"),
        ("gcp_cis_benchmark", "gcp_cis_benchmark_data", "gcp"),
        # Databricks has no official CIS benchmark: read the canonical
        # ``databricks_security`` key, falling back to the deprecated alias.
        ("databricks_security", "databricks_cis_benchmark", "databricks"),
    ):
        cis_data = report_json.get(section_key) or report_json.get(legacy_key)
        if not cis_data:
            continue
        result.append(BenchmarkInput(section_key, cis_data, default_cloud_provider))
    return result


def project_benchmarks(graph: UnifiedGraph, benchmarks: list[BenchmarkInput]) -> None:
    cloud_resource_alias_index = _build_cloud_resource_alias_index(graph)
    for benchmark in benchmarks:
        _project_benchmark(graph, benchmark, cloud_resource_alias_index)


def _project_benchmark(graph: UnifiedGraph, benchmark: BenchmarkInput, cloud_resource_alias_index: _CloudResourceAliasIndex) -> None:
    section_key, cis_data, default_cloud_provider = benchmark.section_key, benchmark.cis_data, benchmark.default_cloud_provider
    cloud_provider = (
        _clean_graph_part(cis_data.get("provider")) or _clean_graph_part(cis_data.get("cloud_provider")) or default_cloud_provider
    )
    checks = cis_data.get("checks", [])
    cloud_account_id = _clean_graph_part(
        cis_data.get("subscription_id") or cis_data.get("account_id") or cis_data.get("aws_account_id") or cis_data.get("project_id")
    )
    for check in checks:
        _project_check(graph, check, section_key, cloud_provider, cloud_account_id, cloud_resource_alias_index)


def _project_check(
    graph: UnifiedGraph,
    check: dict[str, Any],
    section_key: str,
    cloud_provider: str,
    cloud_account_id: str,
    cloud_resource_alias_index: _CloudResourceAliasIndex,
) -> None:
    if str(check.get("status", "")).upper() != "FAIL":
        return
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
                "evaluation_status": "fail",
                "evaluation_scope": "resource" if resource_ids else "account",
                "cis_section": check.get("cis_section", ""),
                "evidence": check.get("evidence", ""),
                "recommendation": check.get("recommendation", ""),
                "resource_ids": resource_ids,
                "cloud_provider": cloud_provider,
                "network_exposure": list(check.get("network_exposure", [])),
            },
            compliance_tags=[] if cloud_provider == "databricks" else [f"CIS-{check_id}"],
            data_sources=[section_key],
            dimensions=NodeDimensions(cloud_provider=cloud_provider),
        )
    )
    _project_resources(graph, resource_ids, section_key, cloud_provider, misconfig_id, cloud_resource_alias_index, cloud_account_id)
    _project_account(graph, resource_ids, section_key, cloud_provider, cloud_account_id, misconfig_id)


def _project_resources(
    graph: UnifiedGraph,
    resource_ids: list[str],
    section_key: str,
    cloud_provider: str,
    misconfig_id: str,
    cloud_resource_alias_index: _CloudResourceAliasIndex,
    cloud_account_id: str,
) -> None:
    for resource_id in sorted(set(resource_ids)):
        resource_node_id = _resolve_cloud_resource_node_id(
            graph,
            cloud_provider,
            resource_id,
            alias_index=cloud_resource_alias_index,
            account_id=cloud_account_id,
        )
        canonical_resource = graph.get_node(resource_node_id) if resource_node_id else None
        resource_node_id = resource_node_id or f"cloud_resource:{cloud_provider or 'generic'}:{resource_id}"
        attributes: dict[str, Any] = {
            "resource_id": resource_id,
            "cloud_provider": cloud_provider,
            "source_section": section_key,
        }
        if canonical_resource is not None:
            # Preserve the inventory's provider-native resource_id
            # (ARN/ARM/GCP name). The CIS spelling is an evidence alias,
            # not a replacement identity.
            attributes = {
                "finding_resource_ids": sorted(
                    {
                        *canonical_resource.attributes.get("finding_resource_ids", []),
                        resource_id,
                    }
                ),
                "finding_source_sections": sorted(
                    {
                        *canonical_resource.attributes.get("finding_source_sections", []),
                        section_key,
                    }
                ),
            }
        graph.add_node(
            UnifiedNode(
                id=resource_node_id,
                entity_type=canonical_resource.entity_type if canonical_resource is not None else EntityType.CLOUD_RESOURCE,
                label=canonical_resource.label if canonical_resource is not None else resource_id,
                attributes=attributes,
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


def _project_account(
    graph: UnifiedGraph, resource_ids: list[str], section_key: str, cloud_provider: str, cloud_account_id: str, misconfig_id: str
) -> None:
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
