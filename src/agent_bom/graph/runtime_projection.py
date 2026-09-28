"""Runtime identity and incident evidence projected into a report graph."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge, _agent_node_id, _mapping_list
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part
from agent_bom.runtime.incident_feedback import (
    RuntimeIncidentRecord,
    incident_attribute,
    iter_observed_targets,
    load_incident_records,
    merge_records,
)
from agent_bom.security import sanitize_sensitive_payload, sanitize_text

_FEEDBACK_RELATIONSHIP: dict[str, RelationshipType] = {
    "reached_credential": RelationshipType.USED_CREDENTIAL,
    "lateral_movement": RelationshipType.ACCESSED,
    "kill_switch": RelationshipType.ACCESSED,
}


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


def project_runtime_session(graph: UnifiedGraph, runtime_graph: dict[str, Any] | None) -> None:
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
