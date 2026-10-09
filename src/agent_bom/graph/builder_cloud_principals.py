"""Cloud IAM principal and group projection from inventory."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


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
