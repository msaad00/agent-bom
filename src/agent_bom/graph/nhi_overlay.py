"""Project discovered non-human identities (NHIs) into the unified graph.

The ``agent_bom.identity`` connectors enumerate *existing* machine identities
(IdP service accounts, API tokens) that agent-bom did not issue. This overlay
emits each one as a ``managed_identity`` node — the same entity type used by the
governance overlay for agent-bom-issued identities — so the
effective-permissions engine and governance traversal treat discovered and
issued identities uniformly:

    agent → managed_identity → tool → vulnerable package

Discovered NHIs carry a ``discovered`` marker and the source provider so they
are distinguishable from issued identities. Nodes are keyed on the provider +
identity id; re-running discovery is idempotent. Matching to existing tool nodes
is by label; an unmatched scope is still recorded on the node attributes so it
stays visible without an edge.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType
from agent_bom.identity.okta_nhi import DiscoveredNonHumanIdentity

_OVERLAY_SOURCE = "nhi-discovery"


def _tool_label_index(graph: UnifiedGraph) -> dict[str, list[str]]:
    index: dict[str, list[str]] = defaultdict(list)
    for node in graph.nodes.values():
        if node.entity_type == EntityType.TOOL:
            index[node.label.strip().lower()].append(node.id)
    return index


def apply_nhi_overlay(
    graph: UnifiedGraph,
    identities: Iterable[DiscoveredNonHumanIdentity],
) -> dict[str, int]:
    """Add discovered NHIs as ``managed_identity`` nodes (+ tool scope) in place.

    Returns a count of added nodes and edges. Idempotent: an identity whose node
    already exists is skipped. Never raises — a malformed identity is ignored.
    """
    tools_by_label = _tool_label_index(graph)
    added_nodes = 0
    added_edges = 0

    for identity in identities:
        try:
            nid = f"managed_identity:{identity.provider}:{identity.identity_id}"
            if nid in graph.nodes:
                continue
            graph.add_node(
                UnifiedNode(
                    id=nid,
                    entity_type=EntityType.MANAGED_IDENTITY,
                    label=identity.name or identity.identity_id,
                    data_sources=[_OVERLAY_SOURCE],
                    status=NodeStatus.ACTIVE if identity.status == "active" else NodeStatus.INACTIVE,
                    # Context node: "info" so it survives default graph filters
                    # (severity_id 0 is dropped) without outranking real findings.
                    severity="info",
                    attributes={
                        "discovered": True,
                        "provider": identity.provider,
                        "identity_id": identity.identity_id,
                        "identity_type": identity.identity_type,
                        "status": identity.status,
                        "owner": identity.owner,
                        "created_at": identity.created_at,
                        "last_used_at": identity.last_used_at,
                        "credential_expires_at": identity.credential_expires_at,
                        "scopes": list(identity.scopes),
                    },
                )
            )
            added_nodes += 1

            for scope in identity.scopes:
                scope_name = scope.strip().lower()
                if not scope_name or scope_name == "*":
                    continue
                for tool_id in tools_by_label.get(scope_name, []):
                    graph.add_edge(
                        UnifiedEdge(
                            source=nid,
                            target=tool_id,
                            relationship=RelationshipType.SCOPED_TO,
                            weight=3.0,
                            provenance={"source": _OVERLAY_SOURCE},
                            evidence={"kind": "discovered_nhi_scope", "provider": identity.provider},
                        )
                    )
                    added_edges += 1
        except Exception:  # noqa: BLE001 — never raise into the builder
            continue

    return {"nodes_added": added_nodes, "edges_added": added_edges}


def apply_nhi_overlay_from_result(graph: UnifiedGraph, result: Any) -> dict[str, int]:
    """Convenience wrapper: project the identities from an ``NHIDiscoveryResult``.

    Only the ``OK`` status contributes nodes; any other status (disabled,
    missing creds, error) is a no-op so the builder can call this unconditionally.
    """
    identities = getattr(result, "identities", None) or ()
    if getattr(result, "status", None) is not None and not getattr(result, "ok", False):
        return {"nodes_added": 0, "edges_added": 0}
    return apply_nhi_overlay(graph, identities)


__all__ = ["apply_nhi_overlay", "apply_nhi_overlay_from_result"]
