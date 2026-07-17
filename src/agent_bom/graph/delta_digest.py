"""Bounded prior-snapshot digest for graph delta-alert computation.

``compute_delta_alerts`` only needs a handful of facts about the *previous*
snapshot: the set of node ids (for new-node detection), the agent nodes (for
removed-agent detection and their event refs), and the attack-path /
interaction-risk keys. Materialising the whole previous ``UnifiedGraph`` just to
diff against it holds a second full graph in memory (#4055 / #4075).

:class:`PriorSnapshotDigest` captures exactly those facts and nothing else, so a
store can build it by streaming the prior snapshot's nodes one at a time — peak
RSS stays bounded by the id-string set and the (small) agent-node subset rather
than every node's attributes/dimensions payload.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType


@dataclass(frozen=True)
class PriorSnapshotDigest:
    """Bounded projection of a previous graph snapshot for delta diffing.

    - ``node_ids``: every prior node id (membership test for new nodes).
    - ``agent_nodes``: prior AGENT nodes only (removed-agent detection + refs).
    - ``attack_path_keys``: ``(source, target)`` of each prior attack path.
    - ``interaction_risk_keys``: ``(pattern, sorted-agents)`` of each prior risk.
    """

    node_ids: frozenset[str] = frozenset()
    agent_nodes: Mapping[str, UnifiedNode] = field(default_factory=dict)
    attack_path_keys: frozenset[tuple[str, str]] = frozenset()
    interaction_risk_keys: frozenset[tuple[str, tuple[str, ...]]] = frozenset()

    @classmethod
    def empty(cls) -> PriorSnapshotDigest:
        """Digest of a non-existent prior snapshot (first scan for a tenant)."""
        return cls()

    @classmethod
    def from_graph(cls, graph: object | None) -> PriorSnapshotDigest:
        """Project a fully materialised ``UnifiedGraph`` into a digest.

        Kept identical to the fields ``compute_delta_alerts`` reads off a full
        graph so the streamed and in-memory paths produce byte-identical alerts.
        Accepts ``None`` (no prior snapshot) → empty digest.
        """
        if graph is None:
            return cls.empty()
        nodes: Mapping[str, UnifiedNode] = graph.nodes  # type: ignore[attr-defined]
        agent_nodes = {nid: node for nid, node in nodes.items() if node.entity_type == EntityType.AGENT}
        return cls(
            node_ids=frozenset(nodes.keys()),
            agent_nodes=agent_nodes,
            attack_path_keys=frozenset((p.source, p.target) for p in graph.attack_paths),  # type: ignore[attr-defined]
            interaction_risk_keys=frozenset(
                (r.pattern, tuple(sorted(r.agents)))
                for r in graph.interaction_risks  # type: ignore[attr-defined]
            ),
        )
