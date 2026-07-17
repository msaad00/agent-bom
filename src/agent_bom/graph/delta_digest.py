"""Bounded prior-snapshot digest for graph delta-alert computation.

The graph write path evaluates delta alerts by comparing a freshly built
snapshot against the tenant's *previous* snapshot. The straightforward
implementation loads the previous snapshot into a second, fully materialised
:class:`~agent_bom.graph.container.UnifiedGraph` (every ``UnifiedNode``, every
edge, plus adjacency indexes) purely to answer the handful of set-membership
questions :func:`agent_bom.graph.webhooks.compute_delta_alerts` actually asks of
the prior graph. At millions of nodes that second graph is what pins peak RSS
(see #4055 / #4075).

``compute_delta_alerts`` reads only four things from the prior graph:

1. the set of prior node ids (to detect *new* nodes),
2. minimal refs (label / severity / status / risk_score) for prior **agent**
   nodes (to detect *removed* agents and render their event refs),
3. the prior attack-path ``(source, target)`` keys, and
4. the prior interaction-risk ``(pattern, agents)`` keys.

:class:`PriorSnapshotDigest` captures exactly that and nothing else. It is a
structural stand-in for the prior graph — a :class:`PriorGraphView` — so it can
be handed straight to the unchanged ``compute_delta_alerts``, which keeps the
delta output byte-identical to the full-graph path while decoupling peak memory
from the prior snapshot's node/edge payloads. Non-agent node ids collapse onto a
single shared sentinel ref, so the digest holds one id-string set plus a small
agent-ref map — never the full node objects, attributes, edges, or adjacency.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NamedTuple

from agent_bom.graph.types import EntityType

if TYPE_CHECKING:
    from agent_bom.graph.container import UnifiedGraph


@dataclass(frozen=True)
class PriorNodeRef:
    """Minimal prior-node projection consumed by ``compute_delta_alerts``.

    Only the attributes the delta walk reads are retained — ``entity_type`` (to
    single out agents), plus ``id`` / ``label`` / ``severity`` / ``status`` /
    ``risk_score`` for rendering a removed-agent event ref. ``status`` is the raw
    persisted string, which equals ``NodeStatus(status).value`` — so the rendered
    ref is identical to the one built from a fully loaded node.
    """

    id: str
    entity_type: EntityType
    label: str
    severity: str
    status: str
    risk_score: float


# Shared sentinel for every non-agent prior node. ``compute_delta_alerts`` only
# ever inspects ``entity_type`` for non-agent prior nodes (to exclude them from
# the removed-agent set) and never resolves them into an event ref, so a single
# shared instance is safe and keeps the digest's memory to one id-string set.
_NON_AGENT_REF = PriorNodeRef(
    id="",
    entity_type=EntityType.RESOURCE,
    label="",
    severity="",
    status="",
    risk_score=0.0,
)


class _PriorNodes(Mapping[str, PriorNodeRef]):
    """Mapping view over prior node ids with agent refs materialised lazily.

    ``__contains__`` and iteration cover *all* prior node ids (bounded by the
    prior snapshot size, but only id strings). ``__getitem__`` returns the real
    agent ref for agent ids and the shared sentinel for everything else present.
    """

    __slots__ = ("_all_ids", "_agent_refs")

    def __init__(self, all_ids: set[str], agent_refs: dict[str, PriorNodeRef]) -> None:
        self._all_ids = all_ids
        self._agent_refs = agent_refs

    def __getitem__(self, key: str) -> PriorNodeRef:
        ref = self._agent_refs.get(key)
        if ref is not None:
            return ref
        if key in self._all_ids:
            return _NON_AGENT_REF
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        return key in self._all_ids

    def __iter__(self) -> Iterator[str]:
        return iter(self._all_ids)

    def __len__(self) -> int:
        return len(self._all_ids)

    def items(self) -> Iterator[tuple[str, PriorNodeRef]]:  # type: ignore[override]
        agent_refs = self._agent_refs
        for nid in self._all_ids:
            yield nid, agent_refs.get(nid, _NON_AGENT_REF)


class _PathKey(NamedTuple):
    source: str
    target: str


class _RiskKey(NamedTuple):
    pattern: str
    agents: tuple[str, ...]


@dataclass(frozen=True)
class PriorSnapshotDigest:
    """Structural stand-in for a prior ``UnifiedGraph`` in delta computation.

    Exposes exactly the ``nodes`` / ``attack_paths`` / ``interaction_risks``
    surface ``compute_delta_alerts`` touches, so it can be passed in place of the
    prior graph with byte-identical results and bounded memory.
    """

    nodes: _PriorNodes
    attack_paths: tuple[_PathKey, ...]
    interaction_risks: tuple[_RiskKey, ...]


class PriorSnapshotDigestBuilder:
    """Incrementally assemble a :class:`PriorSnapshotDigest` from streamed rows.

    Backends feed this from a lazy cursor over the prior snapshot's node,
    attack-path, and interaction-risk rows — so building the digest never
    materialises the prior graph.
    """

    __slots__ = ("_all_ids", "_agent_refs", "_attack_paths", "_interaction_risks")

    def __init__(self) -> None:
        self._all_ids: set[str] = set()
        self._agent_refs: dict[str, PriorNodeRef] = {}
        self._attack_paths: list[_PathKey] = []
        self._interaction_risks: list[_RiskKey] = []

    def add_node(
        self,
        node_id: str,
        entity_type: str | EntityType,
        *,
        label: str = "",
        severity: str = "",
        status: str = "",
        risk_score: float = 0.0,
    ) -> None:
        self._all_ids.add(node_id)
        et = entity_type.value if isinstance(entity_type, EntityType) else entity_type
        if et == EntityType.AGENT.value:
            self._agent_refs[node_id] = PriorNodeRef(
                id=node_id,
                entity_type=EntityType.AGENT,
                label=label,
                severity=severity or "",
                status=status or "",
                risk_score=risk_score or 0.0,
            )

    def add_attack_path(self, source: str, target: str) -> None:
        self._attack_paths.append(_PathKey(source, target))

    def add_interaction_risk(self, pattern: str, agents: Iterable[str]) -> None:
        self._interaction_risks.append(_RiskKey(pattern, tuple(agents)))

    def build(self) -> PriorSnapshotDigest:
        return PriorSnapshotDigest(
            nodes=_PriorNodes(self._all_ids, self._agent_refs),
            attack_paths=tuple(self._attack_paths),
            interaction_risks=tuple(self._interaction_risks),
        )


def digest_from_graph(graph: UnifiedGraph) -> PriorSnapshotDigest:
    """Build a digest from an in-memory graph (test/fallback parity helper)."""
    builder = PriorSnapshotDigestBuilder()
    for node in graph.nodes.values():
        builder.add_node(
            node.id,
            node.entity_type,
            label=node.label,
            severity=node.severity or "",
            status=node.status.value if hasattr(node.status, "value") else str(node.status),
            risk_score=node.risk_score,
        )
    for path in graph.attack_paths:
        builder.add_attack_path(path.source, path.target)
    for risk in graph.interaction_risks:
        builder.add_interaction_risk(risk.pattern, risk.agents)
    return builder.build()


def compute_delta_alerts_from_digest(
    prior: PriorSnapshotDigest | None,
    new_graph: UnifiedGraph,
) -> list[dict[str, Any]]:
    """Delta alerts between a bounded prior digest and a freshly built graph.

    Delegates to the single ``compute_delta_alerts`` implementation so the output
    is byte-identical to the full prior-graph path. Imported lazily (and invoked
    via the module attribute) both to avoid an import cycle with ``webhooks`` and
    so test monkeypatches of ``webhooks.compute_delta_alerts`` are honoured.
    """
    from agent_bom.graph import webhooks

    return webhooks.compute_delta_alerts(prior, new_graph)
