"""Cost (FinOps) fusion: attach LLM spend to graph nodes, roll it up the
CONTAINS hierarchy, and fuse cost with risk.

Closes the FinOps silo: spend lives in :mod:`agent_bom.api.cost_store` today and
nothing answers "which asset is BOTH expensive AND exposed". This overlay reads
priced cost records the caller already loaded (no network, no writes) and:

- **Attaches** per-node spend (``cost_usd`` / ``cost_usd_30d``) on the
  agent / resource node a record names — matched by node label, canonical id,
  agent ``source_id``, or ``cost_center`` allocation tag.
- **Rolls up** spend along existing ``CONTAINS`` edges (agent → account → org,
  resource → project → org) so each parent node carries ``subtree_cost_usd`` =
  the SUM of its own + descendants' spend. Deterministic, cycle- and
  depth-guarded like the other overlays.
- **Fuses** cost × risk: a node that is BOTH high-cost AND high-risk
  (internet-exposed, in a toxic combination, or carrying a critical finding)
  gets a ``cost_risk_priority`` signal and a light advisory interaction risk so
  "expensive AND exposed" surfaces without new scanner inputs.

The overlay is a pure in-place graph mutation: idempotent (applying twice yields
identical attributes), deterministic (every iteration is sorted), and a complete
no-op when no cost records are supplied — the graph stays byte-identical.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.graph.container import InteractionRisk, UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_OVERLAY_SOURCE = "cost-overlay"

# Window (days) used for the rolling spend attribute. 30d mirrors the FinOps
# showback window the cost CLI/API report on.
_WINDOW_DAYS = 30

# A node carrying at least this much rolled-up spend is "high cost" for the
# cost×risk fusion. Kept conservative so the signal stays meaningful; the
# fusion is additive (it only ever sets flags, never lowers risk).
_HIGH_COST_USD = 100.0

# Entity types whose nodes can directly carry first-class LLM spend. Agents are
# the primary carrier (a cost record names an agent); cloud/generic resources
# and models are matched by allocation tags / labels when present.
_COST_BEARING_TYPES = (
    EntityType.AGENT,
    EntityType.CLOUD_RESOURCE,
    EntityType.RESOURCE,
    EntityType.MODEL,
    EntityType.SERVICE_ACCOUNT,
    EntityType.MANAGED_IDENTITY,
)

# Cap the CONTAINS roll-up walk so a pathological graph can never blow up; the
# real estate is org → ou → account → agent (≤ a handful of tiers).
_MAX_ROLLUP_DEPTH = 32


def _record_field(record: Any, name: str) -> Any:
    """Read a field from an LLMCostRecord dataclass or a plain dict.

    The caller may supply either the dataclass (from the cost store) or already
    JSON-decoded dicts (from a report payload); support both without importing —
    keeping this module decoupled from the cost store's write path.
    """
    if isinstance(record, dict):
        return record.get(name)
    return getattr(record, name, None)


def _record_tags(record: Any) -> dict[str, str]:
    tags = _record_field(record, "allocation_tags")
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    return {}


def _node_match_keys(node: UnifiedNode) -> set[str]:
    """Lower-cased identifiers a cost record may name this node by.

    Covers the label, canonical id, the agent ``source_id`` / ``stable_id``,
    ``owner``, and any ``cost_center`` carried on the node so a record's
    ``agent`` / ``cost_center`` matches however the node was projected.
    """
    keys: set[str] = set()
    if node.label:
        keys.add(node.label.strip().lower())
    for attr_key in ("canonical_id", "stable_id", "source_id", "cost_center", "owner", "name"):
        val = node.attributes.get(attr_key)
        if isinstance(val, str) and val.strip():
            keys.add(val.strip().lower())
    keys.discard("")
    keys.discard("unknown")
    return keys


def _window_start(now: datetime) -> datetime:
    return now - timedelta(days=_WINDOW_DAYS)


def _parse_observed_at(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _is_high_risk(node: UnifiedNode) -> bool:
    """A node is high-risk if it is exposed, in a toxic combo, or critical.

    Reuses signals the CNAPP / attack-path overlays already wrote — cost fusion
    runs after them so it sees ``internet_exposed`` / ``toxic_*`` flags and the
    node's resolved severity / risk score.
    """
    attrs = node.attributes
    if attrs.get("internet_exposed"):
        return True
    if attrs.get("toxic_exposed_vulnerable") or attrs.get("toxic_exposed_sensitive"):
        return True
    if (node.severity or "").lower() == "critical":
        return True
    return node.risk_score >= 9.0


def apply_cost_overlay(
    graph: UnifiedGraph,
    cost_records: list[Any],
    now: datetime,
    *,
    high_cost_usd: float = _HIGH_COST_USD,
) -> dict[str, int]:
    """Attach spend to nodes, roll it up CONTAINS, and fuse cost × risk in place.

    Args:
        graph: the unified graph to enrich (mutated in place).
        cost_records: priced ``LLMCostRecord`` dataclasses (or dicts) the caller
            already loaded from the cost store. Never fetched here.
        now: the reference time for the rolling window (no inline ``datetime.now``).
        high_cost_usd: subtree-spend threshold for the high-cost fusion signal.

    Returns counts of nodes stamped, roll-up parents, and fused signals. A node
    receives spend only when a record names it; absence is a clean no-op.
    """
    if not cost_records:
        return {"cost_nodes": 0, "rollup_nodes": 0, "fused_signals": 0}

    window_start = _window_start(now)

    # ── 1. Aggregate records by every key they could match a node on ────────
    # total spend (all-time, within the supplied records) and the rolling
    # 30d window, summed per candidate key (agent name, cost_center, provider).
    total_by_key: dict[str, float] = defaultdict(float)
    window_by_key: dict[str, float] = defaultdict(float)
    calls_by_key: dict[str, int] = defaultdict(int)
    for record in cost_records:
        cost = _record_field(record, "cost_usd")
        cost_val = float(cost) if isinstance(cost, (int, float)) else 0.0
        observed = _parse_observed_at(_record_field(record, "observed_at"))
        in_window = observed is not None and observed >= window_start
        candidate_keys: set[str] = set()
        for field_name in ("agent", "cost_center", "provider"):
            val = _record_field(record, field_name)
            if isinstance(val, str) and val.strip():
                candidate_keys.add(val.strip().lower())
        for tag_val in _record_tags(record).values():
            if tag_val.strip():
                candidate_keys.add(tag_val.strip().lower())
        candidate_keys.discard("unknown")
        for key in candidate_keys:
            total_by_key[key] += cost_val
            calls_by_key[key] += 1
            if in_window:
                window_by_key[key] += cost_val

    # ── 2. Attach spend to the node each key names ──────────────────────────
    # Deterministic: iterate nodes in id order, take the highest-spend matching
    # key so a node tagged by both its name and a cost_center carries the larger
    # (parent) figure rather than an arbitrary one.
    own_cost: dict[str, float] = {}
    cost_nodes = 0
    for node_id in sorted(graph.nodes):
        node = graph.nodes[node_id]
        if node.entity_type not in _COST_BEARING_TYPES:
            continue
        match_keys = _node_match_keys(node) & total_by_key.keys()
        if not match_keys:
            continue
        best_key = max(sorted(match_keys), key=lambda k: total_by_key[k])
        total = round(total_by_key[best_key], 6)
        window = round(window_by_key.get(best_key, 0.0), 6)
        node.attributes["cost_usd"] = total
        node.attributes["cost_usd_30d"] = window
        node.attributes["cost_calls"] = calls_by_key[best_key]
        node.attributes["cost_match_key"] = best_key
        if _OVERLAY_SOURCE not in node.data_sources:
            node.data_sources.append(_OVERLAY_SOURCE)
        own_cost[node_id] = total
        cost_nodes += 1

    # ── 3. Roll up own cost along CONTAINS edges (subtree sums) ─────────────
    rollup_nodes = _roll_up_contains(graph, own_cost)

    # ── 4. Fuse cost × risk where a node is expensive AND high-risk ─────────
    fused_signals = _fuse_cost_risk(graph, own_cost, high_cost_usd)

    return {
        "cost_nodes": cost_nodes,
        "rollup_nodes": rollup_nodes,
        "fused_signals": fused_signals,
    }


def _roll_up_contains(graph: UnifiedGraph, own_cost: dict[str, float]) -> int:
    """Propagate ``own_cost`` upward along CONTAINS edges as ``subtree_cost_usd``.

    ``CONTAINS`` points parent → child (org CONTAINS account CONTAINS agent), so
    a node's subtree spend is its own spend plus the spend of everything it
    transitively contains. Computed with a memoised DFS that is cycle-safe
    (a node already on the stack contributes 0 on re-entry) and depth-bounded.
    Every node that ends up carrying spend gets ``subtree_cost_usd`` stamped;
    returns the number of such nodes.
    """
    # children[parent] = sorted list of nodes this node CONTAINS.
    children: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.relationship == RelationshipType.CONTAINS:
            children[edge.source].append(edge.target)
    for parent in children:
        children[parent] = sorted(set(children[parent]))

    def _subtree_cost(root: str) -> float:
        # Sum each DISTINCT descendant's own cost exactly once. A path/ancestor
        # set breaks cycles (a node already on the way down from ``root`` is not
        # re-counted) and the visited set dedupes shared children in a DAG, so
        # the sum is bounded by the total spend under ``root`` — never inflated
        # by cycles. Depth-guarded for pathological chains. Deterministic:
        # children are pre-sorted.
        total = 0.0
        visited: set[str] = set()
        stack: list[tuple[str, int]] = [(root, 0)]
        while stack:
            node_id, depth = stack.pop()
            if node_id in visited or depth > _MAX_ROLLUP_DEPTH:
                continue
            visited.add(node_id)
            total += own_cost.get(node_id, 0.0)
            for child_id in children.get(node_id, []):
                if child_id not in visited:
                    stack.append((child_id, depth + 1))
        return round(total, 6)

    rollup_nodes = 0
    # Deterministic order: every node that could carry subtree spend, sorted.
    relevant = sorted(set(children) | set(own_cost))
    for node_id in relevant:
        if node_id not in graph.nodes:
            continue
        total = _subtree_cost(node_id)
        if total <= 0.0:
            continue
        graph.nodes[node_id].attributes["subtree_cost_usd"] = total
        rollup_nodes += 1
    return rollup_nodes


def _fuse_cost_risk(graph: UnifiedGraph, own_cost: dict[str, float], high_cost_usd: float) -> int:
    """Flag nodes that are BOTH high-cost AND high-risk.

    Uses ``subtree_cost_usd`` when present (so an expensive subtree under a risky
    parent still fires) else the node's own spend. Sets ``cost_risk_priority``
    and appends one advisory ``InteractionRisk`` per fused node. Additive only:
    never lowers risk, deterministic over a sorted node order, and idempotent
    (the interaction-risk append is de-duplicated on the node label).
    """
    existing_fused = {risk.agents[0] for risk in graph.interaction_risks if risk.pattern == "expensive_and_exposed" and risk.agents}
    fused = 0
    for node_id in sorted(own_cost):
        node = graph.nodes.get(node_id)
        if node is None:
            continue
        spend = float(node.attributes.get("subtree_cost_usd", own_cost.get(node_id, 0.0)))
        if spend < high_cost_usd:
            continue
        if not _is_high_risk(node):
            continue
        # Idempotent: re-applying must not re-stamp or duplicate the advisory.
        already = node.attributes.get("cost_risk_priority") == "expensive_and_exposed"
        node.attributes["cost_risk_priority"] = "expensive_and_exposed"
        node.attributes["cost_risk_spend_usd"] = round(spend, 6)
        if already or node.label in existing_fused:
            continue
        graph.interaction_risks.append(
            InteractionRisk(
                pattern="expensive_and_exposed",
                agents=[node.label],
                risk_score=9.0,
                description=(
                    f"{node.label} carries ${round(spend, 2)} of LLM spend and is high-risk "
                    "(internet-exposed / toxic / critical) — prioritise: expensive AND exposed."
                ),
                owasp_agentic_tag=None,
            )
        )
        existing_fused.add(node.label)
        fused += 1
    return fused
