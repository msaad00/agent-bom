"""Runtime evidence overlay for unified security graphs (#3610).

Annotates nodes with ``evidence_tier`` per
``docs/graph/SECURITY_GRAPH_UX_RUBRIC.md``:

* ``static_scan`` — inferred from inventory / blast radius only
* ``runtime_observed`` — authorized or observed runtime path
* ``runtime_blocked`` — enforcement blocked a matching path
* ``replay_only`` — synthetic / demo replay surfaces (caller-supplied)
"""

from __future__ import annotations

from typing import Any, Mapping

_EVIDENCE_STATIC = "static_scan"
_EVIDENCE_OBSERVED = "runtime_observed"
_EVIDENCE_BLOCKED = "runtime_blocked"
_EVIDENCE_REPLAY = "replay_only"

_RANK = {
    _EVIDENCE_STATIC: 0,
    _EVIDENCE_OBSERVED: 1,
    _EVIDENCE_BLOCKED: 2,
    _EVIDENCE_REPLAY: 3,
}


def _raise_tier(current: str | None, candidate: str) -> str:
    if not current:
        return candidate
    if _RANK.get(candidate, 0) > _RANK.get(current, 0):
        return candidate
    return current


def apply_runtime_evidence_overlay(graph: Any, report_json: Mapping[str, Any] | None = None) -> None:
    """Mutate ``graph`` nodes in-place with ``evidence_tier`` attributes."""
    if graph is None:
        return

    for node in graph.nodes.values():
        attrs = node.attributes
        tier = _EVIDENCE_STATIC
        if attrs.get("observed") or any(key.startswith("observed_") for key in attrs):
            tier = _EVIDENCE_OBSERVED
        if attrs.get("source") == "runtime-feedback" or "runtime-feedback" in (node.data_sources or []):
            tier = _EVIDENCE_OBSERVED
        if attrs.get("replay_only") or attrs.get("demo_replay"):
            tier = _EVIDENCE_REPLAY
        attrs["evidence_tier"] = tier

    for edge in graph.edges:
        evidence = edge.evidence if isinstance(edge.evidence, dict) else {}
        if evidence.get("source") == "runtime-feedback":
            _tag_node(graph, edge.source, _EVIDENCE_OBSERVED)
            _tag_node(graph, edge.target, _EVIDENCE_OBSERVED)
        if str(evidence.get("incident_kind") or "") == "kill_switch":
            _tag_node(graph, edge.source, _EVIDENCE_BLOCKED)
            _tag_node(graph, edge.target, _EVIDENCE_BLOCKED)

    if report_json:
        _apply_proxy_blocks_from_report(graph, report_json)


def _tag_node(graph: Any, node_id: str, tier: str) -> None:
    node = graph.get_node(node_id) if hasattr(graph, "get_node") else graph.nodes.get(node_id)
    if node is None:
        return
    node.attributes["evidence_tier"] = _raise_tier(node.attributes.get("evidence_tier"), tier)


def _apply_proxy_blocks_from_report(graph: Any, report_json: Mapping[str, Any]) -> None:
    """Promote nodes to ``runtime_blocked`` when report carries blocked tool events."""
    events = report_json.get("runtime_enforcement_events")
    if not isinstance(events, list):
        return
    for raw in events:
        if not isinstance(raw, Mapping):
            continue
        if str(raw.get("state") or "") != "blocked":
            continue
        tool = str(raw.get("tool") or "").strip().lower()
        agent = str(raw.get("agent") or "").strip().lower()
        if agent:
            for node_id, node in graph.nodes.items():
                if node.entity_type.value == "agent" and str(node.label).strip().lower() == agent:
                    _tag_node(graph, node_id, _EVIDENCE_BLOCKED)
        if tool:
            for node_id, node in graph.nodes.items():
                if node.entity_type.value == "tool" and str(node.label).strip().lower() == tool:
                    _tag_node(graph, node_id, _EVIDENCE_BLOCKED)


__all__ = ["apply_runtime_evidence_overlay"]
