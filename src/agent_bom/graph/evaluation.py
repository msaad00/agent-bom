"""Graph evaluation harness for scan fixtures and UI graph quality gates."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class ExpectedNode:
    """Node expected to appear in a graph."""

    id: str
    entity_type: str = ""
    label: str = ""


@dataclass(frozen=True, slots=True)
class ExpectedEdge:
    """Directed relationship expected to appear in a graph."""

    source: str
    target: str
    relationship: str


@dataclass(frozen=True, slots=True)
class ExpectedPath:
    """Ordered hop sequence expected to appear in attack-path output."""

    hops: tuple[str, ...]
    id: str = ""


@dataclass(frozen=True, slots=True)
class MetricScore:
    """Precision/recall score for one graph dimension."""

    expected: int
    actual: int
    matched: int
    precision: float
    recall: float
    f1: float
    missing: list[Any] = field(default_factory=list)
    unexpected: list[Any] = field(default_factory=list)

    @property
    def applicable(self) -> bool:
        return self.expected > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected": self.expected,
            "actual": self.actual,
            "matched": self.matched,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "missing": self.missing,
            "unexpected": self.unexpected,
        }


@dataclass(frozen=True, slots=True)
class GraphEvaluationResult:
    """Complete graph evaluation result."""

    name: str
    overall_score: float
    nodes: MetricScore
    edges: MetricScore
    paths: MetricScore
    evidence: dict[str, Any]
    readability: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "overall_score": round(self.overall_score, 4),
            "grade": graph_score_grade(self.overall_score),
            "scores": {
                "nodes": self.nodes.to_dict(),
                "edges": self.edges.to_dict(),
                "paths": self.paths.to_dict(),
            },
            "evidence": self.evidence,
            "readability": self.readability,
            "summary": {
                "expected_nodes": self.nodes.expected,
                "expected_edges": self.edges.expected,
                "expected_paths": self.paths.expected,
                "missing_total": len(self.nodes.missing) + len(self.edges.missing) + len(self.paths.missing),
                "unexpected_total": len(self.nodes.unexpected) + len(self.edges.unexpected) + len(self.paths.unexpected),
            },
        }


def graph_score_grade(score: float) -> str:
    """Return a compact grade for a 0..1 graph score."""

    if score >= 0.95:
        return "excellent"
    if score >= 0.85:
        return "strong"
    if score >= 0.70:
        return "usable"
    if score >= 0.50:
        return "weak"
    return "failing"


def load_expected_graph_spec(path: str | Path) -> dict[str, Any]:
    """Load an expected graph fixture from JSON."""

    try:
        data = json.loads(Path(path).read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid graph evaluation spec JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("graph evaluation spec must be a JSON object")
    return data


def evaluate_graph(actual_graph: Any, expected_spec: Mapping[str, Any]) -> GraphEvaluationResult:
    """Compare an actual graph to an expected graph fixture.

    The actual graph may be an API response dict, graph-export JSON dict, or
    an in-memory object with ``nodes`` / ``edges`` / optional ``attack_paths``
    attributes. Expected fixtures use:

    .. code-block:: json

      {
        "name": "demo MCP blast radius",
        "expected_nodes": ["agent:claude", {"id": "pkg:npm/next@16.2.6"}],
        "expected_edges": [{"source": "...", "target": "...", "relationship": "depends_on"}],
        "expected_paths": [{"hops": ["agent:claude", "server:fs", "pkg:npm/next@16.2.6"]}]
      }
    """

    actual = _ActualGraphIndex.from_graph(actual_graph)
    expected_nodes = {_node_key(node) for node in _parse_expected_nodes(expected_spec.get("expected_nodes", []))}
    expected_edges = {_edge_key(edge) for edge in _parse_expected_edges(expected_spec.get("expected_edges", []))}
    expected_paths = {_path_key(path) for path in _parse_expected_paths(expected_spec.get("expected_paths", []))}

    node_score = _score_sets(expected_nodes, actual.node_ids)
    edge_score = _score_sets(expected_edges, actual.edge_keys)
    path_score = _score_sets(expected_paths, actual.path_keys)

    applicable = [
        (node_score.recall, 0.30, node_score.applicable),
        (edge_score.recall, 0.40, edge_score.applicable),
        (path_score.recall, 0.30, path_score.applicable),
    ]
    weights = sum(weight for _score, weight, enabled in applicable if enabled)
    overall = sum(score * weight for score, weight, enabled in applicable if enabled) / weights if weights else 1.0

    return GraphEvaluationResult(
        name=str(expected_spec.get("name") or "graph-evaluation"),
        overall_score=overall,
        nodes=node_score,
        edges=edge_score,
        paths=path_score,
        evidence=actual.evidence_summary(),
        readability=actual.readability_summary(),
    )


def _parse_expected_nodes(items: Any) -> list[ExpectedNode]:
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise ValueError("expected_nodes must be an array")
    parsed: list[ExpectedNode] = []
    for item in items:
        if isinstance(item, str):
            parsed.append(ExpectedNode(id=item))
        elif isinstance(item, Mapping):
            node_id = str(item.get("id") or "").strip()
            if not node_id:
                raise ValueError("expected node is missing id")
            parsed.append(
                ExpectedNode(
                    id=node_id,
                    entity_type=str(item.get("entity_type") or item.get("kind") or ""),
                    label=str(item.get("label") or ""),
                )
            )
        else:
            raise ValueError("expected node entries must be strings or objects")
    return parsed


def _parse_expected_edges(items: Any) -> list[ExpectedEdge]:
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise ValueError("expected_edges must be an array")
    parsed: list[ExpectedEdge] = []
    for item in items:
        if isinstance(item, Mapping):
            source = str(item.get("source") or item.get("source_id") or "").strip()
            target = str(item.get("target") or item.get("target_id") or "").strip()
            relationship = str(item.get("relationship") or item.get("kind") or "").strip()
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)) and len(item) == 3:
            source, target, relationship = (str(value).strip() for value in item)
        else:
            raise ValueError("expected edge entries must be objects or [source, target, relationship]")
        if not source or not target or not relationship:
            raise ValueError("expected edge is missing source, target, or relationship")
        parsed.append(ExpectedEdge(source=source, target=target, relationship=relationship))
    return parsed


def _parse_expected_paths(items: Any) -> list[ExpectedPath]:
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise ValueError("expected_paths must be an array")
    parsed: list[ExpectedPath] = []
    for item in items:
        if isinstance(item, Mapping):
            hops = item.get("hops")
            path_id = str(item.get("id") or "")
        else:
            hops = item
            path_id = ""
        if not isinstance(hops, Sequence) or isinstance(hops, (str, bytes)) or len(hops) < 2:
            raise ValueError("expected path entries must include at least two hops")
        parsed.append(ExpectedPath(hops=tuple(str(hop).strip() for hop in hops), id=path_id))
    return parsed


def _node_key(node: ExpectedNode) -> str:
    return node.id


def _edge_key(edge: ExpectedEdge) -> tuple[str, str, str]:
    return (edge.source, edge.target, _normalize_relationship(edge.relationship))


def _path_key(path: ExpectedPath) -> tuple[str, ...]:
    return tuple(path.hops)


def _normalize_relationship(value: str) -> str:
    return value.strip().lower().replace(" ", "_")


def _score_sets(expected: set[Any], actual: set[Any]) -> MetricScore:
    matched = expected & actual
    missing = sorted(expected - actual, key=str)
    unexpected = sorted(actual - expected, key=str)
    precision = len(matched) / len(actual) if actual else (1.0 if not expected else 0.0)
    recall = len(matched) / len(expected) if expected else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return MetricScore(
        expected=len(expected),
        actual=len(actual),
        matched=len(matched),
        precision=precision,
        recall=recall,
        f1=f1,
        missing=missing,
        unexpected=unexpected[:50],
    )


@dataclass(frozen=True, slots=True)
class _ActualGraphIndex:
    node_ids: set[str]
    edge_keys: set[tuple[str, str, str]]
    path_keys: set[tuple[str, ...]]
    edge_evidence_count: int
    relationship_types: set[str]
    entity_types: set[str]
    node_count: int
    edge_count: int

    @classmethod
    def from_graph(cls, graph: Any) -> "_ActualGraphIndex":
        nodes = _read_sequence(graph, "nodes")
        edges = _read_sequence(graph, "edges")
        paths = _read_sequence(graph, "attack_paths")

        node_ids: set[str] = set()
        entity_types: set[str] = set()
        for node in nodes:
            node_id = _read_field(node, "id")
            if node_id:
                node_ids.add(node_id)
            entity_type = _read_field(node, "entity_type") or _read_field(node, "kind")
            if entity_type:
                entity_types.add(entity_type)

        edge_keys: set[tuple[str, str, str]] = set()
        relationship_types: set[str] = set()
        edge_evidence_count = 0
        for edge in edges:
            source = _read_field(edge, "source") or _read_field(edge, "source_id")
            target = _read_field(edge, "target") or _read_field(edge, "target_id")
            relationship = _read_field(edge, "relationship") or _read_field(edge, "kind")
            if source and target and relationship:
                normalized = _normalize_relationship(relationship)
                edge_keys.add((source, target, normalized))
                relationship_types.add(normalized)
            evidence = _read_mapping(edge, "evidence") or _read_mapping(edge, "provenance")
            if evidence:
                edge_evidence_count += 1

        path_keys: set[tuple[str, ...]] = set()
        for path in paths:
            hops = _read_raw(path, "hops")
            if isinstance(hops, Sequence) and not isinstance(hops, (str, bytes)) and len(hops) >= 2:
                path_keys.add(tuple(str(hop) for hop in hops))

        return cls(
            node_ids=node_ids,
            edge_keys=edge_keys,
            path_keys=path_keys,
            edge_evidence_count=edge_evidence_count,
            relationship_types=relationship_types,
            entity_types=entity_types,
            node_count=len(nodes),
            edge_count=len(edges),
        )

    def evidence_summary(self) -> dict[str, Any]:
        ratio = self.edge_evidence_count / self.edge_count if self.edge_count else 0.0
        return {
            "edge_evidence_count": self.edge_evidence_count,
            "edge_evidence_ratio": round(ratio, 4),
        }

    def readability_summary(self) -> dict[str, Any]:
        density = self.edge_count / self.node_count if self.node_count else 0.0
        warnings: list[str] = []
        if self.node_count == 0:
            warnings.append("graph has no nodes")
        if self.node_count > 0 and self.edge_count == 0:
            warnings.append("graph has nodes but no relationships")
        if self.node_count >= 50 and len(self.relationship_types) < 3:
            warnings.append("large graph has low relationship diversity")
        if density > 6:
            warnings.append("graph is dense; use filtering or path focus for readability")
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "edge_to_node_ratio": round(density, 4),
            "entity_type_count": len(self.entity_types),
            "relationship_type_count": len(self.relationship_types),
            "warnings": warnings,
        }


def _read_sequence(graph: Any, key: str) -> list[Any]:
    value = _read_raw(graph, key)
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return list(value)
    return []


def _read_mapping(item: Any, key: str) -> Mapping[str, Any]:
    value = _read_raw(item, key)
    return value if isinstance(value, Mapping) else {}


def _read_field(item: Any, key: str) -> str:
    value = _read_raw(item, key)
    if value is None:
        return ""
    raw_value = getattr(value, "value", value)
    return str(raw_value).strip()


def _read_raw(item: Any, key: str) -> Any:
    if isinstance(item, Mapping):
        return item.get(key)
    return getattr(item, key, None)
