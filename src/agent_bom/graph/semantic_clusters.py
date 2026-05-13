"""Semantic graph clusters for API-backed graph readability."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.severity import SEVERITY_RANK
from agent_bom.graph.types import EntityType, RelationshipType

SEMANTIC_CLUSTER_KINDS = (
    "package_family",
    "cve_family",
    "agent_fleet",
    "server_fleet",
    "credential_family",
    "tool_capability",
    "source_environment",
)

_RISK_SEVERITY = (
    (90.0, "critical"),
    (70.0, "high"),
    (40.0, "medium"),
    (1.0, "low"),
)


@dataclass(slots=True)
class SemanticClusterExpansion:
    mode: str = "members"
    member_ids: list[str] = field(default_factory=list)
    collapse_id: str = ""
    reversible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "member_ids": self.member_ids,
            "collapse_id": self.collapse_id,
            "reversible": self.reversible,
        }


@dataclass(slots=True)
class SemanticCluster:
    id: str
    kind: str
    label: str
    layer: str
    entity_types: list[str]
    count: int
    member_ids: list[str]
    max_risk: float
    severity: str
    risk_summary: dict[str, int]
    relationship_counts: dict[str, int]
    expansion: SemanticClusterExpansion

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "layer": self.layer,
            "entity_types": self.entity_types,
            "count": self.count,
            "member_ids": self.member_ids,
            "max_risk": self.max_risk,
            "severity": self.severity,
            "risk_summary": self.risk_summary,
            "relationship_counts": self.relationship_counts,
            "expansion": self.expansion.to_dict(),
        }


def build_semantic_clusters(
    nodes: Iterable[UnifiedNode],
    edges: Iterable[UnifiedEdge],
    *,
    min_members: int = 2,
) -> list[SemanticCluster]:
    """Build reversible semantic clusters from canonical graph nodes.

    The output is intentionally UI-neutral: each cluster includes its members,
    risk rollup, relationship counts, and reversible expansion metadata. The
    dashboard can render these clusters without inferring families client-side.
    """

    node_list = list(nodes)
    edge_list = list(edges)
    groups: dict[tuple[str, str, str, str], list[UnifiedNode]] = defaultdict(list)
    for node in node_list:
        for kind, layer, key, label in _cluster_keys_for_node(node):
            groups[(kind, layer, key, label)].append(node)

    clusters: list[SemanticCluster] = []
    for (kind, layer, key, label), members in groups.items():
        if len(members) < min_members:
            continue
        member_ids = sorted(node.id for node in members)
        cluster_id = f"cluster:{kind}:{_slug(key)}"
        clusters.append(
            SemanticCluster(
                id=cluster_id,
                kind=kind,
                label=label,
                layer=layer,
                entity_types=sorted({_entity_value(node.entity_type) for node in members}),
                count=len(members),
                member_ids=member_ids,
                max_risk=_max_risk(members),
                severity=_cluster_severity(members),
                risk_summary=_risk_summary(members),
                relationship_counts=_relationship_counts(edge_list, set(member_ids)),
                expansion=SemanticClusterExpansion(member_ids=member_ids, collapse_id=cluster_id),
            )
        )

    return sorted(clusters, key=lambda cluster: (-cluster.max_risk, -cluster.count, cluster.kind, cluster.label))


def semantic_cluster_stats(clusters: Iterable[SemanticCluster]) -> dict[str, int]:
    cluster_list = list(clusters)
    member_ids = {member_id for cluster in cluster_list for member_id in cluster.member_ids}
    by_kind = Counter(cluster.kind for cluster in cluster_list)
    return {
        "cluster_count": len(cluster_list),
        "member_count": len(member_ids),
        **{f"{kind}_count": by_kind.get(kind, 0) for kind in SEMANTIC_CLUSTER_KINDS},
    }


def _cluster_keys_for_node(node: UnifiedNode) -> list[tuple[str, str, str, str]]:
    entity_type = _entity_value(node.entity_type)
    attrs = node.attributes or {}
    dims = node.dimensions
    keys: list[tuple[str, str, str, str]] = []

    environment = dims.environment or _string_attr(attrs, "environment", "env", "workspace", "account")
    source = node.data_sources[0] if node.data_sources else _string_attr(attrs, "source", "provider")
    if environment or source:
        env_key = environment or source
        source_part = f" / {source}" if source and source != env_key else ""
        keys.append(("source_environment", "infra", f"{env_key}:{source}", f"{env_key}{source_part}"))

    if entity_type == EntityType.PACKAGE.value:
        ecosystem = dims.ecosystem or _string_attr(attrs, "ecosystem", "package_ecosystem") or "unknown"
        package_name = _package_name(node)
        keys.append(("package_family", "package", f"{ecosystem}:{package_name}", f"{ecosystem} / {package_name}"))
    elif entity_type == EntityType.VULNERABILITY.value:
        cve_family = _cve_family(node)
        keys.append(("cve_family", "finding", cve_family, cve_family))
    elif entity_type == EntityType.AGENT.value:
        fleet = dims.agent_type or environment or source or _string_attr(attrs, "fleet", "agent_type", "kind") or "agents"
        keys.append(("agent_fleet", "orchestration", fleet, f"{fleet} agents"))
    elif entity_type == EntityType.SERVER.value:
        fleet = dims.surface or environment or source or _string_attr(attrs, "fleet", "server_type", "kind") or "servers"
        keys.append(("server_fleet", "mcp_server", fleet, f"{fleet} servers"))
    elif entity_type == EntityType.CREDENTIAL.value:
        family = _credential_family(node)
        keys.append(("credential_family", "identity", family, f"{family} credentials"))
    elif entity_type == EntityType.TOOL.value:
        capability = _string_attr(attrs, "capability", "category", "tool_type") or _tool_capability(node)
        keys.append(("tool_capability", "tool", capability, f"{capability} tools"))

    return keys


def _string_attr(attrs: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = attrs.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _package_name(node: UnifiedNode) -> str:
    attrs = node.attributes or {}
    raw = _string_attr(attrs, "name", "package_name", "package") or node.label or node.id
    if "@" in raw and not raw.startswith("@"):
        raw = raw.split("@", 1)[0]
    return raw.replace("pkg:", "").strip() or "unknown"


def _cve_family(node: UnifiedNode) -> str:
    raw = " ".join([node.id, node.label, *(str(value) for value in (node.attributes or {}).values() if isinstance(value, str))])
    match = re.search(r"CVE-(\d{4})-", raw, flags=re.IGNORECASE)
    if match:
        return f"CVE {match.group(1)}"
    cwe = re.search(r"CWE-(\d+)", raw, flags=re.IGNORECASE)
    if cwe:
        return f"CWE {cwe.group(1)}"
    return "unclassified findings"


def _credential_family(node: UnifiedNode) -> str:
    attrs = node.attributes or {}
    provider = _string_attr(attrs, "provider", "cloud_provider", "service")
    if provider:
        return provider
    label = (node.label or node.id).upper()
    for token in ("AWS", "AZURE", "GCP", "OPENAI", "ANTHROPIC", "GITHUB", "SNOWFLAKE"):
        if token in label:
            return token
    return "generic"


def _tool_capability(node: UnifiedNode) -> str:
    label = (node.label or node.id).lower()
    if any(token in label for token in ("shell", "exec", "command")):
        return "execution"
    if any(token in label for token in ("read", "file", "fs")):
        return "file access"
    if any(token in label for token in ("http", "fetch", "web")):
        return "network access"
    return "general"


def _risk_summary(nodes: Iterable[UnifiedNode]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for node in nodes:
        summary[_node_severity(node)] += 1
    return summary


def _cluster_severity(nodes: Iterable[UnifiedNode]) -> str:
    highest = "none"
    for node in nodes:
        severity = _node_severity(node)
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(highest, 0):
            highest = severity
    return highest


def _node_severity(node: UnifiedNode) -> str:
    severity = (node.severity or "").lower()
    if severity in {"critical", "high", "medium", "low"}:
        return severity
    risk = _node_risk_100(node)
    for threshold, level in _RISK_SEVERITY:
        if risk >= threshold:
            return level
    return "none"


def _max_risk(nodes: Iterable[UnifiedNode]) -> float:
    return max((_node_risk_100(node) for node in nodes), default=0.0)


def _node_risk_100(node: UnifiedNode) -> float:
    risk = float(node.risk_score or 0.0)
    if risk <= 10.0:
        risk *= 10.0
    if risk <= 0 and node.severity:
        risk = float(SEVERITY_RANK.get(node.severity.lower(), 0) * 20)
    return round(min(100.0, max(0.0, risk)), 3)


def _relationship_counts(edges: Iterable[UnifiedEdge], member_ids: set[str]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for edge in edges:
        if edge.source in member_ids or edge.target in member_ids:
            relationship = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
            counts[relationship] += 1
    return dict(sorted(counts.items()))


def _entity_value(entity_type: EntityType | str) -> str:
    return entity_type.value if isinstance(entity_type, EntityType) else str(entity_type)


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "unknown"
