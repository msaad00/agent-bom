"""Pure presentation of recorded graph paths, findings, assets and identities.

No store access, request authentication, traversal admission or mutation.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.exposure import _exposure_path_for_attack_path, _finding_ids_for_nodes
from agent_bom.graph.path_derivation import _build_edge_lookup, _edge_relationships_for_hops, _EdgeLookup, _fusion_signals_for_path
from agent_bom.graph.types import EntityType


def _node_labels_for_types(graph: UnifiedGraph, path_hops: list[str], entity_types: set[EntityType]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for hop in path_hops:
        node = graph.nodes.get(hop)
        if not node or node.entity_type not in entity_types:
            continue
        label = node.label or node.id
        key = label.lower()
        if key in seen:
            continue
        labels.append(label)
        seen.add(key)
    return labels


def _finding_ids_for_path(graph: UnifiedGraph, path_hops: list[str], vuln_ids: list[str]) -> list[str]:
    return _finding_ids_for_nodes(graph.nodes, path_hops, vuln_ids)


def _finding_labels_for_path(graph: UnifiedGraph, path_hops: list[str], vuln_ids: list[str]) -> list[str]:
    """Return operator-readable advisory/node labels, never canonical UUIDs."""
    from agent_bom.graph.asset_entity import finding_id_from_node_attributes

    labels: list[str] = []
    seen: set[str] = set()

    def add(value: object) -> None:
        text = str(value or "").strip()
        if not text or text.lower() in seen:
            return
        labels.append(text)
        seen.add(text.lower())

    for hop in path_hops:
        node = graph.nodes.get(hop)
        if not node or node.entity_type not in {EntityType.VULNERABILITY, EntityType.MISCONFIGURATION}:
            continue
        attrs = node.attributes if isinstance(node.attributes, dict) else {}
        canonical = finding_id_from_node_attributes(attrs)
        for key in ("cve_id", "vulnerability_id", "advisory_id", "rule_id", "title"):
            if attrs.get(key):
                add(attrs[key])
                break
        else:
            if node.label and node.label != canonical:
                add(node.label)
    for value in vuln_ids:
        if value and value not in _finding_ids_for_nodes(graph.nodes, path_hops, []):
            add(value)
    return labels


def _identity_finding_ids_for_path(graph: UnifiedGraph, path: AttackPath) -> list[str]:
    """Canonical occurrence identities scoped to assets on the path."""
    from agent_bom.graph.asset_entity import finding_ids_for_asset_path

    stamped = [
        finding_id
        for hop in path.hops
        if (node := graph.nodes.get(hop)) is not None
        for finding_id in finding_ids_for_asset_path(node.attributes, path.hops)
    ]
    candidates = stamped or list(path.finding_ids) or _finding_ids_for_path(graph, path.hops, path.vuln_ids)
    return list(dict.fromkeys(value for value in candidates if value))


def _node_ids_for_types(graph: UnifiedGraph, path_hops: list[str], entity_types: set[EntityType]) -> list[str]:
    return sorted({hop for hop in path_hops if (node := graph.nodes.get(hop)) is not None and node.entity_type in entity_types})


def _path_identity(path: AttackPath) -> str:
    return f"{path.source}::{path.target}::{'->'.join(path.hops)}"


def _path_semantic_key(graph: UnifiedGraph, path: AttackPath) -> str:
    """Stable presentation identity; asset/agent dimensions prevent over-collapse."""
    findings = sorted(label.lower() for label in _finding_labels_for_path(graph, path.hops, path.vuln_ids))
    if not findings:
        findings = sorted(_identity_finding_ids_for_path(graph, path)) or [path.target]
    agents = _node_ids_for_types(
        graph,
        path.hops,
        {EntityType.AGENT, EntityType.USER, EntityType.GROUP, EntityType.SERVICE_ACCOUNT},
    ) or [path.source]
    packages = _node_ids_for_types(graph, path.hops, {EntityType.PACKAGE})
    assets = _node_ids_for_types(graph, path.hops, {EntityType.SERVER, EntityType.CONTAINER, EntityType.CLOUD_RESOURCE})
    parts = (
        ("finding", findings),
        ("agent", agents),
        ("package", packages),
        ("asset", assets),
    )
    return "&".join(f"{name}={quote(','.join(values), safe='')}" for name, values in parts)


def _first_href_for_agent(agent: str) -> str:
    return f"/agents?name={quote(agent)}"


def _risk_reasons_for_path(graph: UnifiedGraph, path: AttackPath) -> list[dict[str, str]]:
    reasons: list[dict[str, str]] = []
    for kind, label, detail, _boost in _fusion_signals_for_path(graph, path.hops):
        reasons.append({"kind": kind, "label": label, "detail": detail})
    if path.composite_risk >= 90:
        reasons.append(
            {
                "kind": "critical_reach",
                "label": "Critical reach",
                "detail": "Composite risk is at or above the release-blocking threshold.",
            }
        )
    elif path.composite_risk >= 70:
        reasons.append(
            {
                "kind": "high_reach",
                "label": "High reach",
                "detail": "Composite risk is high enough to prioritize before broad topology review.",
            }
        )
    if path.credential_exposure:
        reasons.append(
            {
                "kind": "credential_exposure",
                "label": "Credential exposure",
                "detail": f"{len(path.credential_exposure)} credential signal(s) sit on this path.",
            }
        )
    if path.tool_exposure:
        dangerous_tools = [
            tool
            for tool in path.tool_exposure
            if any(keyword in tool.lower() for keyword in ("shell", "exec", "run", "command", "subprocess", "filesystem"))
        ]
        reasons.append(
            {
                "kind": "tool_reach",
                "label": "Tool reach",
                "detail": (
                    f"{len(dangerous_tools)} execution/file-capable tool(s) are reachable."
                    if dangerous_tools
                    else f"{len(path.tool_exposure)} tool(s) are reachable from the affected agent/server."
                ),
            }
        )
    finding_ids = _finding_ids_for_path(graph, path.hops, path.vuln_ids)
    if finding_ids:
        reasons.append(
            {
                "kind": "finding",
                "label": "Finding in chain",
                "detail": f"{len(finding_ids)} vulnerability or misconfiguration finding(s) anchor this path.",
            }
        )
    if not reasons:
        reasons.append(
            {
                "kind": "topology",
                "label": "Connected exposure",
                "detail": "The graph found a connected exposure path that should be reviewed before full expansion.",
            }
        )
    return reasons[:4]


def _next_actions_for_path(
    graph: UnifiedGraph,
    path: AttackPath,
    *,
    finding_ids: list[str] | None = None,
) -> list[dict[str, str]]:
    findings = finding_ids if finding_ids is not None else _identity_finding_ids_for_path(graph, path)
    agents = _node_labels_for_types(
        graph,
        path.hops,
        {EntityType.AGENT, EntityType.USER, EntityType.GROUP, EntityType.SERVICE_ACCOUNT},
    )
    actions: list[dict[str, str]] = []
    if findings:
        finding_href = (
            f"/findings?cve={quote(findings[0])}"
            if findings[0].upper().startswith(("CVE-", "GHSA-"))
            else f"/findings?finding={quote(findings[0])}"
        )
        actions.append(
            {
                "title": "Validate lead finding",
                "detail": "Open the first finding and confirm the root cause before expanding the graph.",
                "href": finding_href,
            }
        )
    if agents:
        actions.append(
            {
                "title": "Inspect exposed identity",
                "detail": "Review the agent, user, or service account that can trigger this path.",
                "href": _first_href_for_agent(agents[0]),
            }
        )
    if path.credential_exposure:
        actions.append(
            {
                "title": "Contain credentials",
                "detail": "Rotate, scope, or remove exposed credentials before widening blast-radius analysis.",
                "href": "/mesh",
            }
        )
    elif path.tool_exposure:
        actions.append(
            {
                "title": "Review reachable tools",
                "detail": "Check whether the tool permissions turn this finding into a real incident path.",
                "href": "/mesh",
            }
        )
    actions.append(
        {
            "title": "Expand topology",
            "detail": "Open the full lineage graph only when neighboring context is needed.",
            "href": "/graph",
        }
    )
    return actions[:4]


def _fix_first_card_for_path(
    graph: UnifiedGraph,
    path: AttackPath,
    rank: int,
    *,
    edge_lookup: _EdgeLookup | None = None,
    occurrence_paths: list[AttackPath] | None = None,
) -> dict:
    grouped_paths = occurrence_paths or [path]
    findings = list(dict.fromkeys(finding for item in grouped_paths for finding in _identity_finding_ids_for_path(graph, item)))
    finding_labels = list(
        dict.fromkeys(label for item in grouped_paths for label in _finding_labels_for_path(graph, item.hops, item.vuln_ids))
    )
    occurrence_path_ids = list(dict.fromkeys(_path_identity(item) for item in grouped_paths))
    agents = _node_labels_for_types(
        graph,
        path.hops,
        {EntityType.AGENT, EntityType.USER, EntityType.GROUP, EntityType.SERVICE_ACCOUNT},
    )
    servers = _node_labels_for_types(graph, path.hops, {EntityType.SERVER, EntityType.CONTAINER, EntityType.CLOUD_RESOURCE})
    packages = _node_labels_for_types(graph, path.hops, {EntityType.PACKAGE})
    sequence = [graph.nodes[hop].label for hop in path.hops if hop in graph.nodes]
    target_node = graph.nodes.get(path.target)
    display_finding = finding_labels[0] if finding_labels else target_node.label if target_node and target_node.label else "Exposure path"
    title_parts = [display_finding]
    if agents:
        title_parts.append(f"via {agents[0]}")
    if path.tool_exposure:
        title_parts.append(f"with {path.tool_exposure[0]}")
    return {
        "id": _path_identity(path),
        "semantic_key": _path_semantic_key(graph, path),
        "occurrence_count": len(grouped_paths),
        "occurrence_path_ids": occurrence_path_ids,
        "rank": rank,
        "title": " ".join(title_parts),
        "summary": path.summary or "Review this path before opening the full topology graph.",
        "attack_path": path.to_dict(),
        "exposure_path": _exposure_path_for_attack_path(
            path,
            nodes_by_id=graph.nodes,
            edges=graph.edges,
            rank=rank,
            scan_id=graph.scan_id,
            edge_lookup=edge_lookup,
        ),
        "nodes": [graph.nodes[hop].to_dict() for hop in path.hops if hop in graph.nodes],
        "sequence_labels": sequence,
        "risk_reasons": _risk_reasons_for_path(graph, path),
        "next_actions": _next_actions_for_path(graph, path, finding_ids=findings),
        "affected": {
            "agents": agents,
            "servers": servers,
            "packages": packages,
            "findings": findings,
            "finding_labels": finding_labels,
            "credentials": list(path.credential_exposure),
            "tools": list(path.tool_exposure),
        },
    }


def _path_matches_focus(graph: UnifiedGraph, path: AttackPath, *, cve: str, package: str, agent: str) -> bool:
    def norm(value: str) -> str:
        return value.strip().lower()

    cve_n = norm(cve)
    package_n = norm(package)
    agent_n = norm(agent)
    if not cve_n and not package_n and not agent_n:
        return True
    labels = {norm(graph.nodes[hop].label) for hop in path.hops if hop in graph.nodes}
    finding_ids = {norm(value) for value in _finding_ids_for_path(graph, path.hops, path.vuln_ids)}
    if cve_n and cve_n not in labels and cve_n not in finding_ids:
        return False
    if package_n:
        package_labels = {norm(label) for label in _node_labels_for_types(graph, path.hops, {EntityType.PACKAGE})}
        # Finding links carry the package name while graph labels may include
        # its version. Match either exactly; retain npm scopes and never widen
        # an explicitly versioned selector to a different package version.
        package_names = {label[: label.rfind("@")] if label.rfind("@") > 0 else label for label in package_labels}
        if package_n not in package_labels and package_n not in package_names:
            return False
    if agent_n:
        agent_selectors: set[str] = set()
        for hop in path.hops:
            node = graph.nodes.get(hop)
            if node is None or node.entity_type not in {EntityType.AGENT, EntityType.USER, EntityType.GROUP, EntityType.SERVICE_ACCOUNT}:
                continue
            agent_selectors.update((norm(node.id), norm(node.label)))
            # Local agent links carry the name used by the canonical agent:<name>
            # ID. Never strip arbitrary cloud/source prefixes or match substrings.
            if node.entity_type == EntityType.AGENT and node.id.startswith("agent:"):
                agent_selectors.add(norm(node.id.removeprefix("agent:")))
        if agent_n not in agent_selectors:
            return False
    return True


def _serialize_attack_path(
    path: AttackPath,
    edges: list[UnifiedEdge] | None = None,
    *,
    nodes_by_id: dict[str, Any] | None = None,
    rank: int | None = None,
    scan_id: str = "",
    edge_lookup: _EdgeLookup | None = None,
) -> dict:
    data = path.to_dict()
    if edges is not None:
        from agent_bom.graph.attack_path_mitre import derive_attack_path_techniques

        # Re-derive the projection from bounded matching topology. Historical
        # receipt objects stay intact; old serialized mappings cannot supply
        # evidence for an absent, reversed, or non-traversable relationship.
        by_pair = edge_lookup if edge_lookup is not None else _build_edge_lookup(edges)
        proof_graph = UnifiedGraph()
        for hop in path.hops:
            node = (nodes_by_id or {}).get(hop)
            if node is not None:
                proof_graph.add_node(node)
        for index, (source, target) in enumerate(zip(path.hops, path.hops[1:], strict=False)):
            if index < len(path.edges):
                edge = by_pair.get((source, target, path.edges[index]))
                if edge is not None:
                    proof_graph.add_edge(edge)
        mappings = derive_attack_path_techniques(path, proof_graph)
        data["technique_mappings"] = [mapping.to_dict() for mapping in mappings]
        data["mitre_technique_ids"] = sorted({mapping.technique_id for mapping in mappings})
    if not data.get("edges") and edges is not None:
        data["edges"] = _edge_relationships_for_hops(path.hops, edges, edge_lookup=edge_lookup)
    if nodes_by_id is not None:
        # Prefer stamped Finding.id values over CVE labels when available.
        resolved = _finding_ids_for_nodes(nodes_by_id, path.hops, path.vuln_ids)
        if resolved:
            data["finding_ids"] = resolved
        data["exposure_path"] = _exposure_path_for_attack_path(
            path,
            nodes_by_id=nodes_by_id,
            edges=edges,
            rank=rank,
            scan_id=scan_id,
            edge_lookup=edge_lookup,
        )
        if data.get("reachability") == "confirmed" and data["exposure_path"]["reachability"] != "confirmed":
            data["reachability"] = data["exposure_path"]["reachability"]
            data["reachability_basis"] = list(data["exposure_path"]["reachabilityBasis"])
    return data


def _serialize_attack_path_batch(
    paths: list[AttackPath],
    edges: list[UnifiedEdge] | None = None,
    *,
    nodes_by_id: dict[str, Any] | None = None,
    scan_id: str = "",
    rank_offset: int | None = None,
) -> list[dict[str, Any]]:
    """Serialize a page of paths with one topology index shared by every row."""
    edge_lookup = _build_edge_lookup(edges)
    return [
        _serialize_attack_path(
            path,
            edges,
            nodes_by_id=nodes_by_id,
            rank=(rank_offset + index + 1) if rank_offset is not None else None,
            scan_id=scan_id,
            edge_lookup=edge_lookup,
        )
        for index, path in enumerate(paths)
    ]
