"""Align Finding.asset.asset_type with graph EntityType.

``Asset.asset_type`` has historically been a freeform convention string
(``mcp_server``, ``identity``, …). Graph nodes use the strict
:class:`~agent_bom.graph.types.EntityType` enum. This module is the single
normalization + mapping surface so findings, paths, and the investigation UI
share one vocabulary without inventing a separate info-id taxonomy.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.types import EntityType

# Freeform / legacy asset_type → canonical EntityType.
# Unknown values stay unmapped (None) rather than fabricating a type.
_ASSET_TYPE_ALIASES: dict[str, EntityType] = {
    # Direct EntityType values
    **{et.value: et for et in EntityType},
    # Finding / inventory conventions
    "mcp_server": EntityType.SERVER,
    "mcp_tool": EntityType.TOOL,
    "server": EntityType.SERVER,
    "agent": EntityType.AGENT,
    "package": EntityType.PACKAGE,
    "container": EntityType.CONTAINER,
    "cloud_resource": EntityType.CLOUD_RESOURCE,
    "resource": EntityType.RESOURCE,
    "file": EntityType.SOURCE_FILE,
    "source_file": EntityType.SOURCE_FILE,
    "iac_resource": EntityType.CLOUD_RESOURCE,
    "prompt_template": EntityType.CONFIG_FILE,
    "browser_extension": EntityType.CONFIG_FILE,
    "application": EntityType.APPLICATION,
    "data_store": EntityType.DATA_STORE,
    "dataset": EntityType.DATASET,
    "model": EntityType.MODEL,
    "framework": EntityType.FRAMEWORK,
    "credential": EntityType.CREDENTIAL,
    "vulnerability": EntityType.VULNERABILITY,
    "misconfiguration": EntityType.MISCONFIGURATION,
    # Identity aliases — "identity" was used by NHI findings; map to managed_identity
    # when the graph node is an agent-bom issued identity, else service_account.
    "identity": EntityType.MANAGED_IDENTITY,
    "managed_identity": EntityType.MANAGED_IDENTITY,
    "service_account": EntityType.SERVICE_ACCOUNT,
    "service_principal": EntityType.SERVICE_PRINCIPAL,
    "role": EntityType.ROLE,
    "user": EntityType.USER,
    "group": EntityType.GROUP,
    "policy": EntityType.POLICY,
    "federated_identity": EntityType.FEDERATED_IDENTITY,
}


def normalize_asset_type(raw: str | None) -> str:
    """Return a lowercase snake-ish asset type token, or empty string."""
    if raw is None:
        return ""
    text = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in text:
        text = text.replace("__", "_")
    return text


def entity_type_for_asset_type(raw: str | None) -> EntityType | None:
    """Map a Finding asset_type (or alias) to EntityType, or None if unknown."""
    key = normalize_asset_type(raw)
    if not key:
        return None
    return _ASSET_TYPE_ALIASES.get(key)


def canonical_asset_type(raw: str | None) -> str:
    """Prefer EntityType.value when known; otherwise return the normalized token."""
    et = entity_type_for_asset_type(raw)
    if et is not None:
        return et.value
    return normalize_asset_type(raw)


def finding_id_from_node_attributes(attrs: dict | None) -> str | None:
    """Extract a stable Finding.id from vuln/misconfig node attributes."""
    if not isinstance(attrs, dict):
        return None
    for key in ("finding_id", "canonical_finding_id", "unified_finding_id"):
        value = attrs.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def link_findings_to_graph_nodes(findings: list[Any], graph: Any) -> int:
    """Stamp Finding ↔ UnifiedNode FKs both ways. Returns number of findings linked.

    - Finding.finding_node_id ← vuln/misconfig node id when label/CVE matches
    - Finding.node_id ← package/server/identity neighbor via VULNERABLE_TO (or
      the identity node itself for NHI findings)
    - Node.attributes.finding_id ← Finding.id when missing

    Best-effort and idempotent; never raises into callers.
    """
    from agent_bom.graph.types import EntityType, RelationshipType

    nodes = getattr(graph, "nodes", None)
    if not isinstance(nodes, dict) or not findings:
        return 0

    finding_nodes: dict[str, Any] = {}
    for node in nodes.values():
        et = getattr(node, "entity_type", None)
        if et not in {EntityType.VULNERABILITY, EntityType.MISCONFIGURATION}:
            continue
        for key in filter(
            None,
            (
                getattr(node, "id", None),
                getattr(node, "label", None),
                (getattr(node, "attributes", None) or {}).get("vulnerability_id"),
            ),
        ):
            finding_nodes[str(key).lower()] = node

    linked = 0
    for finding in findings:
        fid = str(getattr(finding, "id", "") or "").strip()
        if not fid:
            continue
        cve = str(getattr(finding, "cve_id", None) or getattr(finding, "vulnerability_id", None) or "").strip()
        title = str(getattr(finding, "title", "") or "")
        candidates = [cve, fid]
        if cve:
            candidates.append(f"vuln:{cve}")
        if ":" in title:
            candidates.append(title.split(":", 1)[0].strip())

        match: Any | None = None
        for cand in candidates:
            if not cand:
                continue
            match = finding_nodes.get(cand.lower()) or finding_nodes.get(f"vuln:{cand}".lower())
            if match is not None:
                break
        # NHI / identity findings: match asset identifier to identity-ish nodes
        if match is None:
            asset = getattr(finding, "asset", None)
            identifier = str(getattr(asset, "identifier", None) or getattr(asset, "name", "") or "").strip()
            if identifier and identifier in nodes:
                if not getattr(finding, "node_id", None):
                    setattr(finding, "node_id", identifier)
                linked += 1
                continue

        if match is None:
            continue

        node_id = str(getattr(match, "id", "") or "")
        if node_id and not getattr(finding, "finding_node_id", None):
            setattr(finding, "finding_node_id", node_id)

        attrs = getattr(match, "attributes", None)
        if isinstance(attrs, dict) and not finding_id_from_node_attributes(attrs):
            attrs["finding_id"] = fid
            attrs["canonical_finding_id"] = str(getattr(finding, "canonical_id", None) or fid)

        if not getattr(finding, "node_id", None):
            # Prefer a VULNERABLE_TO predecessor (package/server) as the estate node.
            asset_node_id = None
            for edge in getattr(graph, "edges", []) or []:
                if getattr(edge, "target", None) != node_id:
                    continue
                rel = getattr(edge, "relationship", None)
                rel_val = getattr(rel, "value", rel)
                if rel_val != RelationshipType.VULNERABLE_TO.value:
                    continue
                src = getattr(edge, "source", None)
                if src and src in nodes:
                    asset_node_id = src
                    break
            if asset_node_id:
                setattr(finding, "node_id", asset_node_id)
        linked += 1
    return linked


def link_report_findings_to_graph(report_json: Any, graph: Any) -> int:
    """Stamp Finding ↔ node FKs onto ``graph`` from a serialized scan report.

    Used by the persist path so attack-path ``finding_ids`` resolve to stable
    Finding.id values even though the surfacing graph was thrown away earlier.
    Best-effort; never raises.
    """
    if not isinstance(report_json, dict):
        return 0
    rows = report_json.get("findings")
    if not isinstance(rows, list) or not rows:
        return 0
    try:
        from agent_bom.graph.toxic_findings import toxic_combination_findings_from_data

        findings = toxic_combination_findings_from_data([row for row in rows if isinstance(row, dict)])
        return link_findings_to_graph_nodes(findings, graph)
    except Exception:  # noqa: BLE001 — never fail persist on FK stamping
        return 0


__all__ = [
    "canonical_asset_type",
    "entity_type_for_asset_type",
    "finding_id_from_node_attributes",
    "link_findings_to_graph_nodes",
    "link_report_findings_to_graph",
    "normalize_asset_type",
]
