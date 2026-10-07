"""Adapt explicitly declared SPDX agent/server contexts for topology restoration."""

from __future__ import annotations

from collections import defaultdict

from agent_bom.sbom_formats.spdx_hierarchy import dependency_relationships


def context_document(document: dict) -> dict:
    """Keep software identities and supplied edges; never infer executable commands."""
    rows = document.get("@graph", document.get("elements", document.get("packages", [])))
    edges: dict[str, set[str]] = defaultdict(set)
    containment: dict[str, set[str]] = defaultdict(set)
    for row in [*rows, *document.get("relationships", [])]:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("relationshipType", "")).replace("_", "").lower()
        if kind not in {"contain", "contains", "dependson", "dependencyof"}:
            continue
        source = row.get("from", row.get("spdxElementId"))
        targets = row.get("to", row.get("relatedSpdxElement", []))
        targets = [targets] if isinstance(targets, str) else targets
        if not isinstance(source, str) or not isinstance(targets, list):
            continue
        for target in targets:
            if isinstance(target, str):
                parent, child = (target, source) if kind == "dependencyof" else (source, target)
                edges[parent].add(child)
                if kind in {"contain", "contains"}:
                    containment[parent].add(child)
    for source, target, _scope in dependency_relationships(document):
        edges[source].add(target)
    components = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ref = row.get("SPDXID", row.get("spdxId"))
        if not isinstance(ref, str) or not row.get("name"):
            continue
        properties = []
        purpose = str(row.get("primaryPackagePurpose", row.get("software_primaryPurpose", ""))).lower()
        description = str(row.get("description", row.get("comment", "")))
        if purpose == "application":
            if description.startswith("AI Agent ("):
                properties.append({"name": "agent-bom:type", "value": "ai-agent"})
            elif description.startswith("MCP Server ("):
                properties.append({"name": "agent-bom:type", "value": "mcp-server"})
        components.append(
            {
                "bom-ref": ref,
                "name": row["name"],
                "type": "application" if purpose == "application" else "library",
                "properties": properties,
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "components": components,
        "dependencies": [{"ref": parent, "dependsOn": sorted(children)} for parent, children in edges.items()],
    }
