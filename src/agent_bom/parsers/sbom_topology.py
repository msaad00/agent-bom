"""Restore declared agent/server membership without executing imported commands."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any, cast

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, ServerSurface
from agent_bom.parsers.spdx_context import context_document
from agent_bom.sbom_formats.cyclonedx import component_properties, dependency_map, restore_dependency_hierarchy, software_components
from agent_bom.sbom_formats.spdx_hierarchy import restore_spdx_hierarchy


def _server_members(component: dict, edges: dict[str, set[str]], packages: dict[str, Package]) -> set[str]:
    declared = component_properties(component).get("agent-bom:inventory-members")
    if declared is not None:
        try:
            members = json.loads(declared)
        except ValueError as exc:
            raise ValueError("Invalid SBOM inventory membership") from exc
        if not isinstance(members, list) or any(not isinstance(ref, str) or ref not in packages for ref in members):
            raise ValueError("SBOM inventory membership references unknown packages")
        return set(members)
    # Older exports have dependency edges but no explicit containment for orphans.
    seen: set[str] = set()
    pending = list(edges.get(component["bom-ref"], ()))
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        seen.add(ref)
        pending.extend(edges.get(ref, ()))
    return seen & packages.keys()


def _restore_scoped_hierarchy(document: dict, spdx_document: dict | None, ref: str, scoped_packages: dict[str, Package]) -> None:
    scoped_document = {**document, "metadata": {"component": {"bom-ref": ref}}}
    if spdx_document is None:
        restore_dependency_hierarchy(scoped_document, scoped_packages)
    else:
        source = dict(spdx_document)
        if "@graph" in source:
            source["elements"] = source["@graph"]
        restore_spdx_hierarchy(source, scoped_packages, root_refs={ref})


def restore_context_agents(document: dict, fallback: Agent, name: str | None) -> list[Agent]:
    spdx_document = document if document.get("bomFormat") != "CycloneDX" else None
    if spdx_document is not None:
        document = context_document(spdx_document)
    components = {c["bom-ref"]: c for c in software_components(document) if isinstance(c, dict) and isinstance(c.get("bom-ref"), str)}
    agent_refs = {ref for ref, c in components.items() if component_properties(c).get("agent-bom:type") == "ai-agent"}
    server_refs = {ref for ref, c in components.items() if component_properties(c).get("agent-bom:type") == "mcp-server"}
    if not agent_refs or not server_refs:
        return [fallback]
    packages = {
        str(e["bom_ref"]): p
        for s in fallback.mcp_servers
        for p in s.packages
        for e in p.version_evidence
        if e.get("type") == "sbom" and e.get("bom_ref")
    }
    edges = dependency_map(document)
    servers: dict[str, MCPServer] = {}
    assigned: set[str] = set()
    for ref in sorted(server_refs):
        component = components[ref]
        members = _server_members(component, edges, packages)
        assigned.update(members)
        scoped_packages = {p: deepcopy(packages[p]) for p in sorted(members)}
        _restore_scoped_hierarchy(document, spdx_document, ref, scoped_packages)
        tools = []
        for prop in component.get("properties", []):
            if isinstance(prop, dict) and prop.get("name") == "agent-bom:mcp-tool" and isinstance(prop.get("value"), str):
                tool_name, _, description = prop["value"].partition(": ")
                tools.append(MCPTool(name=tool_name, description=description, discovery_source="sbom", discovery_confidence="declared"))
        servers[ref] = MCPServer(
            name=str(component.get("name") or ref),
            command="sbom",
            # Never execute imported commands; hash the case-sensitive reference.
            args=[fallback.config_path, "component:" + hashlib.sha256(ref.encode()).hexdigest()],
            surface=ServerSurface.SBOM,
            imported_canonical_id=ref.removeprefix("mcp-server-") if ref.startswith("mcp-server-") else None,
            packages=list(scoped_packages.values()),
            tools=tools,
        )
    agents = []
    used_servers: set[str] = set()
    for ref in sorted(agent_refs):
        members = edges.get(ref, set()) & server_refs
        used_servers.update(members)
        provenance = deepcopy(fallback.metadata)
        imported = cast(dict[str, Any], provenance["sbom_import"])
        imported["cloud_inventory"] = None
        imported["component_ref"] = ref
        label = str(components[ref].get("name") or ref)
        agents.append(
            Agent(
                name=f"sbom:{name + '/' if name else ''}{label}",
                agent_type=AgentType.CUSTOM,
                config_path=fallback.config_path,
                source="sbom",
                mcp_servers=[servers[s] for s in sorted(members)],
                metadata=provenance,
            )
        )
    fallback_import = cast(dict[str, Any], fallback.metadata["sbom_import"])
    unassigned = set(packages) - assigned
    detached = server_refs - used_servers
    if unassigned or detached:
        fallback.mcp_servers = [servers[s] for s in sorted(detached)]
        if unassigned:
            fallback.mcp_servers.append(
                MCPServer(
                    name="unassigned SBOM inventory",
                    command="sbom",
                    surface=ServerSurface.SBOM,
                    packages=[packages[p] for p in sorted(unassigned)],
                )
            )
        fallback_import["composition_complete"] = False
        agents.append(fallback)
    cast(dict[str, Any], agents[0].metadata["sbom_import"])["cloud_inventory"] = fallback_import.get("cloud_inventory")
    if agents[-1] is fallback and len(agents) > 1:
        fallback_import["cloud_inventory"] = None
    return agents
