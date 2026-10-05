"""Resolve recorded package parents within one observed server inventory."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from agent_bom.core.packages import normalize_package_ecosystem, normalize_package_name
from agent_bom.models import Package


def package_dependency_edges(packages: list[Package]) -> tuple[list[tuple[str, str]], set[str]]:
    """Return canonical parent/child IDs and unresolved transitive IDs.

    Parent names carry no version constraint. Link only one distinct matching
    identity in the same ecosystem and server; never pick an arbitrary version
    or borrow a package from another agent/environment. Duplicate observations
    of the same canonical package are not ambiguous.
    """
    candidates: dict[tuple[str, str], set[str]] = defaultdict(set)
    for package in packages:
        ecosystem = normalize_package_ecosystem(package.ecosystem)
        candidates[ecosystem, normalize_package_name(package.name, ecosystem)].add(package.stable_id)
    edges: set[tuple[str, str]] = set()
    unresolved: set[str] = set()
    inventory_ids = {package.stable_id for package in packages}
    for package in packages:
        declared = [e.get("parent_stable_ids") for e in package.version_evidence if e.get("type") == "sbom" and "parent_stable_ids" in e]
        if declared:
            parents = {ref for refs in declared if isinstance(refs, list) for ref in refs if isinstance(ref, str)}
            edges.update((ref, package.stable_id) for ref in parents & inventory_ids if ref != package.stable_id)
            if parents - inventory_ids or (not parents and not package.is_direct):
                unresolved.add(package.stable_id)
            continue
        if package.is_direct:
            continue
        ecosystem = normalize_package_ecosystem(package.ecosystem)
        parents = candidates.get((ecosystem, normalize_package_name(package.parent_package or "", ecosystem)), set())
        if len(parents) != 1 or package.stable_id in parents:
            unresolved.add(package.stable_id)
        else:
            edges.add((next(iter(parents)), package.stable_id))
    return sorted(edges), unresolved


def cyclonedx_compositions(components: list[dict], *, incomplete: bool) -> list[dict]:
    """Declare unresolved lineage or registry-derived inventory incomplete."""
    if not components:
        return []
    registry_resolved = any(
        component.get("type") == "library"
        and any(
            prop.get("name") == "agent-bom:resolved-from-registry" and prop.get("value") == "true"
            for prop in component.get("properties", [])
        )
        for component in components
    )
    return [
        {
            "aggregate": "incomplete" if registry_resolved or incomplete else "complete",
            "assemblies": [component["bom-ref"] for component in components if "bom-ref" in component],
        }
    ]


def spdx3_package_relationships(
    packages: list[Package],
    refs: dict[str, str],
    server_id: str,
    next_id: Callable[[str], str],
    annotate: Callable[[str, str], None],
) -> list[dict[str, Any]]:
    """Preserve inventory membership separately from direct dependency edges."""
    edges, unresolved = package_dependency_edges(packages)
    relationships = [
        {
            "type": "Relationship",
            "spdxId": next_id("SPDXRef-Rel"),
            "relationshipType": "dependsOn" if package.is_direct else "contains",
            "from": server_id,
            "to": [refs[package.stable_id]],
        }
        for package in packages
    ]
    relationships.extend(
        {
            "type": "Relationship",
            "spdxId": next_id("SPDXRef-Rel"),
            "relationshipType": "dependsOn",
            "from": refs[parent],
            "to": [refs[child]],
        }
        for parent, child in edges
    )
    for package_id in sorted(unresolved):
        annotate(refs[package_id], "agent-bom:parent-resolution=unresolved")
    return relationships


def add_spdx2_package_relationships(
    packages: list[Package],
    refs: dict[str, str],
    server: dict[str, Any],
    created: str,
    add_relationship: Callable[[str, str, str], None],
) -> None:
    """Keep unresolved lineage explicit while retaining server membership."""
    for package in packages:
        add_relationship(server["SPDXID"], "DEPENDS_ON" if package.is_direct else "CONTAINS", refs[package.stable_id])
    edges, unresolved = package_dependency_edges(packages)
    for parent, child in edges:
        add_relationship(refs[parent], "DEPENDS_ON", refs[child])
    for package_id in sorted(unresolved):
        server.setdefault("annotations", []).append(
            {
                "annotationType": "OTHER",
                "annotator": "Tool: agent-bom",
                "annotationDate": created,
                "comment": f"agent-bom:parent-resolution=unresolved package={refs[package_id]}",
            }
        )


def cyclonedx_package_dependencies(packages: list[Package], ref_for_id: Callable[[str], str]) -> tuple[list[dict], list[str], set[str]]:
    """Render only observed direct roots and resolvable parent dependencies."""
    edges, unresolved = package_dependency_edges(packages)
    dependencies = [{"ref": ref_for_id(parent), "dependsOn": [ref_for_id(child)]} for parent, child in edges]
    roots = [ref_for_id(package.stable_id) for package in packages if package.is_direct]
    return dependencies, roots, unresolved


def imported_bom_incomplete(agents: list) -> bool:
    return any(
        isinstance(agent.metadata.get("sbom_import"), dict) and agent.metadata["sbom_import"].get("composition_complete") is False
        for agent in agents
    )
