"""Restore supplied SPDX dependency evidence without inventing runtime reach."""

from __future__ import annotations

from collections import defaultdict, deque

from agent_bom.models import Package

_SCOPED_TYPES = {"runtime": "runtime", "build": "build", "dev": "dev", "test": "test", "optional": "optional", "provided": "provided"}


def dependency_relationships(document: dict) -> list[tuple[str, str, str]]:
    """Read native SPDX 2 dependency kinds and SPDX 3 lifecycle scopes."""
    result = []
    for rel in [*document.get("elements", document.get("@graph", [])), *document.get("relationships", [])]:
        if not isinstance(rel, dict):
            continue
        kind = str(rel.get("relationshipType", "")).replace("_", "").lower()
        scope = _SCOPED_TYPES.get(kind.removesuffix("dependencyof"), "unknown")
        if kind not in {"dependson", "dependencyof"} and scope == "unknown":
            continue
        if scope == "unknown":
            scope = {
                "development": "dev",
                "build": "build",
                "runtime": "runtime",
                "test": "test",
                "design": "design",
                "other": "other",
            }.get(str(rel.get("scope")), "unknown")
        parent = rel.get("from", rel.get("spdxElementId"))
        children = rel.get("to", rel.get("relatedSpdxElement", []))
        children = [children] if isinstance(children, str) else children
        if not isinstance(parent, str) or not isinstance(children, list):
            continue
        for child in children:
            if isinstance(child, str):
                source, target = (child, parent) if kind.endswith("dependencyof") else (parent, child)
                result.append((source, target, scope))
    return result


def _declared_edges(document: dict) -> tuple[dict[str, set[str]], set[str]]:
    edges: dict[str, set[str]] = defaultdict(set)
    context_ids = {document.get("SPDXID", "SPDXRef-DOCUMENT")}
    for item in [*document.get("packages", []), *document.get("elements", [])]:
        if (
            isinstance(item, dict)
            and str(item.get("primaryPackagePurpose", item.get("software_primaryPurpose", ""))).lower() == "application"
        ):
            context_ids.add(item.get("SPDXID", item.get("spdxId")))
    for source, target, _scope in dependency_relationships(document):
        edges[source].add(target)
    return edges, set(edges) & context_ids


def _supplied_scopes(document: dict, depths: dict[str, int], scoped: bool) -> dict[str, set[str]]:
    scopes: dict[str, set[str]] = defaultdict(set)
    for source, target, scope in dependency_relationships(document):
        if scope != "unknown" and (not scoped or source in depths):
            scopes[target].add(scope)
    return scopes


def restore_spdx_hierarchy(document: dict, packages: dict[str, Package], *, root_refs: set[str] | None = None) -> None:
    edges, roots = _declared_edges(document)
    if root_refs is not None:
        roots = root_refs
    parents: dict[str, set[str]] = defaultdict(set)
    for parent, children in edges.items():
        if parent in packages:
            for child in children:
                if child in packages and child != parent:
                    parents[child].add(parent)
    depths = {root: -1 for root in roots}
    queue = deque(sorted(roots))
    while queue:
        parent = queue.popleft()
        for child in sorted(edges[parent]):
            depth = depths[parent] + (child in packages)
            if child not in depths or depth < depths[child]:
                depths[child] = depth
                queue.append(child)
    scopes = _supplied_scopes(document, depths, root_refs is not None)
    for ref, package in packages.items():
        package.is_direct = (depths[ref] == 0) if ref in depths else None
        package.dependency_depth = max(0, depths.get(ref, 0))
        package.parent_package = packages[next(iter(parents[ref]))].name if len(parents[ref]) == 1 else None
        package.dependency_scope = next(iter(scopes[ref])) if len(scopes[ref]) == 1 else "unknown"
        package.reachability_evidence = "declaration_only"
        package.version_source = "sbom_ingest"
        package.version_evidence.append(
            {
                "type": "sbom",
                "bom_ref": ref,
                "reported_dependency_scope": package.dependency_scope,
                "parent_stable_ids": sorted(packages[p].stable_id for p in parents[ref]),
            }
        )
