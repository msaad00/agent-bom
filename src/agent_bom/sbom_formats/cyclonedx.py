"""Dependency and provenance semantics for CycloneDX software documents."""

from __future__ import annotations

from collections import defaultdict, deque

from agent_bom.advisory_ids import upstream_advisory_ids
from agent_bom.checksums import add_checksum
from agent_bom.models import Package, Vulnerability
from agent_bom.scanners.enrichment_apply import apply_epss_entry

_CONTEXT_ROLES = {"ai-agent", "mcp-server"}


def software_components(document: dict) -> list[dict]:
    """Flatten component containment without treating it as a dependency edge."""
    top = document.get("components", [])
    if not isinstance(top, list):
        raise ValueError("Invalid CycloneDX components")
    pending = list(top)
    metadata = document.get("metadata", {})
    root = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    if isinstance(root, dict):
        children = root.get("components", [])
        if not isinstance(children, list):
            raise ValueError("Invalid CycloneDX nested components")
        pending.extend(children)
    components = []
    refs = set()
    while pending:
        component = pending.pop()
        if not isinstance(component, dict):
            continue
        ref = component.get("bom-ref")
        if isinstance(ref, str):
            if ref in refs:
                raise ValueError("Duplicate CycloneDX component reference")
            refs.add(ref)
        components.append(component)
        children = component.get("components", [])
        if not isinstance(children, list):
            raise ValueError("Invalid CycloneDX nested components")
        pending.extend(children)
    return list(reversed(components))


def component_properties(component: dict) -> dict[str, str]:
    return {
        p["name"]: p["value"]
        for p in component.get("properties", [])
        if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("value"), str)
    }


def is_context_component(component: dict) -> bool:
    return not component.get("purl") and component_properties(component).get("agent-bom:type") in _CONTEXT_ROLES


def dependency_map(document: dict) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = defaultdict(set)
    for row in document.get("dependencies", []):
        if isinstance(row, dict) and isinstance(row.get("ref"), str) and isinstance(row.get("dependsOn"), list):
            edges[row["ref"]].update(value for value in row["dependsOn"] if isinstance(value, str))
    return edges


def restore_package_metadata(package: Package, component: dict) -> None:
    props = component_properties(component)
    for digest in component.get("hashes", []):
        if isinstance(digest, dict) and isinstance(digest.get("alg"), str) and isinstance(digest.get("content"), str):
            add_checksum(package.checksums, digest["alg"], digest["content"])
    package.reachability_evidence = "declaration_only"
    package.version_source = "sbom"
    package.resolved_from_registry = props.get("agent-bom:resolved-from-registry") == "true"
    package.dependency_scope = props.get("agent-bom:dependency-scope", "unknown")
    package.is_direct = props.get("agent-bom:is-direct") == "true"
    parent = props.get("agent-bom:parent-package")
    package.parent_package = parent or None
    depth = props.get("agent-bom:dependency-depth", "0")
    package.dependency_depth = int(depth) if depth.isdecimal() and len(depth) < 7 else 0
    package.version_evidence = [
        {
            "type": "sbom",
            "bom_ref": component.get("bom-ref"),
            "reported_version_source": props.get("agent-bom:version-source"),
            "reported_reachability_evidence": props.get("agent-bom:reachability-evidence"),
        }
    ]


def restore_dependency_hierarchy(document: dict, packages: dict[str, Package]) -> None:
    edges = dependency_map(document)
    components = {c["bom-ref"]: c for c in software_components(document) if isinstance(c, dict) and isinstance(c.get("bom-ref"), str)}
    root = document.get("metadata", {}).get("component", {}).get("bom-ref")
    roots = (
        [root]
        if isinstance(root, str) and root
        else [ref for ref, c in components.items() if component_properties(c).get("agent-bom:type") == "mcp-server"]
    )
    parents: dict[str, set[str]] = defaultdict(set)
    for parent, children in edges.items():
        if parent in packages:
            for child in children:
                if child in packages and parent != child:
                    parents[child].add(parent)
    depths: dict[str, int] = {ref: -1 for ref in roots}
    queue = deque(roots)
    while queue:
        parent = queue.popleft()
        for child in sorted(edges.get(parent, ())):
            depth = depths[parent] + (1 if child in packages else 0)
            if child not in depths or depth < depths[child]:
                depths[child] = depth
                queue.append(child)
    for ref, package in packages.items():
        package.version_evidence[0]["parent_stable_ids"] = sorted(packages[p].stable_id for p in parents[ref])
        if ref in depths:
            package.dependency_depth = max(0, depths[ref])
            package.is_direct = depths[ref] == 0
        if len(parents[ref]) == 1:
            package.parent_package = packages[next(iter(parents[ref]))].name
        elif parents[ref]:
            package.parent_package = None  # the model cannot assert one of several parents


def imported_composition_complete(document: dict) -> bool:
    compositions = document.get("compositions")
    return (
        isinstance(compositions, list)
        and bool(compositions)
        and all(isinstance(c, dict) and c.get("aggregate") == "complete" for c in compositions)
    )


def vulnerability_source(vuln: Vulnerability) -> dict[str, str]:
    """Preserve the distinction between imported assertions and feed lookups."""
    if vuln.severity_source == "sbom":
        return {"name": "SBOM"}
    return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.id}"}


def vulnerability_enrichment_properties(vuln: Vulnerability) -> list[dict[str, str]]:
    """Preserve scalar intelligence with the CVE supplying each value."""
    vuln_properties: list[dict[str, str]] = []
    if vuln.upstream_ids:
        vuln_properties.append({"name": "agent-bom:upstream_ids", "value": ",".join(vuln.upstream_ids)})
    for key in ("epss_cve_id", "kev_cve_id"):
        value = getattr(vuln, key)
        if value:
            vuln_properties.append({"name": f"agent-bom:{key}", "value": value})
    if vuln.is_kev:
        vuln_properties.append({"name": "agent-bom:kev", "value": "true"})
        if vuln.kev_date_added:
            vuln_properties.append({"name": "agent-bom:kev_date_added", "value": vuln.kev_date_added})
        if vuln.kev_due_date:
            vuln_properties.append({"name": "agent-bom:kev_due_date", "value": vuln.kev_due_date})
    if vuln.epss_score is not None:
        vuln_properties.append({"name": "agent-bom:epss_score", "value": str(vuln.epss_score)})
    if vuln.epss_percentile is not None:
        vuln_properties.append({"name": "agent-bom:epss_percentile", "value": str(vuln.epss_percentile)})
    return vuln_properties


def restore_vulnerability_enrichment(vuln: Vulnerability, vuln_data: dict) -> None:
    """Restore only the portable enrichment properties written by this exporter."""
    props = component_properties(vuln_data)
    vuln.upstream_ids = upstream_advisory_ids(props.get("agent-bom:upstream_ids", "").split(","))
    vuln.epss_cve_id = props.get("agent-bom:epss_cve_id")
    vuln.kev_cve_id = props.get("agent-bom:kev_cve_id")
    try:
        score = float(props["agent-bom:epss_score"])
        percentile = float(props["agent-bom:epss_percentile"]) if "agent-bom:epss_percentile" in props else None
    except (KeyError, TypeError, ValueError):
        pass
    else:
        key = vuln.epss_cve_id or vuln.id
        apply_epss_entry(vuln, [key], {key: {"score": score, "percentile": percentile}})
    vuln.is_kev = props.get("agent-bom:kev") == "true"
    if vuln.is_kev:
        vuln.kev_date_added = props.get("agent-bom:kev_date_added")
        vuln.kev_due_date = props.get("agent-bom:kev_due_date")
