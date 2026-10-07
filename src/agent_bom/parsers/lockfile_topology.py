"""Apply explicit lockfile edges and manifest roots to parsed package records."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.file_limits import read_json_limited

Key = tuple[str, str]


def apply_topology(packages: list[Package], edges: dict[Key, set[Key]], roots: dict[Key, str], source: Path) -> None:
    by_key = {(p.name, p.version): p for p in packages}
    parents: dict[Key, set[Key]] = defaultdict(set)
    for parent, children in edges.items():
        for child in children:
            if parent in by_key and child in by_key and parent != child:
                parents[child].add(parent)
    depths = {key: 0 for key in roots if key in by_key}
    scopes = dict(roots)
    queue = deque(sorted(depths))
    while queue:
        parent = queue.popleft()
        for child in sorted(edges.get(parent, ())):
            if child not in by_key:
                continue
            depth = depths[parent] + 1
            if child not in depths or depth < depths[child]:
                depths[child] = depth
                scopes[child] = scopes[parent]
                queue.append(child)
    for key, package in by_key.items():
        package.is_direct = key in roots if key in depths else None
        package.dependency_depth = depths.get(key, 0)
        package.dependency_scope = scopes.get(key, "unknown")
        package.parent_package = next(iter(parents[key]))[0] if len(parents[key]) == 1 else None
        package.reachability_evidence = "lockfile"
        package.version_source = "lockfile"
        package.version_evidence.append(
            {"type": "lockfile", "source_file": str(source), "parent_stable_ids": sorted(by_key[p].stable_id for p in parents[key])}
        )


def _mapping(value: object, source: Path) -> dict:
    if isinstance(value, dict):
        return value
    record_manifest_parse_warning(
        ecosystem="npm", path=str(source), detail="Dependency topology is malformed; relationship coverage is partial"
    )
    return {}


def _manifest_roots(directory: Path, descriptors: dict[str, Key]) -> dict[Key, str]:
    try:
        manifest = read_json_limited(directory / "package.json")
    except (OSError, ValueError):
        return {}
    if not isinstance(manifest, dict):
        return {}
    roots: dict[Key, str] = {}
    for field, scope in [("devDependencies", "dev"), ("optionalDependencies", "optional"), ("dependencies", "runtime")]:
        for name, spec in _mapping(manifest.get(field, {}), directory / "package.json").items():
            key = descriptors.get(f"{name}@{spec}")
            if key:
                roots[key] = scope
    return roots


def _yarn_records(content: str) -> list[tuple[list[str], str, list[tuple[str, str]]]]:
    records: list[tuple[list[str], str, list[tuple[str, str]]]] = []
    selectors: list[str] = []
    version = ""
    deps: list[tuple[str, str]] = []
    in_dependencies = False
    for line in [*content.splitlines(), "END:"]:
        if line and not line[0].isspace() and line.endswith(":") and not line.startswith("#"):
            if selectors and version:
                records.append((selectors, version, deps))
            selectors = [p.strip().strip('"') for p in line[:-1].split(", ")]
            version, deps, in_dependencies = "", [], False
        elif line.startswith("  version "):
            version = line.strip().split(" ", 1)[1].strip('"')
        elif line.startswith("  dependencies:"):
            in_dependencies = True
        elif line.startswith("  ") and not line.startswith("    ") and ":" in line:
            in_dependencies = False
        elif in_dependencies and line.startswith("    "):
            match = re.match(r'\s*("[^"]+"|\S+)\s+"?([^"\s]+)"?$', line)
            if match:
                deps.append((match[1].strip('"'), match[2]))
    return records


def yarn_topology(directory: Path, packages: list[Package], content: str) -> None:
    """Read exact Classic selectors; unresolved selectors remain unknown."""
    if "__metadata:" in content:
        return
    records = _yarn_records(content)
    descriptors: dict[str, Key] = {}
    package_keys = {(p.name, p.version) for p in packages}
    for selectors, version, _ in records:
        for selector in selectors:
            name = selector.rsplit("@", 1)[0]
            if (name, version) in package_keys:
                descriptors[selector] = (name, version)
    edges: dict[Key, set[Key]] = defaultdict(set)
    unresolved = False
    for selectors, _, dependencies in records:
        parent = next((descriptors[s] for s in selectors if s in descriptors), None)
        if parent is None:
            continue
        for name, spec in dependencies:
            child = descriptors.get(f"{name}@{spec}")
            if child:
                edges[parent].add(child)
            else:
                unresolved = True
    apply_topology(packages, edges, _manifest_roots(directory, descriptors), directory / "yarn.lock")
    if unresolved:
        record_manifest_parse_warning(
            ecosystem="npm",
            path=str(directory / "yarn.lock"),
            detail="Yarn dependency selectors are unresolved; topology coverage is partial",
        )


def pnpm_topology(directory: Path, packages: list[Package], document: dict) -> None:
    by_key = {(p.name, p.version): p for p in packages}

    def resolve(name: str, value: object) -> Key | None:
        version = value.get("version") if isinstance(value, dict) else value
        if not isinstance(version, str):
            return None
        key = (name, version.split("(", 1)[0])
        return key if key in by_key else None

    roots: dict[Key, str] = {}
    importers = document.get("importers", {".": document})
    for importer in _mapping(importers, directory / "pnpm-lock.yaml").values():
        importer = _mapping(importer, directory / "pnpm-lock.yaml")
        for field, scope in [("devDependencies", "dev"), ("optionalDependencies", "optional"), ("dependencies", "runtime")]:
            for name, value in _mapping(importer.get(field, {}), directory / "pnpm-lock.yaml").items():
                key = resolve(name, value)
                if key:
                    roots[key] = scope
    edges: dict[Key, set[Key]] = defaultdict(set)
    snapshots = document.get("snapshots", document.get("packages", {}))
    for label, metadata in _mapping(snapshots, directory / "pnpm-lock.yaml").items():
        if not isinstance(label, str):
            continue
        label = label.lstrip("/").split("(", 1)[0]
        name, sep, version = label.rpartition("@")
        if not sep:
            name, _, version = label.rpartition("/")
        parent = (name, version)
        if parent not in by_key or not isinstance(metadata, dict):
            continue
        for child_name, value in _mapping(metadata.get("dependencies", {}), directory / "pnpm-lock.yaml").items():
            child = resolve(child_name, value)
            if child:
                edges[parent].add(child)
    apply_topology(packages, edges, roots, directory / "pnpm-lock.yaml")
