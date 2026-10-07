"""Resolved uv lockfile versions and dependency evidence."""

from __future__ import annotations

import re
import tomllib
from collections import Counter, defaultdict, deque
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.package_utils import normalize_package_name
from agent_bom.parsers.file_limits import read_text_limited
from agent_bom.parsers.uv_workspace import uv_lock_owner


def _name(value: object) -> str:
    return normalize_package_name(str(value), "pypi")


def _direct_names(directory: Path) -> set[str]:
    manifest = directory / "pyproject.toml"
    if not manifest.exists():
        return set()
    project = tomllib.loads(read_text_limited(manifest)).get("project", {})
    names = set()
    for declaration in project.get("dependencies", []):
        match = re.match(r"^([a-zA-Z0-9_.-]+)", declaration)
        if match:
            names.add(_name(match[1]))
    return names


def _edges(row: dict) -> list[tuple[str, str]]:
    edges = []
    groups = [(row.get("dependencies", []), "runtime")]
    for key, scope in (("optional-dependencies", "conditional"), ("dev-dependencies", "dev")):
        groups.extend((values, scope) for values in row.get(key, {}).values())
    for values, scope in groups:
        for dependency in values:
            if isinstance(dependency, str):
                edges.append((_name(dependency), scope))
            elif isinstance(dependency, dict) and dependency.get("name"):
                edges.append((_name(dependency["name"]), "conditional" if dependency.get("marker") else scope))
    return edges


def _member_rows(rows: list[dict], seeds: set[str], relative: str) -> list[dict]:
    selected = set(seeds)
    children: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        targets = {name for name, _scope in _edges(row)}
        children[_name(row.get("name", ""))].update(targets)
        source = row.get("source", {})
        if source.get("editable") == relative or source.get("virtual") == relative:
            selected.update(targets)
    queue = deque(sorted(selected))
    while queue:
        for child in sorted(children.get(queue.popleft(), set()) - selected):
            selected.add(child)
            queue.append(child)
    return [row for row in rows if _name(row.get("name", "")) in selected]


def _parents(rows: list[dict], direct: set[str]) -> tuple[dict[str, str], dict[str, int]]:
    counts = Counter(_name(row.get("name", "")) for row in rows)
    unique = {name for name, count in counts.items() if name and count == 1}
    children = {_name(row["name"]): _edges(row) for row in rows if _name(row.get("name", "")) in unique}
    parents: dict[str, str] = {}
    depths = {name: 0 for name in direct if name in unique}
    queue = deque(sorted(depths))
    while queue:
        parent = queue.popleft()
        for child, scope in sorted(children.get(parent, [])):
            if scope != "runtime" or child not in unique or child in depths:
                continue
            parents[child] = parent
            depths[child] = depths[parent] + 1
            queue.append(child)
    return parents, depths


def _packages(rows: list[dict], direct: set[str], lock_file: Path) -> list[Package]:
    parents, depths = _parents(rows, direct)
    packages = []
    for row in rows:
        name, version = row.get("name"), row.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            record_manifest_parse_warning(ecosystem="pypi", path=str(lock_file), detail="uv lock contains an invalid package identity")
            continue
        normalized = _name(name)
        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=f"pkg:pypi/{name}@{version}",
                is_direct=True if normalized in direct else False if normalized in parents else None,
                parent_package=parents.get(normalized),
                dependency_depth=depths.get(normalized, 0),
                dependency_scope="runtime" if normalized in direct or normalized in parents else "unknown",
                reachability_evidence="lockfile",
                version_source="lockfile",
                version_evidence=[{"type": "lockfile", "source_file": str(lock_file)}],
            )
        )
    return packages


def parse_uv_lock(directory: Path) -> list[Package]:
    """Read authoritative lock versions; members use only their locked closure."""
    owner = uv_lock_owner(directory)
    if owner is None:
        return []
    lock_file = owner / "uv.lock"
    if not lock_file.exists():
        record_manifest_parse_warning(
            ecosystem="pypi", path=str(lock_file), detail="uv workspace lock is missing; resolved Python dependencies were not scanned"
        )
        return []
    try:
        data = tomllib.loads(read_text_limited(lock_file))
        rows = data.get("package", [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("invalid package array")
        direct = _direct_names(directory)
        if direct - {_name(row.get("name", "")) for row in rows}:
            record_manifest_parse_warning(
                ecosystem="pypi", path=str(lock_file), detail="uv lock is missing declared dependencies; Python coverage is incomplete"
            )
        if owner != directory.resolve():
            rows = _member_rows(rows, direct, directory.resolve().relative_to(owner).as_posix())
        return _packages(rows, direct, lock_file)
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        record_manifest_parse_warning(
            ecosystem="pypi", path=str(lock_file), detail="uv lock or project metadata could not be parsed; Python coverage is incomplete"
        )
        return []
