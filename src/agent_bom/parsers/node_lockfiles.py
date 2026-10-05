"""Resolved npm identities and Bun's JSONC lockfile format."""

from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path

from agent_bom.checksums import parse_sri
from agent_bom.core.packages import synthesize_purl
from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.file_limits import read_text_limited
from agent_bom.parsers.npm_semver import npm_exact_version

_SECTIONS = (("dependencies", "runtime"), ("optionalDependencies", "optional"), ("devDependencies", "dev"))


def npm_alias(name: str, spec: str) -> tuple[str, str]:
    """Resolve npm's alias declaration without confusing scoped registry names."""
    if not spec.startswith("npm:"):
        return name, spec
    target = spec[4:]
    package, sep, version = target.rpartition("@")
    return (package, version) if sep and package else (target, "*")


def yarn_descriptor_name(descriptor: str) -> str:
    name, _, spec = descriptor.strip('"').partition("@") if not descriptor.startswith("@") else ("", "", "")
    if descriptor.startswith("@"):
        name, _, spec = descriptor[1:].partition("@")
        name = "@" + name
    return npm_alias(name, spec)[0] if spec.startswith("npm:") and "@" in spec[4:] else name


def _jsonc(text: str) -> dict:
    # Preserve strings before removing comments/commas: URLs and literal ",}"
    # inside names/metadata must not be changed by JSONC normalization.
    quoted = r'"(?:[^"\\]|\\.)*"'
    text = re.sub(f"({quoted})|//[^\n]*|/\\*.*?\\*/", lambda m: m[1] or " ", text, flags=re.S)
    text = re.sub(f"({quoted})|,(\\s*[}}\\]])", lambda m: m[1] or m[2], text)

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate lockfile field")
            result[key] = value
        return result

    data = json.loads(text, object_pairs_hook=unique_pairs)
    if not isinstance(data, dict):
        raise ValueError("Lockfile must be an object")
    return data


def _bun_source(directory: Path) -> tuple[Path, dict, str | None] | None:
    """Use an ancestor lock only when it explicitly owns this workspace."""
    for parent in (directory, *directory.parents):
        lock = parent / "bun.lock"
        if not lock.is_file():
            continue
        data = _jsonc(read_text_limited(lock))
        workspace = directory.relative_to(parent).as_posix()
        if parent == directory:
            return lock, data, None
        workspaces = data.get("workspaces")
        if isinstance(workspaces, dict) and workspace in workspaces:
            return lock, data, workspace
    return None


def has_node_lock(directory: Path) -> bool:
    if any((directory / name).exists() for name in ("yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")):
        return True
    try:
        return _bun_source(directory) is not None
    except (OSError, ValueError, UnicodeError):
        return False


def _bun_resolve(entries: dict, parent: str, dependency: str) -> str | None:
    while parent:
        candidate = f"{parent}/{dependency}"
        if candidate in entries:
            return candidate
        parent = parent.rpartition("/")[0]
    return dependency if dependency in entries else None


def _bun_edges(info: object) -> tuple[list[tuple[str, str]], bool]:
    if not isinstance(info, dict):
        return [], True
    edges: list[tuple[str, str]] = []
    malformed = False
    for section, scope in _SECTIONS:
        deps = info.get(section, {})
        if not isinstance(deps, dict):
            malformed = True
            continue
        edges.extend((dep, scope) for dep in deps)
    return edges, malformed


def _bun_paths(entries: dict, workspaces: dict, selected: str | None) -> tuple[dict[str, tuple[int, str | None, str]], bool]:
    paths: dict[str, tuple[int, str | None, str]] = {}
    queue: deque[str] = deque()
    malformed = False
    for workspace, info in workspaces.items():
        if selected is not None and workspace != selected:
            continue
        edges, invalid = _bun_edges(info)
        malformed |= invalid
        for dep, scope in edges:
            key = _bun_resolve(entries, workspace, dep)
            if key is not None and key not in paths:
                paths[key] = (0, None, scope)
                queue.append(key)
    while queue:
        key = queue.popleft()
        depth, _parent, scope = paths[key]
        entry = entries[key]
        edges, invalid = _bun_edges(entry[2] if len(entry) > 2 else {})
        malformed |= invalid
        parent_name = entry[0].rsplit("@", 1)[0]
        for dep, edge_scope in edges:
            target = _bun_resolve(entries, key, dep)
            if target is not None and target not in paths:
                paths[target] = (depth + 1, parent_name, "dev" if scope == "dev" else edge_scope)
                queue.append(target)
    return paths, malformed


def _bun_merge_identity(existing: Package, candidate: Package) -> Package:
    evidence = existing.version_evidence + candidate.version_evidence
    if candidate.is_direct or (not existing.is_direct and candidate.dependency_depth < existing.dependency_depth):
        existing = candidate
    existing.version_evidence = evidence
    return existing


def parse_bun_packages(directory: Path) -> list[Package]:
    """Read resolved Bun JSONC entries, including aliases and workspace closure."""
    packages: dict[tuple[str, str], Package] = {}
    lock = directory / "bun.lock"
    try:
        source = _bun_source(directory)
        if source is None:
            if (directory / "bun.lockb").exists():
                raise ValueError("Binary Bun lockfile is unsupported")
            return []
        lock, data, selected = source
        entries, workspaces = data.get("packages"), data.get("workspaces")
        if data.get("lockfileVersion") not in {0, 1} or not isinstance(entries, dict) or not isinstance(workspaces, dict):
            raise ValueError("Unsupported Bun lockfile structure")
        valid: dict = {}
        malformed = False
        for key, entry in entries.items():
            if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
                malformed = True
                continue
            name, _, version = entry[0].rpartition("@")
            if version.startswith("workspace:"):
                continue  # workspace source metadata is represented separately
            if not name or npm_exact_version(version) is None:
                malformed = True
                continue
            valid[key] = entry
        paths, invalid_paths = _bun_paths(valid, workspaces, selected)
        malformed |= invalid_paths
        for key, entry in valid.items():
            if selected is not None and key not in paths:
                continue
            name, version = entry[0].rsplit("@", 1)
            depth, parent, scope = paths.get(key, (0, None, "unknown"))
            evidence = {"type": "lockfile", "source_file": str(lock), "installed_name": key}
            identity = (name, version)
            candidate = Package(
                name=name,
                version=version,
                ecosystem="npm",
                purl=synthesize_purl(name, version, "npm"),
                is_direct=key in paths and depth == 0,
                parent_package=parent,
                dependency_depth=depth,
                dependency_scope=scope,
                reachability_evidence="lockfile",
                version_source="lockfile",
                version_evidence=[evidence],
                checksums=parse_sri(entry[3]) if len(entry) > 3 and isinstance(entry[3], str) else {},
            )
            packages[identity] = _bun_merge_identity(packages[identity], candidate) if identity in packages else candidate
        if malformed:
            raise ValueError("Unresolved or malformed Bun package entries")
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
        record_manifest_parse_warning(
            ecosystem="npm",
            path=str(lock),
            detail="Bun lockfile could not be fully parsed; dependency coverage is incomplete. Convert binary locks to bun.lock.",
        )
    return list(packages.values())
