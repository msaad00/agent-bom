"""Cargo lock inventory, explicit dependency edges, and local manifest roots."""

from __future__ import annotations

import tomllib
from collections import defaultdict
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.file_limits import read_text_limited
from agent_bom.parsers.lockfile_topology import apply_topology


def parse_cargo_lock(directory: Path) -> list[Package]:
    lock = directory / "Cargo.lock"
    try:
        rows = tomllib.loads(read_text_limited(lock)).get("package", [])
        manifest = tomllib.loads(read_text_limited(directory / "Cargo.toml")) if (directory / "Cargo.toml").exists() else {}
    except (OSError, ValueError):
        record_manifest_parse_warning(
            ecosystem="cargo", path=str(lock), detail="Cargo lock or manifest could not be read or parsed; dependency coverage is partial"
        )
        return []
    if not isinstance(rows, list) or not isinstance(manifest, dict):
        record_manifest_parse_warning(
            ecosystem="cargo", path=str(lock), detail="Cargo input shape is unsupported; dependency coverage is partial"
        )
        return []
    invalid_rows = [
        row for row in rows if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not isinstance(row.get("version"), str)
    ]
    if invalid_rows:
        record_manifest_parse_warning(
            ecosystem="cargo", path=str(lock), detail="Cargo package entries are malformed; dependency coverage is partial"
        )
    rows = [row for row in rows if row not in invalid_rows]
    root_package = manifest.get("package", {})
    root_package = root_package if isinstance(root_package, dict) else {}
    root_key = (root_package.get("name"), root_package.get("version"))
    packages = [
        Package(
            name=row["name"], version=row["version"], ecosystem="cargo", purl=f"pkg:cargo/{row['name']}@{row['version']}", is_direct=None
        )
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("name"), str)
        and isinstance(row.get("version"), str)
        and ((row["name"], row["version"]) != root_key or row.get("source"))
    ]
    keys = {(p.name, p.version) for p in packages}

    def resolve(value: str):
        tokens = value.split()
        candidates = [key for key in keys if key[0] == tokens[0] and (len(tokens) < 2 or key[1] == tokens[1])]
        return candidates[0] if len(candidates) == 1 else None

    edges = defaultdict(set)
    for row in rows:
        parent = (row.get("name"), row.get("version"))
        for value in row.get("dependencies", []) if isinstance(row.get("dependencies", []), list) else []:
            if isinstance(value, str) and value.strip() and (child := resolve(value)):
                edges[parent].add(child)
    roots = {}
    for field, scope in [("dev-dependencies", "dev"), ("build-dependencies", "build"), ("dependencies", "runtime")]:
        declarations = manifest.get(field, {})
        if not isinstance(declarations, dict):
            record_manifest_parse_warning(ecosystem="cargo", path=str(lock), detail="Cargo dependency declarations are malformed")
            continue
        for name, spec in declarations.items():
            name = spec.get("package", name) if isinstance(spec, dict) else name
            # Root lock edges disambiguate parallel versions when present.
            candidates = [key for key in edges.get(root_key, keys) if key[0] == name]
            if len(candidates) == 1:
                roots[candidates[0]] = scope
    apply_topology(packages, edges, roots, lock)
    return packages
