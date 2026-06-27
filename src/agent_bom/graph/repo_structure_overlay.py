"""Repository folder/file structure overlay.

A code / project scan (``agent-bom agents -p .`` or ``--repo``) already discovers
manifests, lockfiles, packages, and file-scoped findings — but the graph stored
them as a flat ``server → package → vulnerability`` fan-out with no notion of the
*folder structure* the code actually lives in. The cloud graph, by contrast,
renders a readable ``org → account → resource`` containment tree. This overlay
closes that gap for repositories: it materialises the **directory tree** as
first-class graph nodes so a repository scan visualises its folder/file layout,
its file → dependency → vulnerability paths, and its file → finding paths the
same way the cloud graph visualises cloud architecture.

It is a pure, in-place, additive correlation layer over data the report already
carries — it adds **no scanners** and makes **no network calls**:

- **Directory tree** — from ``project_inventory.directories`` (each carries a
  repo-relative ``path`` plus its manifest / lockfile / declaration files), every
  directory and its ancestors become a ``DIRECTORY`` node, linked
  ``CONTAINS`` parent → child so the existing server-side CONTAINS roll-up
  collapses deep trees exactly as it does for the cloud hierarchy.
- **Manifest / config files** — each manifest, lockfile, and declaration file
  becomes a ``CONFIG_FILE`` node ``CONTAINS``-ed by its directory.
- **file → dependency → vuln** — the representative manifest of a directory is
  linked ``DEPENDS_ON`` to the *direct* packages discovered for that directory
  (resolved via the existing project ``SERVER`` node whose label is the
  directory path), so a viewer can trace a vulnerability back through its
  package to the manifest file and folder that introduced it.
- **file → finding** — every existing ``MISCONFIGURATION`` node that names a
  source/config file (SAST / IaC / secrets findings carry a file path) gets a
  ``SOURCE_FILE`` / ``CONFIG_FILE`` node placed in the tree, linked
  ``AFFECTS`` finding → file, so a finding is locatable by folder.

The overlay is **idempotent** (applying twice yields identical nodes / edges),
**deterministic** (every iteration is sorted), and a complete **no-op** (graph
byte-identical) when the report carries no ``project_inventory`` and no
file-scoped findings.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, GraphSemanticLayer, RelationshipType

_OVERLAY_SOURCE = "repo-structure-overlay"

# Source-code file extensions → SOURCE_FILE; everything else placed in the tree
# (manifests, lockfiles, yaml/json/toml config) is a CONFIG_FILE. Conservative:
# anything not recognised as code is treated as config.
_CODE_EXTENSIONS = frozenset(
    {
        "py",
        "pyi",
        "js",
        "jsx",
        "ts",
        "tsx",
        "mjs",
        "cjs",
        "go",
        "rs",
        "rb",
        "java",
        "kt",
        "kts",
        "scala",
        "c",
        "cc",
        "cpp",
        "h",
        "hpp",
        "cs",
        "php",
        "swift",
        "m",
        "sh",
        "bash",
    }
)

# Misconfiguration-node attribute keys that carry the file a finding is about.
_FILE_PATH_ATTRS = ("file_path", "path", "source_file")


def _zero() -> dict[str, int]:
    return {
        "directories": 0,
        "files": 0,
        "contains_edges": 0,
        "file_package_edges": 0,
        "file_finding_edges": 0,
    }


def _norm_path(raw: Any) -> str:
    """Normalise a repo-relative path: forward slashes, no ``./`` / trailing ``/``.

    The repo root (``""`` or ``"."``) normalises to ``""`` so it is the single
    tree root regardless of how the inventory or a finding spelled it.
    """
    if not isinstance(raw, str):
        return ""
    text = raw.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    text = text.strip("/")
    return "" if text == "." else text


def _dir_node_id(dir_path: str) -> str:
    return "directory:." if dir_path == "" else f"directory:{dir_path}"


def _file_node_id(file_path: str, entity_type: EntityType) -> str:
    return f"{entity_type.value}:{file_path}"


def _dir_label(dir_path: str) -> str:
    return "." if dir_path == "" else dir_path.rsplit("/", 1)[-1]


def _parent_dir(dir_path: str) -> str:
    return dir_path.rsplit("/", 1)[0] if "/" in dir_path else ""


def _ancestors(dir_path: str) -> list[str]:
    """Every ancestor directory of *dir_path*, including itself and the root."""
    chain: list[str] = [""]
    if dir_path == "":
        return chain
    parts = dir_path.split("/")
    for i in range(1, len(parts) + 1):
        chain.append("/".join(parts[:i]))
    return chain


def _file_dir(file_path: str) -> str:
    return file_path.rsplit("/", 1)[0] if "/" in file_path else ""


def _file_entity_type(file_path: str) -> EntityType:
    name = file_path.rsplit("/", 1)[-1]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return EntityType.SOURCE_FILE if ext in _CODE_EXTENSIONS else EntityType.CONFIG_FILE


def _looks_like_path(value: Any) -> bool:
    """True when *value* is a concrete repo file path (not a placeholder/blank).

    Rejects the redacted ``project <redacted>`` asset locations and bare names
    with no extension and no separator so we never invent a tree from noise.
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or text.startswith("project ") or "<" in text:
        return False
    return "/" in text or "." in text


def apply_repo_structure_overlay(
    graph: UnifiedGraph,
    report_json: dict[str, Any],
    now: datetime,
) -> dict[str, int]:
    """Materialise the repository folder/file structure into the graph, in place.

    Args:
        graph: the unified graph to enrich (mutated in place). Runs after the
            inventory builder so the project ``SERVER`` and ``PACKAGE`` nodes a
            directory's files link to already exist.
        report_json: the persisted AIBOM report JSON contract. Reads the optional
            ``project_inventory`` block (directory tree + per-directory manifest
            files) and consults existing ``MISCONFIGURATION`` nodes for file
            paths. Never fetched here.
        now: reference time for the created nodes' timestamps (no inline
            ``datetime.now`` — determinism / testability).

    Returns counts of directories, files, and the three edge classes created. A
    complete no-op (all-zero, graph untouched) when neither a project inventory
    nor a file-scoped finding is present.
    """
    counts = _zero()
    now_iso = now.isoformat()

    project_inventory = report_json.get("project_inventory") if isinstance(report_json, dict) else None
    directories = project_inventory.get("directories") if isinstance(project_inventory, dict) else None
    directory_records: dict[str, dict[str, Any]] = {}
    if isinstance(directories, list):
        for record in directories:
            if isinstance(record, dict) and isinstance(record.get("path"), str):
                directory_records[_norm_path(record.get("path"))] = record

    # ── Index existing graph state we stitch onto ───────────────────────────
    # Project SERVER nodes are keyed in the graph by their directory-path label
    # for a local/repo scan (label "" == repo root). Map dir path → packages it
    # depends on so a manifest file can be linked to the deps it declares.
    server_by_dir: dict[str, str] = {}
    for node in graph.nodes.values():
        if node.entity_type == EntityType.SERVER:
            server_by_dir.setdefault(_norm_path(node.label), node.id)
    deps_by_server: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.relationship == RelationshipType.DEPENDS_ON and edge.source in graph.nodes:
            deps_by_server[edge.source].append(edge.target)

    # ── Collect every directory that needs a node (records + their ancestors +
    #    the directories that finding-file paths live in) ─────────────────────
    needed_dirs: set[str] = set()
    for dir_path in directory_records:
        needed_dirs.update(_ancestors(dir_path))

    # File-scoped findings: map an existing misconfiguration node → the file it
    # names, so we can both create the file node and link finding → file.
    finding_files: dict[str, str] = {}  # misconfig_node_id -> normalised file path
    for node in graph.nodes.values():
        if node.entity_type != EntityType.MISCONFIGURATION:
            continue
        attrs = node.attributes or {}
        raw_path = next((attrs.get(key) for key in _FILE_PATH_ATTRS if _looks_like_path(attrs.get(key))), None)
        if raw_path is None:
            continue
        file_path = _norm_path(raw_path)
        if not file_path:
            continue
        finding_files[node.id] = file_path
        needed_dirs.update(_ancestors(_file_dir(file_path)))

    if not needed_dirs:
        return counts

    # ── 1. Directory nodes ──────────────────────────────────────────────────
    for dir_path in sorted(needed_dirs):
        node_id = _dir_node_id(dir_path)
        if node_id not in graph.nodes:
            counts["directories"] += 1
        record = directory_records.get(dir_path, {})
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.DIRECTORY,
                label=_dir_label(dir_path),
                first_seen=now_iso,
                last_seen=now_iso,
                attributes={
                    "path": dir_path or ".",
                    "is_repo_root": dir_path == "",
                    "package_count": record.get("package_count", 0),
                    "direct_packages": record.get("direct_packages", 0),
                    "ecosystems": record.get("ecosystems", {}),
                    "advisory_evidence": record.get("advisory_evidence", ""),
                },
                data_sources=[_OVERLAY_SOURCE],
                dimensions=NodeDimensions(surface=GraphSemanticLayer.CODE.value),
            )
        )

    # ── 2. CONTAINS edges: parent directory → child directory ───────────────
    for dir_path in sorted(needed_dirs):
        if dir_path == "":
            continue
        graph.add_edge(
            UnifiedEdge(
                source=_dir_node_id(_parent_dir(dir_path)),
                target=_dir_node_id(dir_path),
                relationship=RelationshipType.CONTAINS,
                evidence={"source": _OVERLAY_SOURCE},
            )
        )
        counts["contains_edges"] += 1

    # ── 3. Manifest / lockfile / declaration files per directory ─────────────
    for dir_path in sorted(directory_records):
        record = directory_records[dir_path]
        manifest_files = _str_list(record.get("manifest_files"))
        lockfile_files = _str_list(record.get("lockfile_files"))
        declaration_files = _str_list(record.get("declaration_files"))
        all_files = sorted(set(manifest_files) | set(lockfile_files) | set(declaration_files))

        for file_name in all_files:
            file_path = f"{dir_path}/{file_name}" if dir_path else file_name
            entity_type = _file_entity_type(file_path)
            file_id = _file_node_id(file_path, entity_type)
            if file_id not in graph.nodes:
                counts["files"] += 1
            graph.add_node(
                UnifiedNode(
                    id=file_id,
                    entity_type=entity_type,
                    label=file_name,
                    first_seen=now_iso,
                    last_seen=now_iso,
                    attributes={"path": file_path, "directory": dir_path or "."},
                    data_sources=[_OVERLAY_SOURCE],
                    dimensions=NodeDimensions(surface=GraphSemanticLayer.CODE.value),
                )
            )
            graph.add_edge(
                UnifiedEdge(
                    source=_dir_node_id(dir_path),
                    target=file_id,
                    relationship=RelationshipType.CONTAINS,
                    evidence={"source": _OVERLAY_SOURCE},
                )
            )
            counts["contains_edges"] += 1

        # file → dependency: link the representative manifest to the DIRECT
        # packages discovered for this directory (declaration manifest preferred
        # — it is what literally declares direct deps — then any manifest, then a
        # lockfile). Transitive packages stay reachable via the package graph.
        representative = declaration_files or manifest_files or lockfile_files
        server_id = server_by_dir.get(dir_path)
        if representative and server_id:
            rep_name = sorted(representative)[0]
            rep_path = f"{dir_path}/{rep_name}" if dir_path else rep_name
            rep_id = _file_node_id(rep_path, _file_entity_type(rep_path))
            for pkg_id in sorted(set(deps_by_server.get(server_id, []))):
                pkg_node = graph.nodes.get(pkg_id)
                if pkg_node is None or not pkg_node.attributes.get("is_direct", True):
                    continue
                graph.add_edge(
                    UnifiedEdge(
                        source=rep_id,
                        target=pkg_id,
                        relationship=RelationshipType.DEPENDS_ON,
                        evidence={"source": _OVERLAY_SOURCE, "declared_in": rep_path},
                    )
                )
                counts["file_package_edges"] += 1

    # ── 4. file → finding: place each finding's file in the tree + link it ───
    for misconfig_id, file_path in sorted(finding_files.items()):
        entity_type = _file_entity_type(file_path)
        file_id = _file_node_id(file_path, entity_type)
        if file_id not in graph.nodes:
            counts["files"] += 1
            graph.add_node(
                UnifiedNode(
                    id=file_id,
                    entity_type=entity_type,
                    label=file_path.rsplit("/", 1)[-1],
                    first_seen=now_iso,
                    last_seen=now_iso,
                    attributes={"path": file_path, "directory": _file_dir(file_path) or "."},
                    data_sources=[_OVERLAY_SOURCE],
                    dimensions=NodeDimensions(surface=GraphSemanticLayer.CODE.value),
                )
            )
            graph.add_edge(
                UnifiedEdge(
                    source=_dir_node_id(_file_dir(file_path)),
                    target=file_id,
                    relationship=RelationshipType.CONTAINS,
                    evidence={"source": _OVERLAY_SOURCE},
                )
            )
            counts["contains_edges"] += 1
        graph.add_edge(
            UnifiedEdge(
                source=misconfig_id,
                target=file_id,
                relationship=RelationshipType.AFFECTS,
                evidence={"source": _OVERLAY_SOURCE},
            )
        )
        counts["file_finding_edges"] += 1

    return counts


def _str_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, str) and item.strip()]
