"""Code-module overlay — emit ``code_module`` nodes from existing source files.

When the repo-structure overlay (or prior builders) already placed ``SOURCE_FILE``
nodes under directories, this layer groups them into ``CODE_MODULE`` nodes so the
reserved code vocabulary is honest about evidence we already have:

- one ``CODE_MODULE`` per directory that owns ≥1 ``SOURCE_FILE``
- ``DEFINES`` edges from each source file → its module
- ``CONTAINS`` from the directory → module (when the directory node exists)

No-op when there are no source-file nodes. Does not invent import graphs
(``IMPORTS`` / ``EXTERNAL_IMPORT`` stay reserved until parsers emit them).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, GraphSemanticLayer, RelationshipType

_OVERLAY_SOURCE = "code_graph_overlay"


def _norm_path(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _file_dir(path: str) -> str:
    if "/" not in path:
        return ""
    return path.rsplit("/", 1)[0]


def _module_id(dir_path: str) -> str:
    key = dir_path or "."
    return f"code_module:{key}"


def _dir_node_id(dir_path: str) -> str:
    return "directory:." if dir_path == "" else f"directory:{dir_path}"


def apply_code_graph_overlay(
    graph: UnifiedGraph,
    report_json: dict[str, Any],  # noqa: ARG001 — signature mirrors sibling overlays
    now: datetime,
) -> dict[str, int]:
    """Emit CODE_MODULE / DEFINES from existing SOURCE_FILE evidence."""
    del report_json  # reserved for future inventory-backed module names
    counts = {"code_modules": 0, "defines_edges": 0, "contains_edges": 0}
    now_iso = now.isoformat()

    files_by_dir: dict[str, list[str]] = defaultdict(list)
    for node in graph.nodes.values():
        if node.entity_type != EntityType.SOURCE_FILE:
            continue
        path = _norm_path((node.attributes or {}).get("path") or node.label)
        if not path:
            continue
        files_by_dir[_file_dir(path)].append(node.id)

    if not files_by_dir:
        return counts

    for dir_path in sorted(files_by_dir):
        module_id = _module_id(dir_path)
        file_ids = sorted(files_by_dir[dir_path])
        if module_id not in graph.nodes:
            counts["code_modules"] += 1
        label = dir_path.rsplit("/", 1)[-1] if dir_path else "(repo root)"
        graph.add_node(
            UnifiedNode(
                id=module_id,
                entity_type=EntityType.CODE_MODULE,
                label=label,
                first_seen=now_iso,
                last_seen=now_iso,
                attributes={
                    "path": dir_path or ".",
                    "source_file_count": len(file_ids),
                    "evidence_tier": "static_scan",
                },
                data_sources=[_OVERLAY_SOURCE],
                dimensions=NodeDimensions(surface=GraphSemanticLayer.CODE.value),
            )
        )

        dir_id = _dir_node_id(dir_path)
        if dir_id in graph.nodes:
            graph.add_edge(
                UnifiedEdge(
                    source=dir_id,
                    target=module_id,
                    relationship=RelationshipType.CONTAINS,
                    evidence={"source": _OVERLAY_SOURCE},
                )
            )
            counts["contains_edges"] += 1

        for file_id in file_ids:
            graph.add_edge(
                UnifiedEdge(
                    source=file_id,
                    target=module_id,
                    relationship=RelationshipType.DEFINES,
                    evidence={"source": _OVERLAY_SOURCE},
                )
            )
            counts["defines_edges"] += 1

    return counts
