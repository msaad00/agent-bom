"""Tests for the repository folder/file structure graph overlay.

Covers the contract that a repo / project scan materialises a CODE-layer
directory tree (``DIRECTORY`` nodes + ``CONTAINS`` edges), manifest
(``CONFIG_FILE``) nodes, ``file → package (→ vulnerability)`` paths, and that a
deep tree collapses via the existing server-side ``CONTAINS`` roll-up.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.repo_structure_overlay import apply_repo_structure_overlay
from agent_bom.graph.rollup import rollup_view
from agent_bom.graph.types import EntityType, RelationshipType

_NOW = datetime(2026, 6, 27, tzinfo=timezone.utc)


def _repo_report() -> dict:
    """A minimal repo-scan report: two manifest directories + a direct vuln."""
    return {
        "scan_id": "repo-scan",
        "scan_sources": ["local-discovery"],
        "agents": [
            {
                "name": "project",
                "source": "local",
                "mcp_servers": [
                    {
                        # Server label == repo-root directory path ("").
                        "name": "",
                        "packages": [
                            {
                                "name": "flask",
                                "version": "2.0.0",
                                "ecosystem": "pypi",
                                "is_direct": True,
                                "vulnerabilities": [{"id": "CVE-2025-0001", "severity": "high"}],
                            },
                            {
                                "name": "transitive-dep",
                                "version": "1.0.0",
                                "ecosystem": "pypi",
                                "is_direct": False,
                            },
                        ],
                    },
                    {
                        # A nested project under ui/.
                        "name": "ui",
                        "packages": [
                            {
                                "name": "react",
                                "version": "18.0.0",
                                "ecosystem": "npm",
                                "is_direct": True,
                            }
                        ],
                    },
                ],
            }
        ],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2025-0001",
                "severity": "high",
                "package_name": "flask",
                "package_version": "2.0.0",
                "ecosystem": "pypi",
            }
        ],
        "project_inventory": {
            "root": "/repo",
            "directories": [
                {
                    "path": ".",
                    "package_count": 2,
                    "direct_packages": 1,
                    "manifest_files": ["pyproject.toml", "uv.lock"],
                    "lockfile_files": ["uv.lock"],
                    "declaration_files": ["pyproject.toml"],
                    "ecosystems": {"pypi": 2},
                },
                {
                    "path": "ui",
                    "package_count": 1,
                    "direct_packages": 1,
                    "manifest_files": ["package.json"],
                    "lockfile_files": [],
                    "declaration_files": ["package.json"],
                    "ecosystems": {"npm": 1},
                },
            ],
        },
    }


def test_repo_scan_emits_directory_tree_and_file_dependency_vuln_paths() -> None:
    graph = build_unified_graph_from_report(_repo_report())

    # Directory nodes: repo root + the nested ui/ directory, both CODE layer.
    dir_ids = {n.id for n in graph.nodes.values() if n.entity_type == EntityType.DIRECTORY}
    assert "directory:." in dir_ids
    assert "directory:ui" in dir_ids
    for nid in dir_ids:
        assert graph.nodes[nid].dimensions.surface == "code"

    # Manifest files materialised as CONFIG_FILE nodes.
    assert graph.has_node("config_file:pyproject.toml")
    assert graph.has_node("config_file:uv.lock")
    assert graph.has_node("config_file:ui/package.json")

    contains = {(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.CONTAINS}
    # Tree: root → ui (parent → child) and root → its manifest file.
    assert ("directory:.", "directory:ui") in contains
    assert ("directory:.", "config_file:pyproject.toml") in contains
    assert ("directory:ui", "config_file:ui/package.json") in contains

    # file → package: the declaration manifest declares the DIRECT package only.
    depends = {
        (e.source, e.target)
        for e in graph.edges
        if e.relationship == RelationshipType.DEPENDS_ON and e.source.startswith(("config_file:", "source_file:"))
    }
    flask_id = next(n.id for n in graph.nodes.values() if n.entity_type == EntityType.PACKAGE and n.label.startswith("flask"))
    react_id = next(n.id for n in graph.nodes.values() if n.entity_type == EntityType.PACKAGE and n.label.startswith("react"))
    assert ("config_file:pyproject.toml", flask_id) in depends
    assert ("config_file:ui/package.json", react_id) in depends
    # The transitive dependency is NOT linked from the manifest.
    transitive_id = next(n.id for n in graph.nodes.values() if n.entity_type == EntityType.PACKAGE and n.label.startswith("transitive"))
    assert all(target != transitive_id for _, target in depends)

    # file → package → vulnerability is a complete, traversable path.
    vuln_targets = {e.target for e in graph.edges if e.relationship == RelationshipType.VULNERABLE_TO and e.source == flask_id}
    assert vuln_targets, "flask package should be VULNERABLE_TO a vuln node"
    assert graph.has_node("vuln:CVE-2025-0001")


def test_repo_structure_overlay_is_idempotent() -> None:
    report = _repo_report()
    graph = build_unified_graph_from_report(report)
    nodes_before = set(graph.nodes)
    edges_before = {(e.source, e.target, e.relationship) for e in graph.edges}

    # Applying the overlay again must not add or change anything.
    counts = apply_repo_structure_overlay(graph, report, _NOW)

    assert set(graph.nodes) == nodes_before
    assert {(e.source, e.target, e.relationship) for e in graph.edges} == edges_before
    assert counts["directories"] == 0
    assert counts["files"] == 0


def test_repo_structure_overlay_noop_without_inventory() -> None:
    graph = UnifiedGraph(scan_id="empty")
    counts = apply_repo_structure_overlay(graph, {"agents": []}, _NOW)
    assert counts == {
        "directories": 0,
        "files": 0,
        "contains_edges": 0,
        "file_package_edges": 0,
        "file_finding_edges": 0,
    }
    assert not any(n.entity_type == EntityType.DIRECTORY for n in graph.nodes.values())


def test_deep_directory_tree_collapses_via_contains_rollup() -> None:
    """A deep source tree collapses to a single top-level container via the
    existing CONTAINS roll-up — the same mechanism the cloud hierarchy uses."""
    directories = [
        {"path": "/".join(["src"] + ["pkg%d" % i for i in range(depth)]), "manifest_files": ["__init__.py"]} for depth in range(1, 9)
    ]
    report = {
        "scan_id": "deep",
        "agents": [],
        "project_inventory": {"root": "/repo", "directories": directories},
    }
    graph = build_unified_graph_from_report(report)

    directory_count = sum(1 for n in graph.nodes.values() if n.entity_type == EntityType.DIRECTORY)
    assert directory_count >= 9, "every nested directory + the root becomes a node"

    view = rollup_view(graph)
    # The whole directory tree rolls up under the single repo-root container.
    dir_containers = [c for c in view["top_level"] if c["entity_type"] == EntityType.DIRECTORY.value]
    assert len(dir_containers) == 1
    root_container = dir_containers[0]
    assert root_container["id"] == "directory:."
    # Its rolled-up aggregate reaches the deepest descendants, not just children.
    assert root_container["aggregate"]["descendant_count"] >= 8
