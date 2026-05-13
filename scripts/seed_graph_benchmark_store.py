#!/usr/bin/env python3
"""Load graph benchmark estate snapshots into SQLite or Postgres stores."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.api.graph_store import SQLiteGraphStore  # noqa: E402
from agent_bom.graph import AttackPath, EntityType, RelationshipType, build_unified_graph_from_report  # noqa: E402

DEFAULT_REPORT = ROOT / "docs" / "perf" / "results" / "graph-benchmark-estate-sample-report.json"
DEFAULT_SUMMARY = ROOT / "docs" / "perf" / "results" / "graph-benchmark-store-load-sample.json"


def _load_report(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        report = json.load(handle)
    if not isinstance(report, dict):
        raise SystemExit(f"{path} must contain a JSON object.")
    if not isinstance(report.get("agents"), list) or not report["agents"]:
        raise SystemExit(f"{path} must contain at least one agent.")
    return report


def _prune_report(report: dict[str, Any], *, agent_count: int) -> dict[str, Any]:
    pruned = copy.deepcopy(report)
    agents = list(pruned.get("agents", []))[:agent_count]
    retained_names = {str(agent.get("name") or "") for agent in agents if isinstance(agent, dict)}
    blast_radius: list[dict[str, Any]] = []
    for row in pruned.get("blast_radius", []):
        if not isinstance(row, dict):
            continue
        affected_agents = row.get("affected_agents") or []
        if not affected_agents or any(str(agent) in retained_names for agent in affected_agents):
            blast_radius.append(row)
    pruned["agents"] = agents
    pruned["blast_radius"] = blast_radius
    return pruned


def _build_snapshot(report: dict[str, Any], *, scan_id: str, tenant_id: str, created_at: str):
    graph = build_unified_graph_from_report(report, scan_id=scan_id, tenant_id=tenant_id)
    graph.created_at = created_at
    _materialize_attack_paths(graph)
    return graph


def _materialize_attack_paths(graph, *, limit: int = 2_500) -> None:
    incoming: dict[str, list[Any]] = {}
    outgoing: dict[str, list[Any]] = {}
    for edge in graph.edges:
        incoming.setdefault(edge.target, []).append(edge)
        outgoing.setdefault(edge.source, []).append(edge)

    paths: list[AttackPath] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in graph.nodes.values():
        node_type = finding.entity_type.value if isinstance(finding.entity_type, EntityType) else str(finding.entity_type)
        if node_type not in {EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value}:
            continue
        for finding_edge in incoming.get(finding.id, []):
            rel = (
                finding_edge.relationship.value
                if isinstance(finding_edge.relationship, RelationshipType)
                else str(finding_edge.relationship)
            )
            if rel != RelationshipType.VULNERABLE_TO.value:
                continue
            candidate_servers = [finding_edge.source]
            source_node = graph.nodes.get(finding_edge.source)
            source_type = source_node.entity_type.value if source_node and isinstance(source_node.entity_type, EntityType) else ""
            if source_type == EntityType.PACKAGE.value:
                candidate_servers = [
                    edge.source
                    for edge in incoming.get(finding_edge.source, [])
                    if edge.relationship == RelationshipType.DEPENDS_ON and edge.source in graph.nodes
                ]
            for server_id in candidate_servers:
                agent_edges = [edge for edge in incoming.get(server_id, []) if edge.relationship == RelationshipType.USES]
                if not agent_edges:
                    continue
                tool_labels = [
                    graph.nodes[edge.target].label
                    for edge in outgoing.get(server_id, [])
                    if edge.relationship == RelationshipType.PROVIDES_TOOL and edge.target in graph.nodes
                ][:6]
                cred_labels = [
                    graph.nodes[edge.target].label
                    for edge in outgoing.get(server_id, [])
                    if edge.relationship == RelationshipType.EXPOSES_CRED and edge.target in graph.nodes
                ][:6]
                for agent_edge in agent_edges:
                    key = (agent_edge.source, server_id, finding.id)
                    if key in seen:
                        continue
                    seen.add(key)
                    paths.append(
                        AttackPath(
                            source=agent_edge.source,
                            target=finding.id,
                            hops=[agent_edge.source, server_id, finding.id],
                            edges=[RelationshipType.USES.value, RelationshipType.VULNERABLE_TO.value],
                            composite_risk=max(float(finding.risk_score or 0), float(finding_edge.weight or 0)),
                            summary=f"{agent_edge.source} -> {server_id} -> {finding.label}",
                            credential_exposure=cred_labels,
                            tool_exposure=tool_labels,
                            vuln_ids=[finding.label],
                        )
                    )
                    if len(paths) >= limit:
                        graph.attack_paths = paths
                        return
    graph.attack_paths = paths


def _store_for_backend(args: argparse.Namespace):
    if args.backend == "sqlite":
        return SQLiteGraphStore(args.sqlite_db)
    os.environ["AGENT_BOM_POSTGRES_URL"] = args.postgres_dsn or os.environ.get("AGENT_BOM_POSTGRES_URL", "")
    if not os.environ["AGENT_BOM_POSTGRES_URL"]:
        raise SystemExit("--postgres-dsn or AGENT_BOM_POSTGRES_URL is required for --backend postgres.")
    from agent_bom.api.postgres_graph import PostgresGraphStore

    return PostgresGraphStore()


def _sample_node(graph, *, entity_type: EntityType, contains: str = "") -> str:
    contains_l = contains.lower()
    for node in graph.nodes.values():
        node_type = node.entity_type if isinstance(node.entity_type, EntityType) else EntityType(str(node.entity_type))
        if node_type != entity_type:
            continue
        haystack = f"{node.id} {node.label}".lower()
        if not contains_l or contains_l in haystack:
            return node.id
    return ""


def _summary(args: argparse.Namespace, old_graph, current_graph) -> dict[str, Any]:
    report_path = args.report.resolve()
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "owner_issue": 2145,
        "evidence_status": "graph_store_loaded",
        "backend": args.backend,
        "tenant_id": args.tenant_id,
        "old_scan_id": args.old_scan_id,
        "new_scan_id": args.new_scan_id,
        "source_report": str(report_path.relative_to(ROOT) if report_path.is_relative_to(ROOT) else report_path),
        "source_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "benchmark_nodes": {
            "source_node": _sample_node(current_graph, entity_type=EntityType.AGENT),
            "detail_node": _sample_node(current_graph, entity_type=EntityType.PACKAGE, contains=args.detail_package),
        },
        "snapshots": {
            args.old_scan_id: old_graph.stats(),
            args.new_scan_id: current_graph.stats(),
        },
        "commands": {
            "sqlite": (
                "uv run python scripts/seed_graph_benchmark_store.py --backend sqlite --sqlite-db /tmp/agent-bom-graph-benchmark.db"
            ),
            "postgres": ("AGENT_BOM_POSTGRES_URL=postgresql://... uv run python scripts/seed_graph_benchmark_store.py --backend postgres"),
        },
    }


def generate(args: argparse.Namespace) -> dict[str, Any]:
    report = _load_report(args.report)
    old_count = args.old_agent_count or max(1, int(len(report["agents"]) * 0.8))
    if old_count >= len(report["agents"]):
        raise SystemExit("--old-agent-count must be lower than the report agent count.")

    old_report = _prune_report(report, agent_count=old_count)
    current_report = copy.deepcopy(report)
    old_graph = _build_snapshot(
        old_report,
        scan_id=args.old_scan_id,
        tenant_id=args.tenant_id,
        created_at="2026-05-12T00:00:00Z",
    )
    current_graph = _build_snapshot(
        current_report,
        scan_id=args.new_scan_id,
        tenant_id=args.tenant_id,
        created_at="2026-05-13T00:00:00Z",
    )

    store = _store_for_backend(args)
    store.save_graph(old_graph)
    store.save_graph(current_graph)
    if args.backend == "postgres":
        from agent_bom.api import postgres_common

        pool = getattr(postgres_common, "_pool", None)
        if pool is not None:
            pool.close()

    summary = _summary(args, old_graph, current_graph)
    summary["old_agent_count"] = old_count
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed graph benchmark snapshots into a queryable graph store.")
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default="sqlite")
    parser.add_argument("--sqlite-db", type=Path, default=Path("/tmp/agent-bom-graph-benchmark.db"))
    parser.add_argument("--postgres-dsn", default="", help="Postgres DSN. Defaults to AGENT_BOM_POSTGRES_URL.")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--old-scan-id", default="graph-benchmark-estate-old")
    parser.add_argument("--new-scan-id", default="graph-benchmark-estate-current")
    parser.add_argument("--old-agent-count", type=int, default=0)
    parser.add_argument("--detail-package", default="langchain")
    args = parser.parse_args()

    summary = generate(args)
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.summary_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
