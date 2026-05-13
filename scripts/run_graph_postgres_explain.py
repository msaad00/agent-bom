#!/usr/bin/env python3
"""Generate or run Postgres EXPLAIN plans for graph hot-path queries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "docs" / "perf" / "results" / "postgres-graph-explain-sample"
DEFAULT_SUMMARY = ROOT / "docs" / "perf" / "results" / "postgres-graph-explain-sample.json"


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def explain_queries(*, tenant_id: str, scan_id: str, old_scan_id: str, source_node: str, detail_node: str) -> dict[str, str]:
    prefix = "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)"
    tenant = _sql_literal(tenant_id)
    scan = _sql_literal(scan_id)
    old_scan = _sql_literal(old_scan_id)
    source = _sql_literal(source_node)
    detail = _sql_literal(detail_node)
    return {
        "node_search": f"""
{prefix}
SELECT gn.id, gn.entity_type, gn.label, gn.severity_id, gn.risk_score
FROM graph_node_search gns
JOIN graph_nodes gn
  ON gn.id = gns.node_id
 AND gn.scan_id = gns.scan_id
 AND gn.tenant_id = gns.tenant_id
WHERE gns.tenant_id = {tenant}
  AND gns.scan_id = {scan}
  AND LOWER(gns.search_text) LIKE '%langchain%'
ORDER BY gn.severity_id DESC, gn.risk_score DESC, gn.label ASC, gn.id ASC
LIMIT 50;
""".strip(),
        "node_detail": f"""
{prefix}
SELECT source_id, target_id, relationship, direction, weight, traversable
FROM graph_edges
WHERE tenant_id = {tenant}
  AND scan_id = {scan}
  AND (source_id = {detail} OR target_id = {detail});
""".strip(),
        "attack_path_drilldown": f"""
{prefix}
SELECT source_node, target_node, hop_count, composite_risk, path_nodes, path_edges
FROM attack_paths
WHERE tenant_id = {tenant}
  AND scan_id = {scan}
  AND source_node = {source}
ORDER BY composite_risk DESC
LIMIT 100;
""".strip(),
        "graph_diff_nodes": f"""
{prefix}
SELECT COALESCE(new_nodes.id, old_nodes.id) AS node_id,
       CASE
         WHEN old_nodes.id IS NULL THEN 'added'
         WHEN new_nodes.id IS NULL THEN 'removed'
         WHEN old_nodes.attributes <> new_nodes.attributes THEN 'changed'
         ELSE 'same'
       END AS diff_state
FROM (
  SELECT id, attributes FROM graph_nodes
  WHERE tenant_id = {tenant} AND scan_id = {old_scan}
) old_nodes
FULL OUTER JOIN (
  SELECT id, attributes FROM graph_nodes
  WHERE tenant_id = {tenant} AND scan_id = {scan}
) new_nodes USING (id)
WHERE old_nodes.id IS NULL
   OR new_nodes.id IS NULL
   OR old_nodes.attributes <> new_nodes.attributes
LIMIT 500;
""".strip(),
        "bounded_traversal_edges": f"""
{prefix}
WITH RECURSIVE walk(node_id, depth) AS (
  SELECT {source}::text, 0
  UNION ALL
  SELECT e.target_id, walk.depth + 1
  FROM walk
  JOIN graph_edges e
    ON e.tenant_id = {tenant}
   AND e.scan_id = {scan}
   AND e.source_id = walk.node_id
   AND e.traversable = 1
  WHERE walk.depth < 3
)
SELECT DISTINCT node_id, depth
FROM walk
LIMIT 500;
""".strip(),
    }


def _write_queries(output_dir: Path, queries: dict[str, str]) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for name, sql in queries.items():
        path = output_dir / f"{name}.sql"
        path.write_text(sql + "\n", encoding="utf-8")
        paths[name] = str(path)
    return paths


def _display_path(path: str) -> str:
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def _run_psql(psql_bin: str, dsn: str, sql_path: Path, output_path: Path) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [psql_bin, dsn, "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--file", str(sql_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    output_path.write_text(result.stdout + ("\n" + result.stderr if result.stderr else ""), encoding="utf-8")
    return {"returncode": result.returncode, "output": str(output_path)}


def generate(args: argparse.Namespace) -> dict[str, Any]:
    queries = explain_queries(
        tenant_id=args.tenant_id,
        scan_id=args.scan_id,
        old_scan_id=args.old_scan_id,
        source_node=args.source_node,
        detail_node=args.detail_node,
    )
    query_paths = _write_queries(args.output_dir, queries)
    summary: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "owner_issue": 2145,
        "evidence_status": "explain_sql_scaffold_not_measured" if args.dry_run else "explain_analyze_artifacts",
        "tenant_id": args.tenant_id,
        "scan_id": args.scan_id,
        "old_scan_id": args.old_scan_id,
        "edge_targets": args.edge_targets,
        "psql_bin": args.psql_bin,
        "query_artifacts": {name: _display_path(path) for name, path in query_paths.items()},
        "commands": {
            "dry_run": "uv run python scripts/run_graph_postgres_explain.py --dry-run",
            "live": (
                "AGENT_BOM_POSTGRES_DSN=postgresql://... uv run python scripts/run_graph_postgres_explain.py "
                "--run --scan-id <new> --old-scan-id <old>"
            ),
        },
    }
    if args.dry_run:
        summary["gaps"] = [
            "Dry-run writes EXPLAIN SQL only; it does not seed Postgres or execute EXPLAIN ANALYZE.",
            "Measured artifacts must be captured from a database loaded with the matching synthetic estate snapshots.",
        ]
        return summary

    dsn = args.dsn or os.environ.get("AGENT_BOM_POSTGRES_DSN", "")
    if not dsn:
        raise SystemExit("AGENT_BOM_POSTGRES_DSN or --dsn is required unless --dry-run is used.")
    plan_dir = args.output_dir / "plans"
    summary["plans"] = {name: _run_psql(args.psql_bin, dsn, Path(path), plan_dir / f"{name}.txt") for name, path in query_paths.items()}
    summary["gaps"] = [
        "EXPLAIN ANALYZE timings are database-local and should be paired with API client timings for full deployment evidence.",
        "Plan quality depends on loaded scan cardinality, index availability, Postgres version, and tenant/session settings.",
    ]
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or run Postgres EXPLAIN ANALYZE artifacts for graph hot paths.")
    parser.add_argument("--dsn", default="", help="Postgres DSN. Defaults to AGENT_BOM_POSTGRES_DSN.")
    parser.add_argument("--psql-bin", default=os.environ.get("AGENT_BOM_PSQL_BIN", "psql"), help="psql executable path.")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--scan-id", default="graph-benchmark-estate-current")
    parser.add_argument("--old-scan-id", default="graph-benchmark-estate-old")
    parser.add_argument("--source-node", default="agent:agent-00000")
    parser.add_argument("--detail-node", default="package:langchain")
    parser.add_argument("--edge-targets", default="10000,50000,100000", help="Documented target edge counts for the loaded estates.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--dry-run", action="store_true", help="Write SQL artifacts without running psql.")
    parser.add_argument("--run", action="store_true", help="Run psql against the configured DSN.")
    args = parser.parse_args()

    if args.run:
        args.dry_run = False
    elif not args.dry_run:
        args.dry_run = True
    summary = generate(args)
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.summary_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
