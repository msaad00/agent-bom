#!/usr/bin/env python3
"""Run or dry-run repeated Postgres graph hot-path latency probes.

This complements ``run_graph_postgres_explain.py``. EXPLAIN artifacts describe
plans; this script measures repeated client wall-clock latency for the same
query families and writes p50/p95/p99 evidence. Dry-run mode writes the SQL
plan without making latency claims.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.run_graph_postgres_explain import explain_queries
except ModuleNotFoundError:  # pragma: no cover - direct script execution path
    from run_graph_postgres_explain import explain_queries

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "docs" / "perf" / "results" / "postgres-graph-latency-sample"
DEFAULT_SUMMARY = ROOT / "docs" / "perf" / "results" / "postgres-graph-latency-sample.json"


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def _strip_explain(sql: str) -> str:
    lines = sql.splitlines()
    if lines and lines[0].startswith("EXPLAIN "):
        return "\n".join(lines[1:]).strip()
    return sql.strip()


def latency_queries(*, tenant_id: str, scan_id: str, old_scan_id: str, source_node: str, detail_node: str) -> dict[str, str]:
    return {
        name: _strip_explain(sql)
        for name, sql in explain_queries(
            tenant_id=tenant_id,
            scan_id=scan_id,
            old_scan_id=old_scan_id,
            source_node=source_node,
            detail_node=detail_node,
        ).items()
    }


def _write_queries(output_dir: Path, queries: dict[str, str]) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for name, sql in queries.items():
        path = output_dir / f"{name}.sql"
        path.write_text(sql + "\n", encoding="utf-8")
        paths[name] = _display_path(path)
    return paths


def _percentiles(values_ms: list[float]) -> dict[str, float | int]:
    if not values_ms:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0, "samples": 0}
    ordered = sorted(values_ms)

    def pct(percent: float) -> float:
        idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percent)))
        return round(ordered[idx], 3)

    return {
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": round(max(ordered), 3),
        "mean_ms": round(statistics.fmean(ordered), 3),
        "samples": len(ordered),
    }


def _run_psql_once(psql_bin: str, dsn: str, sql_path: Path, timeout: float) -> tuple[int, float, str]:
    started = time.perf_counter()
    result = subprocess.run(
        [psql_bin, dsn, "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--quiet", "--tuples-only", "--file", str(sql_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    error = result.stderr.strip() if result.returncode else ""
    return result.returncode, elapsed_ms, error


def _run_queries(
    *,
    psql_bin: str,
    dsn: str,
    query_paths: dict[str, str],
    repeat: int,
    timeout: float,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for name, display_path in query_paths.items():
        sql_path = ROOT / display_path
        timings: list[float] = []
        failures: list[str] = []
        returncodes: dict[str, int] = {}
        for _ in range(repeat):
            try:
                returncode, elapsed_ms, error = _run_psql_once(psql_bin, dsn, sql_path, timeout)
            except subprocess.TimeoutExpired:
                failures.append("psql timed out")
                returncodes["timeout"] = returncodes.get("timeout", 0) + 1
                continue
            returncodes[str(returncode)] = returncodes.get(str(returncode), 0) + 1
            if returncode == 0:
                timings.append(elapsed_ms)
            elif error:
                failures.append(error)
        results.append(
            {
                "name": name,
                "sql": display_path,
                "latency": _percentiles(timings),
                "returncode_counts": returncodes,
                "failures_sample": failures[:5],
            }
        )
    return results


def generate(args: argparse.Namespace) -> dict[str, Any]:
    queries = latency_queries(
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
        "tenant_id": args.tenant_id,
        "scan_id": args.scan_id,
        "old_scan_id": args.old_scan_id,
        "edge_targets": args.edge_targets,
        "repeat": args.repeat,
        "psql_bin": args.psql_bin,
        "query_artifacts": query_paths,
        "commands": {
            "dry_run": "uv run python scripts/run_graph_postgres_latency.py --dry-run",
            "live": (
                "AGENT_BOM_POSTGRES_DSN=postgresql://... uv run python scripts/run_graph_postgres_latency.py "
                "--run --scan-id <new> --old-scan-id <old> --repeat 30"
            ),
        },
    }
    if args.dry_run:
        summary["evidence_status"] = "postgres_latency_scaffold_not_measured"
        summary["results"] = []
        summary["gaps"] = [
            "Dry-run writes non-EXPLAIN SQL only; it does not seed Postgres or measure latency.",
            "Measured artifacts must record database size, Postgres version, tenant, scan IDs, and repeat count.",
        ]
        return summary

    dsn = args.dsn or os.environ.get("AGENT_BOM_POSTGRES_DSN", "")
    if not dsn:
        raise SystemExit("AGENT_BOM_POSTGRES_DSN or --dsn is required unless --dry-run is used.")
    summary["evidence_status"] = "postgres_latency_client_wall_clock"
    summary["results"] = _run_queries(
        psql_bin=args.psql_bin,
        dsn=dsn,
        query_paths=query_paths,
        repeat=args.repeat,
        timeout=args.timeout,
    )
    summary["gaps"] = [
        "Client-side psql wall-clock timings include process startup and client transfer overhead.",
        "Pair these repeated latencies with EXPLAIN ANALYZE plans before making production SLO claims.",
    ]
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark repeated Postgres graph hot-path latency or emit a dry-run SQL plan.")
    parser.add_argument("--dsn", default="", help="Postgres DSN. Defaults to AGENT_BOM_POSTGRES_DSN.")
    parser.add_argument("--psql-bin", default=os.environ.get("AGENT_BOM_PSQL_BIN", "psql"), help="psql executable path.")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--scan-id", default="graph-benchmark-estate-current")
    parser.add_argument("--old-scan-id", default="graph-benchmark-estate-old")
    parser.add_argument("--source-node", default="agent:agent-00000")
    parser.add_argument("--detail-node", default="package:langchain")
    parser.add_argument("--edge-targets", default="10000,50000,100000", help="Documented target edge counts for the loaded estates.")
    parser.add_argument("--repeat", type=int, default=30, help="psql executions per operation in live mode.")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-query timeout in seconds.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--dry-run", action="store_true", help="Write SQL artifacts without running psql.")
    parser.add_argument("--run", action="store_true", help="Run psql against the configured DSN.")
    args = parser.parse_args()

    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
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
