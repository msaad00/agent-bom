from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.generate_graph_benchmark_estate import generate_estate
from scripts.run_graph_api_benchmark import request_plan
from scripts.run_graph_postgres_explain import explain_queries


def test_synthetic_estate_has_skewed_topology_and_sources() -> None:
    report, summary = generate_estate(agents=120, seed=2145, vulnerable_package_rate=0.08)

    assert len(report["agents"]) == 120
    assert summary["counts"]["servers"] > 120
    assert summary["counts"]["tools"] > summary["counts"]["servers"]
    assert summary["counts"]["blast_radius_rows"] > 0
    assert summary["skew"]["servers_per_agent"]["p95"] > summary["skew"]["servers_per_agent"]["median"]
    assert summary["skew"]["tools_per_server"]["p99"] > summary["skew"]["tools_per_server"]["median"]
    assert {"local", "k8s-fleet", "operator-push", "cloud-inventory"}.issubset(set(report["scan_sources"]))


def test_api_request_plan_covers_issue_2145_hot_paths() -> None:
    operations = request_plan(
        scan_id="new-scan",
        old_scan_id="old-scan",
        new_scan_id="new-scan",
        source_node="agent:agent-00000",
        detail_node="package:langchain",
    )

    names = {operation["name"] for operation in operations}
    assert names == {"graph_search", "node_detail", "attack_path_drilldown", "graph_diff", "bounded_traversal"}
    assert any(operation["path"] == "/v1/graph/search" for operation in operations)
    assert any(operation["path"].startswith("/v1/graph/node/") for operation in operations)
    assert any(operation["path"] == "/v1/graph/paths" for operation in operations)
    assert any(operation["path"] == "/v1/graph/diff" for operation in operations)
    assert any(operation["method"] == "POST" and operation["path"] == "/v1/graph/query" for operation in operations)


def test_postgres_explain_queries_cover_graph_hot_paths() -> None:
    queries = explain_queries(
        tenant_id="default",
        scan_id="new-scan",
        old_scan_id="old-scan",
        source_node="agent:agent-00000",
        detail_node="package:langchain",
    )

    assert set(queries) == {"node_search", "node_detail", "attack_path_drilldown", "graph_diff_nodes", "bounded_traversal_edges"}
    assert all("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)" in sql for sql in queries.values())
    assert "graph_node_search" in queries["node_search"]
    assert "attack_paths" in queries["attack_path_drilldown"]
    assert "FULL OUTER JOIN" in queries["graph_diff_nodes"]
    assert "WITH RECURSIVE" in queries["bounded_traversal_edges"]


def test_graph_benchmark_scripts_write_dry_run_artifacts(tmp_path: Path) -> None:
    estate_report = tmp_path / "estate-report.json"
    estate_summary = tmp_path / "estate-summary.json"
    api_output = tmp_path / "api.json"
    sqlite_db = tmp_path / "graph.db"
    store_summary = tmp_path / "store-load.json"
    explain_dir = tmp_path / "explain"
    explain_summary = tmp_path / "explain.json"

    commands = [
        [
            sys.executable,
            "scripts/generate_graph_benchmark_estate.py",
            "--agents",
            "25",
            "--report-output",
            str(estate_report),
            "--summary-output",
            str(estate_summary),
        ],
        [
            sys.executable,
            "scripts/seed_graph_benchmark_store.py",
            "--backend",
            "sqlite",
            "--sqlite-db",
            str(sqlite_db),
            "--report",
            str(estate_report),
            "--summary-output",
            str(store_summary),
        ],
        [sys.executable, "scripts/run_graph_api_benchmark.py", "--dry-run", "--output", str(api_output)],
        [
            sys.executable,
            "scripts/run_graph_postgres_explain.py",
            "--dry-run",
            "--output-dir",
            str(explain_dir),
            "--summary-output",
            str(explain_summary),
        ],
    ]
    for command in commands:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    assert json.loads(estate_summary.read_text())["evidence_status"] == "synthetic_estate_shape_only"
    store_load = json.loads(store_summary.read_text())
    assert store_load["evidence_status"] == "graph_store_loaded"
    assert store_load["snapshots"]["graph-benchmark-estate-current"]["total_edges"] > 0
    assert store_load["benchmark_nodes"]["source_node"].startswith("agent:")
    assert store_load["benchmark_nodes"]["detail_node"]
    assert json.loads(api_output.read_text())["evidence_status"] == "scaffold_validated_not_measured"
    explain = json.loads(explain_summary.read_text())
    assert explain["evidence_status"] == "explain_sql_scaffold_not_measured"
    assert (explain_dir / "node_search.sql").exists()
