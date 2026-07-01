#!/usr/bin/env python3
"""Validate checked-in graph scale evidence and supported-size claims."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "perf" / "graph-api-postgres-benchmark.md"
POSTGRES_LOAD = ROOT / "docs" / "perf" / "results" / "graph-benchmark-postgres-load-live-2026-07-01.json"
POSTGRES_LATENCY = ROOT / "docs" / "perf" / "results" / "postgres-graph-latency-live-2026-07-01.json"

REQUIRED_QUERIES = {
    "node_search",
    "node_detail",
    "attack_path_drilldown",
    "graph_diff_nodes",
    "graph_history",
    "graph_evidence_manifest_digest",
    "bounded_traversal_edges",
}

P95_LIMIT_MS = 750.0
MIN_SAMPLES = 30
MIN_NODES = 10_000
MIN_EDGES = 10_000


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise AssertionError(f"missing graph scale artifact: {path.relative_to(ROOT)}") from None
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{path.relative_to(ROOT)} is invalid JSON: {exc}") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _check_doc() -> None:
    text = DOC.read_text(encoding="utf-8")
    _require("Owner issue: #3353" in text, "graph benchmark doc must point at lane D issue #3353")
    _require("current measured ceiling" in text.lower(), "graph benchmark doc must state the current measured ceiling")
    _require("100k" in text and "not yet" in text.lower(), "graph benchmark doc must keep 100k+ as not-yet-measured")


def _check_load_artifact() -> tuple[int, int]:
    summary = _load_json(POSTGRES_LOAD)
    _require(summary.get("backend") == "postgres", "graph store load artifact must be for Postgres")
    _require(summary.get("evidence_status") == "graph_store_loaded", "graph store load artifact must be measured")
    _require(summary.get("owner_issue") == 3353, "graph store load artifact owner_issue must be 3353")
    snapshots = summary.get("snapshots")
    _require(isinstance(snapshots, dict), "graph store load artifact must include snapshots")
    current = snapshots.get(summary.get("new_scan_id"))
    _require(isinstance(current, dict), "graph store load artifact must include the current snapshot")
    nodes = int(current.get("total_nodes", 0))
    edges = int(current.get("total_edges", 0))
    _require(nodes >= MIN_NODES, f"Postgres graph evidence must cover at least {MIN_NODES:,} nodes; got {nodes:,}")
    _require(edges >= MIN_EDGES, f"Postgres graph evidence must cover at least {MIN_EDGES:,} edges; got {edges:,}")
    return nodes, edges


def _check_latency_artifact() -> None:
    summary = _load_json(POSTGRES_LATENCY)
    _require(
        summary.get("evidence_status") == "postgres_latency_client_wall_clock",
        "Postgres latency artifact must be measured client wall-clock evidence",
    )
    _require(summary.get("owner_issue") == 3353, "Postgres latency artifact owner_issue must be 3353")
    results = summary.get("results")
    _require(isinstance(results, list) and results, "Postgres latency artifact must include query results")
    names = {str(item.get("name")) for item in results if isinstance(item, dict)}
    missing = sorted(REQUIRED_QUERIES - names)
    _require(not missing, f"Postgres latency artifact missing query families: {missing}")
    for item in results:
        _require(isinstance(item, dict), "Postgres latency result entries must be objects")
        name = str(item.get("name"))
        latency = item.get("latency")
        _require(isinstance(latency, dict), f"{name} latency must be an object")
        samples = int(latency.get("samples", 0))
        p95 = float(latency.get("p95_ms", 0.0))
        _require(samples >= MIN_SAMPLES, f"{name} must have at least {MIN_SAMPLES} samples; got {samples}")
        _require(p95 <= P95_LIMIT_MS, f"{name} p95 {p95}ms exceeds supported-size limit {P95_LIMIT_MS}ms")
        returncodes = item.get("returncode_counts")
        _require(returncodes == {"0": samples}, f"{name} must have all-success return codes; got {returncodes!r}")


def main() -> int:
    try:
        nodes, edges = _check_load_artifact()
        _check_latency_artifact()
        _check_doc()
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"graph scale evidence ok: {nodes:,} nodes / {edges:,} edges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
