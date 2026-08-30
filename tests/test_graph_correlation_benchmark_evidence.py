from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs" / "perf" / "results" / "graph-correlation-local-2026-08-30.json"


def test_graph_correlation_benchmark_records_required_envelopes_and_limits() -> None:
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert payload["schema"] == "agent-bom.graph-correlation-benchmark/v1"
    assert payload["source_commit"] == "aa1a48096296497a4bb5d458db7b9b6404cddb7d"
    assert "not a Postgres" in payload["scope"]
    assert "no low-memory claim" in " ".join(payload["limitations"])

    results = payload["results"]
    assert [item["output_node_envelope"] for item in results] == [5_000, 25_000, 80_000]
    assert [item["output"]["node_count"] for item in results] == [5_000, 25_000, 80_000]
    assert all(item["status"] == "complete" for item in results)
    assert all(item["correlation_wall_seconds"] > 0 for item in results)
    assert all(item["peak_rss_mb"] >= item["baseline_rss_mb"] for item in results)
    assert all(item["manifest_sha256"].startswith("sha256:") for item in results)
    assert all(item["output"]["graph_digest_sha256"].startswith("sha256:") for item in results)
    assert all(set(item["query_plans"]) == {"snapshot_receipts", "snapshot_nodes", "snapshot_edges"} for item in results)
