#!/usr/bin/env python3
"""Run or dry-run graph API benchmark requests.

Dry-run mode validates the request plan and writes a truthful artifact with no
latency claims. Live mode sends bounded requests to an already-running API and
records p50/p95/p99 wall-clock timings from this client.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "perf" / "results" / "graph-api-benchmark-sample.json"


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


def request_plan(*, scan_id: str, old_scan_id: str, new_scan_id: str, source_node: str, detail_node: str) -> list[dict[str, Any]]:
    scan_param = {"scan_id": scan_id} if scan_id else {}
    return [
        {
            "name": "graph_search",
            "method": "GET",
            "path": "/v1/graph/search",
            "query": {"q": "langchain", "entity_types": "package,vulnerability", "limit": "50", **scan_param},
        },
        {
            "name": "node_detail",
            "method": "GET",
            "path": f"/v1/graph/node/{detail_node}",
            "query": scan_param,
        },
        {
            "name": "attack_path_drilldown",
            "method": "GET",
            "path": "/v1/graph/paths",
            "query": {"source_id": source_node, "max_depth": "4", "limit": "100", **scan_param},
        },
        {
            "name": "graph_diff",
            "method": "GET",
            "path": "/v1/graph/diff",
            "query": {"old": old_scan_id, "new": new_scan_id},
        },
        {
            "name": "bounded_traversal",
            "method": "POST",
            "path": "/v1/graph/query",
            "query": {},
            "json": {
                "roots": [source_node],
                "scan_id": scan_id,
                "direction": "both",
                "max_depth": 3,
                "max_nodes": 500,
                "max_edges": 5000,
                "timeout_ms": 2500,
                "traversable_only": True,
                "include_attack_paths": True,
            },
        },
    ]


def _url(base_url: str, operation: dict[str, Any]) -> str:
    base = base_url.rstrip("/") + operation["path"]
    query = operation.get("query") or {}
    return base + ("?" + urlencode(query) if query else "")


def _send(base_url: str, operation: dict[str, Any], *, token: str, tenant_id: str, timeout: float) -> tuple[int, int]:
    body = None
    headers = {"Accept": "application/json", "X-Agent-Bom-Tenant-ID": tenant_id}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if operation["method"] == "POST":
        body = json.dumps(operation.get("json") or {}).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(_url(base_url, operation), data=body, headers=headers, method=operation["method"])
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - benchmark target is user-supplied by CLI.
        payload = response.read()
        return response.status, len(payload)


def run_live(
    *,
    base_url: str,
    operations: list[dict[str, Any]],
    repeat: int,
    token: str,
    tenant_id: str,
    timeout: float,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for operation in operations:
        timings: list[float] = []
        statuses: dict[str, int] = {}
        bytes_read = 0
        failures: list[str] = []
        for _ in range(repeat):
            started = time.perf_counter()
            try:
                status, size = _send(base_url, operation, token=token, tenant_id=tenant_id, timeout=timeout)
                timings.append((time.perf_counter() - started) * 1000)
                statuses[str(status)] = statuses.get(str(status), 0) + 1
                bytes_read = size
            except HTTPError as exc:
                statuses[str(exc.code)] = statuses.get(str(exc.code), 0) + 1
                failures.append(f"HTTP {exc.code}: {exc.reason}")
            except URLError as exc:
                failures.append(str(exc.reason))
            except TimeoutError:
                failures.append("request timed out")
        results.append(
            {
                "name": operation["name"],
                "method": operation["method"],
                "path": operation["path"],
                "status_counts": statuses,
                "response_bytes_last": bytes_read,
                "latency": _percentiles(timings),
                "failures_sample": failures[:5],
            }
        )
    return results


def generate(args: argparse.Namespace) -> dict[str, Any]:
    operations = request_plan(
        scan_id=args.scan_id,
        old_scan_id=args.old_scan_id,
        new_scan_id=args.new_scan_id,
        source_node=args.source_node,
        detail_node=args.detail_node,
    )
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "owner_issue": 2145,
        "base_url": args.base_url,
        "tenant_id": args.tenant_id,
        "repeat": args.repeat,
        "request_plan": operations,
        "commands": {
            "dry_run": "uv run python scripts/run_graph_api_benchmark.py --dry-run",
            "live": (
                "AGENT_BOM_API_TOKEN=... uv run python scripts/run_graph_api_benchmark.py "
                "--base-url http://127.0.0.1:8000 --scan-id <scan> --old-scan-id <old> --new-scan-id <new>"
            ),
        },
    }
    if args.dry_run:
        evidence["evidence_status"] = "scaffold_validated_not_measured"
        evidence["results"] = []
        evidence["gaps"] = [
            "Dry-run does not start the API, authenticate, or measure network/server latency.",
            "Live results must record the API auth mode, tenant, graph backend, and scan IDs used.",
        ]
        return evidence

    evidence["evidence_status"] = "measured_api_client_wall_clock"
    evidence["results"] = run_live(
        base_url=args.base_url,
        operations=operations,
        repeat=args.repeat,
        token=args.token or os.environ.get("AGENT_BOM_API_TOKEN", ""),
        tenant_id=args.tenant_id,
        timeout=args.timeout,
    )
    evidence["gaps"] = [
        "Client-side timings include local network and client JSON transfer time.",
        "Server-side DB plans are measured separately by scripts/run_graph_postgres_explain.py.",
    ]
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark graph API hot paths or emit a dry-run request plan.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Running agent-bom API base URL.")
    parser.add_argument("--tenant-id", default="default", help="Tenant header to send.")
    parser.add_argument("--token", default="", help="Bearer token. Defaults to AGENT_BOM_API_TOKEN.")
    parser.add_argument("--scan-id", default="graph-benchmark-estate-current", help="Scan ID for latest/single-snapshot requests.")
    parser.add_argument("--old-scan-id", default="graph-benchmark-estate-old", help="Old scan ID for /v1/graph/diff.")
    parser.add_argument("--new-scan-id", default="graph-benchmark-estate-current", help="New scan ID for /v1/graph/diff.")
    parser.add_argument("--source-node", default="agent:agent-00000", help="Source node for path/traversal requests.")
    parser.add_argument("--detail-node", default="package:langchain", help="Node ID for detail request.")
    parser.add_argument("--repeat", type=int, default=20, help="Requests per operation in live mode.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="JSON evidence output path.")
    parser.add_argument("--dry-run", action="store_true", help="Write request plan without sending HTTP requests.")
    args = parser.parse_args()

    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
    evidence = generate(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
