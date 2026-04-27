#!/usr/bin/env python3
"""Generate local synthetic scale evidence for graph and fleet hot paths.

The output is intentionally explicit about scope: this is a reproducible local
benchmark for graph build/query and Kubernetes reconciliation CPU paths. It is
not a substitute for the broader Postgres/EKS/load-test evidence tracked in
#1806.
"""

from __future__ import annotations

import argparse
import json
import platform
import resource
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_bom.fleet.k8s_reconcile import reconcile_k8s_inventory
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "perf" / "results" / "scale-evidence-local-2026-04-26.json"
ESTATE_SIZES = (1_000, 5_000, 10_000)


def _rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if platform.system() == "Darwin":
        return usage / (1024 * 1024)
    return usage / 1024


def _percentiles(values_ms: list[float]) -> dict[str, float]:
    if not values_ms:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}
    ordered = sorted(values_ms)

    def pct(percent: float) -> float:
        idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percent)))
        return round(ordered[idx], 3)

    return {
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
    }


def _time_call(fn, *args, repeat: int = 25, **kwargs) -> dict[str, Any]:
    values: list[float] = []
    result: Any = None
    for _ in range(repeat):
        started = time.perf_counter()
        result = fn(*args, **kwargs)
        values.append((time.perf_counter() - started) * 1000)
    return {**_percentiles(values), "runs": repeat, "last_result": result}


def _synth_report(n_agents: int) -> dict[str, Any]:
    agents: list[dict[str, Any]] = []
    blast_radius: list[dict[str, Any]] = []
    for idx in range(n_agents):
        package_a = f"pkg-{idx}-core"
        package_b = f"pkg-{idx}-tool"
        agent_name = f"agent-{idx}"
        server_name = f"server-{idx}"
        agents.append(
            {
                "name": agent_name,
                "type": "claude-desktop" if idx % 2 == 0 else "cursor",
                "status": "configured",
                "mcp_servers": [
                    {
                        "name": server_name,
                        "transport": "sse",
                        "url": f"https://mcp-{idx}.example.internal/sse",
                        "surface": "mcp-server",
                        "credential_env_vars": [f"AGENT_{idx}_TOKEN"] if idx % 10 == 0 else [],
                        "packages": [
                            {"name": package_a, "version": "1.0.0", "ecosystem": "npm", "is_direct": True},
                            {"name": package_b, "version": "2.0.0", "ecosystem": "pypi", "is_direct": False},
                        ],
                        "tools": [{"name": f"tool-{idx}"}],
                    }
                ],
            }
        )
        if idx % 10 == 0:
            blast_radius.append(
                {
                    "vulnerability_id": f"CVE-2026-{idx:06d}",
                    "severity": ["critical", "high", "medium", "low"][(idx // 10) % 4],
                    "package_name": package_a,
                    "package": package_a,
                    "package_version": "1.0.0",
                    "fixed_version": "1.0.1",
                    "affected_agents": [agent_name],
                    "affected_servers": [{"name": server_name}],
                    "owasp_tags": ["LLM05"],
                    "soc2_tags": ["CC6.1"],
                }
            )
    return {
        "scan_id": f"scale-evidence-{n_agents}",
        "generated_at": "2026-04-26T00:00:00Z",
        "tool_version": "local",
        "scan_sources": ["synthetic-scale-evidence"],
        "agents": agents,
        "blast_radius": blast_radius,
    }


def _synth_observations(
    n_items: int,
    *,
    changed_every: int = 17,
    missing_every: int = 29,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    previous: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    for idx in range(n_items):
        base = {
            "tenant_id": "scale-evidence",
            "cluster": "eks-scale",
            "namespace": f"team-{idx % 25}",
            "workload": f"agent-workload-{idx}",
            "agent_name": f"agent-{idx}",
            "server_name": f"server-{idx}",
            "surface": "mcp-server",
            "node_name": f"ip-10-0-{idx % 255}-{idx % 31}",
            "image": f"example.com/agent-{idx % 50}:1.0.0",
            "endpoint": f"https://agent-{idx}.example.internal",
            "observed_at": "2026-04-26T00:00:00+00:00",
            "discovery_sources": ["k8s", "mcp"],
        }
        previous.append(dict(base))
        if idx % missing_every == 0:
            continue
        updated = dict(base)
        if idx % changed_every == 0:
            updated["image"] = f"example.com/agent-{idx % 50}:1.0.1"
        current.append(updated)
    return previous, current


def _measure_graph(n_agents: int) -> dict[str, Any]:
    report = _synth_report(n_agents)
    rss_before = _rss_mb()
    started = time.perf_counter()
    graph = build_unified_graph_from_report(report)
    build_ms = (time.perf_counter() - started) * 1000
    rss_after = _rss_mb()
    roots = [f"agent:{idx}" for idx in range(0, n_agents, max(1, n_agents // 25))]

    search = _time_call(graph.search_nodes, "agent-", repeat=30, limit=80)
    selectors = _time_call(graph.filter_nodes, repeat=30, entity_types={EntityType.AGENT})
    neighborhood = _time_call(graph.traverse_subgraph, roots[:3], repeat=30, max_depth=3, max_nodes=500, max_edges=5_000)

    return {
        "estate_size_agents": n_agents,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "build_ms": round(build_ms, 3),
        "nodes_per_second": round(len(graph.nodes) / max(build_ms / 1000, 0.001), 2),
        "edges_per_second": round(len(graph.edges) / max(build_ms / 1000, 0.001), 2),
        "rss_delta_mb": round(max(0.0, rss_after - rss_before), 3),
        "search": {k: v for k, v in search.items() if k != "last_result"},
        "agent_selector": {k: v for k, v in selectors.items() if k != "last_result"},
        "bounded_neighborhood": {k: v for k, v in neighborhood.items() if k != "last_result"},
    }


def _measure_fleet(n_items: int) -> dict[str, Any]:
    previous, current = _synth_observations(n_items)
    started = time.perf_counter()
    result = reconcile_k8s_inventory(previous, current)
    wall_ms = (time.perf_counter() - started) * 1000
    return {
        "estate_size_observations": n_items,
        "previous": len(previous),
        "current": len(current),
        "wall_ms": round(wall_ms, 3),
        "observations_per_second": round((len(previous) + len(current)) / max(wall_ms / 1000, 0.001), 2),
        "summary": result["summary"],
    }


def generate() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "local synthetic CPU benchmark; Postgres/EKS/load-test evidence remains tracked in #1806",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "graph": [_measure_graph(size) for size in ESTATE_SIZES],
        "fleet": [_measure_fleet(size) for size in ESTATE_SIZES],
        "gaps": [
            "Postgres persistence throughput is not measured by this local synthetic run.",
            "HTTP API p95/p99 under k6 is not measured by this local synthetic run.",
            "EKS multi-node HA behavior remains tracked in #1806.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    evidence = generate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        display = args.output.resolve().relative_to(ROOT)
    except ValueError:
        display = args.output
    print(display)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
