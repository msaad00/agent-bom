#!/usr/bin/env python3
"""Generate a deterministic synthetic graph estate for benchmark evidence.

The shape is intentionally skewed: a small number of agents have many MCP
servers/tools, most have few, and packages include a mix of shared platform
dependencies and unique service dependencies. The output is a scanner-style
report that can be loaded by the existing graph builder without changing graph
runtime behavior.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_REPORT = ROOT / "docs" / "perf" / "results" / "graph-benchmark-estate-sample-report.json"
DEFAULT_SUMMARY = ROOT / "docs" / "perf" / "results" / "graph-benchmark-estate-sample.json"

SOURCES = ("local", "github-action", "k8s-fleet", "operator-push", "cloud-inventory")
AGENT_TYPES = ("claude-desktop", "cursor", "windsurf", "vscode", "cortex-code")
ECOSYSTEMS = ("npm", "pypi", "go", "maven", "oci")
SEVERITIES = ("critical", "high", "medium", "low")
POPULAR_PACKAGES = (
    "langchain",
    "openai",
    "anthropic",
    "mcp-sdk",
    "fastapi",
    "requests",
    "zod",
    "react",
    "next",
    "protobuf",
    "grpc",
    "boto3",
)


def _percentile(values: list[int], pct: float) -> int:
    ordered = sorted(values)
    if not ordered:
        return 0
    idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * pct)))
    return ordered[idx]


def _skewed_server_count(idx: int, rng: random.Random) -> int:
    if idx % 97 == 0:
        return rng.randint(18, 32)
    if idx % 23 == 0:
        return rng.randint(7, 14)
    if idx % 7 == 0:
        return rng.randint(3, 6)
    return 1 if rng.random() < 0.68 else 2


def _skewed_tool_count(agent_idx: int, server_idx: int, rng: random.Random) -> int:
    if agent_idx % 97 == 0 and server_idx < 4:
        return rng.randint(20, 45)
    if agent_idx % 23 == 0:
        return rng.randint(8, 18)
    return rng.randint(1, 5)


def _package_count(agent_idx: int, server_idx: int, rng: random.Random) -> int:
    if agent_idx % 97 == 0:
        return rng.randint(16, 28)
    if server_idx % 5 == 0:
        return rng.randint(8, 14)
    return rng.randint(3, 8)


def _source_mix(idx: int) -> list[str]:
    primary = SOURCES[idx % len(SOURCES)]
    sources = [primary]
    if idx % 5 == 0:
        sources.append("operator-push")
    if idx % 11 == 0:
        sources.append("cloud-inventory")
    return sorted(set(sources))


def _package_name(agent_idx: int, server_idx: int, package_idx: int, rng: random.Random) -> str:
    if rng.random() < 0.42:
        return POPULAR_PACKAGES[(agent_idx + server_idx + package_idx) % len(POPULAR_PACKAGES)]
    if rng.random() < 0.18:
        return f"team-shared-{(agent_idx // 25) % 25}-{package_idx % 9}"
    return f"svc-{agent_idx:05d}-{server_idx:02d}-{package_idx:02d}"


def generate_estate(*, agents: int, seed: int, vulnerable_package_rate: float) -> tuple[dict[str, Any], dict[str, Any]]:
    rng = random.Random(seed)
    report_agents: list[dict[str, Any]] = []
    blast_radius: list[dict[str, Any]] = []
    server_counts: list[int] = []
    tool_counts: list[int] = []
    package_counts: list[int] = []
    source_counts = {source: 0 for source in SOURCES}
    package_seen: set[str] = set()
    vulnerable_seen: set[str] = set()

    for agent_idx in range(agents):
        agent_name = f"agent-{agent_idx:05d}"
        agent_sources = _source_mix(agent_idx)
        for source in agent_sources:
            source_counts[source] += 1
        servers: list[dict[str, Any]] = []
        server_count = _skewed_server_count(agent_idx, rng)
        server_counts.append(server_count)
        for server_idx in range(server_count):
            server_name = f"{agent_name}-mcp-{server_idx:02d}"
            tool_count = _skewed_tool_count(agent_idx, server_idx, rng)
            package_count = _package_count(agent_idx, server_idx, rng)
            tool_counts.append(tool_count)
            package_counts.append(package_count)
            packages: list[dict[str, Any]] = []
            for package_idx in range(package_count):
                package_name = _package_name(agent_idx, server_idx, package_idx, rng)
                package_seen.add(package_name)
                ecosystem = ECOSYSTEMS[(agent_idx + server_idx + package_idx) % len(ECOSYSTEMS)]
                packages.append(
                    {
                        "name": package_name,
                        "version": f"{1 + package_idx % 3}.{server_idx % 10}.{agent_idx % 17}",
                        "ecosystem": ecosystem,
                        "is_direct": package_idx < 2 or rng.random() < 0.22,
                    }
                )
                if package_name not in vulnerable_seen and rng.random() < vulnerable_package_rate:
                    vulnerable_seen.add(package_name)
                    vuln_id = f"CVE-2026-{len(vulnerable_seen):06d}"
                    blast_radius.append(
                        {
                            "vulnerability_id": vuln_id,
                            "severity": SEVERITIES[(agent_idx + package_idx) % len(SEVERITIES)],
                            "package": package_name,
                            "package_name": package_name,
                            "package_version": packages[-1]["version"],
                            "fixed_version": f"{packages[-1]['version']}.1",
                            "affected_agents": [agent_name],
                            "affected_servers": [{"name": server_name}],
                            "exposed_tools": [f"{server_name}-tool-{i:02d}" for i in range(min(tool_count, 4))],
                            "exposed_credentials": [f"{agent_name.upper().replace('-', '_')}_TOKEN"] if agent_idx % 9 == 0 else [],
                            "owasp_tags": ["LLM05", "LLM06"],
                            "soc2_tags": ["CC6.1"],
                        }
                    )
            servers.append(
                {
                    "name": server_name,
                    "transport": "sse" if server_idx % 3 else "stdio",
                    "url": f"https://mcp-{agent_idx % 200}.example.internal/{server_idx}" if server_idx % 3 else "",
                    "surface": "mcp-server",
                    "credential_env_vars": [f"{agent_name.upper().replace('-', '_')}_TOKEN"] if agent_idx % 9 == 0 else [],
                    "packages": packages,
                    "tools": [{"name": f"{server_name}-tool-{tool_idx:02d}"} for tool_idx in range(tool_count)],
                    "discovery_sources": agent_sources,
                    "registry_verified": server_idx % 4 != 0,
                }
            )
        report_agents.append(
            {
                "name": agent_name,
                "type": AGENT_TYPES[agent_idx % len(AGENT_TYPES)],
                "status": "configured",
                "mcp_servers": servers,
                "discovery_sources": agent_sources,
                "source": agent_sources[0],
            }
        )

    report = {
        "scan_id": f"graph-benchmark-estate-{agents}-{seed}",
        "generated_at": "2026-05-13T00:00:00Z",
        "tool_version": "benchmark-scaffold",
        "scan_sources": sorted(source for source, count in source_counts.items() if count),
        "agents": report_agents,
        "blast_radius": blast_radius,
    }
    summary = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_status": "synthetic_estate_shape_only",
        "seed": seed,
        "agents": agents,
        "source_mix_agent_mentions": source_counts,
        "vulnerable_package_rate_target": vulnerable_package_rate,
        "vulnerable_package_rate_observed": round(len(vulnerable_seen) / max(len(package_seen), 1), 4),
        "counts": {
            "servers": sum(server_counts),
            "tools": sum(tool_counts),
            "package_instances": sum(package_counts),
            "unique_packages": len(package_seen),
            "blast_radius_rows": len(blast_radius),
        },
        "skew": {
            "servers_per_agent": {
                "min": min(server_counts, default=0),
                "median": statistics.median(server_counts) if server_counts else 0,
                "p95": _percentile(server_counts, 0.95),
                "p99": _percentile(server_counts, 0.99),
                "max": max(server_counts, default=0),
            },
            "tools_per_server": {
                "min": min(tool_counts, default=0),
                "median": statistics.median(tool_counts) if tool_counts else 0,
                "p95": _percentile(tool_counts, 0.95),
                "p99": _percentile(tool_counts, 0.99),
                "max": max(tool_counts, default=0),
            },
            "packages_per_server": {
                "min": min(package_counts, default=0),
                "median": statistics.median(package_counts) if package_counts else 0,
                "p95": _percentile(package_counts, 0.95),
                "p99": _percentile(package_counts, 0.99),
                "max": max(package_counts, default=0),
            },
        },
    }
    return report, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a skewed synthetic graph estate report and summary.")
    parser.add_argument("--agents", type=int, default=150, help="Number of synthetic agents to generate.")
    parser.add_argument("--seed", type=int, default=2145, help="Deterministic random seed.")
    parser.add_argument("--vulnerable-package-rate", type=float, default=0.08, help="Target vulnerable unique-package rate.")
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT, help="Scanner-style report JSON output path.")
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY, help="Summary JSON output path.")
    args = parser.parse_args()

    if args.agents < 1:
        parser.error("--agents must be >= 1")
    if not 0 <= args.vulnerable_package_rate <= 1:
        parser.error("--vulnerable-package-rate must be between 0 and 1")

    report, summary = generate_estate(agents=args.agents, seed=args.seed, vulnerable_package_rate=args.vulnerable_package_rate)
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.report_output)
    print(args.summary_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
