"""Benchmarks for the unified graph builder hot path.

Pilot teams ask: "at 50k packages × 500 agents, how long does the graph
rebuild on every scan?" This file answers with measured numbers at
1k / 10k / 50k inventory sizes. Numbers land in
docs/PERFORMANCE_BENCHMARKS.md.

Scope: the build step only — we're measuring CPU + memory time to walk
a synthetic report JSON into the UnifiedGraph, not serialising the
result, not persisting to Postgres. Those are separate benchmarks.

Run:
    pytest tests/benchmarks/ --benchmark-only -k graph
    AGENT_BOM_BENCH_FULL=1 pytest tests/benchmarks/ --benchmark-only -k graph_50k
"""

from __future__ import annotations

import os
from typing import Any

import pytest

pytest.importorskip("pytest_benchmark")


def _synth_report(n_agents: int, servers_per_agent: int = 2, pkgs_per_server: int = 5, vulns: int = 1000) -> dict[str, Any]:
    """Build a synthetic AIBOM report JSON with the requested cardinality.

    Shape matches what output.json_fmt.to_json() emits — agents, blast_radius,
    compliance tags — so build_unified_graph_from_report walks the real
    branch set the code uses in production.
    """
    agents = []
    blast_radius = []
    vuln_idx = 0
    for a in range(n_agents):
        servers = []
        for s in range(servers_per_agent):
            pkgs = []
            for p in range(pkgs_per_server):
                pkg_name = f"pkg-{(a * servers_per_agent + s) * pkgs_per_server + p}"
                pkgs.append(
                    {
                        "name": pkg_name,
                        "version": f"1.0.{p % 10}",
                        "ecosystem": "npm",
                        "is_direct": p % 3 == 0,
                    }
                )
            servers.append(
                {
                    "name": f"agent-{a}-server-{s}",
                    "transport": "sse",
                    "url": f"https://mcp.example.com/a{a}s{s}",
                    "packages": pkgs,
                    "tools": [{"name": f"tool-{a}-{s}-{t}"} for t in range(3)],
                    "credential_names": [f"ENV_KEY_{a}_{s}"] if s % 2 else [],
                    "registry_verified": s % 2 == 0,
                }
            )
        agents.append(
            {
                "name": f"agent-{a}",
                "type": "claude-desktop" if a % 2 == 0 else "cursor",
                "servers": servers,
                "status": "configured",
            }
        )

    # Blast-radius entries spread across packages
    for i in range(min(vulns, n_agents * servers_per_agent * pkgs_per_server)):
        a = i % n_agents
        s = (i // n_agents) % servers_per_agent
        pkg_idx = (i // (n_agents * servers_per_agent)) % pkgs_per_server
        pkg_name = f"pkg-{(a * servers_per_agent + s) * pkgs_per_server + pkg_idx}"
        severity = ["critical", "high", "medium", "low"][i % 4]
        blast_radius.append(
            {
                "vulnerability_id": f"CVE-2024-{i:06d}",
                "severity": severity,
                "package": pkg_name,
                "package_name": pkg_name,
                "package_version": "1.0.0",
                "fixed_version": "1.0.99",
                "affected_agents": [f"agent-{a}"],
                "affected_servers": [{"name": f"agent-{a}-server-{s}"}],
                "owasp_tags": [f"LLM{(i % 10) + 1:02d}"],
                "soc2_tags": ["CC6.1"],
            }
        )
        vuln_idx += 1

    return {
        "scan_id": f"bench-{n_agents}",
        "generated_at": "2026-01-01T00:00:00Z",
        "tool_version": "0.79.0",
        "agents": agents,
        "blast_radius": blast_radius,
        "scan_sources": ["mcp-scan"],
    }


class TestGraphBuilderPerformance:
    """Measure build_unified_graph_from_report at realistic pilot scales."""

    @pytest.mark.parametrize(
        "n_agents,servers_per_agent,pkgs_per_server",
        [
            (20, 2, 5),  # ~200 pkgs — single small team
            (100, 2, 5),  # ~1k pkgs — departmental
            (500, 2, 10),  # ~10k pkgs — company-wide
        ],
        ids=["200_pkgs", "1k_pkgs", "10k_pkgs"],
    )
    def test_build_graph(self, benchmark, n_agents: int, servers_per_agent: int, pkgs_per_server: int) -> None:
        from agent_bom.graph.builder import build_unified_graph_from_report

        report = _synth_report(n_agents, servers_per_agent, pkgs_per_server, vulns=n_agents * servers_per_agent * pkgs_per_server)
        graph = benchmark(build_unified_graph_from_report, report)
        # Sanity: graph is non-empty.
        assert len(graph.nodes) > 0

    @pytest.mark.slow
    @pytest.mark.skipif(
        os.environ.get("AGENT_BOM_BENCH_FULL") != "1",
        reason="50k variant is slow; run locally with AGENT_BOM_BENCH_FULL=1",
    )
    def test_build_graph_50k(self, benchmark) -> None:
        """The 'can we still do this in-process at enterprise scale?' signal."""
        from agent_bom.graph.builder import build_unified_graph_from_report

        # 1000 agents × 5 servers × 10 pkgs = 50k packages, ~10k blast_radius entries
        report = _synth_report(n_agents=1000, servers_per_agent=5, pkgs_per_server=10, vulns=10_000)
        graph = benchmark(build_unified_graph_from_report, report)
        # 1000 agents + 5000 servers + dedup'd packages + tools + vuln nodes ≈ 10k+ nodes.
        # Exact count depends on dedup logic; we just need the graph to be meaningfully populated.
        assert len(graph.nodes) > 10_000
