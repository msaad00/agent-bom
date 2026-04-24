"""Operator and runtime MCP tool registration.

This module keeps the high-churn graph, analytics, fleet, cloud benchmark, and
runtime-correlation tool registrations out of ``mcp_server.py`` while preserving
the FastMCP decorator registration surface.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Annotated

from pydantic import Field


def register_operator_tools(
    mcp,
    *,
    read_only,
    execute_tool_async,
    safe_path,
    run_scan_pipeline,
    truncate_response,
    validate_ecosystem,
    get_registry_data_raw,
    build_dep_graph_from_agents,
) -> None:
    """Register graph, analytics, fleet, benchmark, and runtime MCP tools."""
    from agent_bom.mcp_tools.analysis import analytics_query_impl, context_graph_impl
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl
    from agent_bom.mcp_tools.registry import fleet_scan_impl, marketplace_check_impl
    from agent_bom.mcp_tools.runtime import runtime_correlate_impl
    from agent_bom.mcp_tools.sbom import diff_impl
    from agent_bom.mcp_tools.scanning import code_scan_impl

    # ── Tool 13: diff ─────────────────────────────────────────────

    @mcp.tool(annotations=read_only, title="Vulnerability Diff")
    async def diff(
        baseline: Annotated[
            dict | None, Field(description="Baseline report JSON object. If omitted, uses the latest saved report from history.")
        ] = None,
    ) -> str:
        """Compare a fresh scan against a baseline to find new and resolved vulns.

        Runs a new scan, then diffs it against the provided baseline (or the
        latest saved report). Shows new vulnerabilities, resolved ones, and
        changes in the package inventory.

        Returns:
            JSON with new findings, resolved findings, new/removed packages,
            and a human-readable summary.
        """
        return await execute_tool_async(
            "diff",
            diff_impl,
            baseline=baseline,
            _run_scan_pipeline=run_scan_pipeline,
            _truncate_response=truncate_response,
        )

    # ── Tool 14: marketplace_check ───────────────────────────────

    @mcp.tool(annotations=read_only, title="Marketplace Trust Check")
    async def marketplace_check(
        package: Annotated[str, Field(description="Package name, e.g. 'express', 'langchain'.")],
        ecosystem: Annotated[str, Field(description="Package ecosystem: 'npm' or 'pypi'.")] = "npm",
    ) -> str:
        """Pre-install trust check for an MCP server package.

        Queries the package registry (npm or PyPI) for metadata and
        cross-references against the agent-bom MCP threat intelligence registry.
        Returns trust signals including download count, CVE status, and
        registry verification.

        Args:
            package: Package name to check.
            ecosystem: 'npm' or 'pypi'. Defaults to 'npm'.

        Returns:
            JSON with name, version, ecosystem, cve_count, download_count,
            registry_verified, and trust_signals.
        """
        return await execute_tool_async(
            "marketplace_check",
            marketplace_check_impl,
            package=package,
            ecosystem=ecosystem,
            _validate_ecosystem=validate_ecosystem,
            _get_registry_data_raw=get_registry_data_raw,
            _truncate_response=truncate_response,
        )

    # ── Tool 16: code_scan ────────────────────────────────────────

    @mcp.tool(annotations=read_only, title="Code SAST Scan")
    async def code_scan(
        path: Annotated[str, Field(description="Path to source code directory to scan.")],
        config: Annotated[
            str,
            Field(description="Semgrep config. 'auto' = Semgrep Registry rules. Can be a path or registry string."),
        ] = "auto",
    ) -> str:
        """Run SAST (Static Application Security Testing) on source code via Semgrep.

        Scans for security flaws: SQL injection, XSS, command injection,
        hardcoded credentials, insecure deserialization, path traversal, etc.
        Returns findings with CWE classifications and severity levels.

        Requires ``semgrep`` on PATH (``pip install semgrep``).
        """
        return await execute_tool_async(
            "code_scan",
            code_scan_impl,
            path=path,
            config=config,
            _safe_path=safe_path,
            _truncate_response=truncate_response,
        )

    # ── Tool 17: context_graph ──────────────────────────────────

    @mcp.tool(annotations=read_only, title="Context Graph")
    async def context_graph(
        config_path: Annotated[
            str | None,
            Field(description="Path to MCP config directory. Omit to auto-discover."),
        ] = None,
        source_agent: Annotated[
            str | None,
            Field(description="Agent name to compute lateral paths from. Omit for all agents."),
        ] = None,
        max_depth: Annotated[
            int,
            Field(description="Max BFS depth for lateral path discovery (1-6, default 4)."),
        ] = 4,
    ) -> str:
        """Build an agent context graph with lateral movement analysis.

        Models reachability between agents, servers, credentials, tools,
        and vulnerabilities.  Answers: "If agent X is compromised, what
        else becomes reachable?"

        Returns:
            JSON with nodes, edges, lateral_paths, interaction_risks, and stats.
        """
        return await execute_tool_async(
            "context_graph",
            context_graph_impl,
            config_path=config_path,
            source_agent=source_agent,
            max_depth=max_depth,
            _run_scan_pipeline=run_scan_pipeline,
            _truncate_response=truncate_response,
        )

    # ── Tool: graph_export ──────────────────────────────────

    @mcp.tool(annotations=read_only, title="Graph Export")
    async def graph_export(
        config_path: Annotated[
            str | None,
            Field(description="Path to MCP config directory. Omit to auto-discover."),
        ] = None,
        format: Annotated[
            str,
            Field(description="Export format: graphml, cypher, dot, mermaid, or json (default)."),
        ] = "json",
    ) -> str:
        """Export the agent dependency graph in graph-native formats.

        Formats:
        - **graphml** — yEd, Gephi, NetworkX compatible with AIBOM-typed attributes
        - **cypher** — Neo4j import script with AIBOM node labels (AIAgent, MCPServer, Package, Vulnerability)
        - **dot** — Graphviz (pipe through ``dot -Tsvg``)
        - **mermaid** — embed in markdown, GitHub, Notion
        - **json** — machine-readable nodes/edges list

        Returns:
            Graph in the requested format as a string.
        """

        async def _impl() -> str:
            scan_result = await run_scan_pipeline(config_path=config_path)
            if isinstance(scan_result, str):
                return truncate_response(scan_result)

            agents, _blast_radii, _warnings, _sources = scan_result
            agents_data = [asdict(agent) for agent in agents]

            from agent_bom.output.graph_export import (
                to_cypher as _to_cypher,
            )
            from agent_bom.output.graph_export import (
                to_dot as _to_dot,
            )
            from agent_bom.output.graph_export import (
                to_graphml as _to_graphml,
            )
            from agent_bom.output.graph_export import (
                to_json as _graph_to_json,
            )
            from agent_bom.output.graph_export import (
                to_mermaid as _to_mermaid,
            )

            graph = build_dep_graph_from_agents(agents_data)

            _fmt = format.lower()
            if _fmt == "graphml":
                return truncate_response(_to_graphml(graph))
            if _fmt == "cypher":
                return truncate_response(_to_cypher(graph))
            if _fmt == "dot":
                return truncate_response(_to_dot(graph))
            if _fmt == "mermaid":
                return truncate_response(_to_mermaid(graph))
            return truncate_response(json.dumps(_graph_to_json(graph), indent=2))

        return await execute_tool_async("graph_export", _impl)

    @mcp.tool(annotations=read_only, title="Analytics Query")
    async def analytics_query(
        query_type: Annotated[
            str,
            Field(description=("Query type: vuln_trends, top_cves, posture_history, event_summary, fleet_riskiest, or compliance_heatmap")),
        ],
        days: Annotated[
            int,
            Field(description="Lookback window in days (default 30). Used by vuln_trends, posture_history, and compliance_heatmap."),
        ] = 30,
        hours: Annotated[
            int,
            Field(description="Lookback window in hours (default 24). Used by event_summary."),
        ] = 24,
        agent: Annotated[
            str | None,
            Field(description="Filter by agent name. Used by vuln_trends and posture_history."),
        ] = None,
        limit: Annotated[
            int,
            Field(description="Max results for top_cves and fleet_riskiest (default 20)."),
        ] = 20,
    ) -> str:
        """Query vulnerability trends, posture history, and runtime event summaries from ClickHouse.

        Requires AGENT_BOM_CLICKHOUSE_URL to be set. Returns empty results if
        ClickHouse is not configured.
        """
        return await execute_tool_async(
            "analytics_query",
            analytics_query_impl,
            query_type=query_type,
            days=days,
            hours=hours,
            agent=agent,
            limit=limit,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="CIS Benchmark")
    async def cis_benchmark(
        provider: Annotated[
            str,
            Field(description="Cloud provider: 'aws', 'snowflake', 'azure', or 'gcp'."),
        ],
        checks: Annotated[
            str | None,
            Field(description="Comma-separated check IDs to run (e.g. '1.1,2.1'). Omit to run all."),
        ] = None,
        region: Annotated[
            str | None,
            Field(description="AWS region (only for provider=aws). Defaults to us-east-1."),
        ] = None,
        profile: Annotated[
            str | None,
            Field(description="AWS CLI profile (only for provider=aws)."),
        ] = None,
        subscription_id: Annotated[
            str | None,
            Field(description="Azure subscription ID (only for provider=azure). Falls back to AZURE_SUBSCRIPTION_ID env var."),
        ] = None,
        project_id: Annotated[
            str | None,
            Field(description="GCP project ID (only for provider=gcp). Falls back to GOOGLE_CLOUD_PROJECT env var."),
        ] = None,
    ) -> str:
        """Run CIS benchmark checks against a cloud account.

        Evaluates security posture against CIS Foundations Benchmarks:
        - AWS Foundations v3.0: 18 checks (IAM, Storage, Logging, Networking)
        - Snowflake v1.0: 12 checks (Auth, Network, Data Protection, Monitoring, Access Control)
        - Azure Security Benchmark v3.0: 10 checks (IAM, Storage, Logging, Networking, Key Vault)
        - GCP Foundation v3.0: 8 checks (IAM, Logging, Networking, Storage)

        All checks are read-only. Failed checks include MITRE ATT&CK Enterprise technique mappings.
        Requires appropriate credentials for the chosen provider.

        Returns:
            JSON with per-check pass/fail results, evidence, severity, ATT&CK techniques, and pass rate.
        """
        return await execute_tool_async(
            "cis_benchmark",
            cis_benchmark_impl,
            provider=provider,
            checks=checks,
            region=region,
            profile=profile,
            subscription_id=subscription_id,
            project_id=project_id,
            _truncate_response=truncate_response,
        )

    # ── Tool 19: fleet_scan ────────────────────────────────────────

    @mcp.tool(annotations=read_only, title="Fleet Scan")
    async def fleet_scan(
        servers: Annotated[
            str,
            Field(
                description="Comma-separated or newline-separated list of MCP server names to scan. "
                "E.g. '@modelcontextprotocol/server-filesystem, brave-search, glean, 50 sleep'."
            ),
        ],
    ) -> str:
        """Batch-scan a list of MCP server names against the security metadata registry.

        Designed for fleet inventory data (CrowdStrike, SIEM, CSV exports) where
        you have server names but not versions. Returns per-server risk assessment
        with registry match status, risk category, tools, credentials, known CVEs,
        and a verdict (known-high-risk, known-medium, known-low, unknown-unvetted).

        Risk levels are category-derived (filesystem=high, database=medium,
        search=low), not made-up threat scores. Every field is traceable to a source.

        Returns:
            JSON with summary (total, matched, unmatched, risk breakdown)
            and per-server details.
        """
        return await execute_tool_async(
            "fleet_scan",
            fleet_scan_impl,
            servers=servers,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Runtime Correlation")
    async def runtime_correlate(
        config_path: Annotated[
            str,
            Field(description="Path to MCP config directory (e.g. ~/.config/claude) or 'auto' for default discovery."),
        ] = "auto",
        audit_log: Annotated[
            str,
            Field(description="Path to proxy audit JSONL log file (generated by 'agent-bom proxy --log audit.jsonl')."),
        ] = "",
        otel_trace: Annotated[
            str,
            Field(description="Path to OTel OTLP JSON trace file for ML API provenance (detects deprecated/vulnerable model versions)."),
        ] = "",
    ) -> str:
        """Cross-reference vulnerability scan results with proxy runtime audit logs.

        Identifies which vulnerable tools were ACTUALLY CALLED in production,
        distinguishing confirmed attack surface from theoretical risk. Produces
        risk-amplified findings: a vulnerable tool that was called 100 times is
        higher priority than one never invoked.

        Also accepts an OTel trace file (``otel_trace``) to extract ML API call
        provenance: which models were called, token usage, and deprecation advisories.

        Requires a proxy audit log (generated by running agent-bom proxy with
        the --log flag). Without an audit log, returns scan results only.

        Returns:
            JSON with correlated findings (CVE + tool call data + amplified risk),
            summary stats, uncalled vulnerable tools, and ml_api_calls provenance.
        """
        return await execute_tool_async(
            "runtime_correlate",
            runtime_correlate_impl,
            config_path=config_path,
            audit_log=audit_log,
            otel_trace=otel_trace,
            _safe_path=safe_path,
            _run_scan_pipeline=run_scan_pipeline,
            _truncate_response=truncate_response,
        )
