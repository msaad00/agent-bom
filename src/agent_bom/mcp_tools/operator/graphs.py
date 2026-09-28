"""Graphs MCP registrations with per-server dispatch bindings."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Annotated

from pydantic import Field

from .bindings import OperatorToolBindings


def register_context_graph(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Context Graph")
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
        return await bindings.execute_tool_async(
            "context_graph",
            bindings.implementations["context_graph_impl"],
            config_path=config_path,
            source_agent=source_agent,
            max_depth=max_depth,
            _run_scan_pipeline=bindings.run_scan_pipeline,
            _truncate_response=bindings.truncate_response,
        )


def register_graph_export(bindings: OperatorToolBindings) -> None:
    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Graph Export")
    async def graph_export(
        config_path: Annotated[
            str | None,
            Field(description="Path to MCP config directory. Omit to auto-discover."),
        ] = None,
        format: Annotated[
            str,
            Field(description="Export format: graphml, cypher, dot, mermaid, or json (default)."),
        ] = "json",
        mermaid_limit: Annotated[
            int,
            Field(
                ge=0,
                le=5000,
                description="Maximum nodes rendered for Mermaid output; 0 renders the full graph.",
            ),
        ] = 80,
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
            scan_result = await bindings.run_scan_pipeline(config_path=config_path)
            if isinstance(scan_result, str):
                return bindings.truncate_response(scan_result)

            agents, _blast_radii, _warnings, _sources = scan_result
            agents_data = [asdict(agent) for agent in agents]

            graph = bindings.build_dep_graph_from_agents(agents_data)

            _fmt = format.lower()
            if _fmt == "graphml":
                return bindings.truncate_response(bindings.implementations["_to_graphml"](graph))
            if _fmt == "cypher":
                return bindings.truncate_response(bindings.implementations["_to_cypher"](graph))
            if _fmt == "dot":
                return bindings.truncate_response(bindings.implementations["_to_dot"](graph))
            if _fmt == "mermaid":
                if mermaid_limit == 0:
                    return bindings.truncate_response(bindings.implementations["_to_mermaid"](graph, max_nodes=None, max_edges=None))
                return bindings.truncate_response(bindings.implementations["_to_mermaid"](graph, max_nodes=mermaid_limit))
            return bindings.truncate_response(json.dumps(bindings.implementations["_graph_to_json"](graph), indent=2))

        return await bindings.execute_tool_async("graph_export", _impl)


def register_analytics_query(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Analytics Query")
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
        return await bindings.execute_tool_async(
            "analytics_query",
            bindings.implementations["analytics_query_impl"],
            query_type=query_type,
            days=days,
            hours=hours,
            agent=agent,
            limit=limit,
            _truncate_response=bindings.truncate_response,
        )


REGISTRATIONS = (
    register_context_graph,
    register_graph_export,
    register_analytics_query,
)
