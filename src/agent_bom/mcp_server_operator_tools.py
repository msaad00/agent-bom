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
    write_action,
    write_idempotent,
    execute_tool_async,
    execute_tool_sync_async,
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
    from agent_bom.mcp_tools.identity import (
        identity_grant_jit_impl,
        identity_issue_impl,
        identity_revoke_impl,
        identity_revoke_jit_impl,
        identity_rotate_impl,
    )
    from agent_bom.mcp_tools.kspm import kspm_cluster_posture_impl
    from agent_bom.mcp_tools.posture import (
        access_review_impl,
        cloud_inventory_impl,
        cost_allocation_impl,
        cost_forecast_impl,
        credential_expiry_impl,
        nhi_discover_impl,
    )
    from agent_bom.mcp_tools.registry import fleet_scan_impl, marketplace_check_impl
    from agent_bom.mcp_tools.runtime import (
        anomaly_scan_impl,
        audit_integrity_impl,
        audit_query_impl,
        cost_report_impl,
        drift_incidents_impl,
        firewall_check_impl,
        gateway_status_impl,
        proxy_alerts_impl,
        proxy_status_impl,
        runtime_blueprint_drift_impl,
        runtime_blueprints_impl,
        runtime_correlate_impl,
        runtime_production_index_impl,
        shield_break_glass_impl,
        shield_start_impl,
        shield_status_impl,
        shield_unblock_impl,
    )
    from agent_bom.mcp_tools.sbom import diff_impl
    from agent_bom.mcp_tools.scanning import code_scan_impl

    # ── Tool 13: diff ─────────────────────────────────────────────

    @mcp.tool(annotations=write_action, title="Vulnerability Diff")
    async def diff(
        baseline: Annotated[
            dict | None, Field(description="Baseline report JSON object. If omitted, uses the latest saved report from history.")
        ] = None,
    ) -> str:
        """Compare a fresh scan against a baseline to find new and resolved vulns.

        Runs a new scan, then diffs it against the provided baseline (or the
        latest saved report). Shows new vulnerabilities, resolved ones, and
        changes in the package inventory.

        Not read-only: this persists the fresh scan to report history and may
        prune older saved reports, so it is annotated as a (destructive) write.

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

    @mcp.tool(annotations=read_only, title="Semgrep SAST Scan")
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
        Returns findings with CWE classifications and severity levels plus a
        typed ``findings``, ``clean``, ``skipped``, or ``failed`` status.

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
                if mermaid_limit == 0:
                    return truncate_response(_to_mermaid(graph, max_nodes=None, max_edges=None))
                return truncate_response(_to_mermaid(graph, max_nodes=mermaid_limit))
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

    @mcp.tool(annotations=read_only, title="KSPM Cluster Posture")
    async def kspm_cluster_posture(
        namespace: Annotated[
            str,
            Field(description="Kubernetes namespace to inspect (ignored when all_namespaces=True). Defaults to 'default'."),
        ] = "default",
        all_namespaces: Annotated[
            bool,
            Field(description="Inspect every namespace instead of a single one."),
        ] = False,
        context: Annotated[
            str | None,
            Field(description="kubectl context to use (workstation fallback path only). Omit to use the in-cluster SA token."),
        ] = None,
        enable_nodes_configz: Annotated[
            bool,
            Field(description="Opt in to per-node kubelet /configz collection (CIS section 4.2). Off by default."),
        ] = False,
    ) -> str:
        """Evaluate live Kubernetes cluster security posture (KSPM).

        Read-only inspection of running workloads, RBAC, NetworkPolicy coverage,
        and (opt-in) kubelet config against the pinned CIS Kubernetes Benchmark.
        Distinct from image discovery: this returns SECURITY POSTURE, not a
        container-image inventory.

        Every collector carries an explicit execution state — executed / skipped
        / unevaluable (a denied or absent read) / failed — so a partial run is
        reported 'partial' with a coverage-affecting ScanRun issue and can never
        be laundered into a clean pass. The benchmark provenance, collector
        states, ScanRun outcome, and finding summary reconcile 1:1 with the REST
        /v1/kspm/clusters/posture route and the CLI evidence dict.

        Returns:
            JSON with benchmark provenance, per-collector states, the canonical
            ScanRun outcome, a finding count, and a per-severity summary.
        """
        return await execute_tool_async(
            "kspm_cluster_posture",
            kspm_cluster_posture_impl,
            namespace=namespace,
            all_namespaces=all_namespaces,
            context=context,
            enable_nodes_configz=enable_nodes_configz,
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

        Designed for fleet inventory data (EDR, SIEM, CSV exports) where
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

    @mcp.tool(annotations=read_only, title="Runtime Production Index")
    async def runtime_production_index(
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to summarize. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Return metadata-only runtime production posture for agent/tool traffic.

        Summarizes tool-call volume, block rate, policy decisions, authorization
        trace posture, alerts, active sources/sessions, freshness, and retention
        mode without returning prompts, raw arguments, responses, or credential
        values.
        """
        return await execute_tool_async(
            "runtime_production_index",
            runtime_production_index_impl,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Runtime Blueprints")
    async def runtime_blueprints(
        blueprint_id: Annotated[
            str,
            Field(description="Optional blueprint id such as developer, security_analyst, mlops, finance, or admin."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for the response envelope."),
        ] = "default",
    ) -> str:
        """Return canonical role/profile blueprints for runtime policy design."""
        return await execute_tool_async(
            "runtime_blueprints",
            runtime_blueprints_impl,
            blueprint_id=blueprint_id,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Runtime Blueprint Drift")
    async def runtime_blueprint_drift(
        blueprint_id: Annotated[
            str,
            Field(description="Blueprint id to evaluate, such as developer, security_analyst, mlops, finance, or admin."),
        ],
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to summarize. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Compare current runtime traffic with an approved role/profile blueprint."""
        return await execute_tool_async(
            "runtime_blueprint_drift",
            runtime_blueprint_drift_impl,
            blueprint_id=blueprint_id,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Cost Report")
    async def cost_report(
        agent: Annotated[
            str,
            Field(description="Optional agent name to scope spend to a single agent."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to summarize. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Return LLM spend attribution (per agent/model/provider) and budget posture.

        Spend is derived from token counts on ingested OpenTelemetry GenAI spans
        priced via agent-bom's open cost model; no prompts or responses are read.
        """
        return await execute_tool_async(
            "cost_report",
            cost_report_impl,
            agent=agent,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Anomaly Scan")
    async def anomaly_scan(
        z_threshold: Annotated[
            float,
            Field(description="Z-score threshold for flagging an outlier (default 3.0; higher = stricter)."),
        ] = 3.0,
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to summarize. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Surface cost and behavior anomalies: per-agent spend and per-session
        tool-call-rate statistical outliers, for proactive runaway-agent detection."""
        return await execute_tool_async(
            "anomaly_scan",
            anomaly_scan_impl,
            z_threshold=z_threshold,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Drift Incidents")
    async def drift_incidents(
        include_resolved: Annotated[
            bool,
            Field(description="Include resolved incidents. Defaults to open incidents only."),
        ] = False,
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to summarize. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """List open blueprint-drift incidents (observed runtime traffic outside the approved role blueprint).

        Each incident records the blueprint, drift score, and top violations so an
        operator can reconcile the agent or blueprint and resolve it.
        """
        return await execute_tool_async(
            "drift_incidents",
            drift_incidents_impl,
            include_resolved=include_resolved,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Proxy Status")
    async def proxy_status(
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to summarize. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Return current MCP proxy metrics and alert summary, if a session is active."""
        return await execute_tool_async(
            "proxy_status",
            proxy_status_impl,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Proxy Alerts")
    async def proxy_alerts(
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to read. Defaults to the control-plane default tenant."),
        ] = "default",
        severity: Annotated[
            str,
            Field(description="Optional severity filter: critical, high, medium, low, or info."),
        ] = "",
        detector: Annotated[
            str,
            Field(description="Optional detector name filter, for example credential_leak."),
        ] = "",
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum alerts to return."),
        ] = 100,
    ) -> str:
        """Return recent runtime proxy alerts without prompts, arguments, or responses."""
        return await execute_tool_async(
            "proxy_alerts",
            proxy_alerts_impl,
            tenant_id=tenant_id,
            severity=severity,
            detector=detector,
            limit=limit,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Gateway Status")
    async def gateway_status(
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to summarize. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Return gateway policy and inter-agent firewall runtime statistics."""
        return await execute_tool_async(
            "gateway_status",
            gateway_status_impl,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Shield Status")
    async def shield_status(
        session_id: Annotated[
            str,
            Field(description="Shield session id to inspect."),
        ] = "default",
    ) -> str:
        """Return current Shield assessment for a session without changing enforcement state."""
        return await execute_tool_async(
            "shield_status",
            shield_status_impl,
            session_id=session_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Shield Start")
    async def shield_start(
        session_id: Annotated[
            str,
            Field(description="Shield session id to start."),
        ] = "default",
        correlation_window: Annotated[
            float,
            Field(ge=1.0, le=3600.0, description="Alert correlation window in seconds."),
        ] = 30.0,
        operator_role: Annotated[
            str,
            Field(description="Operator role for this write action. Must be admin."),
        ] = "viewer",
        operator_scopes: Annotated[
            str,
            Field(description="Comma-separated operator scopes. Must include shield:write."),
        ] = "",
        reason: Annotated[
            str,
            Field(description="Human audit reason for starting Shield enforcement."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for audit logging."),
        ] = "default",
    ) -> str:
        """Start Shield enforcement for a session. Requires admin role, shield:write scope, and audit reason."""
        return await execute_tool_async(
            "shield_start",
            shield_start_impl,
            destructive=True,
            required_scope="shield:write",
            session_id=session_id,
            correlation_window=correlation_window,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Shield Unblock")
    async def shield_unblock(
        session_id: Annotated[
            str,
            Field(description="Shield session id to unblock."),
        ] = "default",
        operator_role: Annotated[
            str,
            Field(description="Operator role for this write action. Must be admin."),
        ] = "viewer",
        operator_scopes: Annotated[
            str,
            Field(description="Comma-separated operator scopes. Must include shield:write."),
        ] = "",
        reason: Annotated[
            str,
            Field(description="Human audit reason for unblocking Shield enforcement."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for audit logging."),
        ] = "default",
    ) -> str:
        """Unblock Shield enforcement for a session. Requires admin role, shield:write scope, and audit reason."""
        return await execute_tool_async(
            "shield_unblock",
            shield_unblock_impl,
            destructive=True,
            required_scope="shield:write",
            session_id=session_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Shield Break Glass")
    async def shield_break_glass(
        session_id: Annotated[
            str,
            Field(description="Shield session id to override."),
        ] = "default",
        operator_role: Annotated[
            str,
            Field(description="Operator role for this write action. Must be admin."),
        ] = "viewer",
        operator_scopes: Annotated[
            str,
            Field(description="Comma-separated operator scopes. Must include shield:write."),
        ] = "",
        reason: Annotated[
            str,
            Field(description="Human audit reason for emergency Shield override."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for audit logging."),
        ] = "default",
    ) -> str:
        """Run Shield break-glass override. Requires admin role, shield:write scope, and audit reason."""
        return await execute_tool_async(
            "shield_break_glass",
            shield_break_glass_impl,
            destructive=True,
            required_scope="shield:write",
            session_id=session_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Identity Issue")
    async def identity_issue(
        agent_id: Annotated[str, Field(description="Agent identifier the issued identity represents.")],
        role: Annotated[str, Field(description="Identity role label, for example agent or service.")] = "agent",
        blueprint_id: Annotated[str, Field(description="Optional runtime blueprint id bound to the identity.")] = "",
        ttl_seconds: Annotated[int, Field(ge=60, le=31536000, description="Identity lifetime in seconds.")] = 7776000,
        allowed_tools: Annotated[str, Field(description="Comma-separated per-tool scope allowlist. Empty means any tool.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for issuing the identity.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for the identity and audit logging.")] = "default",
    ) -> str:
        """Issue a managed agent identity. Requires admin role, identity:write scope, and an audit reason. Returns the raw token once."""
        return await execute_tool_async(
            "identity_issue",
            identity_issue_impl,
            destructive=True,
            required_scope="identity:write",
            agent_id=agent_id,
            role=role,
            blueprint_id=blueprint_id,
            ttl_seconds=ttl_seconds,
            allowed_tools=allowed_tools,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Identity Rotate")
    async def identity_rotate(
        identity_id: Annotated[str, Field(description="Identity id to rotate.")],
        overlap_seconds: Annotated[int, Field(ge=0, le=86400, description="Seconds the old token stays live during rotation.")] = 3600,
        ttl_seconds: Annotated[int, Field(ge=60, le=31536000, description="Lifetime of the replacement identity in seconds.")] = 7776000,
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for rotating the identity.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for audit logging.")] = "default",
    ) -> str:
        """Rotate a managed identity, keeping the old token live during the overlap window.

        Requires admin role, identity:write scope, and an audit reason.
        """
        return await execute_tool_async(
            "identity_rotate",
            identity_rotate_impl,
            destructive=True,
            required_scope="identity:write",
            identity_id=identity_id,
            overlap_seconds=overlap_seconds,
            ttl_seconds=ttl_seconds,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Identity Revoke")
    async def identity_revoke(
        identity_id: Annotated[str, Field(description="Identity id to revoke.")],
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for revoking the identity.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for audit logging.")] = "default",
    ) -> str:
        """Revoke a managed identity immediately. Requires admin role, identity:write scope, and an audit reason."""
        return await execute_tool_async(
            "identity_revoke",
            identity_revoke_impl,
            destructive=True,
            required_scope="identity:write",
            identity_id=identity_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Identity Grant JIT")
    async def identity_grant_jit(
        identity_id: Annotated[str, Field(description="Identity id to grant time-bound access to.")],
        tool_name: Annotated[str, Field(description="Tool the grant authorizes, beyond the identity's standing scope.")],
        ttl_seconds: Annotated[int, Field(ge=60, le=86400, description="Grant lifetime in seconds.")] = 3600,
        ticket_id: Annotated[str, Field(description="Optional change/incident ticket id for the grant.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for granting access.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for audit logging.")] = "default",
    ) -> str:
        """Grant an identity time-bound JIT access to one tool. Requires admin role, identity:write scope, and an audit reason."""
        return await execute_tool_async(
            "identity_grant_jit",
            identity_grant_jit_impl,
            destructive=True,
            required_scope="identity:write",
            identity_id=identity_id,
            tool_name=tool_name,
            ttl_seconds=ttl_seconds,
            ticket_id=ticket_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Identity Revoke JIT")
    async def identity_revoke_jit(
        grant_id: Annotated[str, Field(description="JIT grant id to revoke.")],
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for revoking the grant.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for audit logging.")] = "default",
    ) -> str:
        """Revoke an active JIT grant immediately. Requires admin role, identity:write scope, and an audit reason."""
        return await execute_tool_async(
            "identity_revoke_jit",
            identity_revoke_jit_impl,
            destructive=True,
            required_scope="identity:write",
            grant_id=grant_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Firewall Check")
    async def firewall_check(
        source_agent: Annotated[str, Field(description="Source agent identity, for example claude-desktop.")],
        target_agent: Annotated[str, Field(description="Target agent or service identity, for example jira-mcp.")],
        source_roles: Annotated[
            str,
            Field(description="Optional comma-separated source roles such as developer,security_analyst."),
        ] = "",
        target_roles: Annotated[
            str,
            Field(description="Optional comma-separated target roles such as production,finance."),
        ] = "",
    ) -> str:
        """Dry-run an inter-agent firewall decision without recording it to the control-plane tally."""
        # firewall_check_impl is a synchronous handler — route it through the
        # sync executor (run in a thread) rather than awaiting its str return.
        return await execute_tool_sync_async(
            "firewall_check",
            firewall_check_impl,
            source_agent=source_agent,
            target_agent=target_agent,
            source_roles=source_roles,
            target_roles=target_roles,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Audit Query")
    async def audit_query(
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to read. Defaults to the control-plane default tenant."),
        ] = "default",
        action: Annotated[
            str,
            Field(description="Optional audit action filter."),
        ] = "",
        resource: Annotated[
            str,
            Field(description="Optional audit resource filter."),
        ] = "",
        since: Annotated[
            str,
            Field(description="Optional ISO timestamp lower bound."),
        ] = "",
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum audit records to return."),
        ] = 100,
        offset: Annotated[
            int,
            Field(ge=0, description="Pagination offset."),
        ] = 0,
    ) -> str:
        """Read tenant-scoped control-plane audit records with filters and paging.

        Returns the immutable, hash-chained audit log of control-plane actions
        (identity, shield, firewall, and policy changes) for one tenant, with
        optional filtering by action, resource, and start time. Read-only: it
        never mutates enforcement state.

        Args:
            tenant_id: Tenant scope to read (default control-plane tenant).
            action: Optional audit action filter (exact match).
            resource: Optional audit resource filter (exact match).
            since: Optional ISO-8601 timestamp lower bound.
            limit: Maximum audit records to return (1-1000).
            offset: Pagination offset.

        Returns:
            JSON with the matched audit records (actor, action, resource,
            timestamp, chain position) and pagination metadata.

        Call this to review who changed what in the control plane; pair with
        ``audit_integrity`` to verify the chain has not been tampered with.
        """
        return await execute_tool_async(
            "audit_query",
            audit_query_impl,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            since=since,
            limit=limit,
            offset=offset,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Audit Integrity")
    async def audit_integrity(
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to verify. Defaults to the control-plane default tenant."),
        ] = "default",
        limit: Annotated[
            int,
            Field(ge=1, le=10000, description="Maximum audit records to verify."),
        ] = 1000,
        include_runtime: Annotated[
            bool,
            Field(description="Also verify the configured runtime proxy audit log when AGENT_BOM_LOG is set."),
        ] = True,
    ) -> str:
        """Verify control-plane and runtime audit chain integrity."""
        return await execute_tool_async(
            "audit_integrity",
            audit_integrity_impl,
            tenant_id=tenant_id,
            limit=limit,
            include_runtime=include_runtime,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Cost Forecast")
    async def cost_forecast(
        agent: Annotated[
            str,
            Field(description="Optional agent name to scope the forecast to a single agent."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to forecast. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Project LLM spend burn rate and budget runway for the active tenant.

        Derives a recent burn rate from persisted cost records and extrapolates
        to the configured budget, returning projected period spend, days of
        runway, and an exhaustion date. Reference only: a forecast never blocks a
        call and returns a clear status with null projections on sparse history.
        """
        return await execute_tool_async(
            "cost_forecast",
            cost_forecast_impl,
            agent=agent,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Cost Allocation")
    async def cost_allocation(
        cost_center: Annotated[
            str,
            Field(description="Optional cost-center / allocation unit to scope the chargeback report and budget."),
        ] = "",
        tag: Annotated[
            str,
            Field(description="Optional allocation tag to add a showback slice (by_tag rollup)."),
        ] = "",
        agent: Annotated[
            str,
            Field(description="Optional agent name to scope spend to a single agent."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to summarize. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Return chargeback / showback LLM spend rollups by cost-center and allocation tag.

        Spend is derived from token counts on ingested OpenTelemetry GenAI spans
        priced via the open cost model. Includes per-cost-center allocation,
        budget posture, and forecast. No prompts or responses are read.
        """
        return await execute_tool_async(
            "cost_allocation",
            cost_allocation_impl,
            cost_center=cost_center,
            tag=tag,
            agent=agent,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Credential Expiry")
    async def credential_expiry() -> str:
        """Return expiring / overdue credential posture for control-plane secrets.

        Surfaces non-secret credential-expiry and rotation governance: which
        secrets are near expiry, overdue for rotation, or past max age, with an
        overall verdict. Never returns secret values.
        """
        return await execute_tool_async(
            "credential_expiry",
            credential_expiry_impl,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="NHI Discover")
    async def nhi_discover(
        providers: Annotated[
            str,
            Field(description="Comma-separated IdP providers to query: okta, entra. Omit to query both."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for the response envelope. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Discover non-human identities (Okta service apps / Entra service principals).

        Read-only and reference-only: returns normalized identity metadata (id,
        name, owner, created, credential expiry, scope references) — never secret
        material. Each provider is gated by its own discovery env flag and token;
        a disabled or unconfigured provider is reported in ``providers`` with a
        clear status rather than failing the request.
        """
        return await execute_tool_async(
            "nhi_discover",
            nhi_discover_impl,
            providers=providers,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Cloud Inventory")
    async def cloud_inventory(
        providers: Annotated[
            str,
            Field(description="Comma-separated cloud providers to summarize: aws, azure, gcp. Omit to query all enabled."),
        ] = "",
        region: Annotated[
            str,
            Field(description="Optional AWS region for AWS inventory (e.g. us-east-1)."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for the response envelope. Defaults to the control-plane default tenant."),
        ] = "default",
    ) -> str:
        """Summarize the estate-wide cloud asset inventory (resource + identity counts).

        Each provider is opt-in via its own ``AGENT_BOM_*_INVENTORY`` env flag and
        credentials; a disabled or unconfigured provider returns a clear status
        and contributes zero nodes. Returns resource/identity counts and a node
        summary only — reference-only, never resource secrets.
        """
        return await execute_tool_async(
            "cloud_inventory",
            cloud_inventory_impl,
            providers=providers,
            region=region,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_idempotent, title="Access Review")
    async def access_review(
        campaign_id: Annotated[
            str,
            Field(description="Optional campaign id to fetch one campaign with its review items. Omit to list campaigns."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope to read. Defaults to the control-plane default tenant."),
        ] = "default",
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum campaigns to list when campaign_id is omitted."),
        ] = 200,
    ) -> str:
        """List or get NHI access-review / recertification campaigns and their status.

        Pass ``campaign_id`` to fetch one campaign with its review items, or omit
        it to list campaigns. Not read-only: listing/fetching recomputes and
        persists each campaign's status (to surface overdue), so this is an
        idempotent write. Creating a campaign or submitting a reviewer decision
        is a separate write action not exposed through this tool.
        """
        return await execute_tool_async(
            "access_review",
            access_review_impl,
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            limit=limit,
            _truncate_response=truncate_response,
        )
