"""Per-server dependencies captured by operator tool registration factories."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations


def capture_operator_implementations() -> Mapping[str, Callable[..., Any]]:
    """Capture current implementation callbacks when a server is registered."""
    import agent_bom.mcp_tools.analysis as analysis
    import agent_bom.mcp_tools.compliance as compliance
    import agent_bom.mcp_tools.exceptions as exceptions
    import agent_bom.mcp_tools.graph as graph
    import agent_bom.mcp_tools.identity as identity
    import agent_bom.mcp_tools.kspm as kspm
    import agent_bom.mcp_tools.posture as posture
    import agent_bom.mcp_tools.registry as registry
    import agent_bom.mcp_tools.risk_campaigns as risk_campaigns
    import agent_bom.mcp_tools.runtime as runtime
    import agent_bom.mcp_tools.sbom as sbom
    import agent_bom.mcp_tools.scanning as scanning
    import agent_bom.mcp_tools.side_scan as side_scan
    import agent_bom.mcp_tools.triage as triage
    import agent_bom.output.graph_export as graph_export

    return MappingProxyType(
        {
            "_graph_to_json": graph_export.to_json,
            "_to_cypher": graph_export.to_cypher,
            "_to_dot": graph_export.to_dot,
            "_to_graphml": graph_export.to_graphml,
            "_to_mermaid": graph_export.to_mermaid,
            "access_review_impl": posture.access_review_impl,
            "analytics_query_impl": analysis.analytics_query_impl,
            "anomaly_scan_impl": runtime.anomaly_scan_impl,
            "approve_exception_impl": exceptions.approve_exception_impl,
            "audit_integrity_impl": runtime.audit_integrity_impl,
            "audit_query_impl": runtime.audit_query_impl,
            "cis_benchmark_impl": compliance.cis_benchmark_impl,
            "cloud_inventory_impl": posture.cloud_inventory_impl,
            "cloud_side_scan_impl": side_scan.cloud_side_scan_impl,
            "code_scan_impl": scanning.code_scan_impl,
            "context_graph_impl": analysis.context_graph_impl,
            "cost_allocation_impl": posture.cost_allocation_impl,
            "cost_forecast_impl": posture.cost_forecast_impl,
            "cost_report_impl": runtime.cost_report_impl,
            "credential_expiry_impl": posture.credential_expiry_impl,
            "diff_impl": sbom.diff_impl,
            "drift_incidents_impl": runtime.drift_incidents_impl,
            "findings_triage_impl": triage.findings_triage_impl,
            "firewall_check_impl": runtime.firewall_check_impl,
            "fleet_scan_impl": registry.fleet_scan_impl,
            "gateway_status_impl": runtime.gateway_status_impl,
            "graph_correlate_impl": graph.graph_correlate_impl,
            "graph_correlation_status_impl": graph.graph_correlation_status_impl,
            "identity_grant_jit_impl": identity.identity_grant_jit_impl,
            "identity_issue_impl": identity.identity_issue_impl,
            "identity_revoke_impl": identity.identity_revoke_impl,
            "identity_revoke_jit_impl": identity.identity_revoke_jit_impl,
            "identity_rotate_impl": identity.identity_rotate_impl,
            "kspm_cluster_posture_impl": kspm.kspm_cluster_posture_impl,
            "list_exceptions_impl": exceptions.list_exceptions_impl,
            "marketplace_check_impl": registry.marketplace_check_impl,
            "nhi_discover_impl": posture.nhi_discover_impl,
            "proxy_alerts_impl": runtime.proxy_alerts_impl,
            "proxy_status_impl": runtime.proxy_status_impl,
            "request_exception_impl": exceptions.request_exception_impl,
            "risk_campaign_workflow_impl": risk_campaigns.risk_campaign_workflow_impl,
            "runtime_blueprint_drift_impl": runtime.runtime_blueprint_drift_impl,
            "runtime_blueprints_impl": runtime.runtime_blueprints_impl,
            "runtime_correlate_impl": runtime.runtime_correlate_impl,
            "runtime_production_index_impl": runtime.runtime_production_index_impl,
            "shield_break_glass_impl": runtime.shield_break_glass_impl,
            "shield_start_impl": runtime.shield_start_impl,
            "shield_status_impl": runtime.shield_status_impl,
            "shield_unblock_impl": runtime.shield_unblock_impl,
        }
    )


@dataclass(frozen=True)
class OperatorToolBindings:
    mcp: FastMCP
    read_only: ToolAnnotations
    write_action: ToolAnnotations
    write_idempotent: ToolAnnotations
    execute_tool_async: Callable[..., Awaitable[str]]
    execute_tool_sync_async: Callable[..., Awaitable[str]]
    safe_path: Callable[..., Any]
    run_scan_pipeline: Callable[..., Awaitable[Any]]
    truncate_response: Callable[..., str]
    validate_ecosystem: Callable[..., Any]
    get_registry_data_raw: Callable[..., Any]
    build_dep_graph_from_agents: Callable[..., Any]
    implementations: Mapping[str, Callable[..., Any]]
