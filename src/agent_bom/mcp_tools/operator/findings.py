"""Findings MCP registrations with per-server dispatch bindings."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .bindings import OperatorToolBindings


def register_graph_correlate(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_idempotent, title="Graph Correlate")
    async def graph_correlate(
        name: Annotated[str, Field(min_length=1, max_length=160, description="Human-readable correlation run name.")],
        scan_ids: Annotated[
            list[str],
            Field(min_length=2, max_length=32, description="Two to 32 exact immutable source snapshot ids."),
        ],
        max_age_hours: Annotated[int, Field(ge=1, le=8760, description="Required source-evidence freshness bound in hours.")],
        idempotency_key: Annotated[
            str,
            Field(min_length=1, max_length=200, description="Caller-stable retry key for this exact correlation request."),
        ],
        reason: Annotated[str, Field(min_length=8, max_length=500, description="Human audit reason for creating the correlation.")],
        allow_stale: Annotated[bool, Field(description="Admit stale evidence while preserving its stale label.")] = False,
        operator_role: Annotated[str, Field(description="Operator role for this write action (audit).")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes (audit).")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope bound by MCP authentication context.")] = "default",
    ) -> str:
        """Create one bounded, provenance-rich correlation snapshot."""

        return await bindings.execute_tool_async(
            "graph_correlate",
            bindings.implementations["graph_correlate_impl"],
            destructive=True,
            required_scope="scan:write",
            name=name,
            scan_ids=scan_ids,
            max_age_hours=max_age_hours,
            idempotency_key=idempotency_key,
            reason=reason,
            allow_stale=allow_stale,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_graph_correlation_status(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Graph Correlation Status")
    async def graph_correlation_status(
        correlation_id: Annotated[str, Field(min_length=1, description="Correlation id returned by graph_correlate.")],
        tenant_id: Annotated[str, Field(description="Tenant scope bound by MCP authentication context.")] = "default",
    ) -> str:
        """Read run state, receipts, freshness, conflicts, and analysis bounds."""

        return await bindings.execute_tool_async(
            "graph_correlation_status",
            bindings.implementations["graph_correlation_status_impl"],
            required_scope="graph:read",
            correlation_id=correlation_id,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_diff(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Vulnerability Diff")
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
        return await bindings.execute_tool_async(
            "diff",
            bindings.implementations["diff_impl"],
            destructive=True,
            required_scope="findings:write",
            baseline=baseline,
            _run_scan_pipeline=bindings.run_scan_pipeline,
            _truncate_response=bindings.truncate_response,
        )


def register_findings_triage(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Record Finding Triage Decision")
    async def findings_triage(
        vulnerability_id: Annotated[str, Field(description="Vulnerability/advisory id being triaged (e.g. CVE-2024-1234).")] = "",
        package: Annotated[str, Field(description="Affected package name, or '*' for all packages (default).")] = "*",
        server_name: Annotated[str, Field(description="Optional MCP server / asset scope for the decision.")] = "",
        assignee: Annotated[str, Field(description="Owner recorded for the triage entry.")] = "",
        queue_state: Annotated[str, Field(description="Queue state: open, assigned, reviewing, or decided.")] = "open",
        decision: Annotated[str, Field(description="Decision: under_investigation, affected, or not_affected.")] = "under_investigation",
        justification: Annotated[
            str, Field(description="OpenVEX justification (required for not_affected), e.g. vulnerable_code_not_present.")
        ] = "",
        decision_reason: Annotated[str, Field(description="Free-text rationale for the decision.")] = "",
        expires_at: Annotated[str, Field(description="Optional ISO-8601 expiry for the triage entry.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this write action (audit).")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes (audit).")] = "",
        reason: Annotated[str, Field(description="Human audit reason for recording the decision.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for the triage entry and audit logging.")] = "default",
    ) -> str:
        """Record a tenant-scoped finding triage decision to the exception store.

        Writes the same entry as the REST ``POST /v1/findings/triage`` endpoint.
        Requires an admin operator + ``findings:write`` scope. A ``not_affected``
        decision requires an OpenVEX ``justification``.
        """
        return await bindings.execute_tool_async(
            "findings_triage",
            bindings.implementations["findings_triage_impl"],
            destructive=True,
            required_scope="findings:write",
            vulnerability_id=vulnerability_id,
            package=package,
            server_name=server_name,
            assignee=assignee,
            queue_state=queue_state,
            decision=decision,
            justification=justification,
            decision_reason=decision_reason,
            expires_at=expires_at,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_list_exceptions(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="List Vulnerability Exceptions")
    async def list_exceptions(
        status: Annotated[
            str,
            Field(description="Optional lifecycle status filter: pending, active, expired, or revoked."),
        ] = "",
        limit: Annotated[
            int,
            Field(ge=1, le=500, description="Maximum tenant-scoped exception records to return."),
        ] = 100,
        tenant_id: Annotated[
            str,
            Field(description="Requested tenant; the MCP server binding remains authoritative."),
        ] = "default",
    ) -> str:
        """List tenant-scoped exception evidence from the canonical store."""
        return await bindings.execute_tool_async(
            "list_exceptions",
            bindings.implementations["list_exceptions_impl"],
            status=status,
            limit=limit,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_request_exception(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Request Vulnerability Exception")
    async def request_exception(
        vulnerability_id: Annotated[str, Field(description="Vulnerability or advisory id to except.")] = "",
        package_name: Annotated[str, Field(description="Affected package name, or '*' for any package.")] = "*",
        server_name: Annotated[str, Field(description="Optional server or asset scope.")] = "",
        exception_reason: Annotated[str, Field(description="Human rationale for the exception request.")] = "",
        expires_at: Annotated[str, Field(description="Optional timezone-aware ISO-8601 expiry.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this audited write.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes for this audited write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for requesting the exception.")] = "",
        tenant_id: Annotated[
            str,
            Field(description="Requested tenant; the MCP server binding remains authoritative."),
        ] = "default",
    ) -> str:
        """Create a pending exception through the shared REST/UI/MCP lifecycle."""
        return await bindings.execute_tool_async(
            "request_exception",
            bindings.implementations["request_exception_impl"],
            destructive=True,
            required_scope="findings:write",
            vulnerability_id=vulnerability_id,
            package_name=package_name,
            server_name=server_name,
            exception_reason=exception_reason,
            expires_at=expires_at,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_approve_exception(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Approve Vulnerability Exception")
    async def approve_exception(
        exception_id: Annotated[str, Field(description="Pending exception id to activate.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this audited write.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes for this audited write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for approving the exception.")] = "",
        tenant_id: Annotated[
            str,
            Field(description="Requested tenant; the MCP server binding remains authoritative."),
        ] = "default",
    ) -> str:
        """Activate a pending exception through the canonical lifecycle store."""
        return await bindings.execute_tool_async(
            "approve_exception",
            bindings.implementations["approve_exception_impl"],
            destructive=True,
            required_scope="findings:write",
            exception_id=exception_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_risk_campaign_workflow(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Manage Remediation Campaign Workflow")
    async def risk_campaign_workflow(
        action: Annotated[
            str,
            Field(description="Workflow action: list, update, verify, verification_queue, ticket_create, or ticket_sync."),
        ] = "list",
        campaign_id: Annotated[str, Field(description="Campaign id for update or verify.")] = "",
        version: Annotated[int, Field(description="Current optimistic-lock version for update or verify.", ge=0)] = 0,
        owner: Annotated[str, Field(description="Owner to assign during update.")] = "",
        sla_due_at: Annotated[str, Field(description="Timezone-aware ISO-8601 SLA deadline during update.")] = "",
        state: Annotated[str, Field(description="Workflow state: open, in_progress, blocked, or done.")] = "",
        connection_id: Annotated[str, Field(description="Stored ticketing connection id for ticket_create.")] = "",
        project: Annotated[str, Field(description="Optional ticketing project override.")] = "",
        issue_type: Annotated[str, Field(description="Optional ticketing issue type override.")] = "",
        cursor: Annotated[str, Field(description="Continuation cursor for bounded queue or ticket actions.")] = "",
        limit: Annotated[int, Field(description="Bounded queue or ticket action page size.", ge=1, le=25)] = 25,
        idempotency_key: Annotated[str, Field(description="Retry key for verify; replays return the original result.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this write action (audit).")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes (audit).")] = "",
        tenant_id: Annotated[str, Field(description="Requested tenant; the MCP server binding remains authoritative.")] = "default",
    ) -> str:
        """List, assign, ticket, or verify a tenant-scoped remediation campaign.

        Uses the same campaign store and verification service as REST and CLI.
        Writes require an authenticated admin operator with ``findings:write``.
        """
        return await bindings.execute_tool_async(
            "risk_campaign_workflow",
            bindings.implementations["risk_campaign_workflow_impl"],
            destructive=True,
            required_scope="findings:write",
            action=action,
            campaign_id=campaign_id,
            version=version,
            owner=owner,
            sla_due_at=sla_due_at,
            state=state,
            connection_id=connection_id,
            project=project,
            issue_type=issue_type,
            cursor=cursor,
            limit=limit,
            idempotency_key=idempotency_key,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


REGISTRATIONS = (
    register_graph_correlate,
    register_graph_correlation_status,
    register_diff,
    register_findings_triage,
    register_list_exceptions,
    register_request_exception,
    register_approve_exception,
    register_risk_campaign_workflow,
)
