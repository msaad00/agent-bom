"""Governance MCP registrations with per-server dispatch bindings."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .bindings import OperatorToolBindings


def register_firewall_check(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.runtime import firewall_check_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Firewall Check")
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
        return await bindings.execute_tool_sync_async(
            "firewall_check",
            firewall_check_impl,
            source_agent=source_agent,
            target_agent=target_agent,
            source_roles=source_roles,
            target_roles=target_roles,
            _truncate_response=bindings.truncate_response,
        )


def register_audit_query(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.runtime import audit_query_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Audit Query")
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
        return await bindings.execute_tool_async(
            "audit_query",
            audit_query_impl,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            since=since,
            limit=limit,
            offset=offset,
            _truncate_response=bindings.truncate_response,
        )


def register_audit_integrity(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.runtime import audit_integrity_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Audit Integrity")
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
        return await bindings.execute_tool_async(
            "audit_integrity",
            audit_integrity_impl,
            tenant_id=tenant_id,
            limit=limit,
            include_runtime=include_runtime,
            _truncate_response=bindings.truncate_response,
        )


def register_cost_forecast(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.posture import cost_forecast_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Cost Forecast")
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
        return await bindings.execute_tool_async(
            "cost_forecast",
            cost_forecast_impl,
            agent=agent,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_cost_allocation(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.posture import cost_allocation_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Cost Allocation")
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
        return await bindings.execute_tool_async(
            "cost_allocation",
            cost_allocation_impl,
            cost_center=cost_center,
            tag=tag,
            agent=agent,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_credential_expiry(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.posture import credential_expiry_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Credential Expiry")
    async def credential_expiry() -> str:
        """Return expiring / overdue credential posture for control-plane secrets.

        Surfaces non-secret credential-expiry and rotation governance: which
        secrets are near expiry, overdue for rotation, or past max age, with an
        overall verdict. Never returns secret values.
        """
        return await bindings.execute_tool_async(
            "credential_expiry",
            credential_expiry_impl,
            _truncate_response=bindings.truncate_response,
        )


def register_nhi_discover(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.posture import nhi_discover_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="NHI Discover")
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
        return await bindings.execute_tool_async(
            "nhi_discover",
            nhi_discover_impl,
            providers=providers,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_cloud_inventory(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.posture import cloud_inventory_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Cloud Inventory")
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
        return await bindings.execute_tool_async(
            "cloud_inventory",
            cloud_inventory_impl,
            providers=providers,
            region=region,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_access_review(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.posture import access_review_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_idempotent, title="Access Review")
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
        return await bindings.execute_tool_async(
            "access_review",
            access_review_impl,
            destructive=True,
            required_scope="identity:write",
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            limit=limit,
            _truncate_response=bindings.truncate_response,
        )


REGISTRATIONS = (
    register_firewall_check,
    register_audit_query,
    register_audit_integrity,
    register_cost_forecast,
    register_cost_allocation,
    register_credential_expiry,
    register_nhi_discover,
    register_cloud_inventory,
    register_access_review,
)
