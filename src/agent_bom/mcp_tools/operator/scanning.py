"""Scanning MCP registrations with per-server dispatch bindings."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .bindings import OperatorToolBindings


def register_cloud_side_scan(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Cloud Side-Scan (Azure/GCP)")
    async def cloud_side_scan(
        provider: Annotated[str, Field(description="Cloud provider: 'azure' or 'gcp' (AWS EBS uses the CLI side-scan entrypoint).")] = "",
        target_id: Annotated[str, Field(description="Managed/persistent disk resource id to scan.")] = "",
        account_id: Annotated[str, Field(description="Azure subscription id / GCP project id owning the disk + collector.")] = "",
        location: Annotated[str, Field(description="Azure location / GCP zone of the temp disk (must match the collector).")] = "",
        collector_id: Annotated[str, Field(description="In-account collector VM/instance the temp disk attaches to.")] = "",
        collector_resource_group: Annotated[str, Field(description="Azure only: resource group of the collector VM.")] = "",
        region: Annotated[str, Field(description="Optional provider region hint for client construction.")] = "",
        idempotency_key: Annotated[str, Field(description="Retry-safe key; the same key reuses one execution record.")] = "",
        scan_secrets_enabled: Annotated[
            bool, Field(description="Include the redacted secret scan (type + location only, never values).")
        ] = True,
        operator_role: Annotated[str, Field(description="Operator role for this write action (audit).")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes (audit).")] = "",
        reason: Annotated[str, Field(description="Human audit reason for triggering the side-scan.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for the execution and durable lifecycle record.")] = "default",
    ) -> str:
        """Trigger one agentless Azure/GCP disk side-scan and read back honest state.

        Runs the same executor as ``agent-bom cloud side-scan`` and the REST
        ``POST /v1/cloud/side-scan``: snapshot the disk, mount a temp copy on an
        in-account collector read-only, record SBOM + CVE + secret *metadata* only,
        and tear every owned temporary resource down. Requires an admin operator +
        ``cloud:write`` scope. Credentials are never accepted here — the
        executor resolves read-only credentials from the provider's default chain
        (``credentialed_smoke=false``). Fail-closed and honest: OFF → ``disabled``;
        missing extra/credentials → ``unavailable``; never a clean-workload claim.
        """
        return await bindings.execute_tool_async(
            "cloud_side_scan",
            bindings.implementations["cloud_side_scan_impl"],
            destructive=True,
            required_scope="cloud:write",
            provider=provider,
            target_id=target_id,
            account_id=account_id,
            location=location,
            collector_id=collector_id,
            collector_resource_group=collector_resource_group,
            region=region,
            idempotency_key=idempotency_key,
            scan_secrets_enabled=scan_secrets_enabled,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_marketplace_check(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Marketplace Trust Check")
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
        return await bindings.execute_tool_async(
            "marketplace_check",
            bindings.implementations["marketplace_check_impl"],
            package=package,
            ecosystem=ecosystem,
            _validate_ecosystem=bindings.validate_ecosystem,
            _get_registry_data_raw=bindings.get_registry_data_raw,
            _truncate_response=bindings.truncate_response,
        )


def register_code_scan(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Semgrep SAST Scan")
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
        return await bindings.execute_tool_async(
            "code_scan",
            bindings.implementations["code_scan_impl"],
            path=path,
            config=config,
            _safe_path=bindings.safe_path,
            _truncate_response=bindings.truncate_response,
        )


REGISTRATIONS = (
    register_cloud_side_scan,
    register_marketplace_check,
    register_code_scan,
)
