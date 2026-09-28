"""Benchmarks MCP registrations with per-server dispatch bindings."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .bindings import OperatorToolBindings


def register_cis_benchmark(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="CIS Benchmark")
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
            Field(description="Optional AWS region scope. Omit to evaluate CIS across all enabled AWS regions."),
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
        return await bindings.execute_tool_async(
            "cis_benchmark",
            bindings.implementations["cis_benchmark_impl"],
            provider=provider,
            checks=checks,
            region=region,
            profile=profile,
            subscription_id=subscription_id,
            project_id=project_id,
            _truncate_response=bindings.truncate_response,
        )


def register_kspm_cluster_posture(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="KSPM Cluster Posture")
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
        return await bindings.execute_tool_async(
            "kspm_cluster_posture",
            bindings.implementations["kspm_cluster_posture_impl"],
            namespace=namespace,
            all_namespaces=all_namespaces,
            context=context,
            enable_nodes_configz=enable_nodes_configz,
            _truncate_response=bindings.truncate_response,
        )


def register_fleet_scan(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Fleet Scan")
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
        return await bindings.execute_tool_async(
            "fleet_scan",
            bindings.implementations["fleet_scan_impl"],
            servers=servers,
            _truncate_response=bindings.truncate_response,
        )


REGISTRATIONS = (
    register_cis_benchmark,
    register_kspm_cluster_posture,
    register_fleet_scan,
)
