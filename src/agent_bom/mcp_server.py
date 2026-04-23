"""agent-bom MCP Server — expose security scanning as MCP tools.

Start with:
    agent-bom mcp server              # stdio (for Claude Desktop, Cursor, etc.)
    agent-bom mcp server --sse        # SSE transport (for remote clients)

Tools (36):
    scan                — Full discovery → scan → output pipeline
    check               — Check a specific package for CVEs before installing
    blast_radius        — Look up blast radius for a specific CVE
    policy_check        — Evaluate a policy against scan results
    registry_lookup     — Query the MCP server security metadata registry
    generate_sbom       — Generate CycloneDX or SPDX SBOM
    compliance          — OWASP/ATLAS/NIST AI RMF compliance posture
    remediate           — Generate actionable remediation plan
    skill_scan          — Scan instruction files for packages, servers, trust, and findings
    skill_verify        — Verify instruction file Sigstore provenance
    skill_trust         — ClawHub-style trust assessment for SKILL.md files
    verify              — Package integrity + SLSA provenance verification
    where               — Show all MCP discovery paths + existence status
    inventory           — List agents/servers without CVE scanning
    tool_risk_assessment — Score live MCP tool capabilities and server risk
    diff                — Compare scan against baseline for new/resolved vulns
    marketplace_check   — Pre-install trust check with registry cross-reference
    code_scan           — SAST scanning via Semgrep with CWE-based compliance mapping
    context_graph       — Agent context graph with lateral movement analysis
    analytics_query     — Query vulnerability trends and runtime events from ClickHouse
    cis_benchmark       — Run CIS benchmark checks against cloud accounts
    fleet_scan          — Batch registry lookup for fleet inventories
    runtime_correlate   — Cross-reference runtime audit logs with CVE findings
    vector_db_scan      — Scan vector databases for embedding poisoning and access risks
    aisvs_benchmark     — OWASP AI Security Verification Standard benchmark
    gpu_infra_scan      — Scan GPU infrastructure for CVEs and misconfigurations
    dataset_card_scan   — Scan dataset cards for licensing and provenance
    training_pipeline_scan — Scan training pipeline artifacts for lineage
    browser_extension_scan — Scan browser extensions for dangerous permissions
    model_provenance_scan  — Check ML model provenance from HuggingFace/Ollama
    prompt_scan         — Scan prompt templates for injection risks
    model_file_scan     — Scan model files for serialization risks
    ai_inventory_scan   — Scan source code for AI SDK imports, model references, shadow AI
    license_compliance_scan — Evaluate package licenses against SPDX compliance policy
    ingest_external_scan   — Ingest Trivy, Grype, or Syft JSON output with blast radius analysis

Resources (3):
    registry://servers  — Browse 427+ server security metadata registry
    policy://template   — Default security policy template
    metrics://tools     — MCP tool execution metrics and limits

Security: Read-only. Never executes MCP servers or reads credential values.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import time
from collections import OrderedDict, deque
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable, Optional, TypeVar

from mcp.server.lowlevel.server import request_ctx as _mcp_request_ctx
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl, Field, TypeAdapter

from agent_bom import mcp_server_runtime as _mcp_runtime
from agent_bom import mcp_server_scan as _mcp_scan
from agent_bom.config import MCP_CALLER_RATE_LIMIT as _MCP_CALLER_RATE_LIMIT
from agent_bom.config import MCP_CALLER_WINDOW_SECONDS as _MCP_CALLER_WINDOW_SECONDS
from agent_bom.config import MCP_MAX_CALLER_STATES as _MCP_MAX_CALLER_STATES
from agent_bom.config import MCP_MAX_CONCURRENT_TOOLS as _MCP_MAX_CONCURRENT_TOOLS
from agent_bom.config import MCP_MAX_FILE_SIZE as _MAX_FILE_SIZE  # noqa: F401 - retained public test import
from agent_bom.config import MCP_MAX_REQUEST_TRACES as _MCP_MAX_REQUEST_TRACES
from agent_bom.config import MCP_MAX_RESPONSE_CHARS as _MAX_RESPONSE_CHARS
from agent_bom.config import MCP_MAX_TOOL_METRICS as _MCP_MAX_TOOL_METRICS
from agent_bom.config import MCP_TOOL_TIMEOUT_SECONDS as _MCP_TOOL_TIMEOUT_SECONDS
from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
from agent_bom.mcp_server_entrypoint import create_smithery_server as _create_smithery_server
from agent_bom.mcp_server_metadata import (
    _SERVER_CARD_PROMPTS as _METADATA_SERVER_CARD_PROMPTS,
)
from agent_bom.mcp_server_metadata import (
    _SERVER_CARD_TOOLS as _METADATA_SERVER_CARD_TOOLS,
)
from agent_bom.mcp_server_metadata import (
    attach_metadata_routes,
)
from agent_bom.mcp_server_metadata import (
    build_server_card as _metadata_build_server_card,
)
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)
_ToolReturn = TypeVar("_ToolReturn")
_HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)

# Backward-compatible exports for tests and downstream imports that still
# read metadata directly from `agent_bom.mcp_server`.
_SERVER_CARD_PROMPTS = _METADATA_SERVER_CARD_PROMPTS
_SERVER_CARD_TOOLS = _METADATA_SERVER_CARD_TOOLS
build_server_card = _metadata_build_server_card

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_VALID_ECOSYSTEMS = SUPPORTED_PACKAGE_ECOSYSTEM_SET

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)


class _StaticBearerTokenVerifier:
    """FastMCP token verifier backed by a single configured bearer token."""

    def __init__(self, token: str):
        self._token = token

    async def verify_token(self, token: str):
        from mcp.server.auth.provider import AccessToken

        if token and hmac.compare_digest(token, self._token):
            return AccessToken(token=token, client_id="agent-bom-static-token", scopes=[], resource=None)
        return None


def _validate_ecosystem(ecosystem: str) -> str:
    """Return cleaned ecosystem string or raise ValueError."""
    return _mcp_runtime.validate_ecosystem(ecosystem, _VALID_ECOSYSTEMS)


def _validate_cve_id(cve_id: str) -> str:
    """Return cleaned CVE/GHSA ID or raise ValueError."""
    return _mcp_runtime.validate_cve_id(cve_id, _CVE_RE, _GHSA_RE)


def _truncate_response(response_str: str) -> str:
    """Truncate response if it exceeds _MAX_RESPONSE_CHARS."""
    return _mcp_runtime.truncate_response(response_str, _MAX_RESPONSE_CHARS)


def _safe_path(path_str: str) -> Path:
    """Resolve a user-provided path and validate against directory traversal."""
    return _mcp_runtime.safe_path(path_str)


def _get_tool_semaphore() -> asyncio.Semaphore:
    """Return a semaphore bound to the current running event loop."""
    return _mcp_runtime.get_tool_semaphore(
        _loop_tool_semaphores,
        max_cached_tool_loops=_MAX_CACHED_TOOL_LOOPS,
        max_concurrent_tools=_MCP_MAX_CONCURRENT_TOOLS,
    )


def _record_tool_metric(
    tool_name: str,
    *,
    elapsed_ms: int,
    success: bool,
    timed_out: bool = False,
    error: str | None = None,
) -> None:
    """Update bounded in-memory metrics for MCP tool calls."""
    _mcp_runtime.record_tool_metric(
        _tool_metrics,
        max_tool_metrics=_MCP_MAX_TOOL_METRICS,
        tool_name=tool_name,
        elapsed_ms=elapsed_ms,
        success=success,
        timed_out=timed_out,
        error=error,
    )


def _tool_metrics_snapshot() -> dict[str, Any]:
    """Return structured MCP tool metrics for resources and health checks."""
    return _mcp_runtime.tool_metrics_snapshot(
        _tool_metrics,
        caller_rate_windows=_caller_rate_windows,
        recent_tool_requests=_recent_tool_requests,
        max_concurrent_tools=_MCP_MAX_CONCURRENT_TOOLS,
        tool_timeout_seconds=_MCP_TOOL_TIMEOUT_SECONDS,
        caller_rate_limit=_MCP_CALLER_RATE_LIMIT,
        caller_window_seconds=_MCP_CALLER_WINDOW_SECONDS,
    )


def _current_tool_request() -> dict[str, str | None]:
    """Return request identity metadata when running inside an MCP request."""
    return _mcp_runtime.current_tool_request(_mcp_request_ctx.get)


def _check_caller_rate_limit(caller: str) -> float | None:
    """Return retry-after seconds when a caller exceeds the bounded MCP rate window."""
    return _mcp_runtime.check_caller_rate_limit(
        _caller_rate_windows,
        caller,
        caller_rate_limit=_MCP_CALLER_RATE_LIMIT,
        caller_window_seconds=_MCP_CALLER_WINDOW_SECONDS,
        max_caller_states=_MCP_MAX_CALLER_STATES,
        monotonic_now=time.monotonic(),
    )


def _record_tool_request(
    tool_name: str,
    *,
    caller: str | None,
    client_id: str | None,
    request_id: str | None,
    status: str,
    elapsed_ms: int,
    error: str | None = None,
) -> None:
    """Store a bounded trace of recent MCP tool requests."""
    _mcp_runtime.record_tool_request(
        _recent_tool_requests,
        tool_name,
        caller=caller,
        client_id=client_id,
        request_id=request_id,
        status=status,
        elapsed_ms=elapsed_ms,
        error=error,
    )


async def _execute_tool_async(
    tool_name: str,
    handler: Callable[..., Awaitable[_ToolReturn]],
    /,
    *args,
    timeout: float | None = None,
    **kwargs,
) -> _ToolReturn | str:
    """Run an async MCP tool with bounded concurrency, timeout, and metrics."""
    timeout_seconds = timeout if timeout and timeout > 0 else _MCP_TOOL_TIMEOUT_SECONDS
    return await _mcp_runtime.execute_tool_async(
        tool_name,
        handler,
        *args,
        timeout_seconds=timeout_seconds,
        request_meta_factory=_current_tool_request,
        check_caller_rate_limit_fn=_check_caller_rate_limit,
        record_tool_metric_fn=_record_tool_metric,
        record_tool_request_fn=_record_tool_request,
        truncate_response_fn=_truncate_response,
        get_tool_semaphore_fn=_get_tool_semaphore,
        sanitize_error_fn=sanitize_error,
        logger=logger,
        **kwargs,
    )


async def _execute_tool_sync_async(
    tool_name: str,
    handler: Callable[..., _ToolReturn],
    /,
    *args,
    tool_timeout: float | None = None,
    **kwargs,
) -> _ToolReturn | str:
    """Run a sync MCP tool under the shared async governance envelope."""
    timeout_seconds = _MCP_TOOL_TIMEOUT_SECONDS if tool_timeout is None else tool_timeout
    response_truncator = kwargs.get("_truncate_response", _truncate_response)
    return await _mcp_runtime.execute_tool_sync_async(
        tool_name,
        handler,
        *args,
        timeout_seconds=timeout_seconds,
        request_meta_factory=_current_tool_request,
        check_caller_rate_limit_fn=_check_caller_rate_limit,
        record_tool_metric_fn=_record_tool_metric,
        record_tool_request_fn=_record_tool_request,
        truncate_response_fn=response_truncator,
        get_tool_semaphore_fn=_get_tool_semaphore,
        sanitize_error_fn=sanitize_error,
        logger=logger,
        **kwargs,
    )


# Dep-graph builder + registry cache live in mcp_server_helpers (#1522 Phase 2).
# Re-bound to their underscore names here so the existing closures inside
# create_mcp_server() don't need to change.
from agent_bom.mcp_server_helpers import build_dep_graph_from_agents as _build_dep_graph_from_agents  # noqa: E402
from agent_bom.mcp_server_helpers import get_registry_data as _get_registry_data  # noqa: E402
from agent_bom.mcp_server_helpers import get_registry_data_raw as _get_registry_data_raw  # noqa: E402

_tool_metrics: OrderedDict[str, dict[str, Any]] = OrderedDict()
_loop_tool_semaphores: OrderedDict[int, asyncio.Semaphore] = OrderedDict()
_caller_rate_windows: OrderedDict[str, deque[float]] = OrderedDict()
_recent_tool_requests: deque[dict[str, Any]] = deque(maxlen=_MCP_MAX_REQUEST_TRACES)
_MAX_CACHED_TOOL_LOOPS = 8


# All agent-bom tools are read-only scanners
_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def _check_mcp_sdk() -> None:
    """Ensure the mcp SDK is available."""
    _mcp_runtime.check_mcp_sdk()


# ---------------------------------------------------------------------------
# Shared scan pipeline helper
# ---------------------------------------------------------------------------


async def _run_scan_pipeline(
    config_path: Optional[str] = None,
    image: Optional[str] = None,
    sbom_path: Optional[str] = None,
    enrich: bool = False,
    transitive: bool = False,
):
    """Run discovery -> extraction -> scanning and return (agents, blast_radii, warnings)."""
    return await _mcp_scan.run_scan_pipeline(
        safe_path=_safe_path,
        config_path=config_path,
        image=image,
        sbom_path=sbom_path,
        enrich=enrich,
        transitive=transitive,
    )


# ---------------------------------------------------------------------------
# MCP Server factory
# ---------------------------------------------------------------------------


def create_mcp_server(*, host: str = "127.0.0.1", port: int = 8000, bearer_token: str | None = None):
    """Create and configure the agent-bom MCP server with all tools.

    When the smithery SDK is installed, the server is automatically enhanced
    with session-config and CORS middleware for Smithery.ai hosted deployment.
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level="INFO")
    _check_mcp_sdk()
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.fastmcp import FastMCP

    from agent_bom import __version__

    auth_settings = None
    token_verifier = None
    if bearer_token:
        resource_url: AnyHttpUrl = _HTTP_URL_ADAPTER.validate_python(f"http://{host}:{port}")
        auth_settings = AuthSettings(
            issuer_url=resource_url,
            resource_server_url=resource_url,
            required_scopes=[],
        )
        token_verifier = _StaticBearerTokenVerifier(bearer_token)

    mcp = FastMCP(
        name="agent-bom",
        host=host,
        port=port,
        auth=auth_settings,
        token_verifier=token_verifier,
        instructions=(
            f"agent-bom v{__version__} — AI infrastructure security scanner with MCP security tools. "
            "Scans packages and images for CVEs (OSV, NVD, EPSS, CISA KEV), maps blast radius "
            "from vulnerabilities to credentials and tools, generates SBOMs (CycloneDX, SPDX), "
            "enforces security policies, and maps to 14 compliance frameworks"
            "(OWASP LLM/MCP/Agentic, MITRE ATLAS, NIST AI RMF/CSF/800-53, FedRAMP, EU AI Act, ISO 27001, SOC 2). "
            "Discovers 30 MCP clients. Read-only, agentless, no credentials required."
        ),
    )
    # Set the actual agent-bom version (FastMCP defaults to SDK version)
    mcp._mcp_server.version = __version__

    # Import tool implementations
    from agent_bom.mcp_server_specialized import register_specialized_ai_tools
    from agent_bom.mcp_tools.analysis import (
        analytics_query_impl,
        blast_radius_impl,
        context_graph_impl,
    )
    from agent_bom.mcp_tools.compliance import (
        cis_benchmark_impl,
        compliance_impl,
        policy_check_impl,
    )
    from agent_bom.mcp_tools.registry import (
        fleet_scan_impl,
        marketplace_check_impl,
        registry_lookup_impl,
    )
    from agent_bom.mcp_tools.runtime import (
        inventory_impl,
        runtime_correlate_impl,
        skill_scan_impl,
        skill_trust_impl,
        skill_verify_impl,
        tool_risk_assessment_impl,
        verify_impl,
        where_impl,
    )
    from agent_bom.mcp_tools.sbom import diff_impl, generate_sbom_impl, remediate_impl
    from agent_bom.mcp_tools.scanning import check_impl, code_scan_impl, scan_impl

    # ── Tool 1: scan ──────────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Security Scan")
    async def scan(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        image: Annotated[str | None, Field(description="Docker image to scan (e.g. 'nginx:1.25', 'ghcr.io/org/app:v1').")] = None,
        sbom_path: Annotated[str | None, Field(description="Path to existing CycloneDX or SPDX JSON SBOM file to ingest.")] = None,
        enrich: Annotated[bool, Field(description="Enable NVD CVSS, EPSS probability, and CISA KEV enrichment.")] = False,
        scorecard: Annotated[
            bool, Field(description="Enrich packages with OpenSSF Scorecard scores (requires resolvable GitHub repos).")
        ] = False,
        transitive: Annotated[bool, Field(description="Resolve transitive dependencies for npx/uvx packages.")] = False,
        verify_integrity: Annotated[
            bool, Field(description="Verify package SHA-256/SRI hashes and SLSA provenance against registries.")
        ] = False,
        fail_severity: Annotated[
            str | None, Field(description="Return failure status if vulns at this severity or higher: critical, high, medium, low.")
        ] = None,
        warn_severity: Annotated[
            str | None,
            Field(
                description=(
                    "Return warning status (gate_status=warn, exit 0) when vulns at this severity or higher exist. "
                    "Use with fail_severity for two-tier CI gates, e.g. warn_severity='medium', fail_severity='critical'."
                )
            ),
        ] = None,
        auto_update_db: Annotated[bool, Field(description="Auto-refresh local vuln DB if stale (>7 days) before scanning.")] = True,
        db_sources: Annotated[
            str | None,
            Field(description="Comma-separated DB sources to sync before scanning (e.g. 'nvd,ghsa,osv,epss,kev')."),
        ] = None,
        output_format: Annotated[
            str,
            Field(description="Output format: 'json' (default), 'sarif', 'cyclonedx', 'spdx', 'junit', 'csv', or 'markdown'."),
        ] = "json",
        policy: Annotated[
            dict | None,
            Field(
                description=(
                    "Policy object to evaluate alongside scan results,"
                    ' e.g. {"rules": [{"id": "no-critical", "severity_gte": "critical", "action": "fail"}]}.'
                )
            ),
        ] = None,
    ) -> str:
        """Run a full AI supply chain security scan.

        Discovers local MCP configurations (Claude Desktop, Cursor, Windsurf,
        VS Code Copilot, OpenClaw, etc.), extracts package dependencies, queries
        OSV.dev for CVEs, assesses config security (credential exposure, tool access),
        computes blast radius, and returns structured results.

        Returns:
            JSON with the complete AI-BOM report including agents, packages,
            vulnerabilities, blast radius, and remediation guidance.
        """
        return await _execute_tool_async(
            "scan",
            scan_impl,
            config_path=config_path,
            image=image,
            sbom_path=sbom_path,
            enrich=enrich,
            scorecard=scorecard,
            transitive=transitive,
            verify_integrity=verify_integrity,
            fail_severity=fail_severity,
            warn_severity=warn_severity,
            auto_update_db=auto_update_db,
            db_sources=db_sources,
            output_format=output_format,
            policy=policy,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 2: check ────────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Package CVE Check")
    async def check(
        package: Annotated[
            str,
            Field(
                description=(
                    "Package name with optional version, e.g. 'express@4.18.2',"
                    " '@modelcontextprotocol/server-filesystem@2025.1.14', or 'requests' (resolves @latest)."
                )
            ),
        ],
        ecosystem: Annotated[
            str,
            Field(
                description=(
                    "Package ecosystem: 'npm', 'pypi', 'go', 'cargo', 'maven', 'nuget', "
                    "'rubygems', 'composer', 'swift', 'pub', 'hex', 'conda', 'deb', 'apk', or 'rpm'."
                )
            ),
        ] = "npm",
    ) -> str:
        """Check a specific package for known CVEs before installing.

        Queries OSV.dev for vulnerabilities in the given package. Use this
        before installing an MCP server or dependency to verify it is safe.

        Args:
            package: Package name with optional version, e.g. "express@4.18.2",
                     "@modelcontextprotocol/server-filesystem@2025.1.14",
                     or just "requests" (resolves @latest).
            ecosystem: Package ecosystem — "npm", "pypi", "go", "cargo",
                       "maven", "nuget", "rubygems", "composer", "swift",
                       "pub", "hex", "conda", "deb", "apk", or "rpm".
                       Defaults to "npm".

        Returns:
            JSON with package, version, ecosystem, vulnerability count,
            and vulnerability details (id, severity, cvss, fix version, summary).
        """
        return await _execute_tool_async(
            "check",
            check_impl,
            package=package,
            ecosystem=ecosystem,
            _validate_ecosystem=_validate_ecosystem,
            _truncate_response=_truncate_response,
        )

    # ── Tool 3: blast_radius ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Blast Radius Analysis")
    async def blast_radius(
        cve_id: Annotated[str, Field(description="CVE identifier to look up, e.g. 'CVE-2024-1234' or 'GHSA-xxxx'.")],
    ) -> str:
        """Look up the blast radius of a specific CVE across your AI agent setup.

        Scans local MCP configurations, finds the specified CVE, and returns
        the full attack chain: which packages are affected, which MCP servers
        use those packages, which agents connect to those servers, and what
        credentials and tools are exposed.

        Args:
            cve_id: The CVE identifier (e.g. "CVE-2024-1234" or "GHSA-xxxx").

        Returns:
            JSON with blast radius details including risk_score,
            affected_servers, affected_agents, exposed_credentials, and
            exposed_tools. Returns found=false if CVE not found.
        """
        return await _execute_tool_async(
            "blast_radius",
            blast_radius_impl,
            cve_id=cve_id,
            _validate_cve_id=_validate_cve_id,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 4: policy_check ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Policy Evaluation")
    async def policy_check(
        policy_json: Annotated[
            str,
            Field(
                description=(
                    "JSON string containing policy rules,"
                    ' e.g. {"rules": [{"id": "no-critical", "severity_gte": "critical", "action": "fail"}]}.'
                )
            ),
        ],
    ) -> str:
        """Evaluate a security policy against current scan results.

        Runs a scan, then evaluates the provided policy rules against the
        findings. Policies can gate on severity thresholds, CISA KEV status,
        AI risk flags, credential exposure, and denied packages.

        Args:
            policy_json: JSON string containing policy rules. Example:
                {"rules": [{"id": "no-critical", "severity_gte": "critical",
                "action": "fail"}, {"id": "no-kev", "kev": true, "action": "fail"}]}

        Returns:
            JSON with passed (bool), violations list, failure_count, and
            warning_count.
        """
        return await _execute_tool_async(
            "policy_check",
            policy_check_impl,
            policy_json=policy_json,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 5: registry_lookup ───────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Registry Lookup")
    async def registry_lookup(
        server_name: Annotated[
            str | None, Field(description="MCP server name to look up, e.g. 'filesystem', '@modelcontextprotocol/server-github'.")
        ] = None,
        package_name: Annotated[
            str | None,
            Field(
                description="Package name to search for, e.g. 'mcp-server-sqlite'. At least one of server_name or package_name is required."
            ),
        ] = None,
    ) -> str:
        """Query the agent-bom MCP server threat intelligence registry.

        Look up risk level, known tools, credential requirements, and
        verification status for known MCP servers. The registry contains
        109+ servers with security metadata.

        Args:
            server_name: MCP server name to look up (e.g. "filesystem",
                         "@modelcontextprotocol/server-github").
            package_name: Package name to search for (e.g. "mcp-server-sqlite").
                          At least one of server_name or package_name is required.

        Returns:
            JSON with registry entry: risk_level, verified, tools,
            credential_env_vars, risk_justification. Returns found=false
            if not found.
        """
        return await _execute_tool_sync_async(
            "registry_lookup",
            registry_lookup_impl,
            server_name=server_name,
            package_name=package_name,
            _get_registry_data=_get_registry_data,
        )

    # ── Tool 6: generate_sbom ─────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Generate SBOM")
    async def generate_sbom(
        format: Annotated[str, Field(description="SBOM format: 'cyclonedx' (CycloneDX 1.6) or 'spdx' (SPDX 3.0).")] = "cyclonedx",
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
    ) -> str:
        """Generate a Software Bill of Materials (SBOM) for your AI agent setup.

        Discovers AI agents and MCP servers, extracts all package dependencies,
        and generates a standards-compliant SBOM.

        Args:
            format: SBOM format — "cyclonedx" (CycloneDX 1.6) or "spdx" (SPDX 3.0).
            config_path: Path to a specific MCP config directory.
                         If not provided, auto-discovers all local agent configs.

        Returns:
            JSON string containing the SBOM in the requested format.
        """
        return await _execute_tool_async(
            "generate_sbom",
            generate_sbom_impl,
            format=format,
            config_path=config_path,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 7: compliance ───────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Compliance Posture")
    async def compliance(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        image: Annotated[str | None, Field(description="Docker image to scan, e.g. 'nginx:1.25'.")] = None,
    ) -> str:
        """Get OWASP LLM Top 10 / OWASP MCP Top 10 / MITRE ATLAS / NIST AI RMF compliance posture.

        Scans local MCP configurations, maps findings to 47 security controls
        across four AI security frameworks, and returns per-control
        pass/warning/fail status with an overall compliance score.

        Args:
            config_path: Path to a specific MCP config directory.
                         If not provided, auto-discovers all local agent configs.
            image: Docker image reference to scan (e.g. "nginx:1.25").

        Returns:
            JSON with overall_score (0-100), overall_status (pass/warning/fail),
            and per-control details for OWASP LLM Top 10 (10 controls),
            OWASP MCP Top 10 (10 controls), MITRE ATLAS (13 techniques),
            and NIST AI RMF (14 subcategories).
        """
        return await _execute_tool_async(
            "compliance",
            compliance_impl,
            config_path=config_path,
            image=image,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 8: remediate ────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Remediation Plan")
    async def remediate(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        image: Annotated[str | None, Field(description="Docker image to scan, e.g. 'nginx:1.25'.")] = None,
    ) -> str:
        """Generate a remediation plan for vulnerabilities in your AI agent setup.

        Scans for vulnerabilities, then generates actionable fix commands for
        each affected package (npm install, pip install), credential scope
        reduction guidance, and reports on unfixable vulnerabilities.

        Args:
            config_path: Path to a specific MCP config directory.
                         If not provided, auto-discovers all local agent configs.
            image: Docker image reference to scan (e.g. "nginx:1.25").

        Returns:
            JSON with package_fixes (upgrade commands by ecosystem),
            credential_fixes (scope reduction steps), and unfixable items.
        """
        return await _execute_tool_async(
            "remediate",
            remediate_impl,
            config_path=config_path,
            image=image,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 9: skill_scan ───────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Skill Scan")
    async def skill_scan(
        path: Annotated[str, Field(description="Path to a skill/instruction file or directory to scan.")] = ".",
    ) -> str:
        """Scan skill and instruction files for trust, findings, and provenance.

        Discovers supported files such as `CLAUDE.md`, `AGENTS.md`,
        `.cursorrules`, and `skills/*.md`, then parses referenced packages,
        MCP servers, credential env vars, audit findings, and trust verdicts.
        """
        return await _execute_tool_sync_async(
            "skill_scan",
            skill_scan_impl,
            path=path,
            _safe_path=_safe_path,
            _truncate_response=_truncate_response,
        )

    # ── Tool 10: skill_verify ────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Skill Provenance Verify")
    async def skill_verify(
        path: Annotated[str, Field(description="Path to a skill/instruction file or directory to verify.")] = ".",
    ) -> str:
        """Verify Sigstore provenance for skill and instruction files."""
        return await _execute_tool_sync_async(
            "skill_verify",
            skill_verify_impl,
            path=path,
            _safe_path=_safe_path,
            _truncate_response=_truncate_response,
        )

    # ── Tool 11: skill_trust ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Skill Trust Assessment")
    async def skill_trust(
        skill_path: Annotated[str, Field(description="Path to a SKILL.md file (or any skill/instruction file) to assess.")],
    ) -> str:
        """Assess the trust level of a SKILL.md file using ClawHub-style categories.

        Parses a SKILL.md file, runs security audit checks, then evaluates
        trust across 5 categories: Purpose & Capability, Instruction Scope,
        Install Mechanism, Credentials, and Persistence & Privilege.

        Returns an overall verdict (benign/suspicious/malicious) with
        confidence level and actionable recommendations.

        Args:
            skill_path: Path to a SKILL.md file (or any skill/instruction file).

        Returns:
            JSON with verdict, confidence, per-category assessments, and
            recommendations.
        """
        return await _execute_tool_sync_async(
            "skill_trust",
            skill_trust_impl,
            skill_path=skill_path,
            _safe_path=_safe_path,
            _truncate_response=_truncate_response,
        )

    # ── Tool 12: verify ─────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Package Integrity Verify")
    async def verify(
        package: Annotated[str, Field(description="Package name with optional version, e.g. 'express@4.18.2' or 'requests==2.31.0'.")],
        ecosystem: Annotated[str, Field(description="Package ecosystem: 'npm' or 'pypi'.")] = "npm",
    ) -> str:
        """Verify package integrity and SLSA provenance against registries.

        Checks SHA-256/SRI hashes against npm/PyPI registries and looks up
        SLSA build provenance attestations to confirm the package was built
        from its claimed source repository.

        Returns:
            JSON with integrity verification (hash match, expected vs actual)
            and provenance status (SLSA level, source repo, build trigger).
        """
        return await _execute_tool_async(
            "verify",
            verify_impl,
            package=package,
            ecosystem=ecosystem,
            _validate_ecosystem=_validate_ecosystem,
            _truncate_response=_truncate_response,
        )

    # ── Tool 13: where ────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Discovery Paths")
    async def where() -> str:
        """Show all MCP discovery paths and which config files exist.

        Lists every known MCP client config path per platform, indicating
        which files are present on the current system. Useful for debugging
        discovery issues or understanding where MCP configs live.

        Returns:
            JSON with per-client config paths, existence status, and platform.
        """
        return await _execute_tool_sync_async("where", where_impl, _truncate_response=_truncate_response)

    # ── Tool 14: inventory ────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Agent Inventory")
    async def inventory(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
    ) -> str:
        """List all discovered MCP configurations and servers without CVE scanning.

        Performs fast discovery and package extraction only — no vulnerability
        scanning. Use this for a quick inventory of configs, servers, and packages.

        Returns:
            JSON with discovered agents, their MCP servers, packages, and
            transport types.
        """
        return await _execute_tool_sync_async(
            "inventory",
            inventory_impl,
            config_path=config_path,
            _truncate_response=_truncate_response,
        )

    @mcp.tool(annotations=_READ_ONLY, title="Tool Capability Risk")
    async def tool_risk_assessment(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        timeout: Annotated[float, Field(description="Per-server introspection timeout in seconds.")] = 10.0,
    ) -> str:
        """Score live-introspected MCP tool capabilities and server risk.

        Uses runtime `tools/list` data to classify tool capabilities
        (READ/WRITE/EXECUTE/NETWORK/etc.) and compute a per-server risk profile.

        Returns:
            JSON with per-server tool profiles, capability counts, dangerous
            combinations, and risk justification.
        """
        return await _execute_tool_sync_async(
            "tool_risk_assessment",
            tool_risk_assessment_impl,
            config_path=config_path,
            timeout=timeout,
            _truncate_response=_truncate_response,
        )

    # ── Tool 13: diff ─────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Vulnerability Diff")
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
        return await _execute_tool_async(
            "diff",
            diff_impl,
            baseline=baseline,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 14: marketplace_check ───────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Marketplace Trust Check")
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
        return await _execute_tool_async(
            "marketplace_check",
            marketplace_check_impl,
            package=package,
            ecosystem=ecosystem,
            _validate_ecosystem=_validate_ecosystem,
            _get_registry_data_raw=_get_registry_data_raw,
            _truncate_response=_truncate_response,
        )

    # ── Tool 16: code_scan ────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Code SAST Scan")
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
        return await _execute_tool_async(
            "code_scan",
            code_scan_impl,
            path=path,
            config=config,
            _safe_path=_safe_path,
            _truncate_response=_truncate_response,
        )

    # ── Tool 17: context_graph ──────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Context Graph")
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
        return await _execute_tool_async(
            "context_graph",
            context_graph_impl,
            config_path=config_path,
            source_agent=source_agent,
            max_depth=max_depth,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool: graph_export ──────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Graph Export")
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
            scan_result = await _run_scan_pipeline(config_path=config_path)
            if isinstance(scan_result, str):
                return _truncate_response(scan_result)

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

            graph = _build_dep_graph_from_agents(agents_data)

            _fmt = format.lower()
            if _fmt == "graphml":
                return _truncate_response(_to_graphml(graph))
            if _fmt == "cypher":
                return _truncate_response(_to_cypher(graph))
            if _fmt == "dot":
                return _truncate_response(_to_dot(graph))
            if _fmt == "mermaid":
                return _truncate_response(_to_mermaid(graph))
            return _truncate_response(json.dumps(_graph_to_json(graph), indent=2))

        return await _execute_tool_async("graph_export", _impl)

    @mcp.tool(annotations=_READ_ONLY, title="Analytics Query")
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
        return await _execute_tool_async(
            "analytics_query",
            analytics_query_impl,
            query_type=query_type,
            days=days,
            hours=hours,
            agent=agent,
            limit=limit,
            _truncate_response=_truncate_response,
        )

    @mcp.tool(annotations=_READ_ONLY, title="CIS Benchmark")
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
        return await _execute_tool_async(
            "cis_benchmark",
            cis_benchmark_impl,
            provider=provider,
            checks=checks,
            region=region,
            profile=profile,
            subscription_id=subscription_id,
            project_id=project_id,
            _truncate_response=_truncate_response,
        )

    # ── Tool 19: fleet_scan ────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Fleet Scan")
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
        return await _execute_tool_async(
            "fleet_scan",
            fleet_scan_impl,
            servers=servers,
            _truncate_response=_truncate_response,
        )

    # ── Resources ────────────────────────────────────────────────

    @mcp.resource("registry://servers")
    def registry_servers_resource() -> str:
        """Browse the MCP server security metadata registry (427+ servers).

        Returns the full registry with risk levels (category-derived), tools,
        credential env vars (heuristic-inferred), and verification status
        for every known MCP server.
        """
        try:
            return _get_registry_data_raw()
        except Exception as exc:
            logger.exception("Registry read failed")
            return json.dumps({"error": f"Failed to read registry: {sanitize_error(exc)}"})

    @mcp.tool(annotations=_READ_ONLY, title="Runtime Correlation")
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
        return await _execute_tool_async(
            "runtime_correlate",
            runtime_correlate_impl,
            config_path=config_path,
            audit_log=audit_log,
            otel_trace=otel_trace,
            _safe_path=_safe_path,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    @mcp.resource("policy://template")
    def policy_template_resource() -> str:
        """Get a default security policy template for agent-bom.

        Returns a ready-to-use policy with common rules: block critical CVEs,
        flag CISA KEV entries, warn on unverified servers, and limit credential
        exposure.
        """
        template = {
            "name": "default-security-policy",
            "version": "1.0",
            "rules": [
                {"id": "no-critical", "severity_gte": "critical", "action": "fail", "message": "Block critical vulnerabilities"},
                {"id": "no-kev", "is_kev": True, "action": "fail", "message": "Block CISA Known Exploited Vulnerabilities"},
                {"id": "warn-high", "severity_gte": "high", "action": "warn", "message": "Warn on high-severity vulnerabilities"},
                {"id": "warn-unverified", "unverified_server": True, "action": "warn", "message": "Warn on unverified MCP servers"},
                {"id": "warn-credentials", "has_credentials": True, "action": "warn", "message": "Flag servers with credential exposure"},
            ],
        }
        return json.dumps(template, indent=2)

    @mcp.resource("metrics://tools")
    def tool_metrics_resource() -> str:
        """Return bounded MCP tool execution metrics for observability."""
        return json.dumps(_tool_metrics_snapshot(), indent=2)

    # ── Prompts ─────────────────────────────────────────────────────

    @mcp.prompt(name="quick-audit", description="Run a complete security audit of your AI agent setup")
    def quick_audit_prompt() -> str:
        return (
            "Scan my local AI agent and MCP server configurations for vulnerabilities. "
            "Show the blast radius for any critical findings and suggest remediation steps. "
            "Include OWASP LLM Top 10, OWASP MCP Top 10, and MITRE ATLAS mappings."
        )

    @mcp.prompt(name="pre-install-check", description="Check an MCP server package for vulnerabilities before installing")
    def pre_install_check_prompt(package: str, ecosystem: str = "npm") -> str:
        return (
            f"Check the MCP server package '{package}' (ecosystem: {ecosystem}) for known CVEs. "
            "Show severity, EPSS score, and whether it's in CISA KEV. Recommend whether to install."
        )

    @mcp.prompt(name="compliance-report", description="Generate OWASP/ATLAS/NIST compliance posture for your AI stack")
    def compliance_report_prompt() -> str:
        return (
            "Scan my AI agent setup, map findings to OWASP LLM Top 10, OWASP MCP Top 10, MITRE ATLAS, and NIST AI RMF. "
            "Generate a compliance summary suitable for security review."
        )

    register_specialized_ai_tools(
        mcp,
        read_only=_READ_ONLY,
        execute_tool_async=_execute_tool_async,
        safe_path=_safe_path,
        truncate_response=_truncate_response,
    )

    attach_metadata_routes(
        mcp,
        auth_required=bool(bearer_token),
        tool_metrics_snapshot=_tool_metrics_snapshot,
    )

    return mcp


def create_smithery_server():
    return _create_smithery_server(create_mcp_server)
