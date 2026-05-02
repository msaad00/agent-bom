"""agent-bom MCP Server — expose security scanning as MCP tools.

Start with:
    agent-bom mcp server                          # stdio (for Claude Desktop, Cursor, etc.)
    agent-bom mcp server --transport sse          # SSE transport (for remote clients)
    agent-bom mcp server --transport streamable-http

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

Resources (6):
    registry://servers  — Browse 427+ server security metadata registry
    policy://template   — Default security policy template
    metrics://tools     — MCP tool execution metrics and limits
    schema://inventory-v1 — Canonical pushed-inventory schema contract
    bestpractices://mcp-hardening — MCP deployment hardening checklist
    compliance://framework-controls — Framework coverage and evidence mapping

Security: Read-only. Never executes MCP servers or reads credential values.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import re
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable, Optional, TypeVar

from mcp.server.lowlevel.server import request_ctx as _mcp_request_ctx
from mcp.types import ToolAnnotations
from pydantic import Field

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
from agent_bom.mcp_server_catalog import (
    attach_resources_and_prompts as _attach_resources_and_prompts,
)
from agent_bom.mcp_server_entrypoint import create_smithery_server as _create_smithery_server
from agent_bom.mcp_server_factory import (
    create_fastmcp_server as _create_fastmcp_server,
)
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
from agent_bom.mcp_server_runtime_catalog import (
    register_runtime_catalog_tools as _register_runtime_catalog_tools,
)
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)
_ToolReturn = TypeVar("_ToolReturn")

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
    offline: bool = False,
):
    """Run discovery -> extraction -> scanning and return (agents, blast_radii, warnings)."""
    return await _mcp_scan.run_scan_pipeline(
        safe_path=_safe_path,
        config_path=config_path,
        image=image,
        sbom_path=sbom_path,
        enrich=enrich,
        transitive=transitive,
        offline=offline,
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

    from agent_bom import __version__

    mcp = _create_fastmcp_server(
        host=host,
        port=port,
        bearer_token=bearer_token,
        version=__version__,
        token_verifier_factory=_StaticBearerTokenVerifier,
    )

    # Import tool implementations
    from agent_bom.mcp_server_specialized import register_specialized_ai_tools
    from agent_bom.mcp_tools.analysis import blast_radius_impl
    from agent_bom.mcp_tools.compliance import (
        compliance_impl,
        policy_check_impl,
    )
    from agent_bom.mcp_tools.registry import registry_lookup_impl
    from agent_bom.mcp_tools.runtime import verify_impl
    from agent_bom.mcp_tools.sbom import generate_sbom_impl, remediate_impl
    from agent_bom.mcp_tools.scanning import check_impl, scan_impl

    # ── Tool 1: scan ──────────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Security Scan")
    async def scan(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        image: Annotated[str | None, Field(description="Docker image to scan (e.g. 'nginx:1.25', 'ghcr.io/org/app:v1').")] = None,
        sbom_path: Annotated[str | None, Field(description="Path to existing CycloneDX or SPDX JSON SBOM file to ingest.")] = None,
        enrich: Annotated[bool, Field(description="Enable NVD CVSS, EPSS probability, and CISA KEV enrichment.")] = False,
        offline: Annotated[
            bool,
            Field(description="Use the local vulnerability DB only and skip registry, OSV, GHSA, and NVIDIA network lookups."),
        ] = True,
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
        auto_update_db: Annotated[
            bool,
            Field(description="Explicitly refresh the local vuln DB if stale (>7 days) before scanning."),
        ] = False,
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
            offline=offline,
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

    _register_runtime_catalog_tools(
        mcp,
        read_only=_READ_ONLY,
        execute_tool_sync_async=_execute_tool_sync_async,
        safe_path=_safe_path,
        truncate_response=_truncate_response,
    )

    from agent_bom.mcp_server_operator_tools import register_operator_tools

    register_operator_tools(
        mcp,
        read_only=_READ_ONLY,
        execute_tool_async=_execute_tool_async,
        safe_path=_safe_path,
        run_scan_pipeline=_run_scan_pipeline,
        truncate_response=_truncate_response,
        validate_ecosystem=_validate_ecosystem,
        get_registry_data_raw=_get_registry_data_raw,
        build_dep_graph_from_agents=_build_dep_graph_from_agents,
    )

    _attach_resources_and_prompts(
        mcp,
        get_registry_data_raw=_get_registry_data_raw,
        sanitize_error_fn=sanitize_error,
        logger=logger,
        tool_metrics_snapshot=_tool_metrics_snapshot,
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
