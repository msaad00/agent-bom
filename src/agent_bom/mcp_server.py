"""agent-bom MCP Server — expose security scanning as MCP tools.

Start with:
    agent-bom mcp-server              # stdio (for Claude Desktop, Cursor, etc.)
    agent-bom mcp-server --sse        # SSE transport (for remote clients)

Tools (32):
    scan                — Full discovery → scan → output pipeline
    check               — Check a specific package for CVEs before installing
    blast_radius        — Look up blast radius for a specific CVE
    policy_check        — Evaluate a policy against scan results
    registry_lookup     — Query the MCP server security metadata registry
    generate_sbom       — Generate CycloneDX or SPDX SBOM
    compliance          — OWASP/ATLAS/NIST AI RMF compliance posture
    remediate           — Generate actionable remediation plan
    skill_trust         — ClawHub-style trust assessment for SKILL.md files
    verify              — Package integrity + SLSA provenance verification
    where               — Show all MCP discovery paths + existence status
    inventory           — List agents/servers without CVE scanning
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

Resources (2):
    registry://servers  — Browse 427+ server security metadata registry
    policy://template   — Default security policy template

Security: Read-only. Never executes MCP servers or reads credential values.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Annotated, Optional

from mcp.types import ToolAnnotations
from pydantic import Field

from agent_bom.config import MCP_MAX_FILE_SIZE as _MAX_FILE_SIZE
from agent_bom.config import MCP_MAX_RESPONSE_CHARS as _MAX_RESPONSE_CHARS
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_VALID_ECOSYSTEMS = frozenset({"npm", "pypi", "go", "cargo", "maven", "nuget", "rubygems"})

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)


def _validate_ecosystem(ecosystem: str) -> str:
    """Return cleaned ecosystem string or raise ValueError."""
    cleaned = ecosystem.lower().strip()
    if cleaned not in _VALID_ECOSYSTEMS:
        raise ValueError(f"Invalid ecosystem: {ecosystem!r}. Valid: {', '.join(sorted(_VALID_ECOSYSTEMS))}")
    return cleaned


def _validate_cve_id(cve_id: str) -> str:
    """Return cleaned CVE/GHSA ID or raise ValueError."""
    cleaned = cve_id.strip()
    if not cleaned:
        raise ValueError("CVE ID cannot be empty")
    if not (_CVE_RE.match(cleaned) or _GHSA_RE.match(cleaned)):
        raise ValueError(f"Invalid CVE ID format: {cleaned!r}. Expected CVE-YYYY-NNNNN or GHSA-xxxx-xxxx-xxxx")
    return cleaned


def _truncate_response(response_str: str) -> str:
    """Truncate response if it exceeds _MAX_RESPONSE_CHARS."""
    if len(response_str) <= _MAX_RESPONSE_CHARS:
        return response_str
    return (
        response_str[:_MAX_RESPONSE_CHARS] + '\n\n{"_truncated": true, "message": '
        '"Response truncated at 500,000 characters. '
        'Use more specific parameters to reduce output size."}'
    )


def _safe_path(path_str: str) -> Path:
    """Resolve a user-provided path and validate against directory traversal."""
    from agent_bom.security import SecurityError, validate_path

    try:
        return validate_path(path_str, restrict_to_home=True)
    except SecurityError as exc:
        raise ValueError(str(exc)) from exc


# Cached registry data (loaded once, reused across requests)
_registry_cache: dict | None = None
_registry_raw_cache: str | None = None


def _get_registry_data() -> dict:
    """Load and cache the MCP registry JSON as a dict."""
    global _registry_cache
    if _registry_cache is None:
        registry_path = Path(__file__).parent / "mcp_registry.json"
        _registry_cache = json.loads(registry_path.read_text())
    return _registry_cache


def _get_registry_data_raw() -> str:
    """Load and cache the MCP registry JSON as raw text."""
    global _registry_raw_cache
    if _registry_raw_cache is None:
        registry_path = Path(__file__).parent / "mcp_registry.json"
        _registry_raw_cache = registry_path.read_text()
    return _registry_raw_cache


# All agent-bom tools are read-only scanners
_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def _check_mcp_sdk() -> None:
    """Ensure the mcp SDK is available."""
    try:
        import mcp  # noqa: F401
    except ImportError:
        raise ImportError("mcp SDK is required for the MCP server. Install with: pip install 'agent-bom[mcp-server]'") from None


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
    """Run discovery -> extraction -> scanning and return (agents, blast_radii, warnings).

    Async version -- safe to call from within an existing event loop (e.g.
    FastMCP's async context).  Falls back to asyncio.run() when no loop
    is running (CLI usage).
    """
    from agent_bom.discovery import discover_all
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType
    from agent_bom.parsers import extract_packages
    from agent_bom.scanners import scan_agents, scan_agents_with_enrichment

    warnings: list[str] = []
    scan_sources: list[str] = []

    # Validate user-provided paths against directory traversal
    if config_path:
        try:
            config_path = str(_safe_path(config_path))
        except ValueError as exc:
            return json.dumps({"error": sanitize_error(exc)})

    if sbom_path:
        try:
            sbom_path = str(_safe_path(sbom_path))
        except ValueError as exc:
            return json.dumps({"error": sanitize_error(exc)})

    if image:
        try:
            from agent_bom.security import validate_image_ref

            validate_image_ref(image)
        except Exception as exc:
            return json.dumps({"error": sanitize_error(exc)})

    agents = discover_all(project_dir=config_path)
    if agents:
        scan_sources.append("agent_discovery")

    # Docker image scanning
    if image:
        try:
            from agent_bom.image import scan_image as _scan_image

            img_packages, _strategy = _scan_image(image)
            if img_packages:
                img_server = MCPServer(
                    name=f"image:{image}",
                    command="",
                    args=[],
                    env={},
                    transport=TransportType.UNKNOWN,
                    packages=img_packages,
                )
                agents.append(
                    Agent(
                        name=f"image:{image}",
                        agent_type=AgentType.CUSTOM,
                        config_path="",
                        mcp_servers=[img_server],
                    )
                )
                scan_sources.append("image")
        except Exception as exc:
            msg = f"Image scan failed for {image}: {sanitize_error(exc)}"
            logger.warning(msg)
            warnings.append(msg)

    # SBOM ingestion
    if sbom_path:
        try:
            # File size check
            sbom_file = Path(sbom_path)
            if sbom_file.exists() and sbom_file.stat().st_size > _MAX_FILE_SIZE:
                msg = f"SBOM file too large ({sbom_file.stat().st_size} bytes, max {_MAX_FILE_SIZE})"
                warnings.append(msg)
            else:
                from agent_bom.sbom import load_sbom

                sbom_packages, _warnings, _sbom_name = load_sbom(sbom_path)
                if sbom_packages:
                    sbom_server = MCPServer(
                        name=f"sbom:{Path(sbom_path).name}",
                        command="",
                        args=[],
                        env={},
                        transport=TransportType.UNKNOWN,
                        packages=sbom_packages,
                    )
                    agents.append(
                        Agent(
                            name=f"sbom:{Path(sbom_path).name}",
                            agent_type=AgentType.CUSTOM,
                            config_path=sbom_path,
                            mcp_servers=[sbom_server],
                        )
                    )
                    scan_sources.append("sbom")
        except Exception as exc:
            msg = f"SBOM load failed for {sbom_path}: {exc}"
            logger.warning(msg)
            warnings.append(msg)

    if not agents:
        return [], [], warnings, scan_sources

    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)

    if enrich:
        blast_radii = await scan_agents_with_enrichment(agents)
    else:
        blast_radii = await scan_agents(agents)
    return agents, blast_radii, warnings, scan_sources


# ---------------------------------------------------------------------------
# MCP Server factory
# ---------------------------------------------------------------------------


def create_mcp_server(*, host: str = "127.0.0.1", port: int = 8000):
    """Create and configure the agent-bom MCP server with all tools.

    When the smithery SDK is installed, the server is automatically enhanced
    with session-config and CORS middleware for Smithery.ai hosted deployment.
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level="INFO")
    _check_mcp_sdk()
    from mcp.server.fastmcp import FastMCP

    from agent_bom import __version__

    mcp = FastMCP(
        name="agent-bom",
        host=host,
        port=port,
        instructions=(
            f"agent-bom v{__version__} — AI infrastructure security scanner with 32 tools. "
            "Scans packages and images for CVEs (OSV, NVD, EPSS, CISA KEV), maps blast radius "
            "from vulnerabilities to credentials and tools, generates SBOMs (CycloneDX, SPDX), "
            "enforces security policies, and maps to 14 compliance frameworks "
            "(OWASP LLM/MCP/Agentic, MITRE ATLAS, NIST AI RMF/CSF/800-53, FedRAMP, EU AI Act, ISO 27001, SOC 2). "
            "Discovers 22 MCP clients. Read-only, agentless, no credentials required."
        ),
    )
    # Set the actual agent-bom version (FastMCP defaults to SDK version)
    mcp._mcp_server.version = __version__

    # Import tool implementations
    from agent_bom.mcp_tools.analysis import (
        analytics_query_impl,
        blast_radius_impl,
        context_graph_impl,
    )
    from agent_bom.mcp_tools.cloud import gpu_infra_scan_impl, vector_db_scan_impl
    from agent_bom.mcp_tools.compliance import (
        aisvs_benchmark_impl,
        cis_benchmark_impl,
        compliance_impl,
        license_compliance_scan_impl,
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
        skill_trust_impl,
        verify_impl,
        where_impl,
    )
    from agent_bom.mcp_tools.sbom import diff_impl, generate_sbom_impl, remediate_impl
    from agent_bom.mcp_tools.scanning import check_impl, code_scan_impl, scan_impl
    from agent_bom.mcp_tools.specialized import (
        ai_inventory_scan_impl,
        browser_extension_scan_impl,
        dataset_card_scan_impl,
        model_file_scan_impl,
        model_provenance_scan_impl,
        prompt_scan_impl,
        training_pipeline_scan_impl,
    )

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
        return await scan_impl(
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
        ecosystem: Annotated[str, Field(description="Package ecosystem: 'npm', 'pypi', 'go', 'cargo', 'maven', or 'nuget'.")] = "npm",
    ) -> str:
        """Check a specific package for known CVEs before installing.

        Queries OSV.dev for vulnerabilities in the given package. Use this
        before installing an MCP server or dependency to verify it is safe.

        Args:
            package: Package name with optional version, e.g. "express@4.18.2",
                     "@modelcontextprotocol/server-filesystem@2025.1.14",
                     or just "requests" (resolves @latest).
            ecosystem: Package ecosystem — "npm", "pypi", "go", "cargo",
                       "maven", or "nuget". Defaults to "npm".

        Returns:
            JSON with package, version, ecosystem, vulnerability count,
            and vulnerability details (id, severity, cvss, fix version, summary).
        """
        return await check_impl(
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
        return await blast_radius_impl(
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
        return await policy_check_impl(
            policy_json=policy_json,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 5: registry_lookup ───────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Registry Lookup")
    def registry_lookup(
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
        return registry_lookup_impl(
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
        return await generate_sbom_impl(
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
        return await compliance_impl(
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
        return await remediate_impl(
            config_path=config_path,
            image=image,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    # ── Tool 9: skill_trust ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Skill Trust Assessment")
    def skill_trust(
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
        return skill_trust_impl(
            skill_path=skill_path,
            _safe_path=_safe_path,
            _truncate_response=_truncate_response,
        )

    # ── Tool 10: verify ─────────────────────────────────────────────

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
        return await verify_impl(
            package=package,
            ecosystem=ecosystem,
            _validate_ecosystem=_validate_ecosystem,
            _truncate_response=_truncate_response,
        )

    # ── Tool 11: where ────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Discovery Paths")
    def where() -> str:
        """Show all MCP discovery paths and which config files exist.

        Lists every known MCP client config path per platform, indicating
        which files are present on the current system. Useful for debugging
        discovery issues or understanding where MCP configs live.

        Returns:
            JSON with per-client config paths, existence status, and platform.
        """
        return where_impl(_truncate_response=_truncate_response)

    # ── Tool 12: inventory ────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Agent Inventory")
    def inventory(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
    ) -> str:
        """List all discovered MCP configurations and servers without CVE scanning.

        Performs fast discovery and package extraction only — no vulnerability
        scanning. Use this for a quick inventory of configs, servers, and packages.

        Returns:
            JSON with discovered agents, their MCP servers, packages, and
            transport types.
        """
        return inventory_impl(
            config_path=config_path,
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
        return await diff_impl(
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
        return await marketplace_check_impl(
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
        return await code_scan_impl(
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
        return await context_graph_impl(
            config_path=config_path,
            source_agent=source_agent,
            max_depth=max_depth,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )

    @mcp.tool(annotations=_READ_ONLY, title="Analytics Query")
    async def analytics_query(
        query_type: Annotated[
            str,
            Field(description="Query type: vuln_trends, top_cves, posture_history, or event_summary"),
        ],
        days: Annotated[
            int,
            Field(description="Lookback window in days (default 30). Used by vuln_trends and posture_history."),
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
            Field(description="Max results for top_cves (default 20)."),
        ] = 20,
    ) -> str:
        """Query vulnerability trends, posture history, and runtime event summaries from ClickHouse.

        Requires AGENT_BOM_CLICKHOUSE_URL to be set. Returns empty results if
        ClickHouse is not configured.
        """
        return await analytics_query_impl(
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
        return await cis_benchmark_impl(
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
        return await fleet_scan_impl(
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
        return await runtime_correlate_impl(
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

    # ── Tool 21: vector_db_scan ───────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Vector DB Scan")
    async def vector_db_scan(
        hosts: Annotated[
            str | None,
            Field(description="Comma-separated hosts to probe (default: 127.0.0.1). Example: '127.0.0.1,10.0.0.5'."),
        ] = None,
    ) -> str:
        """Scan for running vector databases and assess their security posture.

        Probes well-known ports for Qdrant (6333), Weaviate (8080), Chroma (8000),
        and Milvus (9091). For each discovered instance checks:
        - Authentication required (no_auth flag if collections accessible without credentials)
        - Network exposure (network_exposed if accessible beyond localhost)
        - Number of collections/indexes exposed without auth
        - MAESTRO layer: KC4: Memory & Context

        Returns:
            JSON with per-database risk assessment including risk_level, risk_flags, and metadata.
        """
        return await vector_db_scan_impl(
            hosts=hosts,
            _truncate_response=_truncate_response,
        )

    # ── Tool 22: aisvs_benchmark ──────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="AISVS Benchmark")
    async def aisvs_benchmark(
        checks: Annotated[
            str | None,
            Field(description=("Comma-separated AISVS check IDs to run (e.g. 'AI-4.1,AI-6.1'). Omit to run all 9 checks.")),
        ] = None,
    ) -> str:
        """Run AISVS v1.0 (AI Security Verification Standard) compliance checks.

        Evaluates the local AI system stack against OWASP AISVS v1.0 controls:
        - AI-4.1 Model files use safe serialization (not pickle/pt/bin)
        - AI-4.2 Model files have cryptographic integrity digest
        - AI-4.3 Ollama inference API not network-exposed without auth
        - AI-5.2 No ML development tools (Jupyter, MLflow, Ray) network-exposed
        - AI-6.1 Vector stores require authentication
        - AI-6.2 Vector stores bound to localhost only
        - AI-7.1 No known malicious or typosquatted ML packages installed
        - AI-7.2 Locally cached models have verifiable provenance
        - AI-8.1 MCP server tool definitions include input schemas

        Each check is tagged with its MAESTRO layer (KC1-KC6).

        Returns:
            JSON with per-check pass/fail results, evidence, severity, MAESTRO layer, and pass rate.
        """
        return await aisvs_benchmark_impl(
            checks=checks,
            _truncate_response=_truncate_response,
        )

    # ── Tool 23: gpu_infra_scan ────────────────────────────────────
    @mcp.tool(annotations=_READ_ONLY, title="GPU Infrastructure Scan")
    async def gpu_infra_scan(
        k8s_context: Annotated[
            str | None,
            Field(description="kubectl context to use for K8s GPU node discovery. Omit for current context."),
        ] = None,
        probe_dcgm: Annotated[
            bool,
            Field(description="Whether to probe DCGM exporter endpoints on port 9400 (unauthenticated metrics leak detection)."),
        ] = True,
    ) -> str:
        """Discover GPU/AI compute infrastructure: containers, K8s nodes, and DCGM endpoints.

        Scans for GPU-enabled workloads from the local Docker daemon and Kubernetes
        clusters. Identifies NVIDIA base images, CUDA/cuDNN versions, explicit GPU
        device assignments, and unauthenticated DCGM exporter endpoints.

        Discovery targets (MAESTRO KC6):
        - NVIDIA base images (nvcr.io/nvidia/, nvidia/cuda, etc.)
        - CUDA/cuDNN versions from container labels and env vars
        - GPU-assigned containers (Docker --gpus, K8s nvidia.com/gpu requests)
        - Unauthenticated DCGM exporter endpoints (port 9400 — GPU metrics leak)
        - Kubernetes GPU node inventory with capacity and allocatable counts

        Requires docker and/or kubectl on PATH. All discovery is best-effort
        (returns empty results rather than failing if tools are unavailable).

        Returns:
            JSON with GPU containers, K8s nodes, DCGM endpoints, CUDA version
            inventory, and a risk summary with unauthenticated DCGM count.
        """
        return await gpu_infra_scan_impl(
            k8s_context=k8s_context,
            probe_dcgm=probe_dcgm,
            _truncate_response=_truncate_response,
        )

    # ── Tool 24: dataset_card_scan ──────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Dataset Card Scan")
    async def dataset_card_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for dataset cards (dataset_info.json, README.md frontmatter, .dvc files)."),
        ],
    ) -> str:
        """Scan a directory for ML dataset card metadata and provenance.

        Discovers and parses:
        - HuggingFace dataset_info.json (auto-generated metadata)
        - HuggingFace README.md YAML frontmatter (dataset cards)
        - DVC .dvc tracking files (data versioning provenance)

        Flags: UNLICENSED_DATASET, NO_DATASET_CARD, UNVERSIONED_DATA, REMOTE_DATA_SOURCE.
        Tags findings with compliance frameworks: OWASP LLM (LLM03), MITRE ATLAS,
        NIST AI RMF (MAP-3.5), EU AI Act (ART-10).
        """
        return await dataset_card_scan_impl(
            directory=directory,
            _truncate_response=_truncate_response,
        )

    # ── Tool 25: training_pipeline_scan ──────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Training Pipeline Scan")
    async def training_pipeline_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for training pipeline artifacts (MLflow, Kubeflow, W&B)."),
        ],
    ) -> str:
        """Scan a directory for ML training pipeline lineage and provenance.

        Discovers and parses:
        - MLflow: meta.yaml, MLmodel, requirements.txt, conda.yaml
        - Kubeflow: Argo workflow YAML, KFP v2 pipelineSpec YAML
        - W&B: wandb-metadata.json, config.yaml, wandb-summary.json

        Flags: UNSAFE_SERIALIZATION, MISSING_PROVENANCE, MISSING_REQUIREMENTS, EXPOSED_CREDENTIALS.
        Tags findings with compliance frameworks: OWASP LLM (LLM03), MITRE ATLAS (AML.T0020),
        NIST AI RMF (MAP-3.5, GOVERN-1.7).
        """
        return await training_pipeline_scan_impl(
            directory=directory,
            _truncate_response=_truncate_response,
        )

    # ── Tool 26: browser_extension_scan ──────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Browser Extension Scan")
    async def browser_extension_scan(
        include_low_risk: Annotated[
            bool,
            Field(description="Include low-risk extensions in results (default: only medium+ risk)."),
        ] = False,
    ) -> str:
        """Scan installed browser extensions for dangerous permissions.

        Scans Chrome, Chromium, Brave, Edge, and Firefox for extensions with:
        - nativeMessaging (can execute arbitrary commands)
        - debugger (can intercept all browser traffic)
        - cookies/clipboardRead on AI domains
        - Broad host access patterns (*://*/*)
        - AI assistant domain access (claude.ai, chatgpt.com, cursor.sh)

        Deduplicates across profiles. Returns risk-ranked results.
        """
        return await browser_extension_scan_impl(
            include_low_risk=include_low_risk,
            _truncate_response=_truncate_response,
        )

    # ── Tool 27: model_provenance_scan ───────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Model Provenance Scan")
    async def model_provenance_scan(
        model_id: Annotated[
            str,
            Field(description="HuggingFace model ID (e.g. 'meta-llama/Llama-3-8B') or Ollama model name (e.g. 'llama3')."),
        ],
        source: Annotated[
            str,
            Field(description="Model source: 'huggingface' or 'ollama' (default: huggingface)."),
        ] = "huggingface",
    ) -> str:
        """Check ML model provenance and supply chain metadata.

        Queries HuggingFace Hub or Ollama for:
        - Serialization format (safetensors=safe, pickle/pt=unsafe)
        - SHA256 digest verification
        - Gated/private status
        - Model card presence
        - Risk assessment (critical/high/medium/safe)

        Returns structured provenance data for supply chain risk assessment.
        """
        return await model_provenance_scan_impl(
            model_id=model_id,
            source=source,
            _truncate_response=_truncate_response,
        )

    # ── Tool 28: prompt_scan ─────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Prompt Template Scan")
    async def prompt_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for prompt template files (.prompt, system_prompt.*, prompts/ directories)."),
        ],
    ) -> str:
        """Scan prompt template files for injection risks and security issues.

        Discovers and analyzes:
        - .prompt files
        - system_prompt.* files
        - Files in prompts/ directories

        Checks for injection patterns, unsafe variable interpolation, and
        missing guardrails in prompt templates.
        """
        return await prompt_scan_impl(
            directory=directory,
            _truncate_response=_truncate_response,
        )

    # ── Tool 29: model_file_scan ─────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Model File Scan")
    async def model_file_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for ML model files (.gguf, .safetensors, .onnx, .pt, .pkl, .h5, etc.)."),
        ],
    ) -> str:
        """Scan a directory for ML model files and assess serialization risks.

        Discovers model files and checks:
        - Serialization format (safetensors=safe, pickle/joblib=unsafe)
        - File size and format metadata
        - GGUF/GGML quantization details
        - Known unsafe patterns in pickle-based formats

        Returns structured results with risk assessment per model file.
        """
        return await model_file_scan_impl(
            directory=directory,
            _truncate_response=_truncate_response,
        )

    # ── Tool 30: ai_inventory_scan ────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="AI Inventory Scan")
    async def ai_inventory_scan(
        directory: Annotated[
            str,
            Field(description="Directory to scan for AI SDK imports, model refs, API keys, shadow AI (Python/JS/TS/Java/Go/Rust/Ruby)."),
        ],
    ) -> str:
        """Scan source code for AI component usage patterns.

        Detects:
        - AI SDK imports (openai, anthropic, langchain, etc.) across 7 languages
        - Model string references (gpt-4o, claude-3-5-sonnet, llama-3, etc.)
        - Hardcoded API keys (sk-proj-*, sk-ant-*, hf_*, etc.)
        - Deprecated model usage with recommended replacements
        - Shadow AI: SDKs imported in code but not declared in package manifests

        Returns structured inventory with severity classification.
        """
        return await ai_inventory_scan_impl(
            directory=directory,
            _truncate_response=_truncate_response,
        )

    # ── Tool 31: license_compliance_scan ────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="License Compliance Scan")
    async def license_compliance_scan(
        scan_json: Annotated[
            str,
            Field(
                description=(
                    "JSON string of a previous scan result (from the 'scan' tool) "
                    "containing agents with packages. Or a JSON array of "
                    '{"name": "pkg", "version": "1.0", "ecosystem": "npm", "license": "MIT"} objects.'
                ),
            ),
        ],
        policy_json: Annotated[
            str,
            Field(
                default="",
                description=(
                    'Optional JSON policy: {"license_block": ["GPL-*"], "license_warn": ["LGPL-*"]}. '
                    "Uses default policy (block GPL/AGPL/SSPL/BUSL/EUPL/OSL, warn LGPL/MPL/EPL/CDDL) if empty."
                ),
            ),
        ] = "",
    ) -> str:
        """Evaluate package licenses against compliance policy.

        Categorizes each package license using the full SPDX catalog (2,500+ licenses)
        with proper expression parsing (OR/AND/WITH), deprecated ID normalization,
        and network-copyleft detection (AGPL, EUPL, OSL).

        Risk tiers: permissive (low), weak-copyleft (medium), strong-copyleft (high),
        network-copyleft (critical), commercial-risk (critical), source-available (high).

        Returns structured report with compliance status, findings, and risk summary.
        """
        return await license_compliance_scan_impl(
            scan_json=scan_json,
            policy_json=policy_json,
            _truncate_response=_truncate_response,
        )

    # ── Tool 32: ingest_external_scan ───────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Ingest External Scanner Report")
    async def ingest_external_scan(
        scan_json: Annotated[
            str,
            Field(
                description="JSON string from Trivy, Grype, or Syft scan output",
            ),
        ],
    ) -> str:
        """Ingest Trivy, Grype, or Syft JSON scan output and return packages with blast radius analysis.

        Auto-detects the scanner format from the JSON structure:
        - Trivy (``trivy fs --format json``): Results + Vulnerabilities
        - Grype (``grype --output json``): matches array
        - Syft (``syft --output syft-json``): artifacts + schema

        Returns a summary of ingested packages and their vulnerability counts.
        Pass the full JSON string from the scanner's ``--format json`` / ``--output json``
        output as the ``scan_json`` argument.
        """
        import json as _json

        from agent_bom.parsers.external_scanners import detect_and_parse

        try:
            data = _json.loads(scan_json)
            packages = detect_and_parse(data)
            return _json.dumps(
                {
                    "packages": len(packages),
                    "ingested": [
                        {
                            "name": p.name,
                            "version": p.version,
                            "ecosystem": p.ecosystem,
                            "vulnerabilities": len(p.vulnerabilities),
                        }
                        for p in packages[:50]
                    ],
                }
            )
        except Exception as e:  # noqa: BLE001
            return _json.dumps({"error": str(e)})

    # ── Custom routes: metadata + health ─────────────────────────────

    @mcp.custom_route("/.well-known/mcp/server-card.json", methods=["GET"])
    async def server_card_route(request):
        from starlette.responses import JSONResponse

        return JSONResponse(build_server_card())

    @mcp.custom_route("/", methods=["GET"])
    async def root_metadata_route(request):
        """Root metadata for trust evaluators (OpenClaw, Smithery, etc.)."""
        from starlette.responses import JSONResponse

        from agent_bom import __version__

        return JSONResponse(
            {
                "name": "agent-bom",
                "version": __version__,
                "description": "Security scanner for AI infrastructure and supply chain",
                "homepage": "https://github.com/msaad00/agent-bom",
                "source": "https://github.com/msaad00/agent-bom",
                "license": "Apache-2.0",
                "pypi": "https://pypi.org/project/agent-bom/",
                "documentation": "https://github.com/msaad00/agent-bom#readme",
                "server_card": "/.well-known/mcp/server-card.json",
            }
        )

    @mcp.custom_route("/health", methods=["GET"])
    async def health_route(request):
        """Health check endpoint for monitoring and trust verification."""
        from starlette.responses import JSONResponse

        from agent_bom import __version__

        return JSONResponse(
            {
                "status": "healthy",
                "name": "agent-bom",
                "version": __version__,
            }
        )

    return mcp


# ---------------------------------------------------------------------------
# Server card — /.well-known/mcp/server-card.json
# ---------------------------------------------------------------------------

_SERVER_CARD_TOOLS = [
    {"name": "scan", "description": "Full discovery → scan → output pipeline", "annotations": {"readOnlyHint": True}},
    {"name": "check", "description": "Check a specific package for CVEs before installing", "annotations": {"readOnlyHint": True}},
    {"name": "blast_radius", "description": "Look up blast radius for a specific CVE", "annotations": {"readOnlyHint": True}},
    {
        "name": "policy_check",
        "description": (
            "Evaluate security policy rules against scan findings — supports 17 conditions"
            " including severity, KEV, EPSS, credential exposure, and custom expressions"
        ),
        "annotations": {"readOnlyHint": True},
    },
    {"name": "registry_lookup", "description": "Query MCP server threat intelligence registry", "annotations": {"readOnlyHint": True}},
    {"name": "generate_sbom", "description": "Generate CycloneDX or SPDX SBOM", "annotations": {"readOnlyHint": True}},
    {
        "name": "compliance",
        "description": (
            "Map scan findings to 14 compliance frameworks:"
            " OWASP LLM/MCP/Agentic, MITRE ATLAS, NIST AI RMF/CSF/800-53, FedRAMP, EU AI Act, ISO 27001, SOC 2, CIS Controls"
        ),
        "annotations": {"readOnlyHint": True},
    },
    {"name": "remediate", "description": "Generate actionable remediation plan", "annotations": {"readOnlyHint": True}},
    {"name": "skill_trust", "description": "ClawHub-style trust assessment for SKILL.md files", "annotations": {"readOnlyHint": True}},
    {
        "name": "verify",
        "description": "Verify package integrity via Sigstore cosign signatures and SLSA provenance attestation",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "where",
        "description": "List all 22 MCP client config discovery paths with existence status — useful for debugging discovery issues",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "inventory",
        "description": "Quick agent and server discovery without vulnerability scanning — shows what's configured, not what's vulnerable",
        "annotations": {"readOnlyHint": True},
    },
    {"name": "diff", "description": "Compare scan against baseline for new/resolved vulns", "annotations": {"readOnlyHint": True}},
    {
        "name": "marketplace_check",
        "description": "Pre-install marketplace trust check with registry cross-reference",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "code_scan",
        "description": "SAST scanning via Semgrep with CWE-based compliance mapping",
        "annotations": {"readOnlyHint": True},
    },
    {"name": "context_graph", "description": "Agent context graph with lateral movement analysis", "annotations": {"readOnlyHint": True}},
    {
        "name": "analytics_query",
        "description": "Query vulnerability trends, posture history, and runtime events from ClickHouse",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "cis_benchmark",
        "description": "Run CIS benchmark checks against AWS, Snowflake, Azure, or GCP accounts; Databricks security best practices",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "fleet_scan",
        "description": "Batch registry lookup for multiple MCP servers — returns risk levels, tool counts, and trust signals for each",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "runtime_correlate",
        "description": "Cross-reference scan results with proxy audit logs to find actually-called vulnerable tools",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "vector_db_scan",
        "description": "Discover running vector databases (Qdrant, Weaviate, Chroma, Milvus) and assess auth + exposure (MAESTRO KC4)",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "aisvs_benchmark",
        "description": "OWASP AISVS v1.0 compliance checks — model safety, vector store auth, inference exposure, supply chain",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "gpu_infra_scan",
        "description": "Discover GPU containers, K8s GPU nodes, CUDA versions, and unauthenticated DCGM endpoints (MAESTRO KC6)",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "dataset_card_scan",
        "description": "Scan dataset cards (HuggingFace, DVC) for licensing, provenance, and compliance tags (LLM03, ART-10)",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "training_pipeline_scan",
        "description": "Scan MLflow/Kubeflow/W&B training artifacts for lineage, serialization risks, and compliance tags",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "browser_extension_scan",
        "description": "Scan installed browser extensions for dangerous permissions and AI assistant domain access",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "model_provenance_scan",
        "description": "Check ML model provenance from HuggingFace Hub or Ollama for supply chain risk signals",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "prompt_scan",
        "description": "Scan prompt template files for injection risks and unsafe variable interpolation",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "model_file_scan",
        "description": "Scan model files (.gguf, .safetensors, .pkl, .pt) for serialization risks and format metadata",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "ai_inventory_scan",
        "description": "Scan source code for AI SDK imports, model refs, API keys, shadow AI, deprecated models (7 languages)",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "license_compliance_scan",
        "description": (
            "Evaluate package licenses against SPDX compliance policy"
            " — 2,500+ licenses, network-copyleft detection, deprecated ID normalization"
        ),
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "ingest_external_scan",
        "description": "Ingest Trivy, Grype, or Syft JSON scan output and return packages with blast radius analysis",
        "annotations": {"readOnlyHint": True},
    },
]

_SERVER_CARD_PROMPTS = [
    {"name": "quick-audit", "description": "Run a complete security audit of your AI agent setup"},
    {"name": "pre-install-check", "description": "Check an MCP server package for vulnerabilities before installing"},
    {"name": "compliance-report", "description": "Generate OWASP LLM + OWASP MCP + ATLAS + NIST compliance posture for your AI stack"},
]


def build_server_card() -> dict:
    """Build MCP server card metadata for auto-discovery.

    Returns a dict suitable for serving at ``/.well-known/mcp/server-card.json``.
    Used by Smithery, ToolHive, and other MCP clients to discover capabilities.
    """
    from agent_bom import __version__

    return {
        "name": "agent-bom",
        "version": __version__,
        "description": (
            "Security scanner for AI infrastructure and supply chain — CVE scanning, blast radius analysis, "
            "policy enforcement, and SBOM generation for MCP servers and AI agents."
        ),
        "repository": "https://github.com/msaad00/agent-bom",
        "transport": ["stdio", "sse", "streamable-http"],
        "tools": _SERVER_CARD_TOOLS,
        "prompts": _SERVER_CARD_PROMPTS,
        "capabilities": {
            "frameworks": ["OWASP LLM Top 10", "OWASP MCP Top 10", "MITRE ATLAS", "NIST AI RMF"],
            "sbom_formats": ["CycloneDX 1.6", "SPDX 3.0", "SARIF 2.1.0"],
            "data_sources": ["OSV.dev", "NVD", "EPSS", "CISA KEV", "Snyk", "MCP Registry", "Smithery"],
            "discovery_sources": [
                "Local MCP configs",
                "AWS Bedrock",
                "Azure AI Foundry",
                "GCP Vertex AI",
                "Databricks",
                "Snowflake",
                "Docker images",
                "Kubernetes",
                "SBOMs",
            ],
            "registry_servers": 427,
            "read_only": True,
        },
        "license": "Apache-2.0",
        "pypi": "agent-bom",
        "install": "pip install agent-bom[mcp-server]",
    }


# ---------------------------------------------------------------------------
# Smithery-compatible entry point
# ---------------------------------------------------------------------------


def create_smithery_server():
    """Smithery-compatible server factory.

    When the ``smithery`` SDK is installed, the ``@smithery.server()``
    decorator patches the FastMCP instance with CORS + session-config
    middleware so Smithery can host it.  Falls back to the plain server
    when the SDK is absent (local stdio usage).
    """
    try:
        from smithery.decorators import smithery

        @smithery.server()
        def _factory():
            return create_mcp_server()

        return _factory()
    except ImportError:
        # smithery SDK not installed — return plain FastMCP server
        return create_mcp_server()
