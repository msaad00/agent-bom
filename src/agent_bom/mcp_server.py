"""agent-bom MCP Server — expose security scanning as MCP tools.

Start with:
    agent-bom mcp-server              # stdio (for Claude Desktop, Cursor, etc.)
    agent-bom mcp-server --sse        # SSE transport (for remote clients)

Tools (23):
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
    """Run discovery → extraction → scanning and return (agents, blast_radii, warnings).

    Async version — safe to call from within an existing event loop (e.g.
    FastMCP's async context).  Falls back to asyncio.run() when no loop
    is running (CLI usage).
    """
    from agent_bom.discovery import discover_all
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType
    from agent_bom.parsers import extract_packages
    from agent_bom.scanners import scan_agents, scan_agents_with_enrichment

    warnings: list[str] = []

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

    # Docker image scanning
    if image:
        try:
            from agent_bom.image import scan_image

            img_agents, _warnings = scan_image(image)
            agents.extend(img_agents)
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
        except Exception as exc:
            msg = f"SBOM load failed for {sbom_path}: {exc}"
            logger.warning(msg)
            warnings.append(msg)

    if not agents:
        return [], [], warnings

    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)

    if enrich:
        blast_radii = await scan_agents_with_enrichment(agents)
    else:
        blast_radii = await scan_agents(agents)
    return agents, blast_radii, warnings


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
            f"agent-bom v{__version__} — AI supply chain security scanner. "
            "Scans packages and images for CVEs, assesses credential exposure and tool access risks, "
            "maps blast radius from vulnerabilities to credentials and tools, generates SBOMs, "
            "and enforces security policies. Agentless, read-only, non-root."
        ),
    )
    # Set the actual agent-bom version (FastMCP defaults to SDK version)
    mcp._mcp_server.version = __version__

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
        policy: Annotated[
            dict | None,
            Field(
                description='Policy object to evaluate alongside scan results, e.g. {"rules": [{"id": "no-critical", "severity_gte": "critical", "action": "fail"}]}.'
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
        try:
            from agent_bom.models import AIBOMReport
            from agent_bom.output import to_json

            agents, blast_radii, scan_warnings = await _run_scan_pipeline(
                config_path,
                image,
                sbom_path,
                enrich,
                transitive=transitive,
            )
            if not agents:
                result = {"status": "no_agents_found", "agents": [], "blast_radii": []}
                if scan_warnings:
                    result["warnings"] = scan_warnings
                return json.dumps(result)

            # Integrity verification
            if verify_integrity:
                from agent_bom.http_client import create_client
                from agent_bom.integrity import verify_package_integrity

                async with create_client(timeout=15.0) as client:
                    for agent in agents:
                        for server in agent.mcp_servers:
                            for pkg in server.packages:
                                try:
                                    result = await verify_package_integrity(pkg, client)
                                    if result:
                                        pkg.integrity = result
                                except Exception as exc:
                                    logger.debug("Integrity check failed for %s: %s", pkg.name, exc)

            # OpenSSF Scorecard enrichment
            if scorecard:
                try:
                    from agent_bom.scorecard import enrich_packages_with_scorecard

                    all_pkgs = [p for a in agents for s in a.mcp_servers for p in s.packages]
                    if all_pkgs:
                        await enrich_packages_with_scorecard(all_pkgs)
                except Exception as exc:
                    logger.debug("Scorecard enrichment failed: %s", exc)

            report = AIBOMReport(agents=agents, blast_radii=blast_radii)
            result = to_json(report)

            # Policy evaluation
            if policy:
                from agent_bom.policy import _validate_policy, evaluate_policy

                _validate_policy(policy)
                result["policy_results"] = evaluate_policy(policy, blast_radii)

            # Severity gate
            if fail_severity:
                from agent_bom.models import Severity

                severity_order = ["critical", "high", "medium", "low"]
                try:
                    threshold = Severity(fail_severity.lower())
                    threshold_idx = severity_order.index(threshold.value)
                except (ValueError, KeyError):
                    return json.dumps({"error": f"Invalid severity: {fail_severity}. Use: critical, high, medium, low"})
                gate_fail = any(
                    severity_order.index(sev) <= threshold_idx
                    for br in blast_radii
                    if (sev := br.vulnerability.severity.value) in severity_order
                )
                result["gate_status"] = "fail" if gate_fail else "pass"
                result["gate_severity"] = fail_severity.lower()

            if scan_warnings:
                result["warnings"] = scan_warnings
            return _truncate_response(json.dumps(result, indent=2, default=str))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

    # ── Tool 2: check ────────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Package CVE Check")
    async def check(
        package: Annotated[
            str,
            Field(
                description="Package name with optional version, e.g. 'express@4.18.2', '@modelcontextprotocol/server-filesystem@2025.1.14', or 'requests' (resolves @latest)."
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
        try:
            from agent_bom.models import Package as Pkg
            from agent_bom.scanners import build_vulnerabilities, query_osv_batch

            # Parse name@version
            spec = package.strip()
            if "@" in spec and not spec.startswith("@"):
                name, version = spec.rsplit("@", 1)
            elif spec.startswith("@") and spec.count("@") > 1:
                last_at = spec.rindex("@")
                name, version = spec[:last_at], spec[last_at + 1 :]
            else:
                name, version = spec, "latest"

            try:
                eco = _validate_ecosystem(ecosystem)
            except ValueError as exc:
                logger.exception("MCP tool error")
                return json.dumps({"error": sanitize_error(exc)})
            pkg = Pkg(name=name, version=version, ecosystem=eco)

            # Resolve "latest" via registry
            if version in ("latest", ""):
                from agent_bom.http_client import create_client
                from agent_bom.resolver import resolve_package_version

                async with create_client(timeout=15.0) as client:
                    resolved = await resolve_package_version(pkg, client)
                if resolved:
                    version = pkg.version
                else:
                    return json.dumps(
                        {
                            "package": name,
                            "ecosystem": eco,
                            "error": f"Could not resolve latest version for {name}",
                        }
                    )

            results = await query_osv_batch([pkg])
            key = f"{eco}:{name}@{version}"
            vuln_data = results.get(key, [])

            if not vuln_data:
                return json.dumps(
                    {
                        "package": name,
                        "version": version,
                        "ecosystem": eco,
                        "vulnerabilities": 0,
                        "status": "clean",
                        "message": f"No known vulnerabilities in {name}@{version}",
                    }
                )

            vulns = build_vulnerabilities(vuln_data, pkg)
            return json.dumps(
                {
                    "package": name,
                    "version": version,
                    "ecosystem": eco,
                    "vulnerabilities": len(vulns),
                    "status": "vulnerable",
                    "details": [
                        {
                            "id": v.id,
                            "severity": v.severity.value,
                            "cvss_score": v.cvss_score,
                            "fixed_version": v.fixed_version,
                            "summary": (v.summary or "")[:200],
                            "compliance_tags": v.compliance_tags,
                        }
                        for v in vulns
                    ],
                },
                indent=2,
                default=str,
            )
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            validated_cve = _validate_cve_id(cve_id)
        except ValueError as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

        try:
            _agents, blast_radii, _warnings = await _run_scan_pipeline()

            matches = [br for br in blast_radii if br.vulnerability.id.upper() == validated_cve.upper()]
            if not matches:
                return json.dumps(
                    {
                        "cve_id": cve_id,
                        "found": False,
                        "message": f"CVE {cve_id} not found in current scan results",
                    }
                )

            results = []
            for br in matches:
                results.append(
                    {
                        "cve_id": br.vulnerability.id,
                        "severity": br.vulnerability.severity.value,
                        "cvss_score": br.vulnerability.cvss_score,
                        "risk_score": br.risk_score,
                        "package": f"{br.package.name}@{br.package.version}",
                        "ecosystem": br.package.ecosystem,
                        "affected_servers": [s.name for s in br.affected_servers],
                        "affected_agents": [a.name for a in br.affected_agents],
                        "exposed_credentials": br.exposed_credentials,
                        "exposed_tools": [t.name for t in br.exposed_tools],
                        "fixed_version": br.vulnerability.fixed_version,
                        "ai_risk_context": br.ai_risk_context,
                    }
                )
            return _truncate_response(json.dumps({"cve_id": cve_id, "found": True, "blast_radii": results}, indent=2, default=str))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

    # ── Tool 4: policy_check ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Policy Evaluation")
    async def policy_check(
        policy_json: Annotated[
            str,
            Field(
                description='JSON string containing policy rules, e.g. {"rules": [{"id": "no-critical", "severity_gte": "critical", "action": "fail"}]}.'
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
        try:
            from agent_bom.policy import _validate_policy, evaluate_policy

            policy = json.loads(policy_json)
            _validate_policy(policy)

            _agents, blast_radii, _warnings = await _run_scan_pipeline()
            result = evaluate_policy(policy, blast_radii)
            return json.dumps(result, indent=2, default=str)
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"Invalid JSON: {exc}"})
        except ValueError as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        search_term = (server_name or package_name or "").strip()
        if not search_term:
            return json.dumps({"error": "Provide server_name or package_name"})

        try:
            data = _get_registry_data()
        except Exception as exc:
            logger.exception("Registry read failed")
            return json.dumps({"error": f"Failed to read registry: {sanitize_error(exc)}"})

        servers = data.get("servers", {})
        search_lower = search_term.lower()

        for key, entry in servers.items():
            if (
                search_lower in key.lower()
                or search_lower in entry.get("package", "").lower()
                or search_lower in entry.get("name", "").lower()
            ):
                return json.dumps(
                    {
                        "found": True,
                        "id": key,
                        "name": entry.get("name", key),
                        "package": entry.get("package", ""),
                        "ecosystem": entry.get("ecosystem", ""),
                        "latest_version": entry.get("latest_version", ""),
                        "risk_level": entry.get("risk_level", "unknown"),
                        "risk_justification": entry.get("risk_justification", ""),
                        "verified": entry.get("verified", False),
                        "tools": entry.get("tools", []),
                        "credential_env_vars": entry.get("credential_env_vars", []),
                        "known_cves": entry.get("known_cves", []),
                        "category": entry.get("category", ""),
                        "license": entry.get("license", ""),
                        "source_url": entry.get("source_url", ""),
                    },
                    indent=2,
                )

        return json.dumps({"found": False, "query": search_term, "message": "No matching server found in registry"})

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
        try:
            from agent_bom.models import AIBOMReport
            from agent_bom.output import to_cyclonedx, to_spdx

            agents, blast_radii, _warnings = await _run_scan_pipeline(config_path=config_path)
            if not agents:
                return json.dumps({"error": "No agents found to generate SBOM from"})

            report = AIBOMReport(agents=agents, blast_radii=blast_radii)

            if format.lower() == "spdx":
                return _truncate_response(json.dumps(to_spdx(report), indent=2, default=str))
            else:
                return _truncate_response(json.dumps(to_cyclonedx(report), indent=2, default=str))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.atlas import ATLAS_TECHNIQUES
            from agent_bom.nist_ai_rmf import NIST_AI_RMF
            from agent_bom.owasp import OWASP_LLM_TOP10
            from agent_bom.owasp_mcp import OWASP_MCP_TOP10

            agents, blast_radii, _warnings = await _run_scan_pipeline(config_path, image)

            # Convert BlastRadius objects to dicts for aggregation
            br_dicts = []
            for br in blast_radii:
                br_dicts.append(
                    {
                        "severity": br.vulnerability.severity.value,
                        "package": f"{br.package.name}@{br.package.version}",
                        "affected_agents": [a.name for a in br.affected_agents],
                        "owasp_tags": list(br.owasp_tags),
                        "atlas_tags": list(br.atlas_tags),
                        "nist_ai_rmf_tags": list(br.nist_ai_rmf_tags),
                        "owasp_mcp_tags": list(br.owasp_mcp_tags),
                    }
                )

            def _build_controls(catalog, tag_field, id_key):
                controls = []
                for code, name in sorted(catalog.items()):
                    sev_bk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    pkgs, ags, findings = set(), set(), 0
                    for br in br_dicts:
                        if code in br.get(tag_field, []):
                            findings += 1
                            sev = (br.get("severity") or "").lower()
                            if sev in sev_bk:
                                sev_bk[sev] += 1
                            if br.get("package"):
                                pkgs.add(br["package"])
                            for a in br.get("affected_agents", []):
                                ags.add(a)
                    status = "pass" if findings == 0 else ("fail" if sev_bk["critical"] > 0 or sev_bk["high"] > 0 else "warning")
                    controls.append(
                        {
                            id_key: code,
                            "name": name,
                            "findings": findings,
                            "status": status,
                            "severity_breakdown": sev_bk,
                            "affected_packages": sorted(pkgs),
                            "affected_agents": sorted(ags),
                        }
                    )
                return controls

            owasp = _build_controls(OWASP_LLM_TOP10, "owasp_tags", "code")
            atlas = _build_controls(ATLAS_TECHNIQUES, "atlas_tags", "code")
            nist = _build_controls(NIST_AI_RMF, "nist_ai_rmf_tags", "code")
            owasp_mcp = _build_controls(OWASP_MCP_TOP10, "owasp_mcp_tags", "code")

            all_controls = owasp + atlas + nist + owasp_mcp
            total = len(all_controls)
            total_pass = sum(1 for c in all_controls if c["status"] == "pass")
            score = round((total_pass / total) * 100, 1) if total > 0 else 100.0
            has_fail = any(c["status"] == "fail" for c in all_controls)
            has_warn = any(c["status"] == "warning" for c in all_controls)

            return _truncate_response(
                json.dumps(
                    {
                        "overall_score": score,
                        "overall_status": "fail" if has_fail else ("warning" if has_warn else "pass"),
                        "total_controls": total,
                        "owasp_llm_top10": owasp,
                        "mitre_atlas": atlas,
                        "nist_ai_rmf": nist,
                        "owasp_mcp_top10": owasp_mcp,
                    },
                    indent=2,
                    default=str,
                )
            )
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.models import AIBOMReport
            from agent_bom.remediate import generate_remediation

            agents, blast_radii, _warnings = await _run_scan_pipeline(config_path, image)
            if not agents:
                return json.dumps(
                    {
                        "package_fixes": [],
                        "credential_fixes": [],
                        "unfixable": [],
                        "message": "No agents found — nothing to remediate",
                    }
                )

            report = AIBOMReport(agents=agents, blast_radii=blast_radii)
            plan = generate_remediation(report, blast_radii)

            return _truncate_response(
                json.dumps(
                    {
                        "generated_at": plan.generated_at,
                        "package_fixes": [
                            {
                                "package": f.package,
                                "ecosystem": f.ecosystem,
                                "current_version": f.current_version,
                                "fixed_version": f.fixed_version,
                                "command": f.command,
                                "vulns": f.vulns[:5],
                                "agents": f.agents[:5],
                                "references": f.references[:10],
                            }
                            for f in plan.package_fixes
                        ],
                        "credential_fixes": [
                            {
                                "credential": f.credential_name,
                                "locations": f.locations[:5],
                                "risk": f.risk_description,
                                "fix_steps": f.fix_steps,
                            }
                            for f in plan.credential_fixes
                        ],
                        "unfixable": plan.unfixable[:10],
                    },
                    indent=2,
                    default=str,
                )
            )
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.parsers.skill_audit import audit_skill_result
            from agent_bom.parsers.skills import parse_skill_file
            from agent_bom.parsers.trust_assessment import assess_trust

            try:
                p = _safe_path(skill_path)
            except ValueError as exc:
                logger.exception("MCP tool error")
                return json.dumps({"error": sanitize_error(exc)})
            if not p.is_file():
                return json.dumps({"error": f"File not found: {skill_path}"})
            if p.stat().st_size > _MAX_FILE_SIZE:
                return json.dumps({"error": f"File too large ({p.stat().st_size} bytes, max {_MAX_FILE_SIZE})"})

            scan = parse_skill_file(p)
            audit = audit_skill_result(scan)
            trust = assess_trust(scan, audit)

            result = trust.to_dict()

            # Instruction file provenance check (Sigstore)
            try:
                from agent_bom.integrity import verify_instruction_file

                provenance = verify_instruction_file(p)
                if provenance.verified:
                    result["provenance"] = {
                        "status": "verified",
                        "signer": provenance.signer_identity,
                        "rekor_index": provenance.rekor_log_index,
                        "sha256": provenance.sha256,
                    }
                elif provenance.has_sigstore_bundle:
                    result["provenance"] = {
                        "status": "bundle_found_but_invalid",
                        "reason": provenance.reason,
                        "sha256": provenance.sha256,
                    }
                else:
                    result["provenance"] = {
                        "status": "unsigned",
                        "sha256": provenance.sha256,
                    }
            except Exception:
                result["provenance"] = {"status": "check_failed"}

            return json.dumps(result, indent=2)
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.http_client import create_client
            from agent_bom.integrity import (
                check_package_provenance,
                verify_package_integrity,
            )
            from agent_bom.models import Package as Pkg

            spec = package.strip()
            try:
                eco = _validate_ecosystem(ecosystem)
            except ValueError as exc:
                logger.exception("MCP tool error")
                return json.dumps({"error": sanitize_error(exc)})

            # Parse name@version or name==version
            if eco == "pypi" and "==" in spec:
                name, version = spec.split("==", 1)
            elif "@" in spec and not spec.startswith("@"):
                name, version = spec.rsplit("@", 1)
            elif spec.startswith("@") and spec.count("@") > 1:
                last_at = spec.rindex("@")
                name, version = spec[:last_at], spec[last_at + 1 :]
            else:
                name, version = spec, "latest"

            pkg = Pkg(name=name, version=version, ecosystem=eco)

            async with create_client(timeout=15.0) as client:
                integrity = await verify_package_integrity(pkg, client)
                provenance = await check_package_provenance(pkg, client)

            result = {
                "package": name,
                "version": version,
                "ecosystem": eco,
                "integrity": integrity.to_dict() if integrity and hasattr(integrity, "to_dict") else integrity,
                "provenance": provenance.to_dict() if provenance and hasattr(provenance, "to_dict") else provenance,
            }
            return json.dumps(result, indent=2, default=str)
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            import platform

            from agent_bom.discovery import CONFIG_LOCATIONS

            current_os = platform.system()
            clients = []
            for agent_type, platforms in CONFIG_LOCATIONS.items():
                paths = platforms.get(current_os, [])
                entries = []
                for p in paths:
                    try:
                        expanded = Path(p).expanduser()
                        entries.append(
                            {
                                "path": str(expanded),
                                "exists": expanded.exists(),
                            }
                        )
                    except Exception:
                        entries.append({"path": p, "exists": False, "error": "path expansion failed"})
                clients.append(
                    {
                        "client": agent_type.value,
                        "platform": current_os,
                        "config_paths": entries,
                    }
                )
            return json.dumps({"clients": clients, "platform": current_os}, indent=2)
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.discovery import discover_all
            from agent_bom.parsers import extract_packages

            agents = discover_all(project_dir=config_path)
            if not agents:
                return json.dumps({"status": "no_agents_found", "agents": []})

            for agent in agents:
                for server in agent.mcp_servers:
                    if not server.packages:
                        server.packages = extract_packages(server)

            result = []
            for agent in agents:
                servers = []
                for s in agent.mcp_servers:
                    servers.append(
                        {
                            "name": s.name,
                            "command": s.command,
                            "transport": s.transport.value,
                            "packages": [{"name": p.name, "version": p.version, "ecosystem": p.ecosystem} for p in s.packages],
                        }
                    )
                result.append(
                    {
                        "name": agent.name,
                        "agent_type": agent.agent_type.value,
                        "config_path": agent.config_path,
                        "servers": servers,
                    }
                )
            return _truncate_response(json.dumps({"agents": result, "total_agents": len(result)}, indent=2))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.history import diff_reports, latest_report, load_report, save_report
            from agent_bom.models import AIBOMReport
            from agent_bom.output import to_json

            agents, blast_radii, _warnings = await _run_scan_pipeline()
            if not agents:
                return json.dumps({"error": "No agents found — nothing to diff"})

            report = AIBOMReport(agents=agents, blast_radii=blast_radii)
            current = to_json(report)

            if baseline is None:
                latest = latest_report()
                if latest:
                    baseline = load_report(latest)
                else:
                    save_report(current)
                    return json.dumps(
                        {
                            "message": "No baseline found. Current scan saved as first baseline.",
                            "current_summary": current.get("summary", {}),
                        },
                        indent=2,
                        default=str,
                    )

            result = diff_reports(baseline, current)
            save_report(current)
            return _truncate_response(json.dumps(result, indent=2, default=str))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            name = package.strip()
            if not name or len(name) > 200:
                return json.dumps({"error": "Invalid package name"})

            try:
                eco = _validate_ecosystem(ecosystem)
            except ValueError as exc:
                logger.exception("MCP tool error")
                return json.dumps({"error": sanitize_error(exc)})

            # Fetch package metadata from registry
            from agent_bom.http_client import create_client

            version = "unknown"
            download_count = 0
            license_info = None

            async with create_client(timeout=15.0) as client:
                if eco == "npm":
                    try:
                        resp = await client.get(f"https://registry.npmjs.org/{name}")
                        if resp.status_code == 200:
                            data = resp.json()
                            dist_tags = data.get("dist-tags", {})
                            version = dist_tags.get("latest", "unknown")
                            license_info = data.get("license")
                    except Exception:
                        logger.debug("npm registry lookup failed for %s", name)
                    # npm download count
                    try:
                        resp = await client.get(f"https://api.npmjs.org/downloads/point/last-week/{name}")
                        if resp.status_code == 200:
                            download_count = resp.json().get("downloads", 0)
                    except Exception:
                        logger.debug("npm download count lookup failed for %s", name)
                elif eco == "pypi":
                    try:
                        resp = await client.get(f"https://pypi.org/pypi/{name}/json")
                        if resp.status_code == 200:
                            data = resp.json()
                            version = data.get("info", {}).get("version", "unknown")
                            license_info = data.get("info", {}).get("license")
                    except Exception:
                        logger.debug("PyPI metadata lookup failed for %s", name)

            # Check CVEs
            from agent_bom.models import Package as Pkg
            from agent_bom.scanners import build_vulnerabilities, query_osv_batch

            pkg = Pkg(name=name, version=version, ecosystem=eco)
            results = await query_osv_batch([pkg])
            key = f"{eco}:{name}@{version}"
            vuln_data = results.get(key, [])
            vulns = build_vulnerabilities(vuln_data, pkg) if vuln_data else []

            # Cross-reference MCP registry
            registry_verified = False
            try:
                data_raw = _get_registry_data_raw()
                registry = json.loads(data_raw)
                if isinstance(registry, dict):
                    servers = registry.get("servers", registry)
                    for _k, v in servers.items() if isinstance(servers, dict) else []:
                        pkgs = v.get("packages", [])
                        if name in pkgs or any(name in p for p in pkgs):
                            registry_verified = True
                            break
            except Exception:
                logger.debug("MCP registry verification failed for %s", name)

            # Build trust signals
            trust_signals = []
            if len(vulns) == 0:
                trust_signals.append("no-known-cves")
            if registry_verified:
                trust_signals.append("registry-verified")
            if download_count > 100_000:
                trust_signals.append("high-adoption")
            elif download_count > 10_000:
                trust_signals.append("moderate-adoption")
            if license_info:
                trust_signals.append(f"license:{license_info}")

            return json.dumps(
                {
                    "package": name,
                    "version": version,
                    "ecosystem": eco,
                    "cve_count": len(vulns),
                    "download_count": download_count,
                    "registry_verified": registry_verified,
                    "license": license_info,
                    "trust_signals": trust_signals,
                    "vulnerabilities": [{"id": v.id, "severity": v.severity.value} for v in vulns[:10]],
                },
                indent=2,
                default=str,
            )
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            scan_path = _safe_path(path)
        except ValueError as exc:
            return json.dumps({"error": sanitize_error(exc)})

        try:
            from agent_bom.sast import SASTScanError, scan_code

            _packages, sast_result = scan_code(str(scan_path), config=config)
            return _truncate_response(json.dumps(sast_result.to_dict(), indent=2))
        except SASTScanError as exc:
            return json.dumps({"error": sanitize_error(exc)})
        except Exception as exc:
            logger.error("code_scan error: %s", exc)
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.context_graph import (
                NodeKind,
                build_context_graph,
                compute_interaction_risks,
                find_lateral_paths,
                to_serializable,
            )
            from agent_bom.models import AIBOMReport
            from agent_bom.output import to_json

            agents, blast_radii, _warnings = await _run_scan_pipeline(config_path)
            if not agents:
                return json.dumps({"error": "No agents found"})

            report = AIBOMReport(agents=agents, blast_radii=blast_radii)
            report_json = to_json(report)
            graph = build_context_graph(
                report_json["agents"],
                report_json.get("blast_radius", []),
            )

            paths: list = []
            depth = max(1, min(max_depth, 6))
            if source_agent:
                node_id = f"agent:{source_agent}"
                if node_id in graph.nodes:
                    paths = find_lateral_paths(graph, node_id, max_depth=depth)
            else:
                for nid, node in graph.nodes.items():
                    if node.kind == NodeKind.AGENT:
                        paths.extend(find_lateral_paths(graph, nid, max_depth=depth))

            risks = compute_interaction_risks(graph)
            result = to_serializable(graph, paths, risks)
            return _truncate_response(json.dumps(result, indent=2, default=str))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.api.server import _get_analytics_store

            store = _get_analytics_store()
            valid_types = {"vuln_trends", "top_cves", "posture_history", "event_summary"}
            if query_type not in valid_types:
                return json.dumps({"error": f"Invalid query_type. Use one of: {', '.join(sorted(valid_types))}"})

            # Validate agent name to prevent SQL injection via ClickHouse
            import re as _re

            if agent and not _re.fullmatch(r"[a-zA-Z0-9._\-/ ]{1,200}", agent):
                return json.dumps(
                    {"error": "Invalid agent name. Use only alphanumeric, dot, dash, underscore, slash, space (max 200 chars)."}
                )

            if query_type == "vuln_trends":
                data = store.query_vuln_trends(days=days, agent=agent)
            elif query_type == "top_cves":
                data = store.query_top_cves(limit=limit)
            elif query_type == "posture_history":
                data = store.query_posture_history(agent=agent, days=days)
            else:
                data = store.query_event_summary(hours=hours)

            return json.dumps({"query_type": query_type, "results": data, "count": len(data)}, indent=2, default=str)
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            check_list = [c.strip() for c in checks.split(",")] if checks else None

            # Validate inputs to prevent injection
            import re as _re

            if region and not _re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-\d{1,2}", region):
                return json.dumps({"error": f"Invalid AWS region format: {region}"})
            if profile and not _re.fullmatch(r"[a-zA-Z0-9._-]{1,100}", profile):
                return json.dumps({"error": "Invalid AWS profile name. Use alphanumeric, dot, dash, underscore (max 100 chars)."})

            if provider == "aws":
                from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_aws_cis

                report = run_aws_cis(region=region, profile=profile, checks=check_list)
            elif provider == "snowflake":
                from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_sf_cis

                report = run_sf_cis(checks=check_list)
            elif provider == "azure":
                from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_azure_cis

                report = run_azure_cis(subscription_id=subscription_id, checks=check_list)
            elif provider == "gcp":
                from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis

                report = run_gcp_cis(project_id=project_id, checks=check_list)
            else:
                return json.dumps({"error": f"Unsupported provider: {provider}. Use 'aws', 'snowflake', 'azure', or 'gcp'."})

            return _truncate_response(json.dumps(report.to_dict(), indent=2, default=str))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.fleet_scan import fleet_scan as _fleet_scan

            # Parse input: support comma-separated and newline-separated
            names: list[str] = []
            for line in servers.replace(",", "\n").split("\n"):
                name = line.strip()
                if name:
                    names.append(name)

            if not names:
                return json.dumps({"error": "No server names provided"})

            if len(names) > 1000:
                return json.dumps({"error": f"Too many servers ({len(names)}). Maximum is 1,000 per request."})

            result = _fleet_scan(names)
            return _truncate_response(result.to_json())
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
    ) -> str:
        """Cross-reference vulnerability scan results with proxy runtime audit logs.

        Identifies which vulnerable tools were ACTUALLY CALLED in production,
        distinguishing confirmed attack surface from theoretical risk. Produces
        risk-amplified findings: a vulnerable tool that was called 100 times is
        higher priority than one never invoked.

        Requires a proxy audit log (generated by running agent-bom proxy with
        the --log flag). Without an audit log, returns scan results only.

        Returns:
            JSON with correlated findings (CVE + tool call data + amplified risk),
            summary stats, and uncalled vulnerable tools.
        """
        try:
            # Normalize "auto" → None so _run_scan_pipeline uses default discovery
            effective_config = None if config_path == "auto" else config_path
            report = await _run_scan_pipeline(effective_config)
            result: dict = {
                "scan_summary": {
                    "agents": report.total_agents,
                    "servers": report.total_servers,
                    "vulnerabilities": len(report.blast_radii),
                },
            }

            if audit_log:
                # Validate audit_log path to prevent directory traversal
                safe_audit = _safe_path(audit_log)
                from agent_bom.runtime_correlation import correlate as _correlate

                corr = _correlate(report.blast_radii, audit_log_path=str(safe_audit))
                result["correlation"] = corr.to_dict()
            else:
                result["correlation"] = {
                    "note": "No audit log provided. Run 'agent-bom proxy --log audit.jsonl' to capture tool calls, then pass the log path.",
                    "vulnerable_tools": len({t.name for br in report.blast_radii for t in br.exposed_tools}) if report.blast_radii else 0,
                }

            return json.dumps(result, indent=2, default=str)
        except Exception as exc:
            logger.exception("Runtime correlation failed")
            return json.dumps({"error": f"Correlation failed: {sanitize_error(exc)}"})

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
        try:
            from agent_bom.cloud.vector_db import discover_pinecone, discover_vector_dbs

            host_list = [h.strip() for h in hosts.split(",")] if hosts else None
            self_hosted = discover_vector_dbs(hosts=host_list)
            pinecone_results = discover_pinecone()
            all_results = [r.to_dict() for r in self_hosted] + [r.to_dict() for r in pinecone_results]
            return _truncate_response(
                json.dumps(
                    {
                        "databases_found": len(all_results),
                        "self_hosted_count": len(self_hosted),
                        "cloud_count": len(pinecone_results),
                        "results": all_results,
                    },
                    indent=2,
                    default=str,
                )
            )
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.cloud.aisvs_benchmark import run_benchmark as _run_aisvs

            check_list = [c.strip() for c in checks.split(",")] if checks else None
            report = _run_aisvs(checks=check_list)
            return _truncate_response(json.dumps(report.to_dict(), indent=2, default=str))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
        try:
            from agent_bom.cloud.gpu_infra import scan_gpu_infra

            report = await scan_gpu_infra(k8s_context=k8s_context, probe_dcgm=probe_dcgm)
            result = {
                "risk_summary": report.risk_summary,
                "gpu_containers": [
                    {
                        "container_id": c.container_id,
                        "name": c.name,
                        "image": c.image,
                        "status": c.status,
                        "is_nvidia_base": c.is_nvidia_base,
                        "cuda_version": c.cuda_version,
                        "cudnn_version": c.cudnn_version,
                        "gpu_requested": c.gpu_requested,
                    }
                    for c in report.gpu_containers
                ],
                "k8s_gpu_nodes": [
                    {
                        "name": n.name,
                        "gpu_capacity": n.gpu_capacity,
                        "gpu_allocatable": n.gpu_allocatable,
                        "gpu_allocated": n.gpu_allocated,
                        "cuda_driver_version": n.cuda_driver_version,
                    }
                    for n in report.gpu_nodes
                ],
                "dcgm_endpoints": [
                    {
                        "host": ep.host,
                        "port": ep.port,
                        "url": ep.url,
                        "authenticated": ep.authenticated,
                        "gpu_count": ep.gpu_count,
                        "risk": "unauthenticated GPU metrics exposure" if not ep.authenticated else "ok",
                    }
                    for ep in report.dcgm_endpoints
                ],
                "warnings": report.warnings,
            }
            return _truncate_response(json.dumps(result, indent=2, default=str))
        except Exception as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

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
                "description": "AI supply chain security scanner",
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
    {"name": "policy_check", "description": "Evaluate security policy rules", "annotations": {"readOnlyHint": True}},
    {"name": "registry_lookup", "description": "Query MCP server threat intelligence registry", "annotations": {"readOnlyHint": True}},
    {"name": "generate_sbom", "description": "Generate CycloneDX or SPDX SBOM", "annotations": {"readOnlyHint": True}},
    {
        "name": "compliance",
        "description": "10-framework compliance posture (OWASP LLM + MCP + Agentic, ATLAS, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CIS)",
        "annotations": {"readOnlyHint": True},
    },
    {"name": "remediate", "description": "Generate actionable remediation plan", "annotations": {"readOnlyHint": True}},
    {"name": "skill_trust", "description": "ClawHub-style trust assessment for SKILL.md files", "annotations": {"readOnlyHint": True}},
    {"name": "verify", "description": "Package integrity + SLSA provenance verification", "annotations": {"readOnlyHint": True}},
    {"name": "where", "description": "Show all MCP discovery paths + existence status", "annotations": {"readOnlyHint": True}},
    {"name": "inventory", "description": "List agents/servers without CVE scanning", "annotations": {"readOnlyHint": True}},
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
        "description": "Batch-scan MCP server names against registry for fleet inventory assessment",
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
            "AI supply chain security scanner — CVE scanning, blast radius analysis, "
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
