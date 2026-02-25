"""agent-bom MCP Server — expose security scanning as MCP tools.

Start with:
    agent-bom mcp-server              # stdio (for Claude Desktop, Cursor, etc.)
    agent-bom mcp-server --sse        # SSE transport (for remote clients)

Tools (13):
    scan              — Full discovery → scan → output pipeline
    check             — Check a specific package for CVEs before installing
    blast_radius      — Look up blast radius for a specific CVE
    policy_check      — Evaluate a policy against scan results
    registry_lookup   — Query the MCP server threat intelligence registry
    generate_sbom     — Generate CycloneDX or SPDX SBOM
    compliance        — OWASP/ATLAS/NIST AI RMF compliance posture
    remediate         — Generate actionable remediation plan
    skill_trust       — ClawHub-style trust assessment for SKILL.md files
    verify            — Package integrity + SLSA provenance verification
    where             — Show all MCP discovery paths + existence status
    inventory         — List agents/servers without CVE scanning
    diff              — Compare scan against baseline for new/resolved vulns

Resources (2):
    registry://servers  — Browse 427+ server threat intel registry
    policy://template   — Default security policy template

Security: Read-only. Never executes MCP servers or reads credential values.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated, Optional

from mcp.types import ToolAnnotations
from pydantic import Field

logger = logging.getLogger(__name__)

# All agent-bom tools are read-only scanners
_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def _check_mcp_sdk() -> None:
    """Ensure the mcp SDK is available."""
    try:
        import mcp  # noqa: F401
    except ImportError:
        raise ImportError(
            "mcp SDK is required for the MCP server. "
            "Install with: pip install 'agent-bom[mcp-server]'"
        ) from None


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
    """Run discovery → extraction → scanning and return (agents, blast_radii).

    Async version — safe to call from within an existing event loop (e.g.
    FastMCP's async context).  Falls back to asyncio.run() when no loop
    is running (CLI usage).
    """
    from agent_bom.discovery import discover_all
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType
    from agent_bom.parsers import extract_packages
    from agent_bom.scanners import scan_agents, scan_agents_with_enrichment

    agents = discover_all(project_dir=config_path)

    # Docker image scanning
    if image:
        try:
            from agent_bom.image import scan_image
            img_agents, _warnings = scan_image(image)
            agents.extend(img_agents)
        except Exception as exc:
            logger.warning("Image scan failed for %s: %s", image, exc)

    # SBOM ingestion
    if sbom_path:
        try:
            from agent_bom.sbom import load_sbom
            sbom_packages, _warnings = load_sbom(sbom_path)
            if sbom_packages:
                sbom_server = MCPServer(
                    name=f"sbom:{Path(sbom_path).name}",
                    command="",
                    args=[],
                    env={},
                    transport=TransportType.UNKNOWN,
                    packages=sbom_packages,
                )
                agents.append(Agent(
                    name=f"sbom:{Path(sbom_path).name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=sbom_path,
                    mcp_servers=[sbom_server],
                ))
        except Exception as exc:
            logger.warning("SBOM load failed for %s: %s", sbom_path, exc)

    if not agents:
        return [], []

    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)

    if enrich:
        blast_radii = await scan_agents_with_enrichment(agents)
    else:
        blast_radii = await scan_agents(agents)
    return agents, blast_radii


# ---------------------------------------------------------------------------
# MCP Server factory
# ---------------------------------------------------------------------------

def create_mcp_server(*, host: str = "127.0.0.1", port: int = 8000):
    """Create and configure the agent-bom MCP server with all tools.

    When the smithery SDK is installed, the server is automatically enhanced
    with session-config and CORS middleware for Smithery.ai hosted deployment.
    """
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
            "maps blast radius, generates SBOMs, and enforces security policies. Agentless, read-only."
        ),
    )
    # Set the actual agent-bom version (FastMCP defaults to SDK version)
    mcp._mcp_server.version = __version__

    # ── Tool 1: scan ──────────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
    async def scan(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        image: Annotated[str | None, Field(description="Docker image to scan (e.g. 'nginx:1.25', 'ghcr.io/org/app:v1').")] = None,
        sbom_path: Annotated[str | None, Field(description="Path to existing CycloneDX or SPDX JSON SBOM file to ingest.")] = None,
        enrich: Annotated[bool, Field(description="Enable NVD CVSS, EPSS probability, and CISA KEV enrichment.")] = False,
        transitive: Annotated[bool, Field(description="Resolve transitive dependencies for npx/uvx packages.")] = False,
        verify_integrity: Annotated[bool, Field(description="Verify package SHA-256/SRI hashes and SLSA provenance against registries.")] = False,
        fail_severity: Annotated[str | None, Field(description="Return failure status if vulns at this severity or higher: critical, high, medium, low.")] = None,
        policy: Annotated[dict | None, Field(description="Policy object to evaluate alongside scan results, e.g. {\"rules\": [{\"id\": \"no-critical\", \"severity_gte\": \"critical\", \"action\": \"fail\"}]}.")] = None,
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

            agents, blast_radii = await _run_scan_pipeline(
                config_path, image, sbom_path, enrich, transitive=transitive,
            )
            if not agents:
                return json.dumps({"status": "no_agents_found", "agents": [], "blast_radii": []})

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
                                except Exception:
                                    pass

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

                threshold = Severity(fail_severity.lower())
                severity_order = ["critical", "high", "medium", "low"]
                threshold_idx = severity_order.index(threshold.value)
                gate_fail = any(
                    severity_order.index(br.vulnerability.severity.value) <= threshold_idx
                    for br in blast_radii
                    if br.vulnerability.severity.value in severity_order
                )
                result["gate_status"] = "fail" if gate_fail else "pass"
                result["gate_severity"] = fail_severity.lower()

            return json.dumps(result, indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 2: check ────────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
    async def check(
        package: Annotated[str, Field(description="Package name with optional version, e.g. 'express@4.18.2', '@modelcontextprotocol/server-filesystem@2025.1.14', or 'requests' (resolves @latest).")],
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
                name, version = spec[:last_at], spec[last_at + 1:]
            else:
                name, version = spec, "latest"

            eco = ecosystem.lower().strip()
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
                    return json.dumps({
                        "package": name,
                        "ecosystem": eco,
                        "error": f"Could not resolve latest version for {name}",
                    })

            results = await query_osv_batch([pkg])
            key = f"{eco}:{name}@{version}"
            vuln_data = results.get(key, [])

            if not vuln_data:
                return json.dumps({
                    "package": name,
                    "version": version,
                    "ecosystem": eco,
                    "vulnerabilities": 0,
                    "status": "clean",
                    "message": f"No known vulnerabilities in {name}@{version}",
                })

            vulns = build_vulnerabilities(vuln_data, pkg)
            return json.dumps({
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
                    }
                    for v in vulns
                ],
            }, indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 3: blast_radius ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
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
            _agents, blast_radii = await _run_scan_pipeline()

            matches = [br for br in blast_radii if br.vulnerability.id.upper() == cve_id.upper()]
            if not matches:
                return json.dumps({
                    "cve_id": cve_id,
                    "found": False,
                    "message": f"CVE {cve_id} not found in current scan results",
                })

            results = []
            for br in matches:
                results.append({
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
                })
            return json.dumps({"cve_id": cve_id, "found": True, "blast_radii": results}, indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 4: policy_check ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
    async def policy_check(
        policy_json: Annotated[str, Field(description="JSON string containing policy rules, e.g. {\"rules\": [{\"id\": \"no-critical\", \"severity_gte\": \"critical\", \"action\": \"fail\"}]}.")],
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

            _agents, blast_radii = await _run_scan_pipeline()
            result = evaluate_policy(policy, blast_radii)
            return json.dumps(result, indent=2, default=str)
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"Invalid JSON: {exc}"})
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 5: registry_lookup ───────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
    def registry_lookup(
        server_name: Annotated[str | None, Field(description="MCP server name to look up, e.g. 'filesystem', '@modelcontextprotocol/server-github'.")] = None,
        package_name: Annotated[str | None, Field(description="Package name to search for, e.g. 'mcp-server-sqlite'. At least one of server_name or package_name is required.")] = None,
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

        registry_path = Path(__file__).parent / "mcp_registry.json"
        try:
            data = json.loads(registry_path.read_text())
        except Exception as exc:
            return json.dumps({"error": f"Failed to read registry: {exc}"})

        servers = data.get("servers", {})
        search_lower = search_term.lower()

        for key, entry in servers.items():
            if (search_lower in key.lower()
                    or search_lower in entry.get("package", "").lower()
                    or search_lower in entry.get("name", "").lower()):
                return json.dumps({
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
                }, indent=2)

        return json.dumps({"found": False, "query": search_term, "message": "No matching server found in registry"})

    # ── Tool 6: generate_sbom ─────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
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

            agents, blast_radii = await _run_scan_pipeline(config_path=config_path)
            if not agents:
                return json.dumps({"error": "No agents found to generate SBOM from"})

            report = AIBOMReport(agents=agents, blast_radii=blast_radii)

            if format.lower() == "spdx":
                return json.dumps(to_spdx(report), indent=2, default=str)
            else:
                return json.dumps(to_cyclonedx(report), indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 7: compliance ───────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
    async def compliance(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        image: Annotated[str | None, Field(description="Docker image to scan, e.g. 'nginx:1.25'.")] = None,
    ) -> str:
        """Get OWASP LLM Top 10 / MITRE ATLAS / NIST AI RMF compliance posture.

        Scans local MCP configurations, maps findings to 37 security controls
        across three AI security frameworks, and returns per-control
        pass/warning/fail status with an overall compliance score.

        Args:
            config_path: Path to a specific MCP config directory.
                         If not provided, auto-discovers all local agent configs.
            image: Docker image reference to scan (e.g. "nginx:1.25").

        Returns:
            JSON with overall_score (0-100), overall_status (pass/warning/fail),
            and per-control details for OWASP LLM Top 10 (10 controls),
            MITRE ATLAS (13 techniques), and NIST AI RMF (14 subcategories).
        """
        try:
            from agent_bom.atlas import ATLAS_TECHNIQUES
            from agent_bom.nist_ai_rmf import NIST_AI_RMF
            from agent_bom.owasp import OWASP_LLM_TOP10

            agents, blast_radii = await _run_scan_pipeline(config_path, image)

            # Convert BlastRadius objects to dicts for aggregation
            br_dicts = []
            for br in blast_radii:
                br_dicts.append({
                    "severity": br.vulnerability.severity.value,
                    "package": f"{br.package.name}@{br.package.version}",
                    "affected_agents": [a.name for a in br.affected_agents],
                    "owasp_tags": list(br.owasp_tags),
                    "atlas_tags": list(br.atlas_tags),
                    "nist_ai_rmf_tags": list(br.nist_ai_rmf_tags),
                })

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
                    status = "pass" if findings == 0 else (
                        "fail" if sev_bk["critical"] > 0 or sev_bk["high"] > 0 else "warning"
                    )
                    controls.append({
                        id_key: code, "name": name, "findings": findings,
                        "status": status, "severity_breakdown": sev_bk,
                        "affected_packages": sorted(pkgs),
                        "affected_agents": sorted(ags),
                    })
                return controls

            owasp = _build_controls(OWASP_LLM_TOP10, "owasp_tags", "code")
            atlas = _build_controls(ATLAS_TECHNIQUES, "atlas_tags", "code")
            nist = _build_controls(NIST_AI_RMF, "nist_ai_rmf_tags", "code")

            total = len(owasp) + len(atlas) + len(nist)
            total_pass = sum(1 for c in owasp + atlas + nist if c["status"] == "pass")
            score = round((total_pass / total) * 100, 1) if total > 0 else 100.0
            has_fail = any(c["status"] == "fail" for c in owasp + atlas + nist)
            has_warn = any(c["status"] == "warning" for c in owasp + atlas + nist)

            return json.dumps({
                "overall_score": score,
                "overall_status": "fail" if has_fail else ("warning" if has_warn else "pass"),
                "total_controls": total,
                "owasp_llm_top10": owasp,
                "mitre_atlas": atlas,
                "nist_ai_rmf": nist,
            }, indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 8: remediate ────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
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

            agents, blast_radii = await _run_scan_pipeline(config_path, image)
            if not agents:
                return json.dumps({
                    "package_fixes": [],
                    "credential_fixes": [],
                    "unfixable": [],
                    "message": "No agents found — nothing to remediate",
                })

            report = AIBOMReport(agents=agents, blast_radii=blast_radii)
            plan = generate_remediation(report, blast_radii)

            return json.dumps({
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
            }, indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 9: skill_trust ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
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
            from pathlib import Path as _Path

            from agent_bom.parsers.skill_audit import audit_skill_result
            from agent_bom.parsers.skills import parse_skill_file
            from agent_bom.parsers.trust_assessment import assess_trust

            p = _Path(skill_path).expanduser().resolve()
            if not p.is_file():
                return json.dumps({"error": f"File not found: {skill_path}"})

            scan = parse_skill_file(p)
            audit = audit_skill_result(scan)
            trust = assess_trust(scan, audit)

            return json.dumps(trust.to_dict(), indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 10: verify ─────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
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
            eco = ecosystem.lower().strip()

            # Parse name@version or name==version
            if eco == "pypi" and "==" in spec:
                name, version = spec.split("==", 1)
            elif "@" in spec and not spec.startswith("@"):
                name, version = spec.rsplit("@", 1)
            elif spec.startswith("@") and spec.count("@") > 1:
                last_at = spec.rindex("@")
                name, version = spec[:last_at], spec[last_at + 1:]
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
            return json.dumps({"error": str(exc)})

    # ── Tool 11: where ────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
    def where() -> str:
        """Show all MCP discovery paths and which config files exist.

        Lists every known MCP client config path per platform, indicating
        which files are present on the current system. Useful for debugging
        discovery issues or understanding where MCP configs live.

        Returns:
            JSON with per-client config paths, existence status, and platform.
        """
        import platform

        from agent_bom.discovery import CONFIG_LOCATIONS

        current_os = platform.system()
        clients = []
        for agent_type, platforms in CONFIG_LOCATIONS.items():
            paths = platforms.get(current_os, [])
            entries = []
            for p in paths:
                expanded = Path(p).expanduser()
                entries.append({
                    "path": str(expanded),
                    "exists": expanded.exists(),
                })
            clients.append({
                "client": agent_type.value,
                "platform": current_os,
                "config_paths": entries,
            })
        return json.dumps({"clients": clients, "platform": current_os}, indent=2)

    # ── Tool 12: inventory ────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
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
                    servers.append({
                        "name": s.name,
                        "command": s.command,
                        "transport": s.transport.value,
                        "packages": [
                            {"name": p.name, "version": p.version, "ecosystem": p.ecosystem}
                            for p in s.packages
                        ],
                    })
                result.append({
                    "name": agent.name,
                    "agent_type": agent.agent_type.value,
                    "config_path": agent.config_path,
                    "servers": servers,
                })
            return json.dumps({"agents": result, "total_agents": len(result)}, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 13: diff ─────────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY)
    async def diff(
        baseline: Annotated[dict | None, Field(description="Baseline report JSON object. If omitted, uses the latest saved report from history.")] = None,
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

            agents, blast_radii = await _run_scan_pipeline()
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
                    return json.dumps({
                        "message": "No baseline found. Current scan saved as first baseline.",
                        "current_summary": current.get("summary", {}),
                    }, indent=2, default=str)

            result = diff_reports(baseline, current)
            save_report(current)
            return json.dumps(result, indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Resources ────────────────────────────────────────────────

    @mcp.resource("registry://servers")
    def registry_servers_resource() -> str:
        """Browse the MCP server threat intelligence registry (427+ servers).

        Returns the full registry with risk levels, tools, credential
        requirements, and verification status for every known MCP server.
        """
        registry_path = Path(__file__).parent / "mcp_registry.json"
        return registry_path.read_text()

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
                {"id": "no-critical", "severity_gte": "critical", "action": "fail",
                 "message": "Block critical vulnerabilities"},
                {"id": "no-kev", "is_kev": True, "action": "fail",
                 "message": "Block CISA Known Exploited Vulnerabilities"},
                {"id": "warn-high", "severity_gte": "high", "action": "warn",
                 "message": "Warn on high-severity vulnerabilities"},
                {"id": "warn-unverified", "unverified_server": True, "action": "warn",
                 "message": "Warn on unverified MCP servers"},
                {"id": "warn-credentials", "has_credentials": True, "action": "warn",
                 "message": "Flag servers with credential exposure"},
            ],
        }
        return json.dumps(template, indent=2)

    # ── Prompts ─────────────────────────────────────────────────────

    @mcp.prompt(name="quick-audit", description="Run a complete security audit of your AI agent setup")
    def quick_audit_prompt() -> str:
        return (
            "Scan my local AI agent and MCP server configurations for vulnerabilities. "
            "Show the blast radius for any critical findings and suggest remediation steps. "
            "Include OWASP LLM Top 10 and MITRE ATLAS mappings."
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
            "Scan my AI agent setup, map findings to OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF. "
            "Generate a compliance summary suitable for security review."
        )

    # ── Custom route: server card ────────────────────────────────────

    @mcp.custom_route("/.well-known/mcp/server-card.json", methods=["GET"])
    async def server_card_route(request):
        from starlette.responses import JSONResponse
        return JSONResponse(build_server_card())

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
    {"name": "compliance", "description": "OWASP / MITRE ATLAS / NIST AI RMF posture", "annotations": {"readOnlyHint": True}},
    {"name": "remediate", "description": "Generate actionable remediation plan", "annotations": {"readOnlyHint": True}},
    {"name": "skill_trust", "description": "ClawHub-style trust assessment for SKILL.md files", "annotations": {"readOnlyHint": True}},
    {"name": "verify", "description": "Package integrity + SLSA provenance verification", "annotations": {"readOnlyHint": True}},
    {"name": "where", "description": "Show all MCP discovery paths + existence status", "annotations": {"readOnlyHint": True}},
    {"name": "inventory", "description": "List agents/servers without CVE scanning", "annotations": {"readOnlyHint": True}},
    {"name": "diff", "description": "Compare scan against baseline for new/resolved vulns", "annotations": {"readOnlyHint": True}},
]

_SERVER_CARD_PROMPTS = [
    {"name": "quick-audit", "description": "Run a complete security audit of your AI agent setup"},
    {"name": "pre-install-check", "description": "Check an MCP server package for vulnerabilities before installing"},
    {"name": "compliance-report", "description": "Generate OWASP/ATLAS/NIST compliance posture for your AI stack"},
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
            "frameworks": ["OWASP LLM Top 10", "MITRE ATLAS", "NIST AI RMF"],
            "sbom_formats": ["CycloneDX 1.6", "SPDX 3.0", "SARIF 2.1.0"],
            "data_sources": ["OSV.dev", "NVD", "EPSS", "CISA KEV", "Snyk", "MCP Registry", "Smithery"],
            "discovery_sources": [
                "Local MCP configs", "AWS Bedrock", "Azure AI Foundry", "GCP Vertex AI",
                "Databricks", "Snowflake", "Docker images", "Kubernetes", "SBOMs",
            ],
            "registry_servers": 112,
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
