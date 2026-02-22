"""agent-bom MCP Server — expose security scanning as MCP tools.

Start with:
    agent-bom mcp-server              # stdio (for Claude Desktop, Cursor, etc.)
    agent-bom mcp-server --sse        # SSE transport (for remote clients)

Tools:
    scan              — Full discovery → scan → output pipeline
    blast_radius      — Look up blast radius for a specific CVE
    policy_check      — Evaluate a policy against scan results
    registry_lookup   — Query the MCP server threat intelligence registry
    generate_sbom     — Generate CycloneDX or SPDX SBOM
    compliance        — OWASP/ATLAS/NIST AI RMF compliance posture
    remediate         — Generate actionable remediation plan

Security: Read-only. Never executes MCP servers or reads credential values.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


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

def create_mcp_server():
    """Create and configure the agent-bom MCP server with all tools."""
    _check_mcp_sdk()
    from mcp.server.fastmcp import FastMCP

    from agent_bom import __version__

    mcp = FastMCP(
        name="agent-bom",
        instructions=(
            f"agent-bom v{__version__} — AI supply chain security scanner. "
            "Scans AI agents and MCP servers for CVEs, maps blast radius, "
            "generates SBOMs, and enforces security policies. Read-only."
        ),
    )

    # ── Tool 1: scan ──────────────────────────────────────────────────

    @mcp.tool()
    async def scan(
        config_path: Optional[str] = None,
        image: Optional[str] = None,
        sbom_path: Optional[str] = None,
        enrich: bool = False,
    ) -> str:
        """Run a full security scan of AI agents and MCP servers.

        Discovers local MCP configurations (Claude Desktop, Cursor, Windsurf,
        VS Code Copilot, OpenClaw, etc.), extracts package dependencies, queries
        OSV.dev for CVEs, computes blast radius, and returns structured results.

        Args:
            config_path: Path to a specific MCP config directory to scan.
                         If not provided, auto-discovers all local agent configs.
            image: Docker image reference to scan (e.g. "nginx:1.25").
            sbom_path: Path to an existing SBOM file (CycloneDX or SPDX JSON).
            enrich: Enable NVD CVSS, EPSS, and CISA KEV enrichment.

        Returns:
            JSON with the complete AI-BOM report including agents, packages,
            vulnerabilities, blast radius, and remediation guidance.
        """
        try:
            from agent_bom.models import AIBOMReport
            from agent_bom.output import to_json

            agents, blast_radii = await _run_scan_pipeline(config_path, image, sbom_path, enrich)
            if not agents:
                return json.dumps({"status": "no_agents_found", "agents": [], "blast_radii": []})

            report = AIBOMReport(agents=agents, blast_radii=blast_radii)
            return json.dumps(to_json(report), indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Tool 2: blast_radius ──────────────────────────────────────────

    @mcp.tool()
    async def blast_radius(cve_id: str) -> str:
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

    # ── Tool 3: policy_check ──────────────────────────────────────────

    @mcp.tool()
    async def policy_check(policy_json: str) -> str:
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

    # ── Tool 4: registry_lookup ───────────────────────────────────────

    @mcp.tool()
    def registry_lookup(
        server_name: Optional[str] = None,
        package_name: Optional[str] = None,
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

    # ── Tool 5: generate_sbom ─────────────────────────────────────────

    @mcp.tool()
    async def generate_sbom(
        format: str = "cyclonedx",
        config_path: Optional[str] = None,
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

    # ── Tool 6: compliance ───────────────────────────────────────────

    @mcp.tool()
    async def compliance(
        config_path: Optional[str] = None,
        image: Optional[str] = None,
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

    # ── Tool 7: remediate ────────────────────────────────────────────

    @mcp.tool()
    async def remediate(
        config_path: Optional[str] = None,
        image: Optional[str] = None,
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

    return mcp
