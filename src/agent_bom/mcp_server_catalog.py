from __future__ import annotations

import json
import logging
from typing import Any, Callable


def attach_resources_and_prompts(
    mcp,
    *,
    get_registry_data_raw: Callable[[], str],
    sanitize_error_fn: Callable[[Exception], str],
    logger: logging.Logger,
    tool_metrics_snapshot: Callable[[], dict[str, Any]],
) -> None:
    """Attach the stable MCP resource and prompt catalog."""

    @mcp.resource("registry://servers")
    def registry_servers_resource() -> str:
        """Browse the MCP server security metadata registry (427+ servers).

        Returns the full registry with risk levels (category-derived), tools,
        credential env vars (heuristic-inferred), and verification status
        for every known MCP server.
        """
        try:
            return get_registry_data_raw()
        except Exception as exc:
            logger.exception("Registry read failed")
            return json.dumps({"error": f"Failed to read registry: {sanitize_error_fn(exc)}"})

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
        return json.dumps(tool_metrics_snapshot(), indent=2)

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
