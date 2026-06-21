from __future__ import annotations

from typing import Any

NSA_MCP_SECURITY_REPORT_URL = "https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf"


def strict_args_tool_count() -> int:
    """Return the number of strict-args MCP tools, derived from the server card.

    Every registered ``@mcp.tool`` is hardened with ``additionalProperties=false``
    and listed in ``_SERVER_CARD_TOOLS``; counting the card keeps the hardening
    surface honest as new tools land (no hand-maintained literal to drift).
    """
    from agent_bom.mcp_server_metadata import _SERVER_CARD_TOOLS

    return len(_SERVER_CARD_TOOLS)


def build_mcp_hardening_catalog() -> dict[str, Any]:
    """Return operator-facing MCP hardening controls and agent-bom evidence.

    This is an implementation mapping for operator review. It is not an NSA
    certification claim.
    """

    controls: list[dict[str, Any]] = [
        {
            "id": "supported_project_inventory",
            "nsa_theme": "Choose supported MCP projects when possible",
            "risk": "Unmaintained or ambiguous MCP packages become trusted runtime dependencies.",
            "agent_bom_surfaces": [
                "registry_lookup",
                "marketplace_check",
                "fleet_scan",
                "intel_sources",
                "mcp registry freshness gate",
            ],
            "operator_action": "Prefer pinned, maintained servers; review package provenance and registry freshness before install.",
            "evidence": ["MCP registry metadata", "package provenance", "freshness status", "security intelligence matches"],
            "status": "covered",
        },
        {
            "id": "explicit_trust_boundaries",
            "nsa_theme": "Design for boundaries",
            "risk": "Agent, model, plugin, user, and data-zone assumptions can blend across MCP calls.",
            "agent_bom_surfaces": [
                "context_graph",
                "exposure_paths",
                "runtime_blueprints",
                "runtime_blueprint_drift",
                "gateway policy",
            ],
            "operator_action": "Group tools by role and data classification; route remote or sensitive traffic through gateway policy.",
            "evidence": ["graph nodes and edges", "blueprint allowed categories", "drift decisions", "gateway relay metrics"],
            "status": "covered",
        },
        {
            "id": "strict_parameter_validation",
            "nsa_theme": "Validate parameters",
            "risk": "Malformed, oversized, or context-confused tool parameters can trigger injection, DoS, or data leakage.",
            "agent_bom_surfaces": [
                f"{strict_args_tool_count()} strict-args MCP tools",
                "MCP wrapper additionalProperties=false",
                "API VALIDATION_ERROR responses",
                "policy_check",
            ],
            "operator_action": "Reject unknown fields, validate ranges and contexts, and keep parameter forwarding explicit.",
            "evidence": ["tools/list schemas", "strict runtime validation", "correlation_id validation errors"],
            "status": "covered",
        },
        {
            "id": "sandbox_tool_execution",
            "nsa_theme": "Constrain and sandbox tool execution",
            "risk": "Compromised MCP tools can move laterally, escalate privileges, or reach unnecessary files and networks.",
            "agent_bom_surfaces": [
                "tool_risk_assessment",
                "runtime proxy",
                "gateway policy",
                "sandbox warnings",
                "Docker and Helm deployment docs",
            ],
            "operator_action": (
                "Run untrusted MCP servers with least privilege, container isolation, and explicit network/file allow-lists."
            ),
            "evidence": ["tool capability classes", "runtime block decisions", "deployment values", "sandbox posture notes"],
            "status": "covered_with_operator_controls",
        },
        {
            "id": "message_integrity_and_replay",
            "nsa_theme": "Sign and verify MCP messages",
            "risk": "Bearer-token or session reuse can permit replay, tampering, or unauthorized reuse of sensitive actions.",
            "agent_bom_surfaces": [
                "audit_integrity",
                "OCSF event relationships",
                "correlation_id",
                "signed posture webhook outbox",
                "Shield admin gates",
            ],
            "operator_action": (
                "Preserve audit-chain signatures, bind events to source-agent identity, and require audited reasons for write actions."
            ),
            "evidence": ["hmac-sha256 chain status", "source_agent labels", "posture outbox status", "Shield write audit events"],
            "status": "covered",
        },
        {
            "id": "output_pipeline_filtering",
            "nsa_theme": "Filter and monitor output pipelines and chained execution",
            "risk": "Tool output can become prompt input downstream and carry hidden instructions or exfiltration pivots.",
            "agent_bom_surfaces": [
                "prompt-injection sentinel rules",
                "runtime_correlate",
                "proxy response inspection",
                "redacted findings views",
            ],
            "operator_action": "Treat every MCP output as untrusted input; inspect, redact, and rate-limit before reuse.",
            "evidence": ["runtime alerts", "redaction mode", "detector findings", "policy decisions"],
            "status": "covered",
        },
        {
            "id": "audit_logging_and_detection",
            "nsa_theme": "Instrument for logging and detection",
            "risk": "Missing traces prevent attribution, incident response, RBAC investigation, and tenant accountability.",
            "agent_bom_surfaces": [
                "runtime_production_index",
                "audit_query",
                "audit_integrity",
                "proxy_alerts",
                "Langfuse OTLP profile",
                "OCSF export",
            ],
            "operator_action": "Export posture events to SIEM/OTLP, keep audit integrity enabled, and alert on anomalous method flows.",
            "evidence": ["production index", "audit chain", "OCSF events", "OTLP traces", "proxy alerts"],
            "status": "covered",
        },
        {
            "id": "vulnerability_tracking",
            "nsa_theme": "Track and patch MCP related vulnerabilities",
            "risk": "New MCP package, framework, and toolchain vulnerabilities can invalidate previously approved deployments.",
            "agent_bom_surfaces": [
                "scan",
                "check",
                "intel_lookup",
                "intel_match",
                "intel_daily_brief",
                "generate_sbom",
            ],
            "operator_action": "Maintain MCP inventory, rescan on advisories, and attach SBOM/SARIF evidence to remediation workflows.",
            "evidence": ["SARIF", "CycloneDX", "SPDX", "daily brief matches", "KEV and EPSS enrichment"],
            "status": "covered",
        },
        {
            "id": "network_discovery",
            "nsa_theme": "Scan local network for open or vulnerable MCP servers",
            "risk": "Unauthorized or unauthenticated MCP services may appear outside approved change control.",
            "agent_bom_surfaces": [
                "where",
                "inventory",
                "fleet_scan",
                "registry_lookup",
                "deployment freshness checks",
            ],
            "operator_action": "Periodically compare approved inventory to discovered local, CI, and fleet MCP configurations.",
            "evidence": ["inventory snapshots", "discovery provenance", "registry matches", "differential reports"],
            "status": "covered_for_config_discovery",
        },
    ]
    return {
        "title": "MCP hardening checklist",
        "schema_version": "mcp.hardening.v1",
        "source": {
            "name": "NSA CSI: Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation",
            "published": "2026-05",
            "url": NSA_MCP_SECURITY_REPORT_URL,
        },
        "claim_boundary": (
            "agent-bom maps NSA MCP security design considerations to product controls and operator evidence. "
            "This is not a certification, endorsement, or compliance attestation."
        ),
        "control_count": len(controls),
        "controls": controls,
        "recommended_outputs": {
            "ci": "SARIF with --fail-on-severity high",
            "automation": "JSON",
            "human_review": "HTML or Markdown",
            "sbom": "CycloneDX or SPDX",
            "runtime": "OCSF events or OTLP traces",
        },
        "runtime_controls": [
            "proxy",
            "gateway",
            "audit chain",
            "rate limit",
            "policy gate",
            "source-agent identity",
            "Shield admin gate",
            "sandbox warning",
        ],
    }
