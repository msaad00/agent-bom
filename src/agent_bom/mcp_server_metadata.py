"""Metadata and route helpers for the agent-bom MCP server."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

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
            "Map scan findings to framework-aware controls:"
            " OWASP LLM/MCP/Agentic, MITRE ATLAS, NIST AI RMF/CSF/800-53, FedRAMP, EU AI Act, ISO 27001, SOC 2, CIS Controls"
        ),
        "annotations": {"readOnlyHint": True},
    },
    {"name": "remediate", "description": "Generate actionable remediation plan", "annotations": {"readOnlyHint": True}},
    {
        "name": "skill_scan",
        "description": "Scan instruction files for packages, MCP servers, trust verdicts, and findings",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "skill_verify",
        "description": "Verify Sigstore provenance for instruction and skill files",
        "annotations": {"readOnlyHint": True},
    },
    {"name": "skill_trust", "description": "ClawHub-style trust assessment for SKILL.md files", "annotations": {"readOnlyHint": True}},
    {
        "name": "verify",
        "description": "Verify package integrity via Sigstore cosign signatures and SLSA provenance attestation",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "where",
        "description": "List all 30 MCP client config discovery paths with existence status — useful for debugging discovery issues",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "tool_risk_assessment",
        "description": "Use live tools/list introspection to score MCP tool capabilities and server risk",
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
        "name": "graph_export",
        "description": "Export dependency graph in graph-native formats (GraphML, Neo4j Cypher, DOT, Mermaid)",
        "annotations": {"readOnlyHint": True},
    },
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


def build_server_card() -> dict[str, Any]:
    from agent_bom import __version__

    return {
        "name": "agent-bom",
        "version": __version__,
        "description": ("Security scanner and graph for AI supply chain and infrastructure — agents, MCP, runtime, and blast radius."),
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


def build_root_metadata(*, auth_required: bool) -> dict[str, Any]:
    from agent_bom import __version__

    return {
        "name": "agent-bom",
        "version": __version__,
        "description": ("Security scanner and graph for AI supply chain and infrastructure — agents, MCP, runtime, and blast radius."),
        "homepage": "https://github.com/msaad00/agent-bom",
        "source": "https://github.com/msaad00/agent-bom",
        "license": "Apache-2.0",
        "pypi": "https://pypi.org/project/agent-bom/",
        "documentation": "https://github.com/msaad00/agent-bom#readme",
        "server_card": "/.well-known/mcp/server-card.json",
        "auth_required": auth_required,
    }


def build_health_payload(*, auth_required: bool, tool_metrics_summary: dict[str, Any]) -> dict[str, Any]:
    from agent_bom import __version__

    return {
        "status": "healthy",
        "name": "agent-bom",
        "version": __version__,
        "auth_required": auth_required,
        "tool_count": tool_metrics_summary["tool_count"],
        "mcp_metrics": tool_metrics_summary,
    }


def attach_metadata_routes(
    mcp: Any,
    *,
    auth_required: bool,
    tool_metrics_snapshot: Callable[[], dict[str, Any]],
) -> None:
    @mcp.custom_route("/.well-known/mcp/server-card.json", methods=["GET"])
    async def server_card_route(request):
        from starlette.responses import JSONResponse

        return JSONResponse(build_server_card())

    @mcp.custom_route("/", methods=["GET"])
    async def root_metadata_route(request):
        from starlette.responses import JSONResponse

        return JSONResponse(build_root_metadata(auth_required=auth_required))

    @mcp.custom_route("/health", methods=["GET"])
    async def health_route(request):
        from starlette.responses import JSONResponse

        metrics = tool_metrics_snapshot()["summary"]
        return JSONResponse(build_health_payload(auth_required=auth_required, tool_metrics_summary=metrics))
