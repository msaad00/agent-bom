"""CLI entry point for agent-bom."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from agent_bom import __version__
from agent_bom.discovery import discover_all
from agent_bom.models import AIBOMReport
from agent_bom.output import (
    export_badge,
    export_cyclonedx,
    export_html,
    export_json,
    export_prometheus,
    export_sarif,
    export_spdx,
    print_agent_tree,
    print_attack_flow_tree,
    print_blast_radius,
    print_compact_agents,
    print_compact_blast_radius,
    print_compact_export_hint,
    print_compact_remediation,
    print_compact_summary,
    print_diff,
    print_export_hint,
    print_policy_results,
    print_posture_summary,
    print_remediation_plan,
    print_severity_chart,
    print_summary,
    print_threat_frameworks,
    push_otlp,
    push_to_gateway,
    to_cyclonedx,
    to_json,
    to_prometheus,
    to_sarif,
    to_spdx,
)
from agent_bom.parsers import extract_packages
from agent_bom.resolver import resolve_all_versions_sync
from agent_bom.scanners import scan_agents_sync
from agent_bom.security import sanitize_env_vars

BANNER = r"""
   ___                    __     ____  ____  __  ___
  / _ | ___ ____ ___  ___/ /_   / __ )/ __ \/  |/  /
 / __ |/ _ `/ -_) _ \/ __/_  / / __  / / / / /|_/ /
/_/ |_/\_, /\__/_//_/\__/ /_/ /____/\____/_/  /_/
      /___/
  AI Bill of Materials for Agents & MCP Servers
"""

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _make_console(quiet: bool = False, output_format: str = "console", no_color: bool = False) -> Console:
    """Create a Console that routes output correctly.

    - quiet mode: suppress all output
    - json/cyclonedx format: route to stderr (keep stdout clean for piping)
    - no_color: disable all ANSI styling (for piping / CI)
    - console format: normal stdout
    """
    if quiet:
        return Console(stderr=True, quiet=True)
    if output_format != "console":
        return Console(stderr=True, no_color=no_color)
    return Console(no_color=no_color)


def _build_agents_from_inventory(inventory_data: dict, source_path: str) -> list:
    """Build Agent objects from parsed inventory dict (JSON or CSV)."""
    from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

    agents = []
    for agent_data in inventory_data.get("agents", []):
        mcp_servers = []
        for server_data in agent_data.get("mcp_servers", []):
            # Parse pre-populated tools (e.g. from Snowflake/cloud inventory)
            tools = []
            for tool_data in server_data.get("tools", []):
                if isinstance(tool_data, str):
                    tools.append(MCPTool(name=tool_data, description=""))
                elif isinstance(tool_data, dict):
                    tools.append(
                        MCPTool(
                            name=tool_data.get("name", ""),
                            description=tool_data.get("description", ""),
                            input_schema=tool_data.get("input_schema"),
                        )
                    )

            # Parse pre-known packages (e.g. from cloud asset scan)
            packages = []
            for pkg_data in server_data.get("packages", []):
                if isinstance(pkg_data, str):
                    if "@" in pkg_data:
                        name, version = pkg_data.rsplit("@", 1)
                    else:
                        name, version = pkg_data, "unknown"
                    packages.append(Package(name=name, version=version, ecosystem="unknown"))
                elif isinstance(pkg_data, dict):
                    packages.append(
                        Package(
                            name=pkg_data.get("name", ""),
                            version=pkg_data.get("version", "unknown"),
                            ecosystem=pkg_data.get("ecosystem", "unknown"),
                            purl=pkg_data.get("purl"),
                        )
                    )

            server = MCPServer(
                name=server_data.get("name", ""),
                command=server_data.get("command", ""),
                args=server_data.get("args", []),
                env=sanitize_env_vars(server_data.get("env", {})),
                transport=TransportType(server_data.get("transport", "stdio")),
                url=server_data.get("url"),
                config_path=agent_data.get("config_path"),
                working_dir=server_data.get("working_dir"),
                mcp_version=server_data.get("mcp_version"),
                tools=tools,
                packages=packages,
            )
            mcp_servers.append(server)

        agent = Agent(
            name=agent_data.get("name", "unknown"),
            agent_type=AgentType(agent_data.get("agent_type", agent_data.get("type", "custom"))),
            config_path=agent_data.get("config_path", source_path),
            mcp_servers=mcp_servers,
            version=agent_data.get("version"),
            source=agent_data.get("source", inventory_data.get("source")),
        )
        agents.append(agent)

    return agents


_update_check_result: str | None = None
_update_check_done = threading.Event()


def _check_for_update_bg() -> None:
    """Background thread: compare __version__ against PyPI latest. Non-blocking."""
    global _update_check_result  # noqa: PLW0603
    try:
        import urllib.request

        cache_dir = Path.home() / ".cache" / "agent-bom"
        cache_file = cache_dir / "update-check.txt"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # Only hit PyPI once per 24 hours
        import time

        if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
            _update_check_result = cache_file.read_text().strip() or None
            _update_check_done.set()
            return

        with urllib.request.urlopen(  # noqa: S310  # nosec B310
            "https://pypi.org/pypi/agent-bom/json", timeout=5
        ) as resp:
            data = json.loads(resp.read())
        latest = data["info"]["version"]

        from packaging.version import Version

        if Version(latest) > Version(__version__):
            msg = (
                f"[yellow]Update available:[/yellow] agent-bom {__version__} → [bold]{latest}[/bold]\n"
                f"  Run: [cyan]pip install --upgrade agent-bom[/cyan]"
            )
        else:
            msg = ""
        cache_file.write_text(msg)
        _update_check_result = msg or None
    except Exception:  # noqa: BLE001
        _update_check_result = None
    finally:
        _update_check_done.set()


def _print_update_notice(console: Console) -> None:
    """Print update notice if a newer version was found (non-blocking)."""
    _update_check_done.wait(timeout=0.1)  # don't block the user
    if _update_check_result:
        console.print()
        console.print(_update_check_result)


def _check_optional_dep(name: str) -> str:
    """Return 'found (vX.Y.Z)' or 'not installed' for an optional binary dep."""
    import shutil
    import subprocess

    path = shutil.which(name)
    if not path:
        return "not installed"
    try:
        result = subprocess.run([path, "version"], capture_output=True, text=True, timeout=3)  # noqa: S603
        ver = (result.stdout or result.stderr).strip().split("\n")[0]
        return f"found ({ver})" if ver else "found"
    except Exception:
        return "found"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    version=__version__,
    prog_name="agent-bom",
    message=(
        f"agent-bom {__version__}\n"
        f"Python {sys.version.split()[0]} · {sys.platform}\n"
        f"Syft:  {_check_optional_dep('syft')}\n"
        f"Grype: {_check_optional_dep('grype')}\n"
        "Docs:  https://github.com/msaad00/agent-bom"
    ),
)
def main():
    """agent-bom — AI Bill of Materials for agents, MCP servers, containers & IaC.

    \b
    Maps the full trust chain: agent → MCP server → packages → CVEs → blast radius.

    \b
    Quick start:
      agent-bom scan                        auto-discover local agents
      agent-bom check lodash@4.17.20        pre-install CVE check
      agent-bom scan --enrich               add NVD CVSS + EPSS + CISA KEV
      agent-bom scan -f html -o report.html --open   HTML dashboard
      agent-bom proxy --command "uvx ..."   runtime enforcement proxy
      agent-bom introspect --all            live server tool listing
      agent-bom api                         start REST API (port 8422)
      agent-bom serve                       API + dashboard (port 8422)

    \b
    Docs:  https://github.com/msaad00/agent-bom
    """
    pass


@main.command()
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan")
@click.option("--config-dir", type=click.Path(exists=True), help="Custom agent config directory to scan")
@click.option("--inventory", type=str, default=None, help="Inventory file (JSON or CSV). Use '-' for stdin.")
@click.option("--output", "-o", type=str, help="Output file path (use '-' for stdout)")
@click.option(
    "--open", "open_report", is_flag=True, default=False, help="Auto-open HTML/graph-html report in default browser after generation"
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(
        ["console", "json", "cyclonedx", "sarif", "spdx", "text", "html", "prometheus", "graph", "graph-html", "mermaid", "svg", "badge"]
    ),
    default="console",
    help="Output format",
)
@click.option(
    "--mermaid-mode",
    type=click.Choice(["supply-chain", "attack-flow", "lifecycle"]),
    default="supply-chain",
    help="Mermaid diagram mode: supply-chain (full hierarchy), attack-flow (CVE blast radius), or lifecycle (gantt timeline)",
)
@click.option(
    "--push-gateway",
    "push_gateway",
    default=None,
    metavar="URL",
    help="Prometheus Pushgateway URL to push metrics after scan (e.g. http://localhost:9091)",
)
@click.option(
    "--otel-endpoint",
    "otel_endpoint",
    default=None,
    metavar="URL",
    help="OpenTelemetry OTLP/HTTP collector endpoint (e.g. http://localhost:4318). Requires pip install 'agent-bom[otel]'",
)
@click.option("--dry-run", is_flag=True, help="Show what files and APIs would be accessed without scanning, then exit 0")
@click.option("--no-scan", is_flag=True, help="Skip vulnerability scanning (inventory only)")
@click.option("--no-tree", is_flag=True, help="Skip dependency tree output")
@click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages")
@click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution")
@click.option(
    "--deps-dev", "deps_dev", is_flag=True, help="Use deps.dev for transitive dependency resolution and license enrichment (all ecosystems)"
)
@click.option(
    "--license-check",
    "license_check",
    is_flag=True,
    help="Evaluate package licenses against compliance policy (block GPL/AGPL, warn copyleft)",
)
@click.option(
    "--vex",
    "vex_path",
    type=click.Path(exists=True),
    default=None,
    metavar="PATH",
    help="Apply a VEX document (OpenVEX JSON) to suppress resolved vulnerabilities",
)
@click.option(
    "--generate-vex",
    "generate_vex_flag",
    is_flag=True,
    help="Auto-generate a VEX document from scan results (KEV → affected, rest → under_investigation)",
)
@click.option(
    "--vex-output",
    "vex_output_path",
    type=str,
    default=None,
    metavar="PATH",
    help="Write generated VEX document to this file (default: agent-bom.vex.json)",
)
@click.option("--enrich", is_flag=True, help="Enrich vulnerabilities with NVD, EPSS, and CISA KEV data")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", help="NVD API key for higher rate limits")
@click.option("--scorecard", "scorecard_flag", is_flag=True, help="Enrich packages with OpenSSF Scorecard scores")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results (for scripting)")
@click.option(
    "--fail-on-severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit 1 if vulnerabilities of this severity or higher are found",
)
@click.option("--fail-on-kev", is_flag=True, help="Exit 1 if any finding appears in CISA KEV (must use --enrich)")
@click.option("--fail-if-ai-risk", is_flag=True, help="Exit 1 if an AI framework package with credentials has vulnerabilities")
@click.option("--save", "save_report", is_flag=True, help="Save this scan to ~/.agent-bom/history/ for future diffing")
@click.option("--baseline", type=click.Path(exists=True), help="Path to a baseline report JSON to diff against current scan")
@click.option("--policy", type=click.Path(exists=True), help="Policy file (JSON/YAML) with declarative security rules")
@click.option(
    "--sbom", "sbom_file", type=click.Path(exists=True), help="Existing SBOM file to ingest (CycloneDX or SPDX JSON from Syft/Grype/Trivy)"
)
@click.option(
    "--sbom-name",
    "sbom_name",
    default=None,
    metavar="NAME",
    help="Label for the SBOM resource (e.g. 'prod-api-01', 'nginx:1.25'). Auto-detected from SBOM metadata if omitted.",
)
@click.option(
    "--image", "images", multiple=True, metavar="IMAGE", help="Docker image to scan (e.g. nginx:1.25). Repeatable for multiple images."
)
@click.option(
    "--image-tar",
    "image_tars",
    multiple=True,
    metavar="TAR",
    help="OCI image tarball to scan without Docker/Syft/Grype (e.g. image.tar from 'docker save'). Repeatable.",
)
@click.option("--k8s", is_flag=True, help="Discover container images from a Kubernetes cluster via kubectl")
@click.option("--namespace", default="default", show_default=True, help="Kubernetes namespace (used with --k8s)")
@click.option("--all-namespaces", "-A", is_flag=True, help="Scan all Kubernetes namespaces (used with --k8s)")
@click.option("--context", "k8s_context", default=None, help="kubectl context to use (used with --k8s)")
@click.option("--registry-user", default=None, envvar="AGENT_BOM_REGISTRY_USER", help="Registry username for private image scanning")
@click.option("--registry-pass", default=None, envvar="AGENT_BOM_REGISTRY_PASS", help="Registry password for private image scanning")
@click.option("--platform", "image_platform", default=None, help="Image platform for multi-arch manifests (e.g. linux/amd64, linux/arm64)")
@click.option(
    "--tf-dir",
    "tf_dirs",
    multiple=True,
    type=click.Path(exists=True),
    metavar="DIR",
    help="Terraform directory to scan for AI resources, providers, and hardcoded secrets. Repeatable.",
)
@click.option(
    "--gha",
    "gha_path",
    type=click.Path(exists=True),
    metavar="REPO",
    help="Repository root to scan GitHub Actions workflows for AI usage and credential exposure.",
)
@click.option(
    "--agent-project",
    "agent_projects",
    multiple=True,
    type=click.Path(exists=True),
    metavar="DIR",
    help="Python project using an agent framework (OpenAI Agents SDK, Google ADK, LangChain, AutoGen, "
    "CrewAI, LlamaIndex, Pydantic AI, smolagents, Semantic Kernel, Haystack). Repeatable.",
)
@click.option(
    "--skill",
    "skill_paths",
    multiple=True,
    type=click.Path(exists=True),
    metavar="PATH",
    help="Skill/instruction file to scan (CLAUDE.md, .cursorrules, skill.md). "
    "Extracts MCP server refs, packages, and credential env vars. Repeatable.",
)
@click.option("--no-skill", is_flag=True, help="Skip all skill/instruction file scanning (auto-discovery + explicit --skill paths)")
@click.option("--skill-only", is_flag=True, help="Scan ONLY skill/instruction files; skip agent/package/CVE scanning")
@click.option("--scan-prompts", is_flag=True, help="Scan prompt template files (.prompt, system_prompt.*, prompts/) for security risks")
@click.option(
    "--browser-extensions",
    "browser_extensions",
    is_flag=True,
    help="Scan installed browser extensions (Chrome, Brave, Edge, Firefox) for dangerous permissions "
    "that could expose AI assistant sessions or MCP tool calls.",
)
@click.option(
    "--jupyter",
    "jupyter_dirs",
    multiple=True,
    type=click.Path(exists=True),
    metavar="DIR",
    help="Scan Jupyter notebooks (.ipynb) for AI library imports, model references, and credentials. Repeatable.",
)
@click.option(
    "--model-files",
    "model_dirs",
    multiple=True,
    type=click.Path(exists=True),
    metavar="DIR",
    help="Scan for ML model binary files (.gguf, .safetensors, .onnx, .pt, .pkl, etc.). Repeatable.",
)
@click.option("--model-provenance", is_flag=True, help="Enable SHA-256 hash and Sigstore signature checks for --model-files scans")
@click.option(
    "--dataset-cards",
    "dataset_dirs",
    multiple=True,
    type=click.Path(exists=True),
    metavar="DIR",
    help="Scan for dataset cards (dataset_info.json, README.md frontmatter, .dvc files). Repeatable.",
)
@click.option(
    "--training-pipelines",
    "training_dirs",
    multiple=True,
    type=click.Path(exists=True),
    metavar="DIR",
    help="Scan for ML training pipeline metadata (MLflow runs, Kubeflow pipelines, W&B logs). Repeatable.",
)
@click.option(
    "--hf-model",
    "hf_models",
    multiple=True,
    metavar="NAME",
    help="Check HuggingFace model provenance (org/model format, e.g. meta-llama/Llama-3.1-8B). Repeatable.",
)
@click.option(
    "--introspect", is_flag=True, help="Connect to live MCP servers to discover runtime tools/resources (read-only, requires mcp SDK)"
)
@click.option("--introspect-timeout", type=float, default=10.0, show_default=True, help="Timeout per MCP server for --introspect (seconds)")
@click.option(
    "--enforce",
    is_flag=True,
    help="Run tool poisoning detection and enforcement checks (description injection, capability combos, CVE exposure, drift)",
)
@click.option("--verify-integrity", is_flag=True, help="Verify package integrity (SHA256/SRI) and SLSA provenance against registries")
@click.option(
    "--verify-instructions",
    is_flag=True,
    help="Verify instruction file provenance (CLAUDE.md, .cursorrules, SKILL.md) via Sigstore bundles",
)
@click.option("--context-graph", "context_graph_flag", is_flag=True, help="Compute agent context graph with lateral movement analysis")
@click.option(
    "--graph-backend",
    "graph_backend",
    type=click.Choice(["auto", "memory", "networkx"]),
    default="auto",
    show_default=True,
    help="Graph backend for context graph analysis (auto tries networkx, falls back to memory)",
)
@click.option(
    "--dynamic-discovery",
    is_flag=True,
    help="Enable dynamic content-based MCP config discovery beyond known clients",
)
@click.option(
    "--dynamic-max-depth",
    type=int,
    default=4,
    show_default=True,
    help="Max directory depth for dynamic discovery filesystem scanning",
)
@click.option(
    "--include-processes",
    is_flag=True,
    help="Scan running host processes for MCP servers (requires psutil: pip install psutil)",
)
@click.option(
    "--include-containers",
    is_flag=True,
    help="Scan running Docker containers for MCP servers (requires docker CLI on PATH)",
)
@click.option(
    "--k8s-mcp",
    "k8s_mcp",
    is_flag=True,
    help="Scan Kubernetes cluster for MCP pods, services, and CRDs (requires kubectl on PATH)",
)
@click.option("--k8s-namespace", default="default", show_default=True, help="Kubernetes namespace for --k8s-mcp")
@click.option(
    "--k8s-all-namespaces",
    "k8s_all_namespaces",
    is_flag=True,
    help="Scan all Kubernetes namespaces for --k8s-mcp",
)
@click.option("--k8s-context", "k8s_mcp_context", default=None, help="kubectl context for --k8s-mcp (uses current context if omitted)")
@click.option(
    "--health-check",
    "health_check",
    is_flag=True,
    help="Probe discovered MCP servers for liveness (reachability + tool count, requires mcp SDK)",
)
@click.option(
    "--hc-timeout",
    type=float,
    default=5.0,
    show_default=True,
    help="Timeout per server for --health-check (seconds)",
)
@click.option(
    "--ai-enrich",
    is_flag=True,
    help="Enrich findings with LLM-generated risk narratives, executive summary, and threat chains. Auto-detects Ollama (free, local) or uses litellm (pip install 'agent-bom[ai-enrich]')",
)
@click.option(
    "--ai-model",
    default="openai/gpt-4o-mini",
    show_default=True,
    metavar="MODEL",
    help="LLM model for --ai-enrich. Auto-detects Ollama if running. Examples: ollama/llama3.2 (free, local), ollama/mistral, openai/gpt-4o-mini",
)
@click.option(
    "--remediate",
    "remediate_path",
    type=str,
    default=None,
    metavar="PATH",
    help="Generate remediation.md with fix commands for all findings",
)
@click.option(
    "--remediate-sh",
    "remediate_sh_path",
    type=str,
    default=None,
    metavar="PATH",
    help="Generate remediation.sh script with package upgrade commands",
)
@click.option(
    "--apply",
    "apply_fixes_flag",
    is_flag=True,
    help="Auto-apply package version fixes to dependency files (package.json, requirements.txt)",
)
@click.option("--apply-dry-run", is_flag=True, help="Preview what --apply would change without modifying files")
@click.option(
    "--code",
    "code_paths",
    multiple=True,
    type=click.Path(exists=True),
    metavar="PATH",
    help="Source code directory to scan for security flaws via Semgrep (SAST). Repeatable.",
)
@click.option(
    "--sast-config",
    default="auto",
    show_default=True,
    metavar="CONFIG",
    help="Semgrep config for --code scans (e.g. 'p/security-audit'). Default: auto.",
)
@click.option(
    "--filesystem",
    "filesystem_paths",
    multiple=True,
    type=click.Path(exists=True),
    metavar="PATH",
    help="Filesystem directory or tar archive to scan for packages via Syft (e.g. mounted VM disk snapshot). Repeatable.",
)
@click.option("--aws", is_flag=True, help="Discover AI agents from AWS Bedrock, Lambda, and ECS")
@click.option("--aws-region", default=None, metavar="REGION", help="AWS region (default: AWS_DEFAULT_REGION)")
@click.option("--aws-profile", default=None, metavar="PROFILE", help="AWS credential profile")
@click.option("--azure", "azure_flag", is_flag=True, help="Discover agents from Azure AI Foundry and Container Apps")
@click.option("--azure-subscription", default=None, metavar="ID", envvar="AZURE_SUBSCRIPTION_ID", help="Azure subscription ID")
@click.option("--gcp", "gcp_flag", is_flag=True, help="Discover agents from Google Cloud Vertex AI and Cloud Run")
@click.option("--gcp-project", default=None, metavar="PROJECT", envvar="GOOGLE_CLOUD_PROJECT", help="GCP project ID")
@click.option(
    "--coreweave", "coreweave_flag", is_flag=True, help="Discover GPU VMs, NVIDIA NIM inference, and InfiniBand training from CoreWeave"
)
@click.option("--coreweave-context", default=None, metavar="CTX", help="kubectl context for CoreWeave cluster")
@click.option("--coreweave-namespace", default=None, metavar="NS", help="Limit CoreWeave discovery to a namespace")
@click.option("--databricks", "databricks_flag", is_flag=True, help="Discover agents from Databricks clusters and model serving")
@click.option("--snowflake", "snowflake_flag", is_flag=True, help="Discover Cortex agents and Snowpark apps from Snowflake")
@click.option(
    "--snowflake-authenticator",
    default=None,
    envvar="SNOWFLAKE_AUTHENTICATOR",
    metavar="METHOD",
    help="Snowflake auth method: externalbrowser (SSO, default), snowflake_jwt (key-pair), oauth. No passwords stored.",
)
@click.option("--cortex-observability", is_flag=True, help="Include Cortex agent observability telemetry (requires --snowflake)")
@click.option("--nebius", "nebius_flag", is_flag=True, help="Discover AI workloads from Nebius GPU cloud")
@click.option("--nebius-api-key", default=None, envvar="NEBIUS_API_KEY", metavar="KEY", help="Nebius API key")
@click.option("--nebius-project-id", default=None, envvar="NEBIUS_PROJECT_ID", metavar="ID", help="Nebius project ID")
@click.option("--aws-include-lambda", is_flag=True, help="Discover standalone Lambda functions (used with --aws)")
@click.option("--aws-include-eks", is_flag=True, help="Discover EKS cluster workloads via kubectl (used with --aws)")
@click.option("--aws-include-step-functions", is_flag=True, help="Discover Step Functions workflows (used with --aws)")
@click.option("--aws-include-ec2", is_flag=True, help="Discover EC2 instances by tag (used with --aws)")
@click.option("--aws-ec2-tag", default=None, metavar="KEY=VALUE", help="EC2 tag filter for --aws-include-ec2 (e.g. 'Environment=ai-prod')")
@click.option("--aws-cis-benchmark", is_flag=True, help="Run CIS AWS Foundations Benchmark v3.0 checks (used with --aws)")
@click.option("--snowflake-cis-benchmark", is_flag=True, help="Run CIS Snowflake Benchmark v1.0 checks (used with --snowflake)")
@click.option("--azure-cis-benchmark", is_flag=True, help="Run CIS Azure Security Benchmark v3.0 checks (requires AZURE_SUBSCRIPTION_ID)")
@click.option("--gcp-cis-benchmark", is_flag=True, help="Run CIS GCP Foundation Benchmark v3.0 checks (requires GOOGLE_CLOUD_PROJECT)")
@click.option("--databricks-security", is_flag=True, help="Run Databricks Security Best Practices checks (used with --databricks)")
@click.option(
    "--aisvs", "aisvs_flag", is_flag=True, help="Run AISVS v1.0 compliance checks (model safety, vector store auth, inference exposure)"
)
@click.option(
    "--vector-db-scan",
    "vector_db_scan",
    is_flag=True,
    help="Scan for running vector databases (Qdrant, Weaviate, Chroma, Milvus) and assess security",
)
@click.option(
    "--gpu-scan",
    "gpu_scan_flag",
    is_flag=True,
    help="Discover GPU-enabled containers and K8s nodes (NVIDIA base images, CUDA versions, DCGM endpoints). Requires docker/kubectl on PATH.",
)
@click.option("--gpu-k8s-context", "gpu_k8s_context", default=None, metavar="CTX", help="kubectl context for --gpu-scan K8s node discovery")
@click.option("--no-dcgm-probe", "no_dcgm_probe", is_flag=True, help="Skip DCGM exporter endpoint probing during --gpu-scan")
@click.option("--huggingface", "hf_flag", is_flag=True, help="Discover models, Spaces, and endpoints from Hugging Face Hub")
@click.option(
    "--verify-model-hashes",
    "verify_model_hashes",
    is_flag=True,
    help="Verify SHA-256 of local model weight files against HuggingFace Hub metadata",
)
@click.option("--hf-token", default=None, envvar="HF_TOKEN", metavar="TOKEN", help="Hugging Face API token")
@click.option("--hf-username", default=None, metavar="USER", help="Hugging Face username to scope discovery")
@click.option("--hf-organization", default=None, metavar="ORG", help="Hugging Face organization to scope discovery")
@click.option("--wandb", "wandb_flag", is_flag=True, help="Discover runs and artifacts from Weights & Biases")
@click.option("--wandb-api-key", default=None, envvar="WANDB_API_KEY", metavar="KEY", help="W&B API key")
@click.option("--wandb-entity", default=None, envvar="WANDB_ENTITY", metavar="ENTITY", help="W&B entity (team or user)")
@click.option("--wandb-project", default=None, metavar="PROJECT", help="W&B project name")
@click.option("--mlflow", "mlflow_flag", is_flag=True, help="Discover models and experiments from MLflow")
@click.option("--mlflow-tracking-uri", default=None, envvar="MLFLOW_TRACKING_URI", metavar="URI", help="MLflow tracking server URI")
@click.option("--openai", "openai_flag", is_flag=True, help="Discover assistants and fine-tuned models from OpenAI")
@click.option("--openai-api-key", default=None, envvar="OPENAI_API_KEY", metavar="KEY", help="OpenAI API key")
@click.option("--openai-org-id", default=None, envvar="OPENAI_ORG_ID", metavar="ORG", help="OpenAI organization ID")
@click.option("--ollama", "ollama_flag", is_flag=True, help="Discover locally downloaded Ollama models")
@click.option("--ollama-host", default=None, envvar="OLLAMA_HOST", metavar="URL", help="Ollama API host (default: http://localhost:11434)")
@click.option(
    "--smithery",
    "smithery_flag",
    is_flag=True,
    help="Use Smithery.ai registry as fallback for unknown MCP servers (extends coverage from 112 to 2800+ servers)",
)
@click.option(
    "--smithery-token", default=None, envvar="SMITHERY_API_KEY", metavar="KEY", help="Smithery API key (or set SMITHERY_API_KEY env var)"
)
@click.option(
    "--mcp-registry",
    "mcp_registry_flag",
    is_flag=True,
    help="Use Official MCP Registry as fallback for unknown MCP servers (free, no auth)",
)
@click.option("--snyk", "snyk_flag", is_flag=True, help="Enrich vulnerabilities with Snyk intelligence (requires SNYK_TOKEN)")
@click.option("--snyk-token", default=None, envvar="SNYK_TOKEN", metavar="KEY", help="Snyk API token (or set SNYK_TOKEN env var)")
@click.option("--snyk-org", default=None, envvar="SNYK_ORG_ID", metavar="ORG", help="Snyk organization ID (or set SNYK_ORG_ID env var)")
@click.option(
    "--jira-url",
    default=None,
    envvar="JIRA_URL",
    metavar="URL",
    help="Jira base URL for ticket creation (e.g. https://company.atlassian.net)",
)
@click.option("--jira-user", default=None, envvar="JIRA_USER", metavar="EMAIL", help="Jira user email (or set JIRA_USER env var)")
@click.option("--jira-token", default=None, envvar="JIRA_API_TOKEN", metavar="TOKEN", help="Jira API token (or set JIRA_API_TOKEN env var)")
@click.option("--jira-project", default=None, envvar="JIRA_PROJECT", metavar="KEY", help="Jira project key (e.g. SEC)")
@click.option("--slack-webhook", default=None, envvar="SLACK_WEBHOOK_URL", metavar="URL", help="Slack incoming webhook URL for scan alerts")
@click.option("--jira-discover", is_flag=True, help="Discover AI agents from Jira automation rules and installed apps")
@click.option("--servicenow", "servicenow_flag", is_flag=True, help="Discover AI agents from ServiceNow Flow Designer and IntegrationHub")
@click.option("--servicenow-instance", default=None, envvar="SERVICENOW_INSTANCE", metavar="URL", help="ServiceNow instance URL")
@click.option("--servicenow-user", default=None, envvar="SERVICENOW_USER", metavar="USER", help="ServiceNow username")
@click.option("--servicenow-password", default=None, envvar="SERVICENOW_PASSWORD", metavar="PWD", help="ServiceNow password")
@click.option("--slack-discover", is_flag=True, help="Discover installed Slack apps and bots in workspace")
@click.option("--slack-bot-token", default=None, envvar="SLACK_BOT_TOKEN", metavar="TOKEN", help="Slack bot token for app discovery")
@click.option("--push-url", default=None, envvar="AGENT_BOM_PUSH_URL", metavar="URL", help="Push scan results to central dashboard URL")
@click.option("--push-api-key", default=None, envvar="AGENT_BOM_PUSH_API_KEY", metavar="KEY", help="API key for push authentication")
@click.option(
    "--vanta-token", default=None, envvar="VANTA_API_TOKEN", metavar="TOKEN", help="Vanta API token for compliance evidence upload"
)
@click.option("--drata-token", default=None, envvar="DRATA_API_TOKEN", metavar="TOKEN", help="Drata API token for GRC evidence upload")
@click.option(
    "--siem",
    "siem_type",
    default=None,
    envvar="AGENT_BOM_SIEM_TYPE",
    type=click.Choice(["splunk", "datadog", "elasticsearch", "opensearch"], case_sensitive=False),
    metavar="TYPE",
    help="Push findings to SIEM: splunk | datadog | elasticsearch | opensearch",
)
@click.option(
    "--siem-url", default=None, envvar="AGENT_BOM_SIEM_URL", metavar="URL", help="SIEM endpoint URL (e.g. https://splunk.corp:8088)"
)
@click.option("--siem-token", default=None, envvar="AGENT_BOM_SIEM_TOKEN", metavar="TOKEN", help="SIEM authentication token / API key")
@click.option(
    "--siem-index",
    default=None,
    envvar="AGENT_BOM_SIEM_INDEX",
    metavar="INDEX",
    help="SIEM index / sourcetype (e.g. main, agent-bom-alerts)",
)
@click.option(
    "--siem-format",
    default="ocsf",
    envvar="AGENT_BOM_SIEM_FORMAT",
    type=click.Choice(["raw", "ocsf"], case_sensitive=False),
    show_default=True,
    help="Event format for SIEM push: ocsf (default) or raw",
)
@click.option(
    "--clickhouse-url",
    default=None,
    envvar="AGENT_BOM_CLICKHOUSE_URL",
    metavar="URL",
    help="ClickHouse HTTP URL for analytics (e.g. http://localhost:8123)",
)
@click.option(
    "--verbose", "-v", is_flag=True, help="Full output — dependency tree, all findings, severity chart, threat frameworks, debug logging"
)
@click.option(
    "--log-level",
    "log_level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default=None,
    help="Set log level (overrides --verbose). Env: AGENT_BOM_LOG_LEVEL",
)
@click.option("--log-json", "log_json", is_flag=True, help="Emit structured JSON logs to stderr (for SIEM ingestion)")
@click.option("--log-file", "log_file", type=click.Path(), default=None, help="Write JSON logs to file")
@click.option("--no-color", is_flag=True, help="Disable colored output (useful for piping, CI logs, accessibility)")
@click.option(
    "--preset",
    type=click.Choice(["ci", "enterprise", "quick"]),
    default=None,
    help="Scan preset: ci (quiet, json, fail-on-critical), enterprise (enrich, introspect, transitive, verify-integrity, verify-instructions), quick (no transitive, no enrich)",
)
@click.option(
    "--compliance-export",
    "compliance_export",
    type=click.Choice(["cmmc", "fedramp", "nist-ai-rmf"]),
    default=None,
    help="Export compliance evidence bundle (ZIP) for CMMC, FedRAMP, or NIST AI RMF audits",
)
@click.option(
    "--self-scan", "self_scan", is_flag=True, default=False, help="Scan agent-bom's own installed dependencies for vulnerabilities."
)
@click.option("--demo", is_flag=True, default=False, help="Run a demo scan with bundled inventory containing known-vulnerable packages.")
@click.option(
    "--correlate",
    "correlate_log",
    type=click.Path(exists=True),
    default=None,
    metavar="AUDIT_LOG",
    help="Cross-reference scan results with proxy audit log (JSONL) to identify which vulnerable tools were actually called.",
)
def scan(
    project: Optional[str],
    config_dir: Optional[str],
    inventory: Optional[str],
    output: Optional[str],
    output_format: str,
    dry_run: bool,
    no_scan: bool,
    no_tree: bool,
    transitive: bool,
    max_depth: int,
    deps_dev: bool,
    license_check: bool,
    vex_path: Optional[str],
    generate_vex_flag: bool,
    vex_output_path: Optional[str],
    enrich: bool,
    nvd_api_key: Optional[str],
    scorecard_flag: bool,
    quiet: bool,
    fail_on_severity: Optional[str],
    fail_on_kev: bool,
    fail_if_ai_risk: bool,
    save_report: bool,
    baseline: Optional[str],
    policy: Optional[str],
    sbom_file: Optional[str],
    sbom_name: Optional[str],
    images: tuple,
    image_tars: tuple,
    k8s: bool,
    namespace: str,
    all_namespaces: bool,
    k8s_context: Optional[str],
    registry_user: Optional[str],
    registry_pass: Optional[str],
    image_platform: Optional[str],
    mermaid_mode: str,
    push_gateway: Optional[str],
    otel_endpoint: Optional[str],
    tf_dirs: tuple,
    gha_path: Optional[str],
    agent_projects: tuple,
    skill_paths: tuple,
    no_skill: bool,
    skill_only: bool,
    scan_prompts: bool,
    browser_extensions: bool,
    jupyter_dirs: tuple,
    model_dirs: tuple,
    model_provenance: bool,
    dataset_dirs: tuple,
    training_dirs: tuple,
    hf_models: tuple,
    introspect: bool,
    introspect_timeout: float,
    enforce: bool,
    verify_integrity: bool,
    verify_instructions: bool,
    context_graph_flag: bool,
    graph_backend: str,
    dynamic_discovery: bool,
    dynamic_max_depth: int,
    include_processes: bool,
    include_containers: bool,
    k8s_mcp: bool,
    k8s_namespace: str,
    k8s_all_namespaces: bool,
    k8s_mcp_context: Optional[str],
    health_check: bool,
    hc_timeout: float,
    ai_enrich: bool,
    ai_model: str,
    aws: bool,
    aws_region: Optional[str],
    aws_profile: Optional[str],
    azure_flag: bool,
    azure_subscription: Optional[str],
    gcp_flag: bool,
    gcp_project: Optional[str],
    coreweave_flag: bool,
    coreweave_context: Optional[str],
    coreweave_namespace: Optional[str],
    databricks_flag: bool,
    snowflake_flag: bool,
    snowflake_authenticator: str | None,
    cortex_observability: bool,
    nebius_flag: bool,
    nebius_api_key: Optional[str],
    nebius_project_id: Optional[str],
    aws_include_lambda: bool,
    aws_include_eks: bool,
    aws_include_step_functions: bool,
    aws_include_ec2: bool,
    aws_ec2_tag: Optional[str],
    aws_cis_benchmark: bool,
    snowflake_cis_benchmark: bool,
    azure_cis_benchmark: bool,
    gcp_cis_benchmark: bool,
    databricks_security: bool,
    aisvs_flag: bool,
    vector_db_scan: bool,
    gpu_scan_flag: bool,
    gpu_k8s_context: Optional[str],
    no_dcgm_probe: bool,
    hf_flag: bool,
    verify_model_hashes: bool,
    hf_token: Optional[str],
    hf_username: Optional[str],
    hf_organization: Optional[str],
    wandb_flag: bool,
    wandb_api_key: Optional[str],
    wandb_entity: Optional[str],
    wandb_project: Optional[str],
    mlflow_flag: bool,
    mlflow_tracking_uri: Optional[str],
    openai_flag: bool,
    openai_api_key: Optional[str],
    openai_org_id: Optional[str],
    ollama_flag: bool,
    ollama_host: Optional[str],
    smithery_flag: bool,
    smithery_token: Optional[str],
    mcp_registry_flag: bool,
    snyk_flag: bool,
    snyk_token: Optional[str],
    snyk_org: Optional[str],
    remediate_path: Optional[str],
    remediate_sh_path: Optional[str],
    apply_fixes_flag: bool,
    apply_dry_run: bool,
    code_paths: tuple,
    sast_config: str,
    filesystem_paths: tuple,
    jira_url: Optional[str],
    jira_user: Optional[str],
    jira_token: Optional[str],
    jira_project: Optional[str],
    slack_webhook: Optional[str],
    jira_discover: bool,
    servicenow_flag: bool,
    servicenow_instance: Optional[str],
    servicenow_user: Optional[str],
    servicenow_password: Optional[str],
    slack_discover: bool,
    slack_bot_token: Optional[str],
    push_url: Optional[str],
    push_api_key: Optional[str],
    vanta_token: Optional[str],
    drata_token: Optional[str],
    siem_type: Optional[str],
    siem_url: Optional[str],
    siem_token: Optional[str],
    siem_index: Optional[str],
    siem_format: str,
    clickhouse_url: Optional[str],
    verbose: bool,
    log_level: Optional[str],
    log_json: bool,
    log_file: Optional[str],
    no_color: bool,
    preset: Optional[str],
    open_report: bool,
    compliance_export: Optional[str],
    self_scan: bool,
    demo: bool,
    correlate_log: Optional[str],
):
    """Discover agents, extract dependencies, scan for vulnerabilities.

    \b
    Exit codes:
      0  Clean — no violations, no vulnerabilities at or above threshold
      1  Fail — policy failure, or vulnerabilities found at or above
                --fail-on-severity / --fail-on-kev / --fail-if-ai-risk
    """
    import time as _time

    from agent_bom.logging_config import setup_logging
    from agent_bom.project_config import (
        get_fail_on_severity,
        get_policy_path,
        load_project_config,
    )

    _scan_start = _time.monotonic()

    # Configure logging — explicit --log-level overrides --verbose
    _log_level = log_level or ("DEBUG" if verbose else "WARNING")
    setup_logging(level=_log_level, json_output=log_json, log_file=log_file)

    # Load .agent-bom.yaml project config — CLI flags always win
    _proj_cfg = load_project_config()
    if _proj_cfg:
        if not fail_on_severity:
            fail_on_severity = get_fail_on_severity(_proj_cfg)
        if not enrich and _proj_cfg.get("enrich"):
            enrich = True
        if not transitive and _proj_cfg.get("transitive"):
            transitive = True
        if not fail_on_kev and _proj_cfg.get("fail_on_kev"):
            fail_on_kev = True
        if not policy and (cfg_policy := get_policy_path(_proj_cfg)):
            policy = str(cfg_policy)

    # Apply presets (override defaults, don't override explicit flags)
    if preset == "ci":
        quiet = True
        output_format = output_format if output_format != "console" else "json"
        fail_on_severity = fail_on_severity or "critical"
    elif preset == "enterprise":
        enrich = True
        introspect = True
        transitive = True
        deps_dev = True
        license_check = True
        verify_integrity = True
        verify_instructions = True
        dynamic_discovery = True
        context_graph_flag = True
    elif preset == "quick":
        transitive = False
        enrich = False

    # ── Self-scan mode: scan agent-bom's own installed dependencies ──
    if self_scan:
        import importlib.metadata as _meta
        import json as _json
        import os as _os
        import tempfile as _tempfile

        _pkgs = []
        try:
            _dist = _meta.distribution("agent-bom")
            for _req_str in _dist.requires or []:
                _name = _req_str.split(";")[0].split("[")[0].strip()
                for _op in (">=", "<=", "==", "!=", "~=", ">", "<"):
                    if _op in _name:
                        _name = _name[: _name.index(_op)].strip()
                        break
                if not _name:
                    continue
                try:
                    _ver = _meta.version(_name)
                except _meta.PackageNotFoundError:
                    continue
                _pkgs.append({"name": _name, "version": _ver, "ecosystem": "pypi"})
        except _meta.PackageNotFoundError:
            click.echo("Error: agent-bom package not found. Install it first.", err=True)
            sys.exit(2)

        _self_inventory = {
            "agents": [
                {
                    "name": "agent-bom",
                    "agent_type": "custom",
                    "source": "agent-bom --self-scan",
                    "mcp_servers": [
                        {
                            "name": "agent-bom-mcp-server",
                            "command": "agent-bom mcp-server",
                            "transport": "stdio",
                            "packages": _pkgs,
                        }
                    ],
                }
            ]
        }
        _sf_fd, _sf_path = _tempfile.mkstemp(suffix=".json", prefix="agent-bom-self-scan-")
        with _os.fdopen(_sf_fd, "w") as _sf:
            _json.dump(_self_inventory, _sf)
        inventory = _sf_path
        enrich = True

    # ── Demo mode: load bundled inventory with known-vulnerable packages ──
    if demo:
        import json as _json
        import os as _os
        import tempfile as _tempfile

        from agent_bom.demo import DEMO_INVENTORY

        _demo_fd, _demo_path = _tempfile.mkstemp(suffix=".json", prefix="agent-bom-demo-")
        with _os.fdopen(_demo_fd, "w") as _df:
            _json.dump(DEMO_INVENTORY, _df)
        inventory = _demo_path
        enrich = True

    # Mutual exclusivity: --no-skill and --skill-only cannot be used together
    if no_skill and skill_only:
        click.echo("Error: --no-skill and --skill-only are mutually exclusive.", err=True)
        sys.exit(2)

    # Route console output based on flags
    is_stdout = output == "-"
    con = _make_console(quiet=quiet or is_stdout, output_format=output_format, no_color=no_color)

    # Also set the output module's console so print_summary etc. route correctly
    import agent_bom.output as _out

    _out.console = con

    con.print(BANNER, style="bold blue")

    if demo:
        con.print("\n[bold yellow]Demo mode[/bold yellow] — scanning bundled inventory with known-vulnerable packages.\n")

    # ── Dry-run: show access plan without scanning ────────────────────────────
    if dry_run:
        con.print("\n[bold cyan]🔍 Dry-run — access plan (no files read, no queries made)[/bold cyan]\n")
        reads = []
        if inventory:
            reads.append(f"  [green]Would read:[/green]   {inventory}")
        if project:
            reads.append(f"  [green]Would read:[/green]   {project}  (agent configs)")
        if config_dir:
            reads.append(f"  [green]Would read:[/green]   {config_dir}  (config directory)")
        if not reads:
            from agent_bom.discovery import get_all_discovery_paths

            for client, path in get_all_discovery_paths():
                reads.append(f"  [green]Would read:[/green]   {path}  ({client})")
        for cp in code_paths:
            reads.append(f"  [green]Would scan:[/green]   {cp}  (SAST via semgrep)")
        for tf_dir in tf_dirs:
            reads.append(f"  [green]Would read:[/green]   {tf_dir}  (Terraform .tf files)")
        for ap in agent_projects:
            reads.append(f"  [green]Would read:[/green]   {ap}  (Python agent project)")
        for jdir in jupyter_dirs:
            reads.append(f"  [green]Would read:[/green]   {jdir}  (Jupyter notebooks *.ipynb)")
        for mdir in model_dirs:
            reads.append(f"  [green]Would read:[/green]   {mdir}  (ML model files .gguf, .safetensors, .onnx, .pt, etc.)")
        for ddir in dataset_dirs:
            reads.append(f"  [green]Would read:[/green]   {ddir}  (dataset cards: dataset_info.json, README.md, .dvc)")
        for tdir in training_dirs:
            reads.append(f"  [green]Would read:[/green]   {tdir}  (training pipelines: MLflow, Kubeflow, W&B)")
        if gha_path:
            reads.append(f"  [green]Would read:[/green]   {gha_path}/.github/workflows/  (GitHub Actions)")
        for sp in skill_paths:
            reads.append(f"  [green]Would read:[/green]   {sp}  (skill/instruction file)")
        if no_skill:
            reads.append("  [dim]Skill scanning:[/dim]   disabled (--no-skill)")
        elif not skill_paths:
            reads.append("  [green]Would discover:[/green] skill files (CLAUDE.md, .cursorrules, etc.)")
        if skill_only:
            reads.append("  [bold cyan]Mode:[/bold cyan]           skill-only (skipping agent/package/CVE scanning)")
        for img in images:
            reads.append(f"  [green]Would scan:[/green]   docker image {img}  (via grype → syft → docker)")
        if aws:
            reads.append(f"  [green]Would query:[/green]  AWS Bedrock/Lambda/ECS APIs ({aws_region or 'default region'})")
            if aws_include_lambda:
                reads.append(f"  [green]Would query:[/green]  AWS Lambda ListFunctions API ({aws_region or 'default region'})")
            if aws_include_eks:
                reads.append("  [green]Would query:[/green]  AWS EKS ListClusters + kubectl pod discovery")
            if aws_include_step_functions:
                reads.append("  [green]Would query:[/green]  AWS Step Functions ListStateMachines API")
            if aws_include_ec2:
                reads.append("  [green]Would query:[/green]  AWS EC2 DescribeInstances API (tag-filtered)")
        if azure_flag:
            reads.append("  [green]Would query:[/green]  Azure AI Foundry/Container Apps APIs")
        if gcp_flag:
            reads.append(f"  [green]Would query:[/green]  GCP Vertex AI/Cloud Run APIs ({gcp_project or 'default project'})")
        if databricks_flag:
            reads.append("  [green]Would query:[/green]  Databricks Clusters/Libraries APIs")
        if snowflake_flag:
            reads.append("  [green]Would query:[/green]  Snowflake Cortex Agents/MCP Servers/Search/Snowpark/Streamlit APIs")
        if coreweave_flag:
            reads.append(
                "  [green]Would query:[/green]  CoreWeave VirtualServer/InferenceService CRDs, GPU pods, InfiniBand jobs via kubectl"
            )
        if nebius_flag:
            reads.append("  [green]Would query:[/green]  Nebius K8s/Container APIs")
        if hf_flag:
            reads.append("  [green]Would query:[/green]  Hugging Face Hub Models/Spaces/Endpoints APIs")
        if wandb_flag:
            reads.append("  [green]Would query:[/green]  W&B Runs/Artifacts/Model Registry APIs")
        if mlflow_flag:
            reads.append("  [green]Would query:[/green]  MLflow Tracking Server (models, experiments)")
        if openai_flag:
            reads.append("  [green]Would query:[/green]  OpenAI Assistants/Fine-tuning APIs")
        if ollama_flag:
            _host = ollama_host or "http://localhost:11434"
            reads.append(f"  [green]Would query:[/green]  Ollama API ({_host}/api/tags) + ~/.ollama/models manifests")
        if mcp_registry_flag:
            reads.append(
                "  [green]Would query:[/green]  https://registry.modelcontextprotocol.io/v0/servers  (Official MCP Registry, no auth)"
            )
        if snyk_flag:
            reads.append("  [green]Would query:[/green]  https://api.snyk.io/rest/  (Snyk vulnerability enrichment)")
        for line in reads:
            con.print(line)
        con.print()
        con.print("  [dim]Would query:[/dim]  https://api.osv.dev/v1/querybatch  (batch CVE lookup, no auth required)")
        if enrich:
            con.print("  [dim]Would query:[/dim]  https://services.nvd.nist.gov/rest/json/cves/2.0  (CVSS v4)")
            con.print("  [dim]Would query:[/dim]  https://api.first.org/data/v1/epss  (exploit probability)")
            con.print("  [dim]Would query:[/dim]  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        con.print()

        # ── Data audit: exactly what gets extracted and sent ──────────────
        con.print("[bold cyan]📋 Data Audit — what is extracted and transmitted[/bold cyan]\n")
        con.print("  [bold]Extracted from config files:[/bold]")
        con.print('    • Server names (e.g. "filesystem", "github")')
        con.print('    • Commands and arguments (e.g. "npx @modelcontextprotocol/server-filesystem")')
        con.print('    • Environment variable [bold]NAMES only[/bold] (e.g. "OPENAI_API_KEY")')
        con.print("    • [dim]Values are NEVER read, stored, or logged[/dim]")
        con.print()
        con.print("  [bold]Sent to vulnerability APIs:[/bold]")
        con.print('    • Package name + version only (e.g. "express@4.17.1")')
        con.print("    • [dim]No file paths, config contents, env var values, hostnames, or IP addresses[/dim]")
        con.print()
        con.print("  [bold]Credential detection (name-only pattern matching):[/bold]")
        con.print("    • Flagged patterns: *KEY*, *TOKEN*, *SECRET*, *PASSWORD*, *CREDENTIAL*, *AUTH*")
        con.print("    • Excluded: PATH, HOME, LANG, SHELL, USER, TERM, EDITOR")
        con.print("    • [dim]Detection is purely on env var names — values are never accessed[/dim]")
        con.print()
        con.print("  [bold green]✓ agent-bom is read-only.[/bold green] It never writes to configs or executes MCP servers.")
        con.print("  [bold green]✓ Credential values are never read.[/bold green] Only env var names appear in reports.")
        con.print(
            "  See [link=https://github.com/msaad00/agent-bom/blob/main/PERMISSIONS.md]PERMISSIONS.md[/link] for the full trust contract."
        )
        return

    # Step 1: Discovery
    from rich.rule import Rule

    con.print(Rule("Discovery", style="blue"))

    if skill_only:
        agents = []  # skill-only: no agent discovery

    if not skill_only and inventory:
        label = "stdin" if inventory == "-" else inventory
        con.print(f"\n[bold blue]Loading inventory from {label}...[/bold blue]\n")

        from agent_bom.inventory import load_inventory

        inventory_data = load_inventory(inventory)
        agents = _build_agents_from_inventory(inventory_data, inventory)

        con.print(f"  [green]✓[/green] Loaded {len(agents)} agent(s) from inventory")
    elif not skill_only and config_dir:
        con.print(f"\n[bold blue]Scanning config directory: {config_dir}...[/bold blue]\n")
        with con.status("[bold]Discovering agents and MCP servers...[/bold]", spinner="dots"):
            agents = discover_all(
                project_dir=config_dir,
                dynamic=dynamic_discovery,
                dynamic_max_depth=dynamic_max_depth,
                include_processes=include_processes,
                include_containers=include_containers,
                include_k8s_mcp=k8s_mcp,
                k8s_namespace=k8s_namespace,
                k8s_all_namespaces=k8s_all_namespaces,
                k8s_context=k8s_mcp_context,
            )
    elif not skill_only:
        with con.status("[bold]Discovering agents and MCP servers...[/bold]", spinner="dots"):
            agents = discover_all(
                project_dir=project,
                dynamic=dynamic_discovery,
                dynamic_max_depth=dynamic_max_depth,
                include_processes=include_processes,
                include_containers=include_containers,
                include_k8s_mcp=k8s_mcp,
                k8s_namespace=k8s_namespace,
                k8s_all_namespaces=k8s_all_namespaces,
                k8s_context=k8s_mcp_context,
            )

    any_cloud = (
        aws
        or azure_flag
        or gcp_flag
        or coreweave_flag
        or databricks_flag
        or snowflake_flag
        or nebius_flag
        or hf_flag
        or wandb_flag
        or mlflow_flag
        or openai_flag
        or ollama_flag
    )
    if (
        not skill_only
        and not scan_prompts
        and not agents
        and not images
        and not k8s
        and not code_paths
        and not project  # --project: package scan fallback runs below
        and not sbom_file
        and not tf_dirs
        and not gha_path
        and not agent_projects
        and not jupyter_dirs
        and not any_cloud
    ):
        con.print("\n[bold yellow]No MCP configurations found on this machine.[/bold yellow]")
        con.print()
        con.print("  [bold]Quick start options:[/bold]")
        con.print("    [cyan]agent-bom scan --project .[/cyan]        scan all packages in current directory")
        con.print("    [cyan]agent-bom scan --image myapp:latest[/cyan] scan a Docker image")
        con.print("    [cyan]agent-bom scan --sbom sbom.json[/cyan]   ingest an existing SBOM (CycloneDX / SPDX)")
        con.print("    [cyan]agent-bom check requests@2.25.0[/cyan]   check a single package for CVEs")
        con.print("    [cyan]agent-bom scan --config-dir PATH[/cyan]  point to a directory with MCP configs")
        con.print()
        con.print("  [dim]Supported MCP clients: Claude Desktop, Cursor, VS Code, Windsurf, and 16 more.[/dim]")
        con.print("  [dim]Full options: agent-bom scan --help[/dim]")
        con.print("  [dim]Docs: https://github.com/msaad00/agent-bom[/dim]")
        con.print()
        sys.exit(0)

    # Step 1b: Load SBOM packages if provided
    sbom_packages: list = []
    if not skill_only and sbom_file:
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType
        from agent_bom.sbom import load_sbom

        try:
            sbom_packages, sbom_fmt, sbom_detected_name = load_sbom(sbom_file)
            # Resolve resource name: --sbom-name > SBOM metadata > file stem
            _resource_name = sbom_name or sbom_detected_name or Path(sbom_file).stem
            con.print(f"\n[bold blue]Loaded SBOM ({sbom_fmt}): {len(sbom_packages)} package(s) from '{_resource_name}'[/bold blue]\n")
            # Create a named synthetic agent so blast_radius references the real resource
            sbom_server = MCPServer(
                name=_resource_name,
                command="sbom",
                args=[sbom_file],
                transport=TransportType.STDIO,
                packages=sbom_packages,
            )
            sbom_agent = Agent(
                name=f"sbom:{_resource_name}",
                agent_type=AgentType.CUSTOM,
                config_path=sbom_file,
                source="sbom",
                mcp_servers=[sbom_server],
            )
            agents.append(sbom_agent)
            sbom_packages = []  # consumed — don't merge into another server
        except (FileNotFoundError, ValueError) as e:
            con.print(f"\n  [red]SBOM error: {e}[/red]")
            sys.exit(1)

    # Step 1c: Discover K8s container images (--k8s)
    if not skill_only and k8s:
        from agent_bom.k8s import K8sDiscoveryError, discover_images

        ns_label = "all namespaces" if all_namespaces else f"namespace '{namespace}'"
        con.print(f"\n[bold blue]Discovering container images from Kubernetes ({ns_label})...[/bold blue]\n")
        try:
            k8s_records = discover_images(
                namespace=namespace,
                all_namespaces=all_namespaces,
                context=k8s_context,
            )
            if k8s_records:
                con.print(f"  [green]✓[/green] Found {len(k8s_records)} unique image(s) across pods")
                extra_images = list(images) + [img for img, _pod, _ctr in k8s_records]
                images = tuple(dict.fromkeys(extra_images))  # deduplicate, preserve order
            else:
                con.print(f"  [dim]  No running pods found in {ns_label}[/dim]")
        except K8sDiscoveryError as e:
            con.print(f"\n  [red]K8s discovery error: {e}[/red]")
            sys.exit(1)

    # Step 1d: Scan Docker images (--image)
    if not skill_only and images:
        from agent_bom.image import ImageScanError, scan_image
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType

        con.print(f"\n[bold blue]Scanning {len(images)} container image(s)...[/bold blue]\n")
        for image_ref in images:
            try:
                img_packages, strategy = scan_image(
                    image_ref,
                    registry_user=registry_user,
                    registry_pass=registry_pass,
                    platform=image_platform,
                )
                con.print(f"  [green]✓[/green] {image_ref}: {len(img_packages)} package(s) [dim](via {strategy})[/dim]")
                # Represent the image as a synthetic agent → server
                server = MCPServer(
                    name=image_ref,
                    command="docker",
                    args=["run", image_ref],
                    transport=TransportType.STDIO,
                    packages=img_packages,
                )
                image_agent = Agent(
                    name=f"image:{image_ref}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"docker://{image_ref}",
                    mcp_servers=[server],
                )
                agents.append(image_agent)
            except ImageScanError as e:
                con.print(f"  [yellow]⚠[/yellow] {image_ref}: {e}")

    # Step 1d2: OCI tarball scan (--image-tar)
    if not skill_only and image_tars:
        from agent_bom.image import ImageScanError, scan_image_tar
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType

        con.print(f"\n[bold blue]Scanning {len(image_tars)} OCI image tarball(s)...[/bold blue]\n")
        for tar_path in image_tars:
            try:
                tar_packages, tar_strategy = scan_image_tar(tar_path)
                tar_label = Path(tar_path).name
                con.print(f"  [green]✓[/green] {tar_label}: {len(tar_packages)} package(s) [dim](via {tar_strategy})[/dim]")
                server = MCPServer(
                    name=tar_label,
                    command="",
                    args=[],
                    transport=TransportType.STDIO,
                    packages=tar_packages,
                )
                tar_agent = Agent(
                    name=f"image-tar:{tar_label}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"oci-tar://{tar_path}",
                    mcp_servers=[server],
                )
                agents.append(tar_agent)
            except ImageScanError as e:
                con.print(f"  [yellow]⚠[/yellow] {tar_path}: {e}")

    # Step 1d3: Filesystem / disk snapshot scan (--filesystem)
    if not skill_only and filesystem_paths:
        from agent_bom.filesystem import FilesystemScanError, scan_filesystem
        from agent_bom.models import Agent, AgentType, MCPServer

        con.print(f"\n[bold blue]Scanning {len(filesystem_paths)} filesystem path(s) via Syft...[/bold blue]\n")
        for fs_path in filesystem_paths:
            try:
                fs_packages, fs_strategy = scan_filesystem(fs_path)
                con.print(f"  [green]v[/green] {fs_path}: {len(fs_packages)} package(s) [dim](via {fs_strategy})[/dim]")
                server = MCPServer(name=f"fs:{fs_path}")
                server.packages = fs_packages
                fs_agent = Agent(
                    name=f"filesystem:{Path(fs_path).name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=fs_path,
                    source="filesystem",
                    mcp_servers=[server],
                )
                agents.append(fs_agent)
            except FilesystemScanError as e:
                con.print(f"  [yellow]![/yellow] {fs_path}: {e}")

    # Step 1d3: SAST code scan (--code)
    _sast_data: dict | None = None
    if not skill_only and code_paths:
        from agent_bom.sast import SASTScanError, scan_code

        con.print(f"\n[bold blue]Running SAST scan on {len(code_paths)} path(s) via Semgrep...[/bold blue]\n")
        for code_path in code_paths:
            try:
                sast_packages, sast_result = scan_code(code_path, config=sast_config)
                con.print(
                    f"  [green]v[/green] {code_path}: {sast_result.total_findings} finding(s) "
                    f"in {sast_result.files_scanned} file(s) [dim]({sast_result.scan_time_seconds}s)[/dim]"
                )
                if sast_packages:
                    server = MCPServer(name=f"sast:{Path(code_path).name}")
                    server.packages = sast_packages
                    sast_agent = Agent(
                        name=f"code:{Path(code_path).name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=code_path,
                        source="sast",
                        mcp_servers=[server],
                    )
                    agents.append(sast_agent)
                _sast_data = sast_result.to_dict()
            except SASTScanError as e:
                con.print(f"  [yellow]![/yellow] {code_path}: {e}")

    # Step 1d4: Project package scan fallback
    # When --project is set but discovery found no MCP agents (no Claude/Cursor/VS Code configs),
    # walk the project directory for package manifests so the scan is still useful.
    if not skill_only and project and not agents and not images and not code_paths and not sbom_file:
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType
        from agent_bom.parsers import scan_project_directory

        proj_root = Path(project)
        con.print(f"\n[bold blue]Scanning project directory for package manifests: {proj_root.name}[/bold blue]\n")
        dir_map = scan_project_directory(proj_root)
        if dir_map:
            total_proj_pkgs = sum(len(v) for v in dir_map.values())
            con.print(f"  [green]✓[/green] {proj_root.name}: {total_proj_pkgs} package(s) across {len(dir_map)} manifest(s)")

            proj_servers: list[MCPServer] = []
            for manifest_dir, pkgs in dir_map.items():
                rel = manifest_dir.relative_to(proj_root) if manifest_dir != proj_root else Path(".")
                server_name = str(rel) if str(rel) != "." else proj_root.name
                proj_server = MCPServer(
                    name=server_name,
                    command="project",
                    args=[str(manifest_dir)],
                    transport=TransportType.STDIO,
                    packages=pkgs,
                )
                proj_servers.append(proj_server)

            proj_agent = Agent(
                name=f"project:{proj_root.name}",
                agent_type=AgentType.CUSTOM,
                config_path=str(proj_root),
                source="project",
                mcp_servers=proj_servers,
            )
            agents.append(proj_agent)
        else:
            con.print(f"  [dim]  No package manifests found in {proj_root}[/dim]")

    # Step 1e: Terraform scan (--tf-dir)
    if not skill_only and tf_dirs:
        from agent_bom.terraform import scan_terraform_dir

        con.print(f"\n[bold blue]Scanning {len(tf_dirs)} Terraform director{'ies' if len(tf_dirs) > 1 else 'y'}...[/bold blue]\n")
        for tf_dir in tf_dirs:
            tf_agents, tf_warnings = scan_terraform_dir(tf_dir)
            for w in tf_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if tf_agents:
                ai_resource_count = sum(len(a.mcp_servers) for a in tf_agents)
                pkg_count = sum(a.total_packages for a in tf_agents)
                con.print(
                    f"  [green]✓[/green] {tf_dir}: "
                    f"{len(tf_agents)} AI service(s), {ai_resource_count} server(s), "
                    f"{pkg_count} provider package(s)"
                )
                agents.extend(tf_agents)
            else:
                con.print(f"  [dim]  {tf_dir}: no AI resources or providers found[/dim]")

    # Step 1f: GitHub Actions scan (--gha)
    if not skill_only and gha_path:
        from agent_bom.github_actions import scan_github_actions

        con.print(f"\n[bold blue]Scanning GitHub Actions workflows in {gha_path}...[/bold blue]\n")
        gha_agents, gha_warnings = scan_github_actions(gha_path)
        for w in gha_warnings:
            con.print(f"  [yellow]⚠[/yellow] {w}")
        if gha_agents:
            cred_count = sum(len(s.credential_names) for a in gha_agents for s in a.mcp_servers)
            con.print(f"  [green]✓[/green] {len(gha_agents)} workflow(s) with AI usage, {cred_count} credential(s) detected")
            agents.extend(gha_agents)
        else:
            con.print("  [dim]  No AI-using workflows found[/dim]")

    # Step 1g: Python agent framework scan (--agent-project)
    if not skill_only and agent_projects:
        from agent_bom.python_agents import scan_python_agents

        for ap in agent_projects:
            con.print(f"\n[bold blue]Scanning Python agent project: {ap}...[/bold blue]\n")
            ap_agents, ap_warnings = scan_python_agents(ap)
            for w in ap_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if ap_agents:
                tool_count = sum(len(s.tools) for a in ap_agents for s in a.mcp_servers)
                pkg_count = sum(len(s.packages) for a in ap_agents for s in a.mcp_servers)
                con.print(f"  [green]✓[/green] {len(ap_agents)} agent(s) found, {tool_count} tool(s), {pkg_count} package(s) to scan")
                agents.extend(ap_agents)
            else:
                con.print("  [dim]  No agent framework usage detected[/dim]")

    # Step 1g2: Skill file scanning (--skill + auto-discovery)
    _skill_audit_data: dict | None = None  # will be set if skill audit runs
    _skill_result_obj = None  # SkillScanResult for AI enrichment
    _skill_audit_obj = None  # SkillAuditResult for AI enrichment

    if not no_skill:
        from agent_bom.parsers.skills import discover_skill_files, scan_skill_files

        skill_file_list: list[Path] = []
        for sp in skill_paths:
            p = Path(sp)
            if p.is_dir():
                skill_file_list.extend(discover_skill_files(p))
            else:
                skill_file_list.append(p)
        # Auto-discover skill files in project directory
        search_dir = Path(project) if project else Path.cwd()
        auto_skills = discover_skill_files(search_dir)
        for sf in auto_skills:
            if sf not in skill_file_list:
                skill_file_list.append(sf)

        if skill_file_list:
            skill_result = scan_skill_files(skill_file_list)
            if skill_result.servers or skill_result.packages or skill_result.credential_env_vars:
                con.print(f"\n[bold blue]Scanning {len(skill_file_list)} skill file(s)...[/bold blue]\n")
                for sf in skill_file_list:
                    con.print(f"  [dim]•[/dim] {sf.name}  [dim]{sf.parent}[/dim]")
                if skill_result.servers:
                    from agent_bom.models import Agent, AgentType

                    skill_agent = Agent(
                        name="skill-files",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(skill_file_list[0]),
                        mcp_servers=skill_result.servers,
                    )
                    agents.append(skill_agent)
                    con.print(f"  [green]✓[/green] Found {len(skill_result.servers)} MCP server(s) in skill files")
                if skill_result.packages:
                    from agent_bom.models import Agent, AgentType
                    from agent_bom.models import MCPServer as _SkillSrv

                    skill_server = _SkillSrv(name="skill-packages", command="(from skill files)", packages=skill_result.packages)
                    skill_pkg_agent = Agent(
                        name="skill-packages",
                        agent_type=AgentType.CUSTOM,
                        config_path=", ".join(str(p) for p in skill_file_list[:3]),
                        mcp_servers=[skill_server],
                    )
                    agents.append(skill_pkg_agent)
                    con.print(f"  [green]✓[/green] Found {len(skill_result.packages)} package(s) referenced in skill files")
                if skill_result.credential_env_vars:
                    con.print(
                        f"  [yellow]⚠[/yellow] {len(skill_result.credential_env_vars)} credential env var(s) referenced in skill files"
                    )

                # Step 1g3: Skill security audit
                from agent_bom.parsers.skill_audit import audit_skill_result

                skill_audit = audit_skill_result(skill_result)
                _skill_result_obj = skill_result  # store for AI enrichment
                _skill_audit_obj = skill_audit  # store for AI enrichment
                _skill_audit_data = {
                    "findings": [
                        {
                            "severity": f.severity,
                            "category": f.category,
                            "title": f.title,
                            "detail": f.detail,
                            "source_file": f.source_file,
                            "package": f.package,
                            "server": f.server,
                            "recommendation": f.recommendation,
                            "context": f.context,
                        }
                        for f in skill_audit.findings
                    ],
                    "packages_checked": skill_audit.packages_checked,
                    "servers_checked": skill_audit.servers_checked,
                    "credentials_checked": skill_audit.credentials_checked,
                    "passed": skill_audit.passed,
                }
                if skill_audit.findings:
                    from rich.panel import Panel
                    from rich.table import Table as RichTable

                    sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
                    sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

                    audit_table = RichTable(
                        title=f"Skill Security Audit — {len(skill_audit.findings)} finding(s)",
                        expand=True,
                        padding=(0, 1),
                        title_style="bold yellow",
                    )
                    audit_table.add_column("Sev", justify="center", no_wrap=True, width=10)
                    audit_table.add_column("Category", no_wrap=True, width=20)
                    audit_table.add_column("Finding", ratio=3)
                    audit_table.add_column("Source", ratio=2, style="dim")

                    for finding in skill_audit.findings:
                        style = sev_colors.get(finding.severity, "white")
                        icon = sev_icons.get(finding.severity, "⚪")
                        sev_cell = f"{icon} [{style}]{finding.severity.upper()}[/{style}]"
                        cat_cell = f"[cyan]{finding.category}[/cyan]"
                        detail_parts = [f"[bold]{finding.title}[/bold]"]
                        detail_parts.append(f"[dim]{finding.detail}[/dim]")
                        if finding.recommendation:
                            detail_parts.append(f"[green]→ {finding.recommendation}[/green]")
                        detail_cell = "\n".join(detail_parts)
                        source_parts = []
                        if finding.source_file:
                            source_parts.append(Path(finding.source_file).name)
                        if finding.package:
                            source_parts.append(f"pkg:{finding.package}")
                        if finding.server:
                            source_parts.append(f"srv:{finding.server}")
                        source_cell = "\n".join(source_parts) if source_parts else "—"
                        audit_table.add_row(sev_cell, cat_cell, detail_cell, source_cell)

                    stats_line = (
                        f"[dim]Checked: {skill_audit.packages_checked} pkg(s) · "
                        f"{skill_audit.servers_checked} server(s) · "
                        f"{skill_audit.credentials_checked} credential(s) · "
                        f"{'[green]PASS[/green]' if skill_audit.passed else '[red]FAIL[/red]'}[/dim]"
                    )
                    con.print()
                    con.print(Panel(audit_table, subtitle=stats_line, border_style="yellow"))

    # Step 1g4: Trust assessment (ClawHub-style)
    _trust_assessment_data: dict | None = None
    if _skill_result_obj and _skill_audit_obj:
        from agent_bom.parsers.trust_assessment import TrustLevel, Verdict, assess_trust

        trust_result = assess_trust(_skill_result_obj, _skill_audit_obj)
        _trust_assessment_data = trust_result.to_dict()

        # Console output: trust assessment panel
        from rich.panel import Panel as TrustPanel
        from rich.table import Table as TrustTable

        level_icons = {
            TrustLevel.PASS: "[green]✓[/green]",
            TrustLevel.INFO: "[blue]ℹ[/blue]",
            TrustLevel.WARN: "[yellow]⚠[/yellow]",
            TrustLevel.FAIL: "[red]✗[/red]",
        }
        verdict_styles = {
            Verdict.BENIGN: "green",
            Verdict.SUSPICIOUS: "yellow",
            Verdict.MALICIOUS: "red bold",
        }
        trust_table = TrustTable(expand=True, padding=(0, 1), show_header=True)
        trust_table.add_column("", justify="center", no_wrap=True, width=3)
        trust_table.add_column("Category", no_wrap=True, width=24)
        trust_table.add_column("Summary", ratio=3)

        for cat in trust_result.categories:
            icon = level_icons.get(cat.level, "?")
            trust_table.add_row(icon, f"[bold]{cat.name}[/bold]", cat.summary)

        vstyle = verdict_styles.get(trust_result.verdict, "white")
        verdict_line = f"[{vstyle}]{trust_result.verdict.value.upper()}[/{vstyle}] ({trust_result.confidence.value} confidence)"
        con.print()
        con.print(
            TrustPanel(
                trust_table,
                title=f"[bold]Trust Assessment — {Path(trust_result.source_file).name}[/bold]",
                subtitle=verdict_line,
                border_style=vstyle,
            )
        )

        if trust_result.recommendations:
            for rec in trust_result.recommendations:
                con.print(f"  [dim]→ {rec}[/dim]")

    # Step 1g3b: Prompt template scanning (--scan-prompts)
    _prompt_scan_data: dict | None = None
    if scan_prompts:
        from agent_bom.parsers.prompt_scanner import scan_prompt_files

        search_dir = Path(project) if project else Path.cwd()
        prompt_result = scan_prompt_files(root=search_dir)
        if prompt_result.files_scanned > 0:
            con.print(f"\n[bold blue]Scanned {prompt_result.files_scanned} prompt template file(s)...[/bold blue]\n")
            for pf in prompt_result.prompt_files:
                con.print(f"  [dim]•[/dim] {Path(pf).name}")
            _prompt_scan_data = {
                "files_scanned": prompt_result.files_scanned,
                "prompt_files": prompt_result.prompt_files,
                "findings": [
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "title": f.title,
                        "detail": f.detail,
                        "source_file": f.source_file,
                        "line_number": f.line_number,
                        "matched_text": f.matched_text,
                        "recommendation": f.recommendation,
                    }
                    for f in prompt_result.findings
                ],
                "passed": prompt_result.passed,
            }
            if prompt_result.findings:
                from rich.panel import Panel
                from rich.table import Table as RichTable

                sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
                sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

                prompt_table = RichTable(
                    title=f"Prompt Template Security Scan — {len(prompt_result.findings)} finding(s)",
                    expand=True,
                    padding=(0, 1),
                    title_style="bold magenta",
                )
                prompt_table.add_column("Sev", justify="center", no_wrap=True, width=10)
                prompt_table.add_column("Category", no_wrap=True, width=20)
                prompt_table.add_column("Finding", ratio=3)
                prompt_table.add_column("File", ratio=2, style="dim")

                for finding in prompt_result.findings:
                    style = sev_colors.get(finding.severity, "white")
                    icon = sev_icons.get(finding.severity, "⚪")
                    sev_cell = f"{icon} [{style}]{finding.severity.upper()}[/{style}]"
                    cat_cell = f"[cyan]{finding.category}[/cyan]"
                    detail_parts = [f"[bold]{finding.title}[/bold]"]
                    detail_parts.append(f"[dim]{finding.detail}[/dim]")
                    if finding.recommendation:
                        detail_parts.append(f"[green]→ {finding.recommendation}[/green]")
                    detail_cell = "\n".join(detail_parts)
                    file_info = Path(finding.source_file).name
                    if finding.line_number:
                        file_info += f":{finding.line_number}"
                    prompt_table.add_row(sev_cell, cat_cell, detail_cell, file_info)

                stats_line = (
                    f"[dim]{prompt_result.files_scanned} file(s) scanned · "
                    f"{'[green]PASS[/green]' if prompt_result.passed else '[red]FAIL[/red]'}[/dim]"
                )
                con.print()
                con.print(Panel(prompt_table, subtitle=stats_line, border_style="magenta"))
            else:
                con.print("  [green]✓[/green] No security issues found in prompt templates")

    # Step 1g3c: Browser extension scanning (--browser-extensions)
    _browser_ext_results: dict | None = None
    if browser_extensions:
        from agent_bom.parsers.browser_extensions import discover_browser_extensions

        con.print("\n[bold blue]Scanning browser extensions...[/bold blue]\n")
        br_exts = discover_browser_extensions(include_low_risk=False)
        if br_exts:
            from rich.panel import Panel
            from rich.table import Table as RichTable

            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
            sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

            br_table = RichTable(
                title=f"Browser Extension Security Scan — {len(br_exts)} medium+ risk extension(s)",
                expand=True,
                padding=(0, 1),
                title_style="bold magenta",
            )
            br_table.add_column("Risk", justify="center", no_wrap=True, width=10)
            br_table.add_column("Browser", no_wrap=True, width=10)
            br_table.add_column("Extension", ratio=2)
            br_table.add_column("Findings", ratio=4)

            for ext in br_exts:
                style = sev_colors.get(ext.risk_level, "white")
                icon = sev_icons.get(ext.risk_level, "⚪")
                risk_cell = f"{icon} [{style}]{ext.risk_level.upper()}[/{style}]"
                browser_cell = f"[cyan]{ext.browser}[/cyan]"
                name_cell = f"[bold]{ext.name}[/bold]\n[dim]{ext.version}[/dim]"
                findings_cell = "\n".join(f"[dim]• {r}[/dim]" for r in ext.risk_reasons[:4])
                if len(ext.risk_reasons) > 4:
                    findings_cell += f"\n[dim]  (+{len(ext.risk_reasons) - 4} more)[/dim]"
                br_table.add_row(risk_cell, browser_cell, name_cell, findings_cell)

            crit_count = sum(1 for e in br_exts if e.risk_level == "critical")
            high_count = sum(1 for e in br_exts if e.risk_level == "high")
            stats = f"[dim]{crit_count} critical · {high_count} high · scan complete[/dim]"
            con.print(Panel(br_table, subtitle=stats, border_style="magenta"))
        else:
            con.print("  [green]✓[/green] No medium+ risk browser extensions found")

        # Save for later persistence to report (report created after all scans)
        _browser_ext_results = {
            "extensions": [e.to_dict() for e in br_exts],
            "total": len(br_exts),
            "critical_count": sum(1 for e in br_exts if e.risk_level == "critical"),
            "high_count": sum(1 for e in br_exts if e.risk_level == "high"),
        }

    # Step 1g4: Jupyter notebook scan (--jupyter)
    if not skill_only and jupyter_dirs:
        from agent_bom.jupyter import scan_jupyter_notebooks

        for jdir in jupyter_dirs:
            con.print(f"\n[bold blue]Scanning Jupyter notebooks in {jdir}...[/bold blue]\n")
            j_agents, j_warnings = scan_jupyter_notebooks(jdir)
            for w in j_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if j_agents:
                pkg_count = sum(len(s.packages) for a in j_agents for s in a.mcp_servers)
                con.print(f"  [green]✓[/green] {len(j_agents)} notebook(s) with AI libraries found, {pkg_count} package(s) to scan")
                agents.extend(j_agents)
            else:
                con.print("  [dim]  No AI library usage detected in notebooks[/dim]")

    # Step 1h: Cloud provider discovery
    cloud_providers: list[tuple[str, dict]] = []
    if not skill_only and aws:
        aws_kwargs: dict = {"region": aws_region, "profile": aws_profile}
        if aws_include_lambda:
            aws_kwargs["include_lambda"] = True
        if aws_include_eks:
            aws_kwargs["include_eks"] = True
        if aws_include_step_functions:
            aws_kwargs["include_step_functions"] = True
        if aws_include_ec2:
            aws_kwargs["include_ec2"] = True
            if aws_ec2_tag and "=" in aws_ec2_tag:
                k, v = aws_ec2_tag.split("=", 1)
                aws_kwargs["ec2_tag_filter"] = {k: v}
        cloud_providers.append(("aws", aws_kwargs))
    if not skill_only and azure_flag:
        cloud_providers.append(("azure", {"subscription_id": azure_subscription}))
    if not skill_only and gcp_flag:
        cloud_providers.append(("gcp", {"project_id": gcp_project}))
    if not skill_only and coreweave_flag:
        cloud_providers.append(("coreweave", {"context": coreweave_context, "namespace": coreweave_namespace}))
    if not skill_only and databricks_flag:
        cloud_providers.append(("databricks", {}))
    if not skill_only and snowflake_flag:
        cloud_providers.append(("snowflake", {"authenticator": snowflake_authenticator} if snowflake_authenticator else {}))
    if not skill_only and nebius_flag:
        cloud_providers.append(("nebius", {"api_key": nebius_api_key, "project_id": nebius_project_id}))
    if not skill_only and hf_flag:
        cloud_providers.append(("huggingface", {"token": hf_token, "username": hf_username, "organization": hf_organization}))
    if not skill_only and wandb_flag:
        cloud_providers.append(("wandb", {"api_key": wandb_api_key, "entity": wandb_entity, "project": wandb_project}))
    if not skill_only and mlflow_flag:
        cloud_providers.append(("mlflow", {"tracking_uri": mlflow_tracking_uri}))
    if not skill_only and openai_flag:
        cloud_providers.append(("openai", {"api_key": openai_api_key, "organization": openai_org_id}))
    if not skill_only and ollama_flag:
        cloud_providers.append(("ollama", {"host": ollama_host}))

    for provider_name, provider_kwargs in cloud_providers:
        from agent_bom.cloud import CloudDiscoveryError, discover_from_provider

        con.print(f"\n[bold blue]Discovering agents from {provider_name.upper()}...[/bold blue]\n")
        try:
            cloud_agents, cloud_warnings = discover_from_provider(provider_name, **provider_kwargs)
            for w in cloud_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if cloud_agents:
                pkg_count = sum(a.total_packages for a in cloud_agents)
                con.print(f"  [green]✓[/green] {len(cloud_agents)} agent(s) discovered, {pkg_count} package(s) to scan")
                agents.extend(cloud_agents)
            else:
                con.print(f"  [dim]  No AI agents found in {provider_name.upper()}[/dim]")
        except CloudDiscoveryError as exc:
            con.print(f"\n  [red]{provider_name.upper()} discovery error: {exc}[/red]")

    # Step 1x: Model hash verification (supply chain integrity)
    if verify_model_hashes:
        from agent_bom.model_hash import verify_model_hashes as _verify_hashes

        _scan_roots = [Path(project)] if project else [Path.home()]
        for _root in _scan_roots:
            with con.status(f"[bold]Verifying model weight hashes under {_root.name}...[/bold]", spinner="dots"):
                _hash_report = _verify_hashes(str(_root), token=hf_token)
            if _hash_report.scanned == 0:
                con.print(f"  [dim]No model weight files found under {_root}[/dim]")
            elif _hash_report.has_tampering:
                con.print(
                    f"  [red]⚠ SUPPLY_CHAIN_TAMPERING[/red] {_hash_report.tampered} tampered file(s) out of {_hash_report.scanned} scanned"
                )
                for r in _hash_report.results:
                    if r.is_tampered:
                        con.print(
                            f"    [red]✗[/red] {r.filename}  expected={r.expected_sha256[:16]}…  got={r.actual_sha256[:16] if r.actual_sha256 else '?'}…"
                        )
            elif _hash_report.offline > 0:
                con.print(f"  [yellow]~[/yellow] {_hash_report.scanned} file(s) found — HuggingFace Hub unreachable, hashes unverified")
            else:
                con.print(
                    f"  [green]✓[/green] {_hash_report.verified} model file(s) verified, {_hash_report.unverified} unverified (not in Hub)"
                )

    # Step 1y: CIS AWS Foundations Benchmark
    cis_benchmark_report = None
    if aws_cis_benchmark:
        from agent_bom.cloud import CloudDiscoveryError

        con.print("\n[bold blue]Running CIS AWS Foundations Benchmark v3.0...[/bold blue]\n")
        try:
            from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_cis

            cis_benchmark_report = run_cis(region=aws_region, profile=aws_profile)
            passed = cis_benchmark_report.passed
            failed = cis_benchmark_report.failed
            total = cis_benchmark_report.total
            rate = cis_benchmark_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="CIS AWS Foundations Benchmark v3.0", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("Evidence", max_width=50)
                _status_style = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _sev_style = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                for c in cis_benchmark_report.checks:
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _status_style.get(c.status.value, c.status.value),
                        _sev_style.get(c.severity, c.severity),
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except CloudDiscoveryError as exc:
            con.print(f"  [red]CIS Benchmark error: {exc}[/red]")

    # Step 1x-sf: CIS Snowflake Benchmark
    sf_cis_benchmark_report = None
    if snowflake_cis_benchmark:
        from agent_bom.cloud import CloudDiscoveryError as _SFCISError

        con.print("\n[bold blue]Running CIS Snowflake Benchmark v1.0...[/bold blue]\n")
        try:
            from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_sf_cis

            sf_cis_benchmark_report = run_sf_cis()
            passed = sf_cis_benchmark_report.passed
            failed = sf_cis_benchmark_report.failed
            total = sf_cis_benchmark_report.total
            rate = sf_cis_benchmark_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="CIS Snowflake Benchmark v1.0", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("Evidence", max_width=50)
                _sf_status_style = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _sf_sev_style = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                for c in sf_cis_benchmark_report.checks:
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _sf_status_style.get(c.status.value, c.status.value),
                        _sf_sev_style.get(c.severity, c.severity),
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except _SFCISError as exc:
            con.print(f"  [red]CIS Snowflake Benchmark error: {exc}[/red]")

    # Step 1x-az: CIS Azure Benchmark
    azure_cis_benchmark_report = None
    if azure_cis_benchmark:
        from agent_bom.cloud import CloudDiscoveryError as _AZCISError

        con.print("\n[bold blue]Running CIS Azure Security Benchmark v3.0...[/bold blue]\n")
        try:
            from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_az_cis

            azure_cis_benchmark_report = run_az_cis()
            passed = azure_cis_benchmark_report.passed
            failed = azure_cis_benchmark_report.failed
            total = azure_cis_benchmark_report.total
            rate = azure_cis_benchmark_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="CIS Azure Security Benchmark v3.0", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("ATT&CK", width=20)
                tbl.add_column("Evidence", max_width=40)
                _az_status = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _az_sev = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                from agent_bom.mitre_attack import tag_cis_check

                for c in azure_cis_benchmark_report.checks:
                    attack = ", ".join(tag_cis_check(c)) or "-"
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _az_status.get(c.status.value, c.status.value),
                        _az_sev.get(c.severity, c.severity),
                        attack,
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except _AZCISError as exc:
            con.print(f"  [red]CIS Azure Benchmark error: {exc}[/red]")

    # Step 1x-gcp: CIS GCP Benchmark
    gcp_cis_benchmark_report = None
    if gcp_cis_benchmark:
        from agent_bom.cloud import CloudDiscoveryError as _GCPCISError

        con.print("\n[bold blue]Running CIS GCP Foundation Benchmark v3.0...[/bold blue]\n")
        try:
            from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis

            gcp_cis_benchmark_report = run_gcp_cis()
            passed = gcp_cis_benchmark_report.passed
            failed = gcp_cis_benchmark_report.failed
            total = gcp_cis_benchmark_report.total
            rate = gcp_cis_benchmark_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="CIS GCP Foundation Benchmark v3.0", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("ATT&CK", width=20)
                tbl.add_column("Evidence", max_width=40)
                _gcp_status = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _gcp_sev = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                from agent_bom.mitre_attack import tag_cis_check as _tag_gcp

                for c in gcp_cis_benchmark_report.checks:
                    attack = ", ".join(_tag_gcp(c)) or "-"
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _gcp_status.get(c.status.value, c.status.value),
                        _gcp_sev.get(c.severity, c.severity),
                        attack,
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except _GCPCISError as exc:
            con.print(f"  [red]CIS GCP Benchmark error: {exc}[/red]")

    # Step 1x-db: Databricks Security Best Practices
    databricks_security_report = None
    if databricks_security:
        from agent_bom.cloud import CloudDiscoveryError as _DBSecError

        con.print("\n[bold blue]Running Databricks Security Best Practices checks...[/bold blue]\n")
        try:
            import os

            from agent_bom.cloud.databricks_security import run_security_checks as run_db_sec

            _db_host = os.environ.get("DATABRICKS_HOST")
            _db_token = os.environ.get("DATABRICKS_TOKEN")
            databricks_security_report = run_db_sec(host=_db_host, token=_db_token)
            passed = databricks_security_report.passed
            failed = databricks_security_report.failed
            total = databricks_security_report.total
            rate = databricks_security_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="Databricks Security Best Practices", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("ATT&CK", width=20)
                tbl.add_column("Evidence", max_width=40)
                _db_status = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _db_sev = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                from agent_bom.mitre_attack import tag_cis_check as _tag_db

                for c in databricks_security_report.checks:
                    attack = ", ".join(_tag_db(c)) or "-"
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _db_status.get(c.status.value, c.status.value),
                        _db_sev.get(c.severity, c.severity),
                        attack,
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except _DBSecError as exc:
            con.print(f"  [red]Databricks security check error: {exc}[/red]")

    # Step 1x-b: Vector DB scan
    vector_db_results = []
    if vector_db_scan:
        from rich.table import Table as _RTable

        con.print("\n[bold blue]Scanning for vector databases...[/bold blue]\n")
        try:
            from agent_bom.cloud.vector_db import discover_pinecone, discover_vector_dbs

            vector_db_results = discover_vector_dbs()
            pinecone_results = discover_pinecone()
            if not vector_db_results and not pinecone_results:
                con.print("  [dim]No running vector databases found. Set PINECONE_API_KEY to scan Pinecone.[/dim]")
            else:
                total = len(vector_db_results) + len(pinecone_results)
                con.print(f"  Found [bold]{total}[/bold] vector database(s)")
                tbl = _RTable(title="Vector DB Security", show_lines=True)
                tbl.add_column("DB", width=10)
                tbl.add_column("Instance", width=20)
                tbl.add_column("Auth", width=8)
                tbl.add_column("Risk", width=10)
                tbl.add_column("Flags")
                _vdb_risk = {
                    "critical": "[red]critical[/]",
                    "high": "[bright_red]high[/]",
                    "medium": "[yellow]medium[/]",
                    "safe": "[green]safe[/]",
                }
                for r in vector_db_results:
                    tbl.add_row(
                        r.db_type,
                        f"{r.host}:{r.port}",
                        "[green]yes[/]" if r.requires_auth else "[red]NO[/]",
                        _vdb_risk.get(r.risk_level, r.risk_level),
                        ", ".join(r.risk_flags) or "-",
                    )
                for r in pinecone_results:
                    tbl.add_row(
                        "pinecone",
                        r.index_name,
                        "[green]API key[/]",
                        _vdb_risk.get(r.risk_level, r.risk_level),
                        ", ".join(r.risk_flags) or "-",
                    )
                con.print()
                con.print(tbl)
        except Exception as exc:
            con.print(f"  [red]Vector DB scan error: {exc}[/red]")

    # Step 1x-b2: GPU infra scan
    gpu_infra_report = None
    if gpu_scan_flag:
        import asyncio as _asyncio

        from rich.table import Table as _RTable

        con.print("\n[bold blue]Scanning GPU/AI compute infrastructure...[/bold blue]\n")
        try:
            from agent_bom.cloud.gpu_infra import gpu_infra_to_agents, scan_gpu_infra

            with con.status("[bold]Probing Docker, K8s, and DCGM endpoints...[/bold]", spinner="dots"):
                gpu_infra_report = _asyncio.run(scan_gpu_infra(k8s_context=gpu_k8s_context, probe_dcgm=not no_dcgm_probe))
            for w in gpu_infra_report.warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            gpu_agents = gpu_infra_to_agents(gpu_infra_report)
            if gpu_agents:
                agents.extend(gpu_agents)
                con.print(
                    f"  [green]✓[/green] {gpu_infra_report.total_gpu_containers} GPU container(s), "
                    f"{len(gpu_infra_report.gpu_nodes)} K8s GPU node(s)"
                )
                if gpu_infra_report.unique_cuda_versions:
                    con.print(f"  CUDA versions: {', '.join(gpu_infra_report.unique_cuda_versions)}")
                if gpu_infra_report.unauthenticated_dcgm_count:
                    con.print(
                        f"  [red]⚠ {gpu_infra_report.unauthenticated_dcgm_count} unauthenticated DCGM exporter(s) — metrics leak[/red]"
                    )
                if gpu_infra_report.dcgm_endpoints:
                    tbl = _RTable(title="DCGM Endpoints", show_lines=False)
                    tbl.add_column("Host", width=20)
                    tbl.add_column("Port", width=8)
                    tbl.add_column("Auth", width=8)
                    tbl.add_column("GPUs", width=6)
                    for ep in gpu_infra_report.dcgm_endpoints:
                        tbl.add_row(
                            ep.host,
                            str(ep.port),
                            "[green]yes[/]" if ep.authenticated else "[red]NO[/]",
                            str(ep.gpu_count) if ep.gpu_count is not None else "?",
                        )
                    con.print()
                    con.print(tbl)
            else:
                con.print("  [dim]No GPU containers or K8s GPU nodes found[/dim]")
        except Exception as exc:
            con.print(f"  [red]GPU scan error: {exc}[/red]")

    # Step 1x-c: AISVS compliance benchmark
    aisvs_report = None
    if aisvs_flag:
        from rich.table import Table as _RTable

        con.print("\n[bold blue]Running AISVS v1.0 compliance checks...[/bold blue]\n")
        try:
            from agent_bom.cloud.aisvs_benchmark import run_benchmark as _run_aisvs

            aisvs_report = _run_aisvs()
            passed = aisvs_report.passed
            failed = aisvs_report.failed
            total = aisvs_report.total
            rate = aisvs_report.pass_rate
            con.print(
                f"  [bold]AISVS v1.0[/bold]: {passed}/{total} checks passed "
                f"([{'green' if rate >= 80 else 'yellow' if rate >= 50 else 'red'}]{rate:.1f}%[/])"
            )
            tbl = _RTable(title="AISVS Compliance", show_lines=True)
            tbl.add_column("Check", width=8)
            tbl.add_column("Title", max_width=45)
            tbl.add_column("Status", width=8)
            tbl.add_column("Sev", width=8)
            tbl.add_column("MAESTRO", width=22)
            tbl.add_column("Evidence", max_width=40)
            _aiv_status = {
                "pass": "[green]PASS[/]",
                "fail": "[red]FAIL[/]",
                "error": "[yellow]ERR[/]",
                "not_applicable": "[dim]N/A[/]",
            }
            from agent_bom.maestro import tag_aisvs_check as _maestro_tag

            for c in aisvs_report.checks:
                maestro = _maestro_tag(c.check_id).value
                tbl.add_row(
                    c.check_id,
                    c.title,
                    _aiv_status.get(c.status.value, c.status.value),
                    c.severity,
                    maestro,
                    c.evidence,
                )
            con.print()
            con.print(tbl)
        except Exception as exc:
            con.print(f"  [red]AISVS benchmark error: {exc}[/red]")

    # Step 1y: SaaS connector discovery
    saas_connectors: list[tuple[str, dict]] = []
    if not skill_only and jira_discover:
        saas_connectors.append(("jira", {"jira_url": jira_url, "email": jira_user, "api_token": jira_token}))
    if not skill_only and servicenow_flag:
        saas_connectors.append(
            ("servicenow", {"instance_url": servicenow_instance, "username": servicenow_user, "password": servicenow_password})
        )
    if not skill_only and slack_discover:
        saas_connectors.append(("slack", {"bot_token": slack_bot_token}))

    for connector_name, connector_kwargs in saas_connectors:
        from agent_bom.connectors import ConnectorError, discover_from_connector

        con.print(f"\n[bold blue]Discovering agents from {connector_name.upper()} connector...[/bold blue]\n")
        try:
            con_agents, con_warnings = discover_from_connector(connector_name, **connector_kwargs)
            for w in con_warnings:
                con.print(f"  [yellow]![/yellow] {w}")
            if con_agents:
                con.print(f"  [green]v[/green] {len(con_agents)} agent(s) discovered from {connector_name.upper()}")
                agents.extend(con_agents)
            else:
                con.print(f"  [dim]  No AI agents found in {connector_name.upper()}[/dim]")
        except ConnectorError as exc:
            con.print(f"\n  [red]{connector_name.upper()} connector error: {exc}[/red]")

    # Step 1z: Multi-source correlation (dedup + merge across sources)
    if not skill_only and agents:
        sources = {a.source or "local" for a in agents}
        if len(sources) > 1:
            from agent_bom.correlate import correlate_agents

            agents, corr_result = correlate_agents(agents)
            if corr_result.cross_source_matches:
                con.print(
                    f"\n  [bold]Correlated:[/bold] {corr_result.cross_source_matches} package(s) "
                    f"merged across {len(corr_result.source_summary)} source(s)"
                )

    # Step 2: Extract packages
    total_packages = 0
    if skill_only:
        blast_radii = []
    else:
        con.print()
        con.print(Rule("Package Extraction", style="blue"))
        con.print()
        if transitive:
            con.print(f"  [cyan]Transitive resolution enabled (max depth: {max_depth})[/cyan]\n")
        for agent in agents:
            for server in agent.mcp_servers:
                if server.security_blocked:
                    if not quiet:
                        con.print(f"    [yellow]⚠ {server.name}: blocked — {', '.join(server.security_warnings)}[/yellow]")
                    continue  # Don't extract from security-blocked servers
                # Keep pre-populated packages from inventory, merge with discovered ones
                pre_populated = list(server.packages)
                _smithery_tok = smithery_token if smithery_flag else None
                discovered = extract_packages(
                    server, resolve_transitive=transitive, max_depth=max_depth, smithery_token=_smithery_tok, mcp_registry=mcp_registry_flag
                )

                # Merge: discovered + pre-populated (deduplicated)
                # Note: SBOM packages are now a separate synthetic agent (sbom:<name>)
                # and pre-populated packages already include them for sbom agents.
                discovered_names = {(p.name, p.ecosystem) for p in discovered}
                merged = discovered + [p for p in pre_populated if (p.name, p.ecosystem) not in discovered_names]
                server.packages = merged

                total_packages += len(server.packages)
                if server.packages:
                    direct_count = sum(1 for p in server.packages if p.is_direct)
                    transitive_count = len(server.packages) - direct_count
                    transitive_str = f" ({transitive_count} transitive)" if transitive_count > 0 else ""
                    pre_str = f" ({len(pre_populated)} from inventory)" if pre_populated else ""
                    con.print(
                        f"  [green]✓[/green] {server.name}: {len(server.packages)} package(s) "
                        f"({server.packages[0].ecosystem}){transitive_str}{pre_str}"
                    )
                else:
                    con.print(f"  [dim]  {server.name}: no local packages found[/dim]")

        con.print(f"\n  [bold]{total_packages} total packages.[/bold]")

        # Step 2a: deps.dev transitive resolution + license enrichment (--deps-dev)
        if deps_dev:
            import asyncio as _asyncio_dd

            from agent_bom.deps_dev import enrich_licenses_deps_dev, resolve_transitive_deps_dev

            all_pkgs = [pkg for agent in agents for server in agent.mcp_servers for pkg in server.packages]
            direct_pkgs = [p for p in all_pkgs if p.is_direct]
            if direct_pkgs:
                con.print("\n  [cyan]deps.dev: resolving transitive dependencies...[/cyan]")
                transitive_pkgs = _asyncio_dd.run(resolve_transitive_deps_dev(direct_pkgs, max_depth=max_depth))
                if transitive_pkgs:
                    # Distribute transitive packages to their origin servers
                    pkg_parent_map: dict[str, list] = {}
                    for tp in transitive_pkgs:
                        pkg_parent_map.setdefault(tp.parent_package or "", []).append(tp)
                    for agent in agents:
                        for server in agent.mcp_servers:
                            existing_names = {(p.name, p.version, p.ecosystem) for p in server.packages}
                            for sp in server.packages:
                                if sp.is_direct and sp.name in pkg_parent_map:
                                    for tp in pkg_parent_map[sp.name]:
                                        if (tp.name, tp.version, tp.ecosystem) not in existing_names:
                                            server.packages.append(tp)
                                            existing_names.add((tp.name, tp.version, tp.ecosystem))
                    con.print(f"  [green]✓[/green] deps.dev: {len(transitive_pkgs)} transitive dependencies resolved")

                # Enrich licenses for all packages
                all_pkgs_updated = [pkg for agent in agents for server in agent.mcp_servers for pkg in server.packages]
                lic_count = _asyncio_dd.run(enrich_licenses_deps_dev(all_pkgs_updated))
                if lic_count:
                    con.print(f"  [green]✓[/green] deps.dev: {lic_count} package license(s) enriched")

                # Enrich supply chain metadata (description, homepage, repo, author)
                try:
                    from agent_bom.http_client import create_client as _sc_client
                    from agent_bom.resolver import enrich_supply_chain_metadata as _sc_enrich

                    async def _do_sc_enrich() -> int:
                        async with _sc_client(timeout=15.0) as client:
                            return await _sc_enrich(all_pkgs_updated, client)

                    sc_count = _asyncio_dd.run(_do_sc_enrich())
                    if sc_count:
                        con.print(f"  [green]✓[/green] supply chain: {sc_count} package metadata enriched")
                except Exception:  # noqa: BLE001
                    pass  # supply chain enrichment is best-effort

        # Step 2b: MCP Runtime Introspection (--introspect)
        _enforcement_data: dict | None = None
        _intro_report = None
        if introspect:
            from agent_bom.mcp_introspect import IntrospectionError, enrich_servers, introspect_servers_sync

            all_servers = [s for a in agents for s in a.mcp_servers]
            con.print(f"\n[bold blue]Introspecting {len(all_servers)} MCP server(s)...[/bold blue]\n")
            try:
                intro_report = introspect_servers_sync(all_servers, timeout=introspect_timeout)
                for w in intro_report.warnings:
                    con.print(f"  [yellow]⚠[/yellow] {w}")
                for r in intro_report.results:
                    if r.success:
                        drift_str = ""
                        if r.has_drift:
                            parts = []
                            if r.tools_added:
                                parts.append(f"+{len(r.tools_added)} tools")
                            if r.tools_removed:
                                parts.append(f"-{len(r.tools_removed)} tools")
                            if r.resources_added:
                                parts.append(f"+{len(r.resources_added)} resources")
                            if r.resources_removed:
                                parts.append(f"-{len(r.resources_removed)} resources")
                            drift_str = f" [yellow]drift: {', '.join(parts)}[/yellow]"
                        con.print(f"  [green]✓[/green] {r.server_name}: {r.tool_count} tools, {r.resource_count} resources{drift_str}")
                    else:
                        con.print(f"  [dim]  {r.server_name}: {r.error}[/dim]")
                enriched = enrich_servers(all_servers, intro_report)
                if enriched:
                    con.print(f"\n  [bold]{enriched} server(s) enriched with runtime data.[/bold]")
                _intro_report = intro_report
            except IntrospectionError as exc:
                con.print(f"  [yellow]⚠[/yellow] {exc}")

        # Step 2b-hc: Post-discovery health checks (--health-check)
        if health_check:
            from agent_bom.mcp_introspect import IntrospectionError as _HCError
            from agent_bom.mcp_introspect import health_check_servers_sync

            hc_servers = [s for a in agents for s in a.mcp_servers]
            con.print(f"\n[bold blue]Health-checking {len(hc_servers)} MCP server(s)...[/bold blue]\n")
            try:
                hc_results = health_check_servers_sync(hc_servers, timeout=hc_timeout)
                reachable = sum(1 for h in hc_results if h.reachable)
                for h in hc_results:
                    if h.reachable:
                        latency_str = f" {h.latency_ms:.0f}ms" if h.latency_ms is not None else ""
                        proto_str = f" [{h.protocol_version}]" if h.protocol_version else ""
                        con.print(f"  [green]✓[/green] {h.server_name}: {h.tool_count} tool(s){latency_str}{proto_str}")
                    else:
                        con.print(f"  [red]✗[/red] {h.server_name}: {h.error or 'unreachable'}")
                con.print(f"\n  [bold]{reachable}/{len(hc_results)} server(s) reachable.[/bold]")
            except _HCError as exc:
                con.print(f"  [yellow]⚠[/yellow] {exc}")

        # Step 2c: Tool poisoning detection + enforcement (--enforce)
        if enforce:
            from agent_bom.enforcement import run_enforcement

            all_enforce_servers = [s for a in agents for s in a.mcp_servers]
            con.print(f"\n[bold blue]Running enforcement checks on {len(all_enforce_servers)} server(s)...[/bold blue]\n")
            enforce_result = run_enforcement(
                servers=all_enforce_servers,
                introspection_report=_intro_report,
            )
            _enforcement_data = enforce_result.to_dict()
            # Display findings
            if enforce_result.findings:
                from rich.table import Table

                etable = Table(title="Enforcement Findings", show_lines=False)
                etable.add_column("Severity", width=10)
                etable.add_column("Category", width=16)
                etable.add_column("Server", width=20)
                etable.add_column("Tool", width=16)
                etable.add_column("Reason")
                sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
                for f in enforce_result.findings:
                    etable.add_row(
                        f"[{sev_colors.get(f.severity, 'white')}]{f.severity.upper()}[/]",
                        f.category,
                        f.server_name,
                        f.tool_name or "—",
                        f.reason,
                    )
                con.print(etable)
            status = "[green]PASS[/green]" if enforce_result.passed else "[red]FAIL[/red]"
            con.print(f"\n  Enforcement: {status} ({enforce_result.critical_count} critical, {enforce_result.high_count} high)")

        # Step 3: Resolve unknown versions
        all_packages = [p for a in agents for s in a.mcp_servers for p in s.packages]
        unresolved = [p for p in all_packages if p.version in ("latest", "unknown", "")]
        if unresolved:
            con.print(f"\n[bold blue]Resolving {len(unresolved)} package version(s)...[/bold blue]\n")
            with con.status("[bold]Querying package registries...[/bold]", spinner="dots"):
                resolved = resolve_all_versions_sync(all_packages)
            con.print(f"\n  [bold]Resolved {resolved}/{len(unresolved)} version(s).[/bold]")

        # Step 3b: Auto-discover metadata for unknown packages
        unknown_pkgs = [
            p
            for p in all_packages
            if not p.resolved_from_registry
            and not getattr(p, "auto_risk_level", None)
            and p.version not in ("unknown", "latest", "")
            and p.ecosystem in ("npm", "pypi", "PyPI")
        ]
        if unknown_pkgs and not no_scan:
            import asyncio as _asyncio_ad

            from agent_bom.autodiscover import enrich_unknown_packages

            con.print(f"\n[bold blue]Auto-discovering metadata for {len(unknown_pkgs)} package(s)...[/bold blue]\n")
            with con.status("[bold]Fetching package metadata...[/bold]", spinner="dots"):
                enriched_count = _asyncio_ad.run(enrich_unknown_packages(unknown_pkgs))
            con.print(f"  [green]✓[/green] Auto-discovered metadata for {enriched_count} package(s)")

        # Step 3c: Version drift detection
        registry_pkgs = [p for p in all_packages if p.resolved_from_registry]
        if registry_pkgs and not quiet:
            from agent_bom.registry import detect_version_drift

            drift = detect_version_drift(registry_pkgs)
            outdated = [d for d in drift if d.status == "outdated"]
            if outdated:
                con.print(f"\n[bold yellow]  {len(outdated)} outdated package(s):[/bold yellow]")
                for d in outdated:
                    con.print(f"    {d.package}: {d.installed} → {d.latest}")

        # Step 4: Vulnerability scan
        con.print()
        con.print(Rule("Vulnerability Scan", style="red"))
        con.print()
        blast_radii = []
        if no_scan:
            con.print("  [dim]Vulnerability scanning skipped (--no-scan)[/dim]")
        elif total_packages == 0:
            con.print("  [dim]No packages to scan[/dim]")
        else:
            _unique_pkgs = len({(p.name, p.version, p.ecosystem) for a in agents for s in a.mcp_servers for p in s.packages})
            with con.status(f"[bold]Scanning {_unique_pkgs} unique package(s) — OSV · NVD · KEV · EPSS...[/bold]", spinner="dots"):
                blast_radii = scan_agents_sync(agents, enable_enrichment=enrich, nvd_api_key=nvd_api_key)
            if blast_radii:
                con.print(f"  [red]⚠[/red] Scan complete — [bold]{len(blast_radii)}[/bold] finding(s)")
            else:
                con.print("  [green]✓[/green] No known vulnerabilities found")

        # Step 4a: Snyk vulnerability enrichment (optional)
        if snyk_flag and not no_scan and total_packages > 0:
            all_pkgs_for_snyk = [p for a in agents for s in a.mcp_servers for p in s.packages]
            if snyk_token:
                try:
                    from agent_bom.snyk import enrich_with_snyk_sync

                    con.print("\n[bold blue]Enriching with Snyk vulnerability data...[/bold blue]\n")
                    with con.status("[bold]Querying Snyk...[/bold]", spinner="dots"):
                        snyk_count = enrich_with_snyk_sync(all_pkgs_for_snyk, token=snyk_token, org_id=snyk_org)
                    if snyk_count:
                        con.print(f"  [green]✓[/green] Snyk: {snyk_count} additional vulnerability(ies) found")
                    else:
                        con.print("  [dim]  Snyk: no additional vulnerabilities found[/dim]")
                except Exception as exc:
                    con.print(f"  [yellow]⚠[/yellow] Snyk enrichment failed: {exc}")
            else:
                con.print("\n[yellow]  --snyk requires SNYK_TOKEN (set env var or use --snyk-token)[/yellow]")

        # Step 4b: OpenSSF Scorecard enrichment (optional)
        if scorecard_flag and not no_scan:
            all_pkgs_for_sc = [p for a in agents for s in a.mcp_servers for p in s.packages]
            if all_pkgs_for_sc:
                import asyncio as _asyncio_sc

                from agent_bom.scorecard import enrich_packages_with_scorecard

                con.print("\n[bold blue]Enriching with OpenSSF Scorecard data...[/bold blue]\n")
                try:
                    sc_count = _asyncio_sc.run(enrich_packages_with_scorecard(all_pkgs_for_sc))
                    if sc_count:
                        con.print(f"  [green]✓[/green] Scorecard: enriched {sc_count} package(s)")
                    else:
                        con.print("  [dim]  Scorecard: no packages with resolvable GitHub repos[/dim]")
                except Exception as exc:
                    con.print(f"  [yellow]⚠[/yellow] Scorecard enrichment failed: {exc}")

        # Step 4c: Integrity + provenance verification (optional)
        if verify_integrity:
            import asyncio as _asyncio

            from agent_bom.http_client import create_client as _create_client
            from agent_bom.integrity import check_package_provenance, verify_package_integrity

            all_pkgs = [pkg for agent in agents for srv in agent.mcp_servers for pkg in srv.packages]
            unique_pkgs = {f"{p.ecosystem}:{p.name}@{p.version}": p for p in all_pkgs if p.version not in ("latest", "unknown", "")}

            async def _verify_all():
                async with _create_client(timeout=15.0) as client:
                    for key, pkg in unique_pkgs.items():
                        integrity = await verify_package_integrity(pkg, client)
                        if integrity and integrity.get("verified"):
                            con.print(f"  [green]✓[/green] {pkg.name}@{pkg.version} — integrity verified (SHA256/SRI)")
                        elif integrity:
                            con.print(f"  [yellow]⚠[/yellow] {pkg.name}@{pkg.version} — no integrity hash found")

                        provenance = await check_package_provenance(pkg, client)
                        if provenance and provenance.get("has_provenance"):
                            con.print(f"  [green]✓[/green] {pkg.name}@{pkg.version} — SLSA provenance attested")
                        elif provenance:
                            con.print(f"  [dim]  {pkg.name}@{pkg.version} — no SLSA provenance[/dim]")

            if unique_pkgs:
                con.print(f"\n[bold blue]🔐 Verifying integrity for {len(unique_pkgs)} package(s)...[/bold blue]\n")
                _asyncio.run(_verify_all())

        # Step 4d: Instruction file provenance verification (optional)
        if verify_instructions:
            from agent_bom.integrity import discover_instruction_files, verify_instruction_files_batch

            project_root = Path(project or ".").resolve()
            instr_files = discover_instruction_files(project_root)
            if instr_files:
                con.print(f"\n[bold blue]🔏 Verifying instruction file provenance ({len(instr_files)} file(s))...[/bold blue]\n")
                verifications = verify_instruction_files_batch(instr_files)
                _instruction_provenance_data = []
                for v in verifications:
                    rel_path = (
                        str(Path(v.file_path).relative_to(project_root)) if v.file_path.startswith(str(project_root)) else v.file_path
                    )
                    if v.verified:
                        con.print(f"  [green]✓[/green] {rel_path} — provenance verified ({v.reason})")
                    elif v.has_sigstore_bundle:
                        con.print(f"  [yellow]⚠[/yellow] {rel_path} — bundle found but invalid ({v.reason})")
                    else:
                        con.print(f"  [dim]  {rel_path} — unsigned (sha256: {v.sha256[:12]}...)[/dim]")
                    _instruction_provenance_data.append(
                        {
                            "file": rel_path,
                            "sha256": v.sha256,
                            "verified": v.verified,
                            "has_bundle": v.has_sigstore_bundle,
                            "signer": v.signer_identity,
                            "rekor_index": v.rekor_log_index,
                            "reason": v.reason,
                        }
                    )
            else:
                con.print("\n  [dim]No instruction files found to verify.[/dim]")

        # Step 4e: Cortex agent observability (optional)
        _cortex_telemetry_data = None
        if cortex_observability and snowflake_flag:
            try:
                from agent_bom.cloud.snowflake import _get_connection
                from agent_bom.cloud.snowflake_observability import get_cortex_telemetry

                con.print("\n[bold blue]📊 Fetching Cortex agent observability telemetry...[/bold blue]\n")
                sf_conn = _get_connection()
                _cortex_telemetry_data = get_cortex_telemetry(sf_conn, hours=24)
                sf_conn.close()

                agent_count = len(_cortex_telemetry_data.get("agents", []))
                if agent_count:
                    con.print(f"  [green]✓[/green] {agent_count} Cortex agent(s) with telemetry")
                    for ag in _cortex_telemetry_data["agents"]:
                        status_color = {"healthy": "green", "degraded": "yellow", "unhealthy": "red"}.get(ag["health"]["status"], "dim")
                        con.print(
                            f"    [{status_color}]●[/{status_color}] {ag['name']}: {ag['total_calls']} calls, {ag['health']['status']}"
                        )
                else:
                    con.print("  [dim]No Cortex agent telemetry found.[/dim]")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Cortex observability failed: {exc}")

    # Build report
    # Determine scan sources for context-aware output and framework applicability
    _scan_sources: list[str] = []
    if inventory or dynamic_discovery:
        _scan_sources.append("agent_discovery")
    if images or image_tars:
        _scan_sources.append("image")
    if sbom_file:
        _scan_sources.append("sbom")
    if k8s or k8s_mcp:
        _scan_sources.append("k8s")
    if filesystem_paths:
        _scan_sources.append("filesystem")
    if tf_dirs:
        _scan_sources.append("terraform")
    if gha_path:
        _scan_sources.append("github_actions")
    if browser_extensions:
        _scan_sources.append("browser_extensions")
    if jupyter_dirs:
        _scan_sources.append("jupyter")
    if gpu_scan_flag:
        _scan_sources.append("gpu_infra")
    if not _scan_sources:
        _scan_sources.append("agent_discovery")  # Default scan type
    report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_sources=_scan_sources)
    if _skill_audit_data:
        report.skill_audit_data = _skill_audit_data
    if _trust_assessment_data:
        report.trust_assessment_data = _trust_assessment_data
    if _prompt_scan_data:
        report.prompt_scan_data = _prompt_scan_data
    if _enforcement_data:
        report.enforcement_data = _enforcement_data
    if _sast_data:
        report.sast_data = _sast_data
    if cis_benchmark_report is not None:
        report.cis_benchmark_data = cis_benchmark_report.to_dict()
    if sf_cis_benchmark_report is not None:
        report.snowflake_cis_benchmark_data = sf_cis_benchmark_report.to_dict()
    if azure_cis_benchmark_report is not None:
        report.azure_cis_benchmark_data = azure_cis_benchmark_report.to_dict()
    if gcp_cis_benchmark_report is not None:
        report.gcp_cis_benchmark_data = gcp_cis_benchmark_report.to_dict()
    if databricks_security_report is not None:
        report.databricks_cis_benchmark_data = databricks_security_report.to_dict()
    if aisvs_report is not None:
        report.aisvs_benchmark_data = aisvs_report.to_dict()
    if vector_db_results:
        report.vector_db_scan_data = [r.to_dict() for r in vector_db_results]
    if gpu_infra_report is not None:
        report.gpu_infra_data = gpu_infra_report.risk_summary

    # ── Context graph: lateral movement analysis ────────────────────
    if context_graph_flag and report.blast_radii:
        from agent_bom.context_graph import (
            build_context_graph,
            compute_interaction_risks,
            find_lateral_paths,
            to_serializable,
        )
        from agent_bom.output import to_json as _to_json_for_graph

        _graph_json = _to_json_for_graph(report)
        _cg = build_context_graph(_graph_json["agents"], _graph_json.get("blast_radius", []))
        _all_paths = []
        for _a in agents:
            _all_paths.extend(find_lateral_paths(_cg, f"agent:{_a.name}"))
        _cg_risks = compute_interaction_risks(_cg)
        report.context_graph_data = to_serializable(_cg, _all_paths, _cg_risks)

        # Centrality analysis via graph backend
        from agent_bom.graph_backend import from_context_graph as _from_cg

        _gb = _from_cg(report.context_graph_data, backend=graph_backend)
        _centrality = _gb.centrality_scores()
        _bottlenecks = _gb.bottleneck_nodes(top_n=5)
        report.context_graph_data["centrality"] = _centrality
        report.context_graph_data["bottleneck_nodes"] = [{"id": nid, "score": score} for nid, score in _bottlenecks]
        report.context_graph_data["stats"]["graph_backend"] = type(_gb).__name__

        _n_paths = len(_all_paths)
        _n_risks = len(_cg_risks)
        _n_bottlenecks = len(_bottlenecks)
        con.print(
            f"  [green]✓[/green] Context graph: {len(_cg.nodes)} nodes, {_n_paths} lateral path(s), "
            f"{_n_risks} risk pattern(s), {_n_bottlenecks} bottleneck(s)"
        )

    # ── License compliance check ─────────────────────────────────────
    if license_check and agents:
        from agent_bom.license_policy import evaluate_license_policy, print_license_report
        from agent_bom.license_policy import to_serializable as _lic_to_ser

        _lic_policy = None
        if policy:
            import json as _lic_json

            try:
                with open(policy) as _pf:
                    _raw_policy = _lic_json.load(_pf)
                    _lic_policy = {k: v for k, v in _raw_policy.items() if k.startswith("license_")}
            except Exception:
                pass  # Use default policy
        _lic_report = evaluate_license_policy(agents, policy=_lic_policy if _lic_policy else None)
        report.license_report = _lic_to_ser(_lic_report)
        if not quiet and output_format == "console":
            print_license_report(_lic_report, con)
        elif not quiet:
            _f_count = len(_lic_report.findings)
            _status = "[green]compliant[/green]" if _lic_report.compliant else "[red]non-compliant[/red]"
            con.print(f"  [green]✓[/green] License check: {_lic_report.total_packages} packages, {_f_count} finding(s), {_status}")

    # ── VEX support ──────────────────────────────────────────────────
    if vex_path and agents:
        from agent_bom.vex import apply_vex, load_vex
        from agent_bom.vex import to_serializable as _vex_to_ser

        _vex_doc = load_vex(vex_path)
        _vex_count = apply_vex(report, _vex_doc)
        report.vex_data = _vex_to_ser(_vex_doc)
        if not quiet:
            con.print(f"  [green]✓[/green] VEX applied: {_vex_count} vulnerabilities updated from {vex_path}")

    if generate_vex_flag and report.blast_radii:
        from agent_bom.vex import export_openvex, generate_vex
        from agent_bom.vex import to_serializable as _vex_to_ser

        _vex_doc = generate_vex(report, auto_triage=True)
        report.vex_data = _vex_to_ser(_vex_doc)
        _vex_out = vex_output_path or "agent-bom.vex.json"
        import json as _vex_json

        with open(_vex_out, "w") as _vf:
            _vex_json.dump(export_openvex(_vex_doc), _vf, indent=2)
        if not quiet:
            _n_stmts = len(_vex_doc.statements)
            con.print(f"  [green]✓[/green] VEX generated: {_n_stmts} statements → {_vex_out}")

    # ── Toxic combination detection ──────────────────────────────────
    if report.blast_radii and (enrich or preset == "enterprise"):
        from agent_bom.toxic_combos import detect_toxic_combinations as _detect_toxic
        from agent_bom.toxic_combos import prioritize_findings as _prioritize
        from agent_bom.toxic_combos import to_serializable as _toxic_ser

        _toxic = _detect_toxic(report, context_graph_data=report.context_graph_data)
        report.toxic_combinations = _toxic_ser(_toxic)
        report.prioritized_findings = _prioritize(report.blast_radii, _toxic)
        if not quiet and _toxic:
            _n_crit = sum(1 for t in _toxic if t.severity == "critical")
            _n_high = sum(1 for t in _toxic if t.severity == "high")
            con.print(f"  [red]![/red] Toxic combinations: {len(_toxic)} detected ({_n_crit} critical, {_n_high} high)")

    # ── Step 1i: Model binary file scan ─────────────────────────────
    if not skill_only and model_dirs:
        from agent_bom.model_files import check_sigstore_signature, scan_model_files, verify_model_hash

        for mdir in model_dirs:
            con.print(f"  [cyan]>[/cyan] Scanning for model files in {mdir}...")
            mf_results, mf_warnings = scan_model_files(mdir)
            # Provenance checks (hash + signature) when --model-provenance
            if model_provenance:
                for mf in mf_results:
                    hash_result = verify_model_hash(mf["path"])
                    mf["sha256"] = hash_result["sha256"]
                    mf["security_flags"].extend(hash_result["security_flags"])

                    sig_result = check_sigstore_signature(mf["path"])
                    mf["signed"] = sig_result["signed"]
                    mf["signature_path"] = sig_result["signature_path"]
                    mf["security_flags"].extend(sig_result["security_flags"])
            report.model_files.extend(mf_results)
            for w in mf_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if mf_results:
                security_count = sum(1 for m in mf_results if m["security_flags"])
                con.print(
                    f"    [green]{len(mf_results)} model file(s) found[/green]"
                    + (f" [red]({security_count} with security flags)[/red]" if security_count else "")
                )

    # ── Step 1j: HuggingFace model provenance ─────────────────────────
    if hf_models:
        from agent_bom.model_files import check_huggingface_provenance

        hf_provenance: list[dict] = []
        for hf_name in hf_models:
            con.print(f"  [cyan]>[/cyan] Checking HuggingFace provenance: {hf_name}...")
            hf_result = check_huggingface_provenance(hf_name)
            hf_provenance.append(hf_result)
            if hf_result["security_flags"]:
                for flag in hf_result["security_flags"]:
                    con.print(f"    [yellow]⚠[/yellow] {flag['type']}: {flag['description']}")
            else:
                author = hf_result.get("author") or "unknown"
                license_val = hf_result.get("license") or "unspecified"
                con.print(f"    [green]✓[/green] {hf_name} — author: {author}, license: {license_val}")
        report.model_provenance = hf_provenance

    # ── Step 1k: Dataset card scan ──────────────────────────────────
    if not skill_only and dataset_dirs:
        from agent_bom.parsers.dataset_cards import scan_dataset_directory

        all_datasets: list[dict] = []
        all_ds_warnings: list[str] = []
        for ddir in dataset_dirs:
            con.print(f"  [cyan]>[/cyan] Scanning for dataset cards in {ddir}...")
            ds_result = scan_dataset_directory(ddir)
            all_datasets.extend(ds_result.datasets)
            all_ds_warnings.extend(ds_result.warnings)
        if all_datasets:
            flagged = sum(1 for d in all_datasets if d.security_flags)
            con.print(
                f"    [green]{len(all_datasets)} dataset(s) found[/green]"
                + (f" [yellow]({flagged} with flags)[/yellow]" if flagged else "")
            )
            report.dataset_cards = {
                "datasets": [d.to_dict() for d in all_datasets],
                "total_datasets": len(all_datasets),
                "flagged_count": flagged,
            }
            _scan_sources.append("dataset_cards")
        for w in all_ds_warnings:
            con.print(f"  [yellow]⚠[/yellow] {w}")

    # ── Step 1l: Training pipeline scan ──────────────────────────────
    if not skill_only and training_dirs:
        from agent_bom.parsers.training_pipeline import scan_training_directory

        all_runs: list = []
        all_serving: list = []
        all_tp_warnings: list[str] = []
        for tdir in training_dirs:
            con.print(f"  [cyan]>[/cyan] Scanning for training pipelines in {tdir}...")
            tp_result = scan_training_directory(tdir)
            all_runs.extend(tp_result.training_runs)
            all_serving.extend(tp_result.serving_configs)
            all_tp_warnings.extend(tp_result.warnings)
        if all_runs:
            flagged = sum(1 for r in all_runs if r.security_flags)
            con.print(
                f"    [green]{len(all_runs)} training run(s) found[/green]"
                + (f" [yellow]({flagged} with flags)[/yellow]" if flagged else "")
            )
            report.training_pipelines = {
                "training_runs": [r.to_dict() for r in all_runs],
                "total_runs": len(all_runs),
                "flagged_count": flagged,
            }
            _scan_sources.append("training_pipelines")
        if all_serving:
            con.print(f"    [green]{len(all_serving)} serving config(s) found[/green]")
            report.serving_configs = [s.to_dict() for s in all_serving]
        for w in all_tp_warnings:
            con.print(f"  [yellow]⚠[/yellow] {w}")

    # Persist browser extension results to report
    if _browser_ext_results is not None:
        report.browser_extensions = _browser_ext_results

    # Step 4c: AI-powered enrichment (optional)
    if ai_enrich:
        from agent_bom.ai_enrich import run_ai_enrichment_sync

        run_ai_enrichment_sync(
            report,
            model=ai_model,
            skill_result=_skill_result_obj,
            skill_audit=_skill_audit_obj,
        )

        # Re-serialize skill audit data with AI enrichment fields
        if _skill_audit_obj:
            _skill_audit_data = {
                "findings": [
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "title": f.title,
                        "detail": f.detail,
                        "source_file": f.source_file,
                        "package": f.package,
                        "server": f.server,
                        "recommendation": f.recommendation,
                        "context": f.context,
                        "ai_analysis": f.ai_analysis,
                        "ai_adjusted_severity": f.ai_adjusted_severity,
                    }
                    for f in _skill_audit_obj.findings
                ],
                "packages_checked": _skill_audit_obj.packages_checked,
                "servers_checked": _skill_audit_obj.servers_checked,
                "credentials_checked": _skill_audit_obj.credentials_checked,
                "passed": _skill_audit_obj.passed,
                "ai_skill_summary": _skill_audit_obj.ai_skill_summary,
                "ai_overall_risk_level": _skill_audit_obj.ai_overall_risk_level,
            }
            report.skill_audit_data = _skill_audit_data

    # Step 4d: Generate remediation files (optional)
    if remediate_path or remediate_sh_path:
        from agent_bom.remediate import export_remediation_md, export_remediation_sh, generate_remediation

        remed_plan = generate_remediation(report, blast_radii)
        if remediate_path:
            export_remediation_md(remed_plan, remediate_path)
            con.print(f"\n  [green]✓[/green] Remediation plan: {remediate_path}")
        if remediate_sh_path:
            export_remediation_sh(remed_plan, remediate_sh_path)
            con.print(f"\n  [green]✓[/green] Remediation script: {remediate_sh_path}")

    # Step 4e: Auto-apply fixes (optional)
    if apply_fixes_flag or apply_dry_run:
        from agent_bom.remediate import apply_fixes as _apply_fixes
        from agent_bom.remediate import generate_remediation as _gen_remed

        remed_plan = _gen_remed(report, blast_radii)
        if remed_plan.package_fixes:
            # Collect project directories from agent config paths
            project_dirs = []
            for agent in agents:
                if agent.config_path:
                    config_dir = Path(agent.config_path).parent
                    # Walk up to find package.json or requirements.txt
                    for d in [config_dir, config_dir.parent, config_dir.parent.parent]:
                        if (d / "package.json").exists() or (d / "requirements.txt").exists():
                            if d not in project_dirs:
                                project_dirs.append(d)
                            break
            # Also try current working directory
            cwd = Path.cwd()
            if cwd not in project_dirs and ((cwd / "package.json").exists() or (cwd / "requirements.txt").exists()):
                project_dirs.append(cwd)

            if project_dirs:
                ar = _apply_fixes(remed_plan, project_dirs, dry_run=apply_dry_run)
                if ar.dry_run:
                    con.print("\n  [yellow]Dry run — no files modified[/yellow]")
                for fix in ar.applied:
                    con.print(f"  [green]✓[/green] {fix.package} {fix.current_version} → {fix.fixed_version} ({fix.ecosystem})")
                for fix in ar.skipped:
                    con.print(f"  [dim]  Skipped {fix.package} — no {fix.ecosystem} dependency file found[/dim]")
                if ar.backed_up:
                    con.print(f"\n  Backups: {', '.join(ar.backed_up)}")
            else:
                con.print("\n  [yellow]⚠ No project directories with dependency files found for --apply[/yellow]")
        else:
            con.print("\n  [green]✓[/green] No fixable vulnerabilities — nothing to apply")

    # Step 4f: Runtime ↔ scan correlation (optional)
    if correlate_log and blast_radii:
        from agent_bom.runtime_correlation import correlate as _correlate_runtime

        try:
            _corr_report = _correlate_runtime(blast_radii, audit_log_path=correlate_log)
            report.runtime_correlation = _corr_report.to_dict()
            if _corr_report.vulnerable_tools_called > 0:
                con.print(
                    f"\n  [red]⚠[/red] Runtime correlation: "
                    f"{_corr_report.vulnerable_tools_called} vulnerable tool(s) were actually called "
                    f"(out of {_corr_report.unique_tools_called} unique tools in audit log)"
                )
                for cf in _corr_report.correlated_findings[:5]:
                    con.print(
                        f"    [red]●[/red] {cf.vulnerability_id} → tool:{cf.tool_name} "
                        f"(called {cf.call_count}x, risk {cf.original_risk_score:.1f}→{cf.correlated_risk_score:.1f})"
                    )
            else:
                con.print(
                    f"\n  [green]✓[/green] Runtime correlation: "
                    f"no vulnerable tools were called ({_corr_report.unique_tools_called} tools in audit log)"
                )
        except Exception as e:
            con.print(f"\n  [yellow]⚠[/yellow] Runtime correlation failed: {e}")

    # Step 5: Output
    if is_stdout:
        # Pipe mode: write clean output to stdout
        if output_format == "cyclonedx":
            sys.stdout.write(json.dumps(to_cyclonedx(report), indent=2))
        elif output_format == "sarif":
            sys.stdout.write(json.dumps(to_sarif(report), indent=2))
        elif output_format == "spdx":
            sys.stdout.write(json.dumps(to_spdx(report), indent=2))
        elif output_format == "html":
            from agent_bom.output import to_html

            sys.stdout.write(to_html(report, blast_radii))
        elif output_format == "prometheus":
            sys.stdout.write(to_prometheus(report, blast_radii))
        elif output_format == "graph":
            from agent_bom.output.graph import build_graph_elements

            elements = build_graph_elements(report, blast_radii)
            sys.stdout.write(json.dumps({"elements": elements, "format": "cytoscape"}, indent=2))
        elif output_format == "mermaid":
            if mermaid_mode == "attack-flow":
                from agent_bom.output.mermaid import to_mermaid

                sys.stdout.write(to_mermaid(report, blast_radii))
            elif mermaid_mode == "lifecycle":
                from agent_bom.output.mermaid import to_mermaid_lifecycle

                sys.stdout.write(to_mermaid_lifecycle(report, blast_radii))
            else:
                from agent_bom.output.mermaid import to_mermaid_supply_chain

                sys.stdout.write(to_mermaid_supply_chain(report))
        elif output_format == "svg":
            from agent_bom.output.svg import to_svg

            sys.stdout.write(to_svg(report, blast_radii))
        elif output_format == "graph-html":
            click.echo("Error: --format graph-html requires --output/-o (cannot write HTML to stdout)", err=True)
            sys.exit(2)
        else:
            sys.stdout.write(json.dumps(to_json(report), indent=2))
        sys.stdout.write("\n")
    elif output_format == "console" and not output:
        if verbose:
            # Full output (--verbose)
            print_summary(report)
            print_posture_summary(report)
            if not no_tree:
                print_agent_tree(report)
            print_severity_chart(report)
            print_blast_radius(report)
            if not no_tree:
                print_attack_flow_tree(report)
            print_threat_frameworks(report)
        else:
            # Compact output (default)
            print_compact_summary(report)
            print_compact_agents(report)
            print_compact_blast_radius(report)

        # AI enrichment output (both modes)
        if report.executive_summary:
            from rich.panel import Panel

            con.print("\n[bold]Executive Summary (AI-Generated)[/bold]")
            con.print(Panel.fit(report.executive_summary, border_style="cyan"))
        if report.ai_threat_chains:
            from rich.panel import Panel

            con.print("\n[bold]Threat Chain Analysis (AI-Generated)[/bold]")
            for chain in report.ai_threat_chains:
                con.print(Panel(chain, border_style="red dim"))
        # AI skill analysis output (if enriched)
        if _skill_audit_obj and _skill_audit_obj.ai_skill_summary:
            from rich.panel import Panel

            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim", "safe": "green"}
            risk = _skill_audit_obj.ai_overall_risk_level or "unknown"
            risk_style = sev_colors.get(risk, "white")
            con.print(f"\n[bold]Skill File AI Analysis[/bold]  [{risk_style}]\\[{risk.upper()}][/{risk_style}]")
            con.print(Panel.fit(_skill_audit_obj.ai_skill_summary, border_style="cyan"))

            # Show AI-adjusted findings
            adjusted = [f for f in _skill_audit_obj.findings if f.ai_adjusted_severity]
            if adjusted:
                for f in adjusted:
                    if f.ai_adjusted_severity == "false_positive":
                        con.print(f"  [green]✓ FP[/green] {f.title}")
                        con.print(f"    [dim]{f.ai_analysis}[/dim]")
                    else:
                        con.print(f"  [yellow]↕ ADJ[/yellow] {f.title}: {f.severity} → {f.ai_adjusted_severity}")
                        if f.ai_analysis:
                            con.print(f"    [dim]{f.ai_analysis}[/dim]")

            # Show AI-detected new findings
            ai_detected = [f for f in _skill_audit_obj.findings if f.context == "ai_analysis"]
            if ai_detected:
                con.print(f"\n  [bold yellow]AI-Detected Threats ({len(ai_detected)})[/bold yellow]")
                for f in ai_detected:
                    style = sev_colors.get(f.severity, "white")
                    con.print(f"    [{style}]\\[{f.severity.upper()}][/{style}] {f.title}")
                    con.print(f"      [dim]{f.detail}[/dim]")
                    if f.recommendation:
                        con.print(f"      [green]→ {f.recommendation}[/green]")

        if verbose:
            print_remediation_plan(report)
            print_export_hint(report)
        else:
            print_compact_remediation(report)
            print_compact_export_hint(report)
    elif output_format == "text" and not output:
        _print_text(report, blast_radii)
    elif output_format == "json":
        out_path = output or "agent-bom-report.json"
        export_json(report, out_path)
        con.print(f"\n  [green]✓[/green] JSON report: {out_path}")
    elif output_format == "cyclonedx":
        out_path = output or "agent-bom.cdx.json"
        export_cyclonedx(report, out_path)
        con.print(f"\n  [green]✓[/green] CycloneDX BOM: {out_path}")
    elif output_format == "sarif":
        out_path = output or "agent-bom.sarif"
        export_sarif(report, out_path)
        con.print(f"\n  [green]✓[/green] SARIF report: {out_path}")
    elif output_format == "spdx":
        out_path = output or "agent-bom.spdx.json"
        export_spdx(report, out_path)
        con.print(f"\n  [green]✓[/green] SPDX 3.0 BOM: {out_path}")
    elif output_format == "html":
        out_path = output or "agent-bom-report.html"
        export_html(report, out_path, blast_radii)
        con.print(f"\n  [green]✓[/green] HTML report: {out_path}")
        if open_report:
            import webbrowser

            con.print(f"  [green]✓[/green] Opening report in browser: {out_path}")
            webbrowser.open(f"file://{Path(out_path).resolve()}")
        else:
            con.print(f"  [dim]Open with:[/dim] open {out_path}")
    elif output_format == "prometheus":
        out_path = output or "agent-bom-metrics.prom"
        export_prometheus(report, out_path, blast_radii)
        con.print(f"\n  [green]✓[/green] Prometheus metrics: {out_path}")
        con.print("  [dim]Scrape with node_exporter textfile or push via --push-gateway[/dim]")
    elif output_format == "graph":
        from agent_bom.output.graph import build_graph_elements

        out_path = output or "agent-bom-graph.json"
        elements = build_graph_elements(report, blast_radii)
        Path(out_path).write_text(json.dumps({"elements": elements, "format": "cytoscape"}, indent=2))
        con.print(f"\n  [green]✓[/green] Graph JSON: {out_path}")
        con.print("  [dim]Cytoscape.js-compatible element list — open with Cytoscape desktop or any JS graph library[/dim]")
    elif output_format == "mermaid":
        out_path = output or "agent-bom-diagram.mmd"
        if mermaid_mode == "attack-flow":
            from agent_bom.output.mermaid import to_mermaid

            Path(out_path).write_text(to_mermaid(report, blast_radii))
        elif mermaid_mode == "lifecycle":
            from agent_bom.output.mermaid import to_mermaid_lifecycle

            Path(out_path).write_text(to_mermaid_lifecycle(report, blast_radii))
        else:
            from agent_bom.output.mermaid import to_mermaid_supply_chain

            Path(out_path).write_text(to_mermaid_supply_chain(report))
        con.print(f"\n  [green]✓[/green] Mermaid diagram ({mermaid_mode}): {out_path}")
        con.print("  [dim]Render with: mermaid-cli, GitHub markdown, or mermaid.live[/dim]")
    elif output_format == "svg":
        from agent_bom.output.svg import export_svg

        out_path = output or "agent-bom-supply-chain.svg"
        export_svg(report, blast_radii, out_path)
        con.print(f"\n  [green]✓[/green] SVG diagram: {out_path}")
        con.print("  [dim]Open in any browser or image viewer[/dim]")
    elif output_format == "graph-html":
        from agent_bom.output.graph import export_graph_html

        out_path = output or "agent-bom-graph.html"
        export_graph_html(report, blast_radii, out_path)
        con.print(f"\n  [green]✓[/green] Interactive graph: {out_path}")
        if open_report:
            import webbrowser

            con.print(f"  [green]✓[/green] Opening report in browser: {out_path}")
            webbrowser.open(f"file://{Path(out_path).resolve()}")
        else:
            con.print(f"  [dim]Open with:[/dim] open {out_path}")
    elif output_format == "badge":
        out_path = output or "agent-bom-badge.json"
        export_badge(report, out_path)
        con.print(f"\n  [green]✓[/green] Badge JSON: {out_path}")
        con.print("  [dim]Use with: https://img.shields.io/endpoint?url=<public-url-to-badge-json>[/dim]")
    elif output_format == "text" and output:
        Path(output).write_text(_format_text(report, blast_radii))
        con.print(f"\n  [green]✓[/green] Text report: {output}")
    elif output:
        if output.endswith(".cdx.json"):
            export_cyclonedx(report, output)
        elif output.endswith(".sarif"):
            export_sarif(report, output)
        elif output.endswith(".spdx.json"):
            export_spdx(report, output)
        elif output.endswith(".html"):
            export_html(report, output, blast_radii)
        else:
            export_json(report, output)
        con.print(f"\n  [green]✓[/green] Report: {output}")

    # Step 5b: Push to Prometheus Pushgateway (if requested)
    if push_gateway:
        from agent_bom.output.prometheus import PushgatewayError

        try:
            push_to_gateway(push_gateway, report, blast_radii)
            con.print(f"\n  [green]✓[/green] Metrics pushed to Pushgateway: {push_gateway}")
        except PushgatewayError as e:
            con.print(f"\n  [yellow]⚠[/yellow] Pushgateway push failed: {e}")

    # Step 5c: OpenTelemetry OTLP export (if requested)
    if otel_endpoint:
        try:
            push_otlp(otel_endpoint, report, blast_radii)
            con.print(f"\n  [green]✓[/green] Metrics exported via OTLP: {otel_endpoint}")
        except ImportError as e:
            con.print(f"\n  [yellow]⚠[/yellow] OTel export skipped: {e}")
        except Exception as e:  # noqa: BLE001
            con.print(f"\n  [yellow]⚠[/yellow] OTLP export failed: {e}")

    # Step 5d: Compliance evidence export (if requested)
    if compliance_export:
        from agent_bom.output import export_compliance_bundle

        ce_path = output or f"compliance-{compliance_export}.zip"
        if not ce_path.endswith(".zip"):
            ce_path += ".zip"
        export_compliance_bundle(report, compliance_export, ce_path)
        con.print(f"\n  [green]✓[/green] Compliance bundle: {ce_path}")

    # Step 6: Save report to history + asset tracking
    current_report_json = to_json(report)
    if save_report:
        from agent_bom.history import save_report as _save

        saved_path = _save(current_report_json)
        con.print(f"\n  [green]✓[/green] Report saved to history: {saved_path}")

        # Update persistent asset tracker (first_seen / last_seen / resolved)
        try:
            from agent_bom.asset_tracker import AssetTracker

            tracker = AssetTracker()
            asset_diff = tracker.record_scan(current_report_json)
            summary = asset_diff["summary"]
            parts = []
            if summary["new_count"]:
                parts.append(f"[red]{summary['new_count']} new[/red]")
            if summary["resolved_count"]:
                parts.append(f"[green]{summary['resolved_count']} resolved[/green]")
            if summary["reopened_count"]:
                parts.append(f"[yellow]{summary['reopened_count']} reopened[/yellow]")
            if parts:
                con.print(f"  [green]✓[/green] Asset tracker: {', '.join(parts)} ({summary['total_open']} open)")
            else:
                con.print(f"  [green]✓[/green] Asset tracker: {summary['total_open']} open (no changes)")
            tracker.close()
        except Exception:
            pass  # asset tracking is best-effort

    # Step 7: Diff against baseline
    if baseline:
        from agent_bom.history import diff_reports, load_report

        baseline_data = load_report(Path(baseline))
        diff = diff_reports(baseline_data, current_report_json)
        print_diff(diff)

    # Step 7b: Policy evaluation
    policy_passed = True
    if policy and blast_radii:
        from agent_bom.policy import evaluate_policy, load_policy

        try:
            policy_data = load_policy(policy)
            policy_result = evaluate_policy(policy_data, blast_radii)
            print_policy_results(policy_result)
            policy_passed = policy_result["passed"]

            # Fire Jira actions for rules with action: "jira"
            jira_viol = policy_result.get("jira_violations", [])
            if jira_viol and jira_url and jira_token and jira_project:
                from agent_bom.policy import fire_policy_jira_actions

                n = fire_policy_jira_actions(
                    policy_result=policy_result,
                    jira_url=jira_url,
                    email=jira_user or "",
                    api_token=jira_token,
                    project_key=jira_project,
                )
                if n:
                    con.print(f"  [green]✓[/green] Policy: created {n} Jira ticket(s) for policy violations")
            elif jira_viol and not (jira_url and jira_token and jira_project):
                con.print(
                    f"  [yellow]⚠[/yellow]  Policy: {len(jira_viol)} rule(s) have action='jira' but "
                    "--jira-url/--jira-token/--jira-project are not set"
                )
        except (FileNotFoundError, ValueError) as e:
            con.print(f"\n  [red]Policy error: {e}[/red]")
            sys.exit(1)

    # Step 7c: ClickHouse analytics (optional, post-scan)
    if clickhouse_url and blast_radii:
        try:
            import uuid as _uuid_ch

            from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

            _ch_store = ClickHouseAnalyticsStore(url=clickhouse_url)
            _scan_id = str(_uuid_ch.uuid4())
            vuln_dicts = [
                {
                    "package": br.package.name,
                    "version": br.package.version,
                    "ecosystem": br.package.ecosystem,
                    "cve_id": br.vulnerability.id,
                    "cvss_score": getattr(br.vulnerability, "cvss_score", 0.0) or 0.0,
                    "epss_score": getattr(br.vulnerability, "epss_score", 0.0) or 0.0,
                    "severity": br.vulnerability.severity.value.lower(),
                    "source": getattr(br.vulnerability, "source", "osv"),
                }
                for br in blast_radii
            ]
            for agent in agents:
                _ch_store.record_scan(_scan_id, agent.name, vuln_dicts)
            if not quiet:
                con.print(f"  [green]✓[/green] Analytics: {len(vuln_dicts)} finding(s) recorded to ClickHouse")
        except Exception as _ch_exc:
            if not quiet:
                con.print(f"  [yellow]⚠[/yellow] ClickHouse analytics: {_ch_exc}")

    # Scan completion divider
    _elapsed = _time.monotonic() - _scan_start
    if output_format == "console" and not output and not quiet:
        con.print()
        con.print(Rule(f"Scan Complete — {_elapsed:.1f}s", style="green" if not blast_radii else "yellow"))

    # Step 8: Enterprise integrations (optional, post-scan)
    if blast_radii and (slack_webhook or jira_url or vanta_token or drata_token):
        import asyncio as _asyncio_int

        findings = []
        for br in blast_radii:
            findings.append(
                {
                    "vulnerability_id": br.vulnerability.id,
                    "severity": br.vulnerability.severity.value.lower(),
                    "package": f"{br.package.name}@{br.package.version}",
                    "risk_score": br.risk_score,
                    "affected_agents": [a.name for a in br.affected_agents] if br.affected_agents else [],
                    "affected_servers": [s.name for s in br.affected_servers] if br.affected_servers else [],
                    "exposed_credentials": list(br.exposed_credentials) if br.exposed_credentials else [],
                    "fixed_version": br.vulnerability.fixed_version,
                    "owasp_tags": list(br.owasp_tags) if br.owasp_tags else [],
                    "owasp_mcp_tags": list(br.owasp_mcp_tags) if br.owasp_mcp_tags else [],
                    "atlas_tags": list(br.atlas_tags) if br.atlas_tags else [],
                    "nist_ai_rmf_tags": list(br.nist_ai_rmf_tags) if br.nist_ai_rmf_tags else [],
                }
            )

        if slack_webhook and findings:
            try:
                from agent_bom.integrations.slack import build_summary_message, send_slack_alert, send_slack_payload

                async def _send_slack():
                    for f in findings[:10]:  # Cap at 10 individual alerts
                        await send_slack_alert(slack_webhook, f)
                    if len(findings) > 1:
                        summary = build_summary_message(findings)
                        await send_slack_payload(slack_webhook, summary)

                _asyncio_int.run(_send_slack())
                con.print(f"  [green]✓[/green] Slack: sent {min(len(findings), 10)} alert(s)")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Slack alert failed: {exc}")

        if jira_url and jira_token and jira_project and findings:
            try:
                from agent_bom.integrations.jira import create_jira_ticket

                async def _create_jira():
                    created = 0
                    for f in findings[:20]:  # Cap at 20 tickets
                        await create_jira_ticket(jira_url, jira_user or "", jira_token, jira_project, f)
                        created += 1
                    return created

                jira_count = _asyncio_int.run(_create_jira())
                con.print(f"  [green]✓[/green] Jira: created {jira_count} ticket(s)")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Jira ticket creation failed: {exc}")

        if vanta_token and findings:
            try:
                from agent_bom.integrations.vanta import upload_evidence

                _asyncio_int.run(upload_evidence(vanta_token, findings))
                con.print("  [green]✓[/green] Vanta: evidence uploaded")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Vanta upload failed: {exc}")

        if drata_token and findings:
            try:
                from agent_bom.integrations.drata import upload_evidence

                _asyncio_int.run(upload_evidence(drata_token, findings))
                con.print("  [green]✓[/green] Drata: evidence uploaded")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Drata upload failed: {exc}")

    # SIEM push — convert blast_radii to OCSF/raw events and send to configured SIEM
    if siem_type and siem_url and blast_radii:
        try:
            from agent_bom.siem import SIEMConfig, create_connector, format_event

            siem_config = SIEMConfig(
                name=siem_type,
                url=siem_url,
                token=siem_token or "",
                index=siem_index or "agent-bom-alerts",
            )
            connector = create_connector(siem_type, siem_config)

            # Build one event per blast radius finding
            events: list[dict] = []
            for br in blast_radii:
                raw = {
                    "type": "scan_alert",
                    "severity": br.vulnerability.severity.value,
                    "message": f"{br.vulnerability.id} in {br.package.name}@{br.package.version}",
                    "vulnerability_id": br.vulnerability.id,
                    "package": br.package.name,
                    "version": br.package.version,
                    "ecosystem": br.package.ecosystem,
                    "is_kev": br.vulnerability.is_kev,
                    "affected_agents": [a.name for a in br.affected_agents],
                    "exposed_credentials": br.exposed_credentials,
                    "atlas_tags": getattr(br, "atlas_tags", []),
                    "attack_tags": getattr(br, "attack_tags", []),
                    "owasp_tags": getattr(br, "owasp_tags", []),
                }
                events.append(format_event(raw, siem_format))

            sent = connector.send_batch(events)
            con.print(f"  [green]✓[/green] SIEM ({siem_type}): pushed {sent}/{len(events)} event(s)")
        except Exception as exc:
            con.print(f"  [yellow]⚠[/yellow] SIEM push failed: {exc}")
    elif siem_type and not siem_url:
        con.print(f"  [yellow]⚠[/yellow] --siem {siem_type} set but --siem-url is required")

    # Step 9: Exit code based on policy flags
    exit_code = 0

    # Filter blast radii to exclude VEX-suppressed vulnerabilities (not_affected / fixed)
    from agent_bom.vex import is_vex_suppressed as _is_vex_suppressed

    _active_blast_radii = [br for br in blast_radii if not _is_vex_suppressed(br.vulnerability)]

    if fail_on_severity and _active_blast_radii:
        threshold = SEVERITY_ORDER.get(fail_on_severity, 0)
        for br in _active_blast_radii:
            sev = br.vulnerability.severity.value.lower()
            if SEVERITY_ORDER.get(sev, 0) >= threshold:
                if not quiet:
                    con.print(f"\n  [red]Exiting with code 1: found {sev} vulnerability ({br.vulnerability.id})[/red]")
                exit_code = 1
                break

    if fail_on_kev and _active_blast_radii:
        kev_findings = [br for br in _active_blast_radii if br.vulnerability.is_kev]
        if kev_findings:
            if not quiet:
                con.print(
                    f"\n  [red bold]Exiting with code 1: {len(kev_findings)} CISA KEV "
                    f"finding(s) found (use --enrich if not already)[/red bold]"
                )
            exit_code = 1

    if fail_if_ai_risk and _active_blast_radii:
        ai_findings = [br for br in _active_blast_radii if br.ai_risk_context and br.exposed_credentials]
        if ai_findings:
            if not quiet:
                con.print(
                    f"\n  [red bold]Exiting with code 1: {len(ai_findings)} AI framework "
                    f"package(s) with vulnerabilities and exposed credentials[/red bold]"
                )
            exit_code = 1

    if not policy_passed:
        exit_code = 1

    # ── Push results to central dashboard ──
    if push_url and report:
        try:
            from agent_bom.push import push_results as _push

            report_data = to_json(report)
            ok = _push(push_url, report_data, api_key=push_api_key)
            if ok and not quiet:
                con.print(f"\n  [green]Results pushed to {push_url}[/green]")
            elif not ok and not quiet:
                con.print(f"\n  [yellow]Push to {push_url} failed[/yellow]")
        except Exception as push_err:
            if not quiet:
                con.print(f"\n  [yellow]Push failed: {push_err}[/yellow]")

    if exit_code:
        sys.exit(exit_code)


def _format_text(report: AIBOMReport, blast_radii: list) -> str:
    """Plain text output for piping to grep/awk."""
    lines = []
    lines.append(f"agent-bom {report.tool_version}")
    lines.append(
        f"agents={report.total_agents} servers={report.total_servers} "
        f"packages={report.total_packages} vulnerabilities={report.total_vulnerabilities}"
    )
    lines.append("")

    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                lines.append(f"{agent.name}\t{server.name}\t{pkg.ecosystem}\t{pkg.name}\t{pkg.version}")

    if blast_radii:
        lines.append("")
        lines.append("VULN_ID\tSEVERITY\tPACKAGE\tFIX\tAGENTS\tCREDENTIALS")
        for br in blast_radii:
            v = br.vulnerability
            lines.append(
                f"{v.id}\t{v.severity.value}\t{br.package.name}@{br.package.version}\t"
                f"{v.fixed_version or '-'}\t{len(br.affected_agents)}\t{len(br.exposed_credentials)}"
            )

    return "\n".join(lines) + "\n"


def _print_text(report: AIBOMReport, blast_radii: list) -> None:
    """Print plain text to stdout."""
    sys.stdout.write(_format_text(report, blast_radii))


@main.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to specific MCP config file")
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan")
@click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages")
@click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results")
def inventory(config: Optional[str], project: Optional[str], transitive: bool, max_depth: int, quiet: bool):
    """Show discovered agents and MCP servers (no vulnerability scan)."""
    con = _make_console(quiet=quiet)

    import agent_bom.output as _out

    _out.console = con

    con.print(BANNER, style="bold blue")

    if config:
        config_path = Path(config)
        try:
            config_data = json.loads(config_path.read_text())
            from agent_bom.discovery import parse_mcp_config
            from agent_bom.models import Agent, AgentType

            servers = parse_mcp_config(config_data, str(config_path))
            agents = (
                [
                    Agent(
                        name=f"custom:{config_path.stem}",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(config_path),
                        mcp_servers=servers,
                    )
                ]
                if servers
                else []
            )
        except Exception as e:
            con.print(f"[red]Error parsing config: {e}[/red]")
            sys.exit(1)
    else:
        agents = discover_all(project_dir=project)

    if not agents:
        con.print("\n[yellow]No MCP configurations found.[/yellow]")
        sys.exit(0)

    con.print("\n[bold blue]Extracting package dependencies...[/bold blue]\n")
    if transitive:
        con.print(f"  [cyan]Transitive resolution enabled (max depth: {max_depth})[/cyan]\n")

    for agent in agents:
        for server in agent.mcp_servers:
            if server.security_blocked:
                continue  # Don't extract from security-blocked servers
            server.packages = extract_packages(server, resolve_transitive=transitive, max_depth=max_depth)

    report = AIBOMReport(agents=agents)
    print_summary(report)
    print_agent_tree(report)


@main.command()
@click.argument("inventory_file", type=click.Path(exists=True))
def validate(inventory_file: str):
    """Validate an inventory file against the agent-bom schema.

    \b
    Exit codes:
      0  Valid — inventory matches the schema
      1  Invalid — schema violations found
    """
    console = Console()
    console.print(BANNER, style="bold blue")

    try:
        import jsonschema
    except ImportError:
        console.print("[red]jsonschema not installed. Run: pip install jsonschema[/red]")
        sys.exit(1)

    schema_path = Path(__file__).parent.parent.parent / "schemas" / "inventory.schema.json"
    if not schema_path.exists():
        # Fallback: look relative to installed package
        import importlib.resources

        try:
            schema_path = Path(str(importlib.resources.files("agent_bom"))) / ".." / ".." / "schemas" / "inventory.schema.json"
        except Exception:
            schema_path = None

    if not schema_path or not schema_path.exists():
        console.print("[red]Schema file not found. Run from the agent-bom repo root.[/red]")
        sys.exit(1)

    with open(schema_path) as f:
        schema = json.load(f)

    with open(inventory_file) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            console.print(f"[red]JSON parse error: {e}[/red]")
            sys.exit(1)

    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))

    if not errors:
        agents = data.get("agents", [])
        total_servers = sum(len(a.get("mcp_servers", [])) for a in agents)
        total_packages = sum(len(s.get("packages", [])) for a in agents for s in a.get("mcp_servers", []))
        console.print(f"\n  [green]✓ Valid[/green] — {len(agents)} agent(s), {total_servers} server(s), {total_packages} package(s)")
        console.print(f"\n  [dim]Scan with:[/dim] agent-bom scan --inventory {inventory_file}")
    else:
        console.print(f"\n  [red]✗ Invalid — {len(errors)} error(s):[/red]\n")
        for err in errors:
            path = " → ".join(str(p) for p in err.path) or "(root)"
            console.print(f"  [red]•[/red] [bold]{path}[/bold]: {err.message}")
        console.print()
        sys.exit(1)


@main.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON for machine consumption")
def where(as_json: bool):
    """Show where agent-bom looks for MCP configurations.

    Lists every config path that would be checked during auto-discovery,
    grouped by MCP client. Paths that exist on your system are marked with ✓.

    Use --json for machine-readable output (useful for auditing).
    """
    import shutil

    from agent_bom.discovery import (
        AGENT_BINARIES,
        COMPOSE_FILE_NAMES,
        CONFIG_LOCATIONS,
        PROJECT_CONFIG_FILES,
        expand_path,
        get_all_discovery_paths,
        get_platform,
    )

    current_platform = get_platform()

    if as_json:
        import json as _json

        entries = []
        for client, path in get_all_discovery_paths(current_platform):
            expanded = str(expand_path(path)) if not path.startswith(".") else path
            entries.append(
                {
                    "client": client,
                    "path": path,
                    "expanded": expanded,
                    "exists": expand_path(path).exists() if not path.startswith(".") else Path(path).exists(),
                }
            )
        click.echo(_json.dumps({"platform": current_platform, "paths": entries}, indent=2))
        return

    console = Console()
    console.print(BANNER, style="bold blue")
    console.print("\n[bold]MCP Client Configuration Locations[/bold]\n")

    total_paths = 0
    found_paths = 0

    for agent_type, platforms in CONFIG_LOCATIONS.items():
        paths = platforms.get(current_platform, [])
        binary = AGENT_BINARIES.get(agent_type)
        binary_status = ""
        if binary:
            if shutil.which(binary):
                binary_status = f" [green](binary: {binary} found)[/green]"
            else:
                binary_status = f" [dim](binary: {binary} not found)[/dim]"

        console.print(f"\n  [bold cyan]{agent_type.value}[/bold cyan]{binary_status}")
        if paths:
            for p in paths:
                total_paths += 1
                expanded = expand_path(p)
                exists = "✓" if expanded.exists() else "✗"
                style = "green" if expanded.exists() else "dim"
                if expanded.exists():
                    found_paths += 1
                console.print(f"    [{style}]{exists} {expanded}[/{style}]")
        else:
            console.print(f"    [dim]  (CLI-based discovery via {binary or 'N/A'})[/dim]")

    # Docker MCP Toolkit paths
    console.print("\n  [bold cyan]Docker MCP Toolkit[/bold cyan]")
    for dp in ["~/.docker/mcp/registry.yaml", "~/.docker/mcp/catalogs/docker-mcp.yaml"]:
        total_paths += 1
        expanded = expand_path(dp)
        exists = "✓" if expanded.exists() else "✗"
        style = "green" if expanded.exists() else "dim"
        if expanded.exists():
            found_paths += 1
        console.print(f"    [{style}]{exists} {expanded}[/{style}]")

    console.print("\n  [bold cyan]Project-level configs[/bold cyan]  [dim](relative to CWD)[/dim]")
    for config_name in PROJECT_CONFIG_FILES:
        total_paths += 1
        exists = Path(config_name).exists()
        mark = "✓" if exists else "✗"
        style = "green" if exists else "dim"
        if exists:
            found_paths += 1
        console.print(f"    [{style}]{mark} ./{config_name}[/{style}]")

    console.print("\n  [bold cyan]Docker Compose files[/bold cyan]  [dim](relative to CWD)[/dim]")
    for cf in COMPOSE_FILE_NAMES:
        total_paths += 1
        exists = Path(cf).exists()
        mark = "✓" if exists else "✗"
        style = "green" if exists else "dim"
        if exists:
            found_paths += 1
        console.print(f"    [{style}]{mark} ./{cf}[/{style}]")

    console.print(f"\n  [bold]Total:[/bold] {total_paths} paths checked, {found_paths} found on this system")


def _parse_package_spec(
    package_spec: str,
    ecosystem: Optional[str] = None,
) -> tuple[str, str, str]:
    """Parse a package spec into (name, version, ecosystem).

    Handles npx/uvx prefixes, scoped npm packages, and name@version.
    """
    spec = package_spec.strip()
    if spec.startswith("npx ") or spec.startswith("uvx "):
        parts = spec.split()
        pkg_args = [p for p in parts[1:] if not p.startswith("-")]
        spec = pkg_args[0] if pkg_args else spec
        if not ecosystem:
            ecosystem = "pypi" if package_spec.startswith("uvx") else "npm"

    if "@" in spec and not spec.startswith("@"):
        name, version = spec.rsplit("@", 1)
    elif spec.startswith("@") and spec.count("@") > 1:
        last_at = spec.rindex("@")
        name, version = spec[:last_at], spec[last_at + 1 :]
    else:
        name, version = spec, "unknown"

    if not ecosystem:
        if name.startswith("@") or "-" in name and "." not in name:
            ecosystem = "npm"
        else:
            ecosystem = "pypi"

    return name, version, ecosystem


@main.command()
@click.argument("package_spec")
@click.option(
    "--ecosystem",
    "-e",
    type=click.Choice(["npm", "pypi", "go", "cargo", "maven", "nuget"]),
    help="Package ecosystem (inferred from name/command if omitted)",
)
@click.option("--quiet", "-q", is_flag=True, help="Only print vuln count, no details")
@click.option("--no-color", is_flag=True, help="Disable colored output")
def check(package_spec: str, ecosystem: Optional[str], quiet: bool, no_color: bool):
    """Check a package for known vulnerabilities before installing.

    \b
    Examples:
      agent-bom check express@4.18.2 --ecosystem npm
      agent-bom check requests@2.28.0 --ecosystem pypi
      agent-bom check "npx @modelcontextprotocol/server-filesystem"

    \b
    Exit codes:
      0  Clean — no known vulnerabilities
      1  Unsafe — vulnerabilities found
    """
    import asyncio

    console = Console(no_color=no_color)

    name, version, ecosystem = _parse_package_spec(package_spec, ecosystem)

    from agent_bom.models import Package
    from agent_bom.scanners import build_vulnerabilities, query_osv_batch

    pkg = Package(name=name, version=version, ecosystem=ecosystem)

    if version == "unknown":
        console.print(f"[yellow]⚠ No version specified for {name} — skipping OSV lookup.[/yellow]")
        console.print("  Provide a version: agent-bom check name@version --ecosystem ecosystem")
        sys.exit(0)

    # Resolve "latest" / empty version from npm/PyPI registry
    if version in ("latest", ""):
        from agent_bom.http_client import create_client
        from agent_bom.resolver import resolve_package_version

        async def _resolve() -> bool:
            async with create_client(timeout=15.0) as client:
                return await resolve_package_version(pkg, client)

        with console.status("[bold]Resolving version from registry...[/bold]", spinner="dots"):
            resolved = asyncio.run(_resolve())
        if resolved:
            console.print(f"  [green]✓ Resolved @latest → {pkg.version}[/green]")
            version = pkg.version
        else:
            console.print(f"[yellow]⚠ Could not resolve latest version for {name} ({ecosystem})[/yellow]")
            console.print("  Provide an explicit version: agent-bom check name@1.2.3 -e ecosystem")
            sys.exit(0)

    console.print(f"\n[bold blue]🔍 Checking {name}@{version} ({ecosystem})[/bold blue]\n")

    with console.status("[bold]Querying OSV...[/bold]", spinner="dots"):
        results = asyncio.run(query_osv_batch([pkg]))
    key = f"{ecosystem}:{name}@{version}"
    vuln_data = results.get(key, [])

    if not vuln_data:
        console.print(f"  [green]✓ No known vulnerabilities in {name}@{version}[/green]\n")
        sys.exit(0)

    vulns = build_vulnerabilities(vuln_data, pkg)

    if not quiet:
        from rich.table import Table

        table = Table(title=f"{name}@{version} — {len(vulns)} vulnerability/ies found")
        table.add_column("ID", width=20)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6, justify="right")
        table.add_column("Fix", width=15)
        table.add_column("Summary", max_width=50)

        severity_styles = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
        }
        for v in vulns:
            sev = v.severity.value.lower()
            style = severity_styles.get(sev, "white")
            fix_display = f"[green]✓ {v.fixed_version}[/green]" if v.fixed_version else "[red dim]No fix[/red dim]"
            # Show summary; fall back to aliases list if empty
            summary_text = v.summary or ""
            if not summary_text or summary_text == "No description available":
                aliases_str = ", ".join(v.aliases[:3]) if v.aliases else ""
                summary_text = f"[dim]See {aliases_str}[/dim]" if aliases_str else "[dim]No description[/dim]"
            table.add_row(
                v.id,
                f"[{style} reverse] {v.severity.value.upper()} [/{style} reverse]",
                f"{v.cvss_score:.1f}" if v.cvss_score else "—",
                fix_display,
                summary_text[:100],
            )
        console.print(table)
        console.print()

    console.print(f"  [red]✗ {len(vulns)} vulnerability/ies found — do not install without review.[/red]\n")
    sys.exit(1)


@main.command()
@click.argument("package_spec", required=False, default=None)
@click.option(
    "--ecosystem",
    "-e",
    type=click.Choice(["npm", "pypi"]),
    help="Package ecosystem (default: pypi for self-verify)",
)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Only print verdict, no details")
def verify(package_spec: Optional[str], ecosystem: Optional[str], as_json: bool, quiet: bool):
    """Verify package integrity and provenance against registries.

    \b
    Self-verify (no arguments):
      agent-bom verify              check THIS installation of agent-bom

    \b
    Verify any package:
      agent-bom verify requests@2.28.0 -e pypi
      agent-bom verify @modelcontextprotocol/server-filesystem@2025.1.14 -e npm

    \b
    Exit codes:
      0  Verified — integrity and provenance checks passed
      1  Unverified — one or more checks failed
      2  Error — could not complete verification
    """
    import asyncio

    from agent_bom.http_client import create_client
    from agent_bom.integrity import (
        check_package_provenance,
        fetch_pypi_release_metadata,
        verify_installed_record,
        verify_package_integrity,
    )
    from agent_bom.models import Package

    console = Console()
    if not quiet:
        console.print(BANNER, style="bold blue")

    # Determine target
    if package_spec is None:
        name, version, eco = "agent-bom", __version__, "pypi"
        if not quiet:
            console.print(f"\n[bold blue]Verifying agent-bom {version} installation...[/bold blue]\n")
        record_result = verify_installed_record("agent-bom")
    else:
        name, version, eco = _parse_package_spec(package_spec, ecosystem)
        record_result = None
        if not quiet:
            console.print(f"\n[bold blue]Verifying {name}@{version} ({eco})...[/bold blue]\n")

    if version in ("unknown", ""):
        console.print("[red]Error: version required. Use name@version format.[/red]")
        sys.exit(2)

    checks: dict[str, dict] = {}
    exit_code = 0

    # RECORD check (self-verify only)
    if record_result is not None:
        if record_result["installed_version"] is None:
            console.print("[red]Error: agent-bom is not installed as a package.[/red]")
            sys.exit(2)
        if not record_result["record_available"]:
            checks["record_integrity"] = {
                "status": "unknown",
                "detail": "RECORD not available (editable install?)",
            }
        elif record_result["record_intact"]:
            checks["record_integrity"] = {
                "status": "pass",
                "detail": f"{record_result['verified_files']}/{record_result['total_files']} files verified",
            }
        else:
            failed = record_result["failed_files"]
            checks["record_integrity"] = {
                "status": "fail",
                "detail": f"{len(failed)} file(s) tampered: {', '.join(failed[:3])}",
            }
            exit_code = 1

    # Registry + provenance checks (async)
    async def _verify():
        async with create_client(timeout=15.0) as client:
            pkg = Package(name=name, version=version, ecosystem=eco)
            integrity = await verify_package_integrity(pkg, client)
            provenance = await check_package_provenance(pkg, client)
            pypi_meta = None
            if eco == "pypi":
                pypi_meta = await fetch_pypi_release_metadata(name, version, client)
            return integrity, provenance, pypi_meta

    try:
        integrity, provenance, pypi_meta = asyncio.run(_verify())
    except Exception as exc:
        console.print(f"[red]Error during verification: {exc}[/red]")
        sys.exit(2)

    # Registry hash check
    if integrity and integrity.get("verified"):
        hash_val = integrity.get("sha256") or integrity.get("sha512_sri") or "present"
        checks["registry_hash"] = {
            "status": "pass",
            "detail": f"sha256:{hash_val[:16]}..." if len(str(hash_val)) > 16 else str(hash_val),
        }
    elif integrity:
        checks["registry_hash"] = {"status": "fail", "detail": "No hash found on registry"}
        exit_code = 1
    else:
        checks["registry_hash"] = {"status": "unknown", "detail": "Could not reach registry"}

    # Provenance check
    if provenance and provenance.get("has_provenance"):
        att_count = provenance.get("attestation_count", 0)
        checks["provenance"] = {
            "status": "pass",
            "detail": f"Attestation found ({att_count} attestation(s))",
        }
    elif provenance:
        checks["provenance"] = {"status": "unknown", "detail": "No provenance attestation"}
    else:
        checks["provenance"] = {"status": "unknown", "detail": "Could not check provenance"}

    # Metadata consistency (self-verify with pypi_meta only)
    if pypi_meta and record_result:
        local_meta = record_result.get("metadata", {})
        mismatches = []
        if pypi_meta.get("version") != version:
            mismatches.append("version")
        pypi_repo = pypi_meta.get("source_repo", "")
        local_repo = local_meta.get("source_repo", "")
        if pypi_repo and local_repo and pypi_repo != local_repo:
            mismatches.append("source_repo")
        if mismatches:
            checks["metadata_match"] = {
                "status": "fail",
                "detail": f"Mismatch: {', '.join(mismatches)}",
            }
            exit_code = 1
        else:
            checks["metadata_match"] = {"status": "pass", "detail": "version, source match PyPI"}

    # JSON output
    if as_json:
        output = {
            "package": name,
            "version": version,
            "ecosystem": eco,
            "checks": checks,
            "verdict": "verified" if exit_code == 0 else "unverified",
        }
        if pypi_meta:
            output["source_repo"] = pypi_meta.get("source_repo", "")
            output["license"] = pypi_meta.get("license", "")
        click.echo(json.dumps(output, indent=2))
        sys.exit(exit_code)

    # Quiet output
    if quiet:
        verdict = "VERIFIED" if exit_code == 0 else "UNVERIFIED"
        console.print(f"{name}@{version}: {verdict}")
        sys.exit(exit_code)

    # Rich table output
    from rich.table import Table

    status_icons = {"pass": "[green]PASS[/green]", "fail": "[red]FAIL[/red]", "unknown": "[yellow]UNKNOWN[/yellow]"}
    check_labels = {
        "record_integrity": "RECORD integrity",
        "registry_hash": "Registry SHA-256",
        "provenance": "Provenance attestation",
        "metadata_match": "Metadata consistency",
    }

    table = Table(title=f"{name}@{version} ({eco})", show_header=True)
    table.add_column("Check", width=25)
    table.add_column("Status", width=10, justify="center")
    table.add_column("Detail", max_width=60)

    for key in ["record_integrity", "registry_hash", "provenance", "metadata_match"]:
        if key in checks:
            c = checks[key]
            table.add_row(check_labels[key], status_icons[c["status"]], c["detail"])

    console.print(table)

    # Source info
    if pypi_meta:
        console.print(f"\n  Source:  {pypi_meta.get('source_repo', 'N/A')}")
        console.print(f"  License: {pypi_meta.get('license', 'N/A')}")

    if exit_code == 0:
        console.print(f"\n  [bold green]VERIFIED[/bold green] — {name}@{version} integrity confirmed\n")
    else:
        console.print("\n  [bold red]UNVERIFIED[/bold red] — one or more checks failed\n")

    sys.exit(exit_code)


@main.command("history")
@click.option("--limit", "-n", type=int, default=10, help="Number of recent scans to show")
def history_cmd(limit: int):
    """List saved scan reports from ~/.agent-bom/history/."""
    from agent_bom.history import list_reports, load_report

    console = Console()
    console.print(BANNER, style="bold blue")

    reports = list_reports()
    if not reports:
        console.print("\n  [dim]No saved scans yet. Run with --save to start tracking history.[/dim]\n")
        return

    console.print(f"\n[bold blue]📂 Scan History[/bold blue]  ({len(reports)} total, showing {min(limit, len(reports))})\n")

    from rich.table import Table

    table = Table()
    table.add_column("File", width=30)
    table.add_column("Generated", width=22)
    table.add_column("Agents", width=7, justify="center")
    table.add_column("Packages", width=9, justify="center")
    table.add_column("Vulns", width=6, justify="center")
    table.add_column("Critical", width=9, justify="center")

    for path in reports[:limit]:
        try:
            data = load_report(path)
            summary = data.get("summary", {})
            table.add_row(
                path.name,
                data.get("generated_at", "unknown")[:19].replace("T", " "),
                str(summary.get("total_agents", "?")),
                str(summary.get("total_packages", "?")),
                str(summary.get("total_vulnerabilities", "?")),
                str(summary.get("critical_findings", "?")),
            )
        except Exception:
            table.add_row(path.name, "—", "—", "—", "—", "—")

    console.print(table)
    console.print(f"\n  [dim]History directory: {reports[0].parent}[/dim]\n")


@main.command("diff")
@click.argument("baseline", type=click.Path(exists=True))
@click.argument("current", type=click.Path(exists=True), required=False)
def diff_cmd(baseline: str, current: Optional[str]):
    """Diff two scan reports to see what changed.

    \b
    Usage:
      agent-bom diff baseline.json                # diff against latest saved scan
      agent-bom diff baseline.json current.json   # diff two specific files

    \b
    Exit codes:
      0  No new findings
      1  New vulnerability findings detected
    """
    from agent_bom.history import diff_reports, latest_report, load_report

    console = Console()

    baseline_data = load_report(Path(baseline))

    if current:
        current_data = load_report(Path(current))
    else:
        latest = latest_report()
        if not latest:
            console.print("[red]No saved scans in history. Run: agent-bom scan --save[/red]")
            sys.exit(1)
        current_data = load_report(latest)

    diff = diff_reports(baseline_data, current_data)
    print_diff(diff)

    if diff["summary"]["new_findings"] > 0:
        sys.exit(1)


@main.command("rescan")
@click.argument("baseline", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=str,
    default=None,
    help="Write verification report to this JSON file",
)
@click.option(
    "--md",
    type=str,
    default=None,
    help="Write human-readable verification report to this Markdown file",
)
@click.option("--enrich", is_flag=True, default=False, help="Enrich re-scan with NVD/EPSS/CISA KEV data")
def rescan_command(baseline: str, output: Optional[str], md: Optional[str], enrich: bool):
    """Re-scan previously vulnerable packages to verify remediation.

    Loads a prior scan result, extracts all vulnerable packages, forces a fresh
    OSV query (bypassing cache), and shows what was resolved vs what remains.

    \b
    Typical remediation verification workflow:
      agent-bom scan --format json --output before.json
      # ... apply fixes: agent-bom apply before.json  OR  pip install -U ...
      agent-bom rescan before.json
      agent-bom rescan before.json --output verification.json --md verification.md

    \b
    Exit codes:
      0  All vulnerabilities resolved
      1  Vulnerabilities remain
      2  Error loading baseline
    """
    import asyncio
    import json as _json

    from rich.console import Console
    from rich.table import Table

    from agent_bom.scan_cache import ScanCache
    from agent_bom.scanners import build_vulnerabilities, query_osv_batch

    con = Console(stderr=True)
    con.print(f"\n  [bold blue]Remediation Verification[/bold blue]  —  baseline: [bold]{baseline}[/bold]\n")

    # ── Load baseline ─────────────────────────────────────────────────────────
    try:
        baseline_data = _json.loads(Path(baseline).read_text())
    except Exception as exc:
        con.print(f"  [red]Error loading baseline: {exc}[/red]")
        sys.exit(2)

    blast_radii = baseline_data.get("blast_radius", [])
    if not blast_radii:
        con.print("  [green]✓[/green] Baseline has no vulnerabilities — nothing to verify.")
        sys.exit(0)

    # ── Extract unique vulnerable packages from baseline ──────────────────────
    seen: set[tuple[str, str, str]] = set()
    vuln_packages: list[tuple[str, str, str]] = []  # (ecosystem, name, version)
    for br in blast_radii:
        pkg_str = br.get("package", "")  # "name@version"
        eco = br.get("ecosystem", "pypi").lower()
        if "@" in pkg_str:
            name, ver = pkg_str.rsplit("@", 1)
        else:
            name, ver = pkg_str, ""
        if ver and (eco, name, ver) not in seen:
            seen.add((eco, name, ver))
            vuln_packages.append((eco, name, ver))

    if not vuln_packages:
        con.print("  [yellow]Could not extract package versions from baseline.[/yellow]")
        sys.exit(2)

    con.print(f"  Re-scanning [bold]{len(vuln_packages)}[/bold] previously vulnerable package(s)...\n")

    # ── Evict cached results so we get fresh OSV data ─────────────────────────
    try:
        cache = ScanCache()
        evicted = cache.evict_many([(eco, name, ver) for eco, name, ver in vuln_packages])
        if evicted:
            con.print(f"  [dim]Cache cleared for {evicted} package(s)[/dim]")
    except Exception:
        pass  # Cache eviction failure is non-fatal

    # ── Re-scan via OSV ───────────────────────────────────────────────────────
    from agent_bom.models import Package

    packages = [Package(name=name, version=ver, ecosystem=eco) for eco, name, ver in vuln_packages]
    try:
        fresh_results = asyncio.run(query_osv_batch(packages))
    except Exception as exc:
        con.print(f"  [red]OSV query failed: {exc}[/red]")
        sys.exit(2)

    # ── Optional NVD/EPSS/KEV enrichment ─────────────────────────────────────
    if enrich:
        try:
            from agent_bom.enrichment import enrich_vulnerabilities

            for pkg in packages:
                key = f"{pkg.ecosystem.lower()}:{pkg.name}@{pkg.version}"
                vulns = [build_vulnerabilities([v], pkg) for v in fresh_results.get(key, [])]
                flat = [v for sub in vulns for v in sub]
                asyncio.run(enrich_vulnerabilities(flat))
        except Exception:
            pass

    # ── Compare before vs after ───────────────────────────────────────────────
    # Build vuln-id sets from baseline
    baseline_vuln_ids: dict[str, set[str]] = {}  # pkg_key → set of vuln IDs
    for br in blast_radii:
        pkg_str = br.get("package", "")
        eco = br.get("ecosystem", "pypi").lower()
        pkg_key = f"{eco}:{pkg_str}"
        vid = br.get("vulnerability_id", "")
        baseline_vuln_ids.setdefault(pkg_key, set()).add(vid)

    resolved: list[dict] = []
    remaining: list[dict] = []
    newly_found: list[dict] = []

    for pkg in packages:
        key = f"{pkg.ecosystem.lower()}:{pkg.name}@{pkg.version}"
        baseline_key = f"{pkg.ecosystem.lower()}:{pkg.name}@{pkg.version}"
        old_ids = baseline_vuln_ids.get(baseline_key, set())
        fresh_vulns = build_vulnerabilities(fresh_results.get(key, []), pkg)
        new_ids = {v.id for v in fresh_vulns}

        for vid in old_ids - new_ids:
            resolved.append({"id": vid, "package": f"{pkg.name}@{pkg.version}", "ecosystem": pkg.ecosystem})
        for vid in old_ids & new_ids:
            v = next((x for x in fresh_vulns if x.id == vid), None)
            remaining.append(
                {
                    "id": vid,
                    "package": f"{pkg.name}@{pkg.version}",
                    "ecosystem": pkg.ecosystem,
                    "severity": v.severity.value if v else "unknown",
                    "fixed_version": v.fixed_version if v else None,
                }
            )
        for vid in new_ids - old_ids:
            v = next((x for x in fresh_vulns if x.id == vid), None)
            newly_found.append(
                {
                    "id": vid,
                    "package": f"{pkg.name}@{pkg.version}",
                    "ecosystem": pkg.ecosystem,
                    "severity": v.severity.value if v else "unknown",
                }
            )

    # ── Print results ─────────────────────────────────────────────────────────
    if resolved:
        con.print(f"  [green bold]✓ Resolved ({len(resolved)}):[/green bold]")
        for r in resolved:
            con.print(f"    [green]✓[/green]  {r['id']}  {r['package']} ({r['ecosystem']})")

    if remaining:
        con.print(f"\n  [red bold]✗ Still vulnerable ({len(remaining)}):[/red bold]")
        tbl = Table(show_header=True, header_style="bold red", box=None, padding=(0, 2))
        tbl.add_column("CVE / Advisory")
        tbl.add_column("Package")
        tbl.add_column("Severity")
        tbl.add_column("Fix available")
        for r in remaining:
            fix = r.get("fixed_version") or "[red dim]none[/red dim]"
            sev = r["severity"].upper()
            sev_style = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
            tbl.add_row(r["id"], f"{r['package']} ({r['ecosystem']})", f"[{sev_style}]{sev}[/{sev_style}]", fix)
        con.print(tbl)
        for r in remaining:
            if r.get("fixed_version"):
                eco = r["ecosystem"].lower()
                name = r["package"].split("@")[0]
                fix = r["fixed_version"]
                if eco == "pypi":
                    con.print(f"    [cyan]pip install '{name}>={fix}'[/cyan]")
                elif eco == "npm":
                    con.print(f"    [cyan]npm install {name}@{fix}[/cyan]")
                elif eco == "go":
                    con.print(f"    [cyan]go get {name}@v{fix}[/cyan]")
                elif eco == "cargo":
                    con.print(f"    [cyan]cargo update -p {name}[/cyan]")

    if newly_found:
        con.print(f"\n  [yellow bold]⚠ New findings ({len(newly_found)}) — not in baseline:[/yellow bold]")
        for r in newly_found:
            con.print(f"    [yellow]![/yellow]  {r['id']}  {r['package']}  [{r['severity']}]")

    # ── Summary ───────────────────────────────────────────────────────────────
    con.print()
    con.print(
        f"  Resolved: [green]{len(resolved)}[/green]  "
        f"Remaining: [{'red' if remaining else 'green'}]{len(remaining)}[/{'red' if remaining else 'green'}]  "
        f"New: [{'yellow' if newly_found else 'dim'}]{len(newly_found)}[/{'yellow' if newly_found else 'dim'}]"
    )

    # ── Write outputs ─────────────────────────────────────────────────────────
    from datetime import datetime, timezone

    verification = {
        "type": "remediation_verification",
        "baseline": str(baseline),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "resolved": len(resolved),
            "remaining": len(remaining),
            "newly_found": len(newly_found),
            "packages_rescanned": len(vuln_packages),
        },
        "resolved": resolved,
        "remaining": remaining,
        "newly_found": newly_found,
    }

    if output:
        Path(output).write_text(_json.dumps(verification, indent=2))
        con.print(f"\n  [green]✓[/green] Verification report: {output}")

    if md:
        lines = [
            "# Remediation Verification Report\n",
            f"**Baseline:** `{baseline}`  \n",
            f"**Verified at:** {verification['verified_at']}  \n",
            f"**Packages re-scanned:** {len(vuln_packages)}\n\n",
            "## Summary\n\n",
            "| Status | Count |\n|--------|-------|\n",
            f"| ✅ Resolved | {len(resolved)} |\n",
            f"| ❌ Remaining | {len(remaining)} |\n",
            f"| ⚠️ Newly found | {len(newly_found)} |\n\n",
        ]
        if resolved:
            lines.append("## Resolved\n\n")
            for r in resolved:
                lines.append(f"- ✅ `{r['id']}` — {r['package']} ({r['ecosystem']})\n")
            lines.append("\n")
        if remaining:
            lines.append("## Still Vulnerable\n\n")
            lines.append("| CVE / Advisory | Package | Severity | Fix |\n|---|---|---|---|\n")
            for r in remaining:
                fix = r.get("fixed_version") or "none"
                lines.append(f"| `{r['id']}` | {r['package']} | {r['severity']} | {fix} |\n")
            lines.append("\n")
        if newly_found:
            lines.append("## New Findings (not in baseline)\n\n")
            for r in newly_found:
                lines.append(f"- ⚠️ `{r['id']}` — {r['package']} [{r['severity']}]\n")
            lines.append("\n")
        Path(md).write_text("".join(lines))
        con.print(f"  [green]✓[/green] Verification report (Markdown): {md}")

    con.print()
    sys.exit(1 if remaining else 0)


@main.command("policy-template")
@click.option("--output", "-o", type=str, default="policy.json", help="Output path for the generated policy file")
def policy_template(output: str):
    """Generate a starter policy file with common rules.

    \b
    Example:
      agent-bom policy-template                    # writes policy.json
      agent-bom policy-template -o my-policy.json  # custom path

    Edit the generated file, then use it with:
      agent-bom scan --policy policy.json
    """
    import json as _json

    from agent_bom.policy import POLICY_TEMPLATE

    console = Console()
    out_path = Path(output)
    out_path.write_text(_json.dumps(POLICY_TEMPLATE, indent=2))
    console.print(f"\n  [green]✓[/green] Policy template written to {out_path}")
    console.print("  [dim]Edit the rules, then run:[/dim]")
    console.print(f"  [bold]agent-bom scan --policy {out_path}[/bold]\n")


@main.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to (use 0.0.0.0 for LAN access)")
@click.option("--port", default=8422, show_default=True, help="API server port")
@click.option("--persist", default=None, metavar="DB_PATH", help="Enable persistent job storage via SQLite (e.g. --persist jobs.db).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option("--log-level", "log_level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False), default="INFO")
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
def serve_cmd(host: str, port: int, persist: Optional[str], cors_allow_all: bool, reload: bool, log_level: str, log_json: bool):
    """Start the API server + Next.js dashboard.

    \b
    Requires:  pip install 'agent-bom[ui]'

    \b
    Usage:
      agent-bom serve
      agent-bom serve --port 8422 --persist jobs.db
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        click.echo(
            "ERROR: FastAPI + Uvicorn are required for `agent-bom serve`.\nInstall them with:  pip install 'agent-bom[ui]'",
            err=True,
        )
        sys.exit(1)

    import os as _os

    if persist:
        _os.environ["AGENT_BOM_DB"] = str(Path(persist).resolve())
    if cors_allow_all:
        _os.environ["AGENT_BOM_CORS_ALL"] = "1"

    _ui_dist = Path(__file__).parent / "ui_dist"
    click.echo(f"\n  API server  →  http://{host}:{port}")
    click.echo(f"  API docs    →  http://{host}:{port}/docs")
    if (_ui_dist / "index.html").exists():
        click.echo(f"  Dashboard   →  http://{host}:{port}")
    else:
        click.echo("  Dashboard   →  not bundled (run: make build-ui)")
    click.echo("  Press Ctrl+C to stop.\n")

    import uvicorn as _uvicorn

    _uvicorn.run(
        "agent_bom.api.server:app",
        host=host,
        port=port,
        reload=reload,
        timeout_keep_alive=5,
        limit_concurrency=500,
    )


@main.command("api")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to (use 0.0.0.0 for LAN access)")
@click.option("--port", default=8422, show_default=True, help="Port to listen on")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option("--workers", default=1, show_default=True, help="Number of worker processes")
@click.option("--cors-origins", default=None, metavar="ORIGINS", help="Comma-separated CORS origins (default: localhost:3000).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option(
    "--api-key", default=None, envvar="AGENT_BOM_API_KEY", metavar="KEY", help="Require API key auth (Bearer token or X-API-Key header)."
)
@click.option(
    "--rate-limit",
    "rate_limit_rpm",
    default=60,
    show_default=True,
    type=int,
    metavar="RPM",
    help="Rate limit for scan endpoints (requests/minute per IP).",
)
@click.option(
    "--persist",
    default=None,
    metavar="DB_PATH",
    help="Enable persistent job storage via SQLite (e.g. --persist jobs.db). Jobs survive restarts.",
)
@click.option(
    "--log-level",
    "log_level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    show_default=True,
    help="Log verbosity level.",
)
@click.option("--log-json", "log_json", is_flag=True, help="Emit structured JSON logs (for log aggregation pipelines).")
def api_cmd(
    host: str,
    port: int,
    reload: bool,
    workers: int,
    cors_origins: str | None,
    cors_allow_all: bool,
    api_key: str | None,
    rate_limit_rpm: int,
    persist: str | None,
    log_level: str,
    log_json: bool,
):
    """Start the agent-bom REST API server.

    \b
    Requires:  pip install 'agent-bom[api]'

    \b
    Endpoints:
      GET  /docs                   Interactive API docs (Swagger UI)
      GET  /health                 Liveness probe
      GET  /version                Version info
      POST /v1/scan                Start a scan (async, returns job_id)
      GET  /v1/scan/{job_id}       Poll status + results
      GET  /v1/scan/{job_id}/stream  SSE real-time progress
      GET  /v1/agents              Quick agent discovery (no CVE scan)
      GET  /v1/jobs                List all scan jobs

    \b
    Usage:
      agent-bom api                           # local dev: http://127.0.0.1:8422
      agent-bom api --host 0.0.0.0            # expose on LAN
      agent-bom api --port 9000               # custom port
      agent-bom api --reload                  # dev mode
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        import uvicorn
    except ImportError:
        click.echo(
            "ERROR: uvicorn is required for `agent-bom api`.\nInstall it with:  pip install 'agent-bom[api]'",
            err=True,
        )
        sys.exit(1)

    import os as _os

    from agent_bom import __version__ as _ver
    from agent_bom.api.server import configure_api, set_job_store

    origins = cors_origins.split(",") if cors_origins else None
    configure_api(
        cors_origins=origins,
        cors_allow_all=cors_allow_all,
        api_key=api_key,
        rate_limit_rpm=rate_limit_rpm,
    )

    pg_url = _os.environ.get("AGENT_BOM_POSTGRES_URL")
    if pg_url and not persist:
        # Postgres takes priority when no explicit --persist flag
        from agent_bom.api.postgres_store import PostgresJobStore

        set_job_store(PostgresJobStore())
    elif persist:
        from agent_bom.api.store import SQLiteJobStore

        set_job_store(SQLiteJobStore(db_path=persist))

    click.echo(f"  agent-bom API v{_ver}")
    click.echo(f"  Listening on http://{host}:{port}")
    click.echo(f"  Docs:         http://{host}:{port}/docs")
    if api_key:
        click.echo("  Auth:         API key required (Bearer / X-API-Key)")
    if pg_url and not persist:
        click.echo("  Storage:      PostgreSQL")
    elif persist:
        click.echo(f"  Storage:      SQLite ({persist})")
    click.echo("  Press Ctrl+C to stop.\n")

    uvicorn.run(
        "agent_bom.api.server:app",
        host=host,
        port=port,
        reload=reload,
        workers=1 if reload else workers,
        log_level=log_level.lower(),
        # Slowloris / connection-exhaustion hardening:
        # Close idle keep-alive connections after 5s (uvicorn default is 5s but
        # we set it explicitly so it's visible and auditable).
        timeout_keep_alive=5,
        # Hard cap on concurrent in-flight requests; prevents thread/FD exhaustion
        # under a slow-connection flood. 500 ≫ any realistic single-server load.
        limit_concurrency=500,
    )


@main.command("mcp-server")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="stdio",
    show_default=True,
    help="MCP transport protocol.",
)
@click.option("--port", default=8423, show_default=True, help="Port for HTTP/SSE transport.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host for HTTP/SSE transport.")
@click.option("--log-level", "log_level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False), default="INFO")
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
def mcp_server_cmd(transport: str, port: int, host: str, log_level: str, log_json: bool):
    """Start agent-bom as an MCP server.

    \b
    Requires:  pip install 'agent-bom[mcp-server]'

    \b
    Exposes 23 security tools via MCP protocol:
      scan              Full scan — CVEs, config security, blast radius, compliance
      check             Check a specific package for CVEs before installing
      blast_radius      Look up blast radius for a specific CVE
      policy_check      Evaluate policy rules against scan findings
      registry_lookup   Query the MCP server security metadata registry
      generate_sbom     Generate CycloneDX or SPDX SBOM
      compliance        10-framework compliance posture
      remediate         Generate actionable remediation plan
      skill_trust       ClawHub-style trust assessment for SKILL.md files
      verify            Package integrity + SLSA provenance verification
      where             Show all MCP discovery paths + existence status
      inventory         List agents/servers without CVE scanning
      diff              Compare scan against baseline for new/resolved vulns
      marketplace_check Pre-install marketplace trust check
      code_scan         SAST scanning via Semgrep with CWE mapping
      context_graph     Agent context graph with lateral movement analysis
      analytics_query   Query vulnerability trends from ClickHouse
      cis_benchmark     Run CIS benchmark checks (AWS/Snowflake)
      fleet_scan        Batch registry lookup for fleet inventories
      runtime_correlate Cross-reference runtime audit logs with CVE findings
      vector_db_scan    Discover vector databases and assess auth exposure
      aisvs_benchmark   OWASP AISVS v1.0 compliance checks
      gpu_infra_scan    GPU container and K8s node inventory + DCGM probe

    \b
    Usage:
      agent-bom mcp-server                                # stdio (Claude Desktop, Cursor)
      agent-bom mcp-server --transport sse                # SSE (remote clients)
      agent-bom mcp-server --transport streamable-http    # Streamable HTTP (Smithery, etc.)

    \b
    Claude Desktop config (~/.claude/claude_desktop_config.json):
      {"mcpServers": {"agent-bom": {"command": "agent-bom", "args": ["mcp-server"]}}}
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        from agent_bom.mcp_server import create_mcp_server
    except ImportError:
        click.echo(
            "ERROR: mcp SDK is required for `agent-bom mcp-server`.\nInstall it with:  pip install 'agent-bom[mcp-server]'",
            err=True,
        )
        sys.exit(1)

    server = create_mcp_server(host=host, port=port)

    if transport in ("sse", "streamable-http"):
        from agent_bom import __version__ as _ver

        click.echo(f"  agent-bom MCP Server v{_ver}", err=True)
        click.echo(f"  Transport: {transport} on http://{host}:{port}", err=True)
        click.echo("  Press Ctrl+C to stop.\n", err=True)
        server.run(transport=transport)
    else:
        server.run(transport="stdio")


@main.command("completions")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completions_cmd(shell: str):
    """Print shell completion script.

    \b
    Setup:
      bash:  eval "$(agent-bom completions bash)"
      zsh:   eval "$(agent-bom completions zsh)"
      fish:  agent-bom completions fish | source

    \b
    Permanent setup (bash):
      agent-bom completions bash >> ~/.bashrc

    Permanent setup (zsh):
      agent-bom completions zsh >> ~/.zshrc
    """
    import os as _os
    import subprocess as _sp

    env = {**_os.environ, "_AGENT_BOM_COMPLETE": f"{shell}_source"}
    try:
        result = _sp.run(["agent-bom"], env=env, capture_output=True, text=True)
        click.echo(result.stdout, nl=False)
    except Exception:  # noqa: BLE001
        # Fallback: print activation instructions
        if shell == "bash":
            click.echo('eval "$(_AGENT_BOM_COMPLETE=bash_source agent-bom)"')
        elif shell == "zsh":
            click.echo('eval "$(_AGENT_BOM_COMPLETE=zsh_source agent-bom)"')
        elif shell == "fish":
            click.echo("eval (env _AGENT_BOM_COMPLETE=fish_source agent-bom)")


@main.command("apply")
@click.argument("scan_json", type=click.Path(exists=True))
@click.option("--dir", "-d", "project_dir", type=click.Path(exists=True), default=".", help="Project directory containing dependency files")
@click.option("--dry-run", is_flag=True, help="Preview changes without modifying files")
@click.option("--no-backup", is_flag=True, help="Skip creating backup files")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt (for CI/scripting)")
def apply_command(scan_json, project_dir, dry_run, no_backup, yes):
    """Apply remediation fixes from a scan result JSON file.

    Reads vulnerability fixes from a previous scan output and modifies
    package.json / requirements.txt with fixed versions.
    Creates backups by default. Use --dry-run to preview first.

    \b
    Example:
        agent-bom scan --format json --output scan.json
        agent-bom apply scan.json --dir ./my-project --dry-run
        agent-bom apply scan.json --dir ./my-project --yes
    """
    from rich.console import Console

    from agent_bom.remediate import apply_fixes_from_json

    con = Console(stderr=True)
    con.print(f"\n  Applying fixes from [bold]{scan_json}[/bold] to [bold]{project_dir}[/bold]")

    if not dry_run and not yes:
        con.print(
            "\n  [yellow]This will modify dependency files in the project directory.[/yellow]\n"
            f"  Backups will be created {'(disabled by --no-backup)' if no_backup else 'automatically'}.\n"
        )
        if not click.confirm("  Proceed?", default=False):
            con.print("  Aborted.")
            return

    result = apply_fixes_from_json(
        scan_json,
        project_dir,
        dry_run=dry_run,
        backup=not no_backup,
    )

    if not result.applied and not result.skipped:
        con.print("  [green]✓[/green] No fixable vulnerabilities in scan output")
        return

    if result.dry_run:
        con.print("  [yellow]Dry run — no files modified[/yellow]\n")

    for fix in result.applied:
        con.print(f"  [green]✓[/green] {fix.package} {fix.current_version} → {fix.fixed_version} ({fix.ecosystem})")

    for fix in result.skipped:
        con.print(f"  [dim]  Skipped {fix.package} — no {fix.ecosystem} dependency file found[/dim]")

    if result.backed_up:
        con.print(f"\n  Backups: {', '.join(result.backed_up)}")

    con.print(f"\n  Applied: {len(result.applied)}, Skipped: {len(result.skipped)}")


@main.group()
def schedule():
    """Manage recurring scan schedules."""


@schedule.command("add")
@click.option("--name", "-n", required=True, help="Schedule name")
@click.option("--cron", "-c", required=True, help="Cron expression (e.g. '0 */6 * * *')")
@click.option("--config", "-f", type=click.Path(exists=True), default=None, help="Scan config JSON file")
def schedule_add(name: str, cron: str, config: Optional[str]):
    """Add a recurring scan schedule."""
    import uuid as _uuid

    from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule, SQLiteScheduleStore
    from agent_bom.api.scheduler import parse_cron_next

    console = Console()

    scan_config: dict = {}
    if config:
        scan_config = json.loads(Path(config).read_text())

    import os as _os
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    next_run = parse_cron_next(cron, now)

    db_path = _os.environ.get("AGENT_BOM_DB")
    store = SQLiteScheduleStore(db_path) if db_path else InMemoryScheduleStore()

    sched = ScanSchedule(
        schedule_id=str(_uuid.uuid4()),
        name=name,
        cron_expression=cron,
        scan_config=scan_config,
        enabled=True,
        next_run=next_run.isoformat() if next_run else None,
        created_at=now.isoformat(),
        updated_at=now.isoformat(),
    )
    store.put(sched)
    console.print(f"[green]Schedule created:[/green] {sched.schedule_id}")
    if next_run:
        console.print(f"  Next run: {next_run.isoformat()}")
    else:
        console.print("  [yellow]Warning: could not compute next run from cron expression[/yellow]")


@schedule.command("list")
def schedule_list():
    """List all scan schedules."""
    import os as _os

    from agent_bom.api.schedule_store import InMemoryScheduleStore, SQLiteScheduleStore

    console = Console()
    db_path = _os.environ.get("AGENT_BOM_DB")
    store = SQLiteScheduleStore(db_path) if db_path else InMemoryScheduleStore()

    schedules = store.list_all()
    if not schedules:
        console.print("[dim]No schedules found.[/dim]")
        return

    for s in schedules:
        status = "[green]enabled[/green]" if s.enabled else "[red]disabled[/red]"
        console.print(f"  {s.schedule_id[:8]}  {s.name}  {s.cron_expression}  {status}  next={s.next_run or 'n/a'}")


@schedule.command("remove")
@click.argument("schedule_id")
def schedule_remove(schedule_id: str):
    """Remove a scan schedule by ID."""
    import os as _os

    from agent_bom.api.schedule_store import InMemoryScheduleStore, SQLiteScheduleStore

    console = Console()
    db_path = _os.environ.get("AGENT_BOM_DB")
    store = SQLiteScheduleStore(db_path) if db_path else InMemoryScheduleStore()

    if store.delete(schedule_id):
        console.print(f"[green]Deleted schedule {schedule_id}[/green]")
    else:
        console.print(f"[red]Schedule {schedule_id} not found[/red]")
        sys.exit(1)


@main.group()
def registry():
    """Manage the MCP server registry."""


@registry.command("list")
@click.option("--category", "-c", default=None, help="Filter by category (e.g. database, filesystem).")
@click.option("--risk-level", "-r", type=click.Choice(["low", "medium", "high"]), default=None, help="Filter by risk level.")
@click.option("--ecosystem", "-e", type=click.Choice(["npm", "pypi"]), default=None, help="Filter by ecosystem.")
@click.option("--format", "-f", "fmt", type=click.Choice(["table", "json"]), default="table", help="Output format.")
def registry_list(category, risk_level, ecosystem, fmt):
    """List all known MCP servers in the registry."""
    from agent_bom.registry import list_registry

    entries = list_registry(ecosystem=ecosystem, category=category, risk_level=risk_level)

    if fmt == "json":
        click.echo(json.dumps(entries, indent=2))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    table = Table(title=f"MCP Server Registry ({len(entries)} servers)")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Version", style="green")
    table.add_column("Ecosystem")
    table.add_column("Category")
    table.add_column("Risk", style="bold")
    table.add_column("Verified")

    risk_colors = {"high": "red", "medium": "yellow", "low": "green"}
    for entry in entries:
        rl = entry.get("risk_level", "")
        color = risk_colors.get(rl, "white")
        table.add_row(
            entry.get("package", entry.get("name", "")),
            entry.get("latest_version", "?"),
            entry.get("ecosystem", ""),
            entry.get("category", ""),
            f"[{color}]{rl}[/{color}]",
            "Yes" if entry.get("verified") else "No",
        )
    con.print(table)


@registry.command("search")
@click.argument("query")
@click.option("--category", "-c", default=None, help="Also filter by category.")
def registry_search(query, category):
    """Search the MCP registry by name or description."""
    from agent_bom.registry import search_registry

    results = search_registry(query, category=category)

    if not results:
        click.echo(f"No results for '{query}'.")
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    table = Table(title=f"Search results for '{query}' ({len(results)} matches)")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Version", style="green")
    table.add_column("Ecosystem")
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Description", max_width=50)

    risk_colors = {"high": "red", "medium": "yellow", "low": "green"}
    for entry in results:
        rl = entry.get("risk_level", "")
        color = risk_colors.get(rl, "white")
        table.add_row(
            entry.get("package", entry.get("name", "")),
            entry.get("latest_version", "?"),
            entry.get("ecosystem", ""),
            entry.get("category", ""),
            f"[{color}]{rl}[/{color}]",
            (entry.get("description", "")[:50] + "...") if len(entry.get("description", "")) > 50 else entry.get("description", ""),
        )
    con.print(table)


@registry.command("update")
@click.option("--concurrency", default=5, type=int, help="Max concurrent API requests.")
@click.option("--dry-run", is_flag=True, help="Show what would be updated without writing.")
def registry_update(concurrency, dry_run):
    """Fetch latest package versions from npm/PyPI for all registry servers."""
    from rich.console import Console

    from agent_bom.registry import update_registry_versions_sync

    con = Console(stderr=True)
    con.print("[bold]Updating MCP registry versions...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = update_registry_versions_sync(concurrency=concurrency, dry_run=dry_run)

    # Show updated packages
    updated = [d for d in result.details if d["status"] == "updated"]
    if updated:
        con.print(f"\n[bold green]Updated {len(updated)} package(s):[/bold green]")
        for d in updated:
            con.print(f"  {d['package']}: {d['old']} → {d['new']}")

    # Show failures
    failed = [d for d in result.details if d["status"] == "failed"]
    if failed:
        con.print(f"\n[yellow]Failed to resolve {len(failed)} package(s):[/yellow]")
        for d in failed[:5]:
            con.print(f"  {d['package']}")
        if len(failed) > 5:
            con.print(f"  ... and {len(failed) - 5} more")

    con.print(
        f"\n[bold]Summary:[/bold] {result.updated} updated, {result.unchanged} unchanged, {result.failed} failed (of {result.total} total)"
    )
    if not dry_run and result.updated > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("enrich")
@click.option("--dry-run", is_flag=True, help="Show enrichment without writing.")
def registry_enrich(dry_run):
    """Enrich registry entries missing risk, tools, or credentials.

    \b
    Fills in empty metadata fields using heuristic inference:
    - risk_level from category/package name patterns
    - credential_env_vars from known service patterns
    - risk_justification from category templates

    Useful after 'registry update' adds new entries from CI.
    """
    from rich.console import Console

    from agent_bom.registry import enrich_registry_entries

    con = Console(stderr=True)
    con.print("[bold]Enriching MCP registry entries...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = enrich_registry_entries(dry_run=dry_run)

    if result.enriched:
        con.print(f"\n[bold green]Enriched {result.enriched} entry/entries:[/bold green]")
        for d in result.details:
            fields = ", ".join(d["fields_enriched"])
            con.print(f"  {d['server']}: {fields}")
    else:
        con.print("\n[green]All entries already have complete metadata.[/green]")

    con.print(f"\n[bold]Summary:[/bold] {result.enriched} enriched, {result.skipped} already complete (of {result.total} total)")
    if not dry_run and result.enriched > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("enrich-cves")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", default=None, help="NVD API key for higher rate limits.")
@click.option("--dry-run", is_flag=True, help="Preview CVE enrichment without writing.")
def registry_enrich_cves(nvd_api_key, dry_run):
    """Enrich registry with CVE data from OSV, EPSS, and CISA KEV.

    \b
    Scans all npm/pypi packages in the registry for known vulnerabilities:
    - Queries OSV batch API for CVEs affecting each package version
    - Fetches EPSS exploit prediction scores
    - Checks CISA KEV (Known Exploited Vulnerabilities) catalog
    - Extracts fix versions from OSV affected ranges

    \b
    Example:
      agent-bom registry enrich-cves
      agent-bom registry enrich-cves --dry-run
    """
    from rich.console import Console

    from agent_bom.registry import enrich_registry_with_cves_sync

    con = Console(stderr=True)
    con.print("[bold]Enriching registry with CVE data (OSV + EPSS + KEV)...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = enrich_registry_with_cves_sync(nvd_api_key=nvd_api_key, dry_run=dry_run)

    if result.enriched:
        con.print(f"\n[bold red]Found vulnerabilities in {result.enriched} server(s):[/bold red]")
        for d in result.details:
            kev_tag = " [KEV]" if d["kev"] else ""
            con.print(f"  {d['server']}: {d['cve_count']} CVEs, {d['ghsa_count']} GHSAs{kev_tag}")
            if d["cves"]:
                con.print(f"    {', '.join(d['cves'][:5])}")
    else:
        con.print("\n[green]No known CVEs found in scannable registry packages.[/green]")

    con.print(
        f"\n[bold]Summary:[/bold] {result.scannable} scannable, {result.enriched} with CVEs, "
        f"{result.total_cves} total CVEs, {result.total_critical} critical, {result.total_kev} KEV "
        f"(of {result.total} total servers)"
    )
    if not dry_run and result.enriched > 0:
        con.print("[green]Registry file updated with CVE data.[/green]")


@registry.command("smithery-sync")
@click.option("--token", envvar="SMITHERY_API_KEY", help="Smithery API key (or set SMITHERY_API_KEY).")
@click.option("--max-pages", type=int, default=10, show_default=True, help="Maximum pages to fetch from Smithery.")
@click.option("--dry-run", is_flag=True, help="Preview without writing to registry.")
def registry_smithery_sync(token, max_pages, dry_run):
    """Import MCP servers from Smithery.ai into the local registry.

    \b
    Fetches servers from smithery.ai and adds new entries that don't already
    exist in mcp_registry.json. Does not overwrite existing entries.
    Extends coverage from ~112 to 2800+ MCP servers.

    \b
    Requires a Smithery API key:
      export SMITHERY_API_KEY=your-key
      agent-bom registry smithery-sync
    """
    from rich.console import Console

    from agent_bom.smithery import sync_from_smithery_sync

    con = Console(stderr=True)
    if not token:
        con.print("[red]Error: Smithery API key required.[/red]")
        con.print("Set SMITHERY_API_KEY env var or use --token.")
        sys.exit(1)

    con.print("[bold]Syncing MCP servers from Smithery.ai...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = sync_from_smithery_sync(token=token, max_pages=max_pages, dry_run=dry_run)

    if result.added:
        con.print(f"\n[bold green]Added {result.added} new server(s):[/bold green]")
        for d in result.details[:20]:
            verified = "[green]verified[/green]" if d["verified"] else "[yellow]unverified[/yellow]"
            con.print(f"  {d['display_name']}: {verified}, {d['use_count']} installs, risk={d['risk_level']}")
        if len(result.details) > 20:
            con.print(f"  ... and {len(result.details) - 20} more")
    else:
        con.print("\n[green]No new servers found (all already in local registry).[/green]")

    con.print(f"\n[bold]Summary:[/bold] {result.added} added, {result.skipped} already known (of {result.total_fetched} fetched)")
    if not dry_run and result.added > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("mcp-sync")
@click.option("--max-pages", type=int, default=10, show_default=True, help="Maximum pages to fetch from the official registry.")
@click.option("--dry-run", is_flag=True, help="Preview without writing to registry.")
def registry_mcp_sync(max_pages, dry_run):
    """Import MCP servers from the Official MCP Registry into the local registry.

    \b
    Fetches servers from registry.modelcontextprotocol.io and adds new entries
    that don't already exist in mcp_registry.json. No authentication required.

    \b
    Usage:
      agent-bom registry mcp-sync
      agent-bom registry mcp-sync --dry-run
    """
    from rich.console import Console

    from agent_bom.mcp_official_registry import sync_from_official_registry_sync

    con = Console(stderr=True)
    con.print("[bold]Syncing MCP servers from Official MCP Registry...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = sync_from_official_registry_sync(max_pages=max_pages, dry_run=dry_run)

    if result.added:
        con.print(f"\n[bold green]Added {result.added} new server(s):[/bold green]")
        for d in result.details[:20]:
            con.print(f"  {d['server']}" + (f" (v{d['version']})" if d.get("version") else ""))
        if len(result.details) > 20:
            con.print(f"  ... and {len(result.details) - 20} more")
    else:
        con.print("\n[green]No new servers found (all already in local registry).[/green]")

    con.print(f"\n[bold]Summary:[/bold] {result.added} added, {result.skipped} already known (of {result.total_fetched} fetched)")
    if not dry_run and result.added > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("glama-sync")
@click.option("--max-pages", type=int, default=10, show_default=True, help="Maximum pages to fetch from Glama.")
@click.option("--dry-run", is_flag=True, help="Preview without writing to registry.")
def registry_glama_sync(max_pages, dry_run):
    """Import MCP servers from Glama.ai into the local registry.

    \b
    Fetches servers from glama.ai/api/mcp/v1/servers and adds new entries
    that don't already exist in mcp_registry.json. No authentication required.

    \b
    Usage:
      agent-bom registry glama-sync
      agent-bom registry glama-sync --max-pages 50 --dry-run
    """
    from rich.console import Console

    from agent_bom.glama import sync_from_glama_sync

    con = Console(stderr=True)
    con.print("[bold]Syncing MCP servers from Glama.ai...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = sync_from_glama_sync(max_pages=max_pages, dry_run=dry_run)

    if result.added:
        con.print(f"\n[bold green]Added {result.added} new server(s):[/bold green]")
        for d in result.details[:20]:
            con.print(f"  {d['server']}")
        if len(result.details) > 20:
            con.print(f"  ... and {len(result.details) - 20} more")
    else:
        con.print("\n[green]No new servers found (all already in local registry).[/green]")

    con.print(f"\n[bold]Summary:[/bold] {result.added} added, {result.skipped} already known (of {result.total_fetched} fetched)")
    if not dry_run and result.added > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("sync-all")
@click.option("--max-pages", type=int, default=10, show_default=True, help="Maximum pages per source.")
@click.option("--smithery-token", envvar="SMITHERY_API_KEY", default=None, help="Smithery API key.")
@click.option("--dry-run", is_flag=True, help="Preview without writing to registry.")
def registry_sync_all(max_pages, smithery_token, dry_run):
    """Sync from ALL registry sources (Official MCP + Smithery + Glama).

    \b
    Runs all three sync sources in sequence and reports combined results.
    Smithery requires SMITHERY_API_KEY env var or --smithery-token flag.

    \b
    Usage:
      agent-bom registry sync-all
      agent-bom registry sync-all --dry-run
    """
    from rich.console import Console

    con = Console(stderr=True)
    con.print("[bold]Syncing from all registry sources...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    total_added = 0
    total_fetched = 0

    # 1. Official MCP Registry
    con.print("\n[blue]1/3[/blue] Official MCP Registry...")
    from agent_bom.mcp_official_registry import sync_from_official_registry_sync

    r1 = sync_from_official_registry_sync(max_pages=max_pages, dry_run=dry_run)
    con.print(f"  Added: {r1.added}, Skipped: {r1.skipped}, Fetched: {r1.total_fetched}")
    total_added += r1.added
    total_fetched += r1.total_fetched

    # 2. Smithery
    con.print("\n[blue]2/3[/blue] Smithery.ai...")
    if smithery_token:
        from agent_bom.smithery import sync_from_smithery_sync

        r2 = sync_from_smithery_sync(token=smithery_token, max_pages=max_pages, dry_run=dry_run)
        con.print(f"  Added: {r2.added}, Skipped: {r2.skipped}, Fetched: {r2.total_fetched}")
        total_added += r2.added
        total_fetched += r2.total_fetched
    else:
        con.print("  [dim]Skipped (no SMITHERY_API_KEY)[/dim]")

    # 3. Glama
    con.print("\n[blue]3/3[/blue] Glama.ai...")
    from agent_bom.glama import sync_from_glama_sync

    r3 = sync_from_glama_sync(max_pages=max_pages, dry_run=dry_run)
    con.print(f"  Added: {r3.added}, Skipped: {r3.skipped}, Fetched: {r3.total_fetched}")
    total_added += r3.added
    total_fetched += r3.total_fetched

    con.print(f"\n[bold]Total:[/bold] {total_added} added from {total_fetched} fetched across all sources")
    if not dry_run and total_added > 0:
        con.print("[green]Registry file updated.[/green]")


@main.command("proxy")
@click.option("--policy", type=click.Path(exists=True), help="Policy file for runtime enforcement")
@click.option("--log", "log_path", default=None, help="Audit log output path (JSONL)")
@click.option("--block-undeclared", is_flag=True, help="Block tool calls not in tools/list response")
@click.option("--detect-credentials", is_flag=True, help="Detect credential leaks in tool responses")
@click.option("--rate-limit-threshold", type=int, default=0, help="Max calls per tool per 60s (0=disabled)")
@click.option("--log-only", is_flag=True, help="Log alerts without blocking (advisory mode)")
@click.option(
    "--alert-webhook", default=None, envvar="AGENT_BOM_ALERT_WEBHOOK", help="Webhook URL for runtime alerts (Slack/Teams/PagerDuty)"
)
@click.option("--metrics-port", default=8422, show_default=True, help="Prometheus metrics port (0 to disable)")
@click.option("--metrics-token", default=None, envvar="AGENT_BOM_METRICS_TOKEN", help="Bearer token for Prometheus /metrics endpoint")
@click.option(
    "--response-sign-key",
    default=None,
    envvar="AGENT_BOM_RESPONSE_SIGN_KEY",
    help="Secret key for HMAC-SHA256 response signing written to audit log (tamper detection)",
)
@click.argument("server_cmd", nargs=-1, required=True)
def proxy_cmd(
    policy,
    log_path,
    block_undeclared,
    detect_credentials,
    rate_limit_threshold,
    log_only,
    alert_webhook,
    metrics_port,
    metrics_token,
    response_sign_key,
    server_cmd,
):
    """Run an MCP server through agent-bom's security proxy.

    \b
    Intercepts JSON-RPC messages between client and server:
    - Logs every tools/call invocation to an audit trail
    - Optionally enforces policy rules in real-time
    - Blocks undeclared tools (not in tools/list response)
    - Detects tool drift (rug pull), dangerous arguments, credential leaks
    - Rate limiting and suspicious sequence detection
    - HMAC-SHA256 response signing in audit log (--response-sign-key)

    \b
    Usage:
      agent-bom proxy -- npx @modelcontextprotocol/server-filesystem /tmp
      agent-bom proxy --log audit.jsonl -- npx @mcp/server-github
      agent-bom proxy --policy policy.json --block-undeclared -- npx @mcp/server-postgres
      agent-bom proxy --detect-credentials --log-only -- npx @mcp/server-github
      agent-bom proxy --log audit.jsonl --response-sign-key $MY_SECRET -- npx @mcp/server-github

    \b
    Configure in your MCP client (e.g. Claude Desktop):
      {
        "mcpServers": {
          "filesystem": {
            "command": "agent-bom",
            "args": ["proxy", "--log", "audit.jsonl", "--detect-credentials",
                     "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
          }
        }
      }
    """
    import asyncio

    from agent_bom.project_config import get_policy_path, load_project_config
    from agent_bom.proxy import run_proxy

    # Auto-load .agent-bom.yaml policy if --policy not explicitly given
    if not policy:
        _cfg = load_project_config()
        if _cfg and (cfg_policy := get_policy_path(_cfg)):
            policy = str(cfg_policy)

    exit_code = asyncio.run(
        run_proxy(
            server_cmd=list(server_cmd),
            policy_path=policy,
            log_path=log_path,
            block_undeclared=block_undeclared,
            detect_credentials=detect_credentials,
            rate_limit_threshold=rate_limit_threshold,
            log_only=log_only,
            alert_webhook=alert_webhook,
            metrics_port=metrics_port,
            metrics_token=metrics_token,
            response_signing_key=response_sign_key,
        )
    )
    sys.exit(exit_code)


@main.command("proxy-configure")
@click.option("--policy", type=click.Path(exists=True), default=None, help="Policy JSON file to pass to each proxy instance")
@click.option("--log-dir", default=None, type=click.Path(), help="Directory for per-server audit JSONL logs")
@click.option("--detect-credentials", is_flag=True, help="Enable credential leak detection in each proxy")
@click.option("--block-undeclared", is_flag=True, help="Block undeclared tools in each proxy")
@click.option(
    "--apply",
    is_flag=True,
    help="Write proxy config back to source JSON config files (default: preview only)",
)
@click.option("--project", default=None, type=click.Path(exists=True), help="Project directory to scan for MCP configs")
def proxy_configure_cmd(policy, log_dir, detect_credentials, block_undeclared, apply, project):
    """Auto-configure the agent-bom proxy for discovered MCP servers.

    \b
    Discovers all MCP servers on this machine, then generates proxy-wrapped
    configuration entries for every STDIO server.  The proxy adds:
    - Audit logging (--log-dir)
    - Policy enforcement (--policy)
    - Credential leak detection (--detect-credentials)
    - Undeclared-tool blocking (--block-undeclared)

    \b
    By default, shows a preview.  Use --apply to write changes back to the
    original config files (JSON only — claude_desktop_config.json, mcp.json…).

    \b
    Example:
      agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials
      agent-bom proxy-configure --policy policy.json --block-undeclared --apply
    """
    from agent_bom.discovery import discover_all
    from agent_bom.proxy_configure import apply_proxy_configs, auto_configure_proxies

    con = Console()

    agents = discover_all(project_dir=project)
    configs = auto_configure_proxies(
        agents,
        policy_path=policy,
        log_dir=log_dir,
        detect_credentials=detect_credentials,
        block_undeclared=block_undeclared,
    )

    if not configs:
        con.print("[yellow]No eligible STDIO MCP servers found (need command + stdio transport).[/yellow]")
        return

    con.print(f"\n[bold blue]Proxy configuration for {len(configs)} MCP server(s):[/bold blue]\n")

    for cfg in configs:
        con.print(f"  [bold]{cfg.server_name}[/bold]  [dim]({cfg.config_path})[/dim]")
        con.print(f"    Original : {cfg.original_command} {' '.join(cfg.original_args)}")
        proxy_preview = f"agent-bom {' '.join(cfg.proxied_args)}"
        con.print(f"    Proxied  : [green]{proxy_preview}[/green]")
        con.print()

    if apply:
        n = apply_proxy_configs(configs, dry_run=False)
        if n:
            con.print(f"[green]✓[/green] Patched {n} config file(s).")
        else:
            con.print("[yellow]⚠[/yellow] No JSON config files were patched (SSE servers, missing files, or no matching entries).")
    else:
        con.print("[dim]Pass --apply to write these changes to config files.[/dim]")


@main.command("guard", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("tool", type=click.Choice(["pip", "npm", "npx"]))
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.option("--min-severity", default="high", type=click.Choice(["critical", "high", "medium"]), help="Minimum severity to block")
@click.option("--allow-risky", is_flag=True, help="Warn but don't block risky packages")
def guard_cmd(tool: str, args: tuple, min_severity: str, allow_risky: bool):
    """Pre-install security guard — scan packages before installing.

    \b
    Wraps pip/npm install to check each package against OSV and NVD
    for known vulnerabilities before allowing installation.

    \b
    Usage:
      agent-bom guard pip install requests flask
      agent-bom guard npm install express

    \b
    Shell alias (recommended):
      alias pip='agent-bom guard pip'
      alias npm='agent-bom guard npm'

    \b
    Blocks install if any package has critical/high CVEs.
    Use --allow-risky to install anyway (with warnings).
    """
    from agent_bom.guard import run_guarded_install
    from agent_bom.logging_config import setup_logging

    setup_logging(level="INFO")

    exit_code = run_guarded_install(
        tool=tool,
        args=list(args),
        min_severity=min_severity,
        allow_risky=allow_risky,
    )
    sys.exit(exit_code)


@main.command("protect")
@click.option(
    "--mode",
    type=click.Choice(["stdin", "http"]),
    default="stdin",
    show_default=True,
    help="Input mode: stdin (line-delimited JSON) or http (HTTP endpoint)",
)
@click.option("--port", default=8423, show_default=True, help="HTTP listen port (used with --mode http)")
@click.option("--host", default="127.0.0.1", show_default=True, help="HTTP bind address (used with --mode http)")
@click.option("--detectors", default="all", show_default=True, help="Comma-separated detector list: drift,args,creds,rate,sequence")
@click.option("--alert-file", default=None, help="Write alerts to JSONL file")
@click.option(
    "--alert-webhook", default=None, envvar="AGENT_BOM_ALERT_WEBHOOK", help="Webhook URL for runtime alerts (Slack/Teams/PagerDuty)"
)
@click.option("--log-level", "log_level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False), default="INFO")
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
def protect_cmd(mode, port, host, detectors, alert_file, alert_webhook, log_level, log_json):
    """Run the runtime protection engine as a standalone monitor.

    \b
    Analyzes tool calls through 5 security detectors:
    - Tool drift detection (rug pull / capability changes)
    - Argument analysis (shell injection, path traversal)
    - Credential leak detection (API keys, tokens in responses)
    - Rate limiting (abnormal call frequency)
    - Sequence analysis (suspicious multi-step patterns)

    \b
    stdin mode (default) — pipe line-delimited JSON:
      echo '{"tool_name":"exec","arguments":{"cmd":"rm -rf /"}}' | agent-bom protect
      cat otel-export.jsonl | agent-bom protect --alert-file alerts.jsonl

    \b
    http mode — start an HTTP endpoint:
      agent-bom protect --mode http --port 8423
      # POST /tool-call, /tool-response, /drift-check; GET /status

    \b
    Input JSON formats:
      Tool call:     {"tool_name": "read_file", "arguments": {"path": "/etc/passwd"}}
      Response:      {"type": "response", "tool_name": "read_file", "text": "..."}
      Drift check:   {"type": "drift", "tools": ["read_file", "exec_cmd"]}
    """
    import asyncio
    import signal

    from agent_bom.alerts.dispatcher import AlertDispatcher
    from agent_bom.logging_config import setup_logging
    from agent_bom.project_config import load_project_config

    # Auto-load .agent-bom.yaml for alert_webhook if not explicitly given
    _proj_cfg = load_project_config()
    if _proj_cfg:
        if not alert_webhook and _proj_cfg.get("alert_webhook"):
            alert_webhook = _proj_cfg["alert_webhook"]
    from agent_bom.runtime.protection import ProtectionEngine
    from agent_bom.runtime.server import run_http_mode, run_stdin_mode

    setup_logging(level=log_level, json_output=log_json)

    # Build dispatcher with configured channels
    dispatcher = AlertDispatcher()

    if alert_webhook:
        dispatcher.add_webhook(alert_webhook)

    # File channel: append alerts as JSONL
    if alert_file:

        class _FileChannel:
            def __init__(self, path: str) -> None:
                self._path = path

            async def send(self, alert: dict) -> bool:
                import json as _json

                with open(self._path, "a") as f:
                    f.write(_json.dumps(alert) + "\n")
                return True

        dispatcher.add_channel(_FileChannel(alert_file))

    # Build engine
    engine = ProtectionEngine(dispatcher=dispatcher)

    # Configure detectors based on selection
    if detectors != "all":
        enabled = {d.strip().lower() for d in detectors.split(",")}
        detector_map = {
            "drift": "drift_detector",
            "args": "arg_analyzer",
            "creds": "cred_detector",
            "rate": "rate_tracker",
            "sequence": "seq_analyzer",
        }
        active_count = 0
        for name, attr in detector_map.items():
            if name not in enabled:
                # Replace with a no-op stub
                setattr(engine, attr, _NoOpDetector())
            else:
                active_count += 1
        engine._stats.detectors_active = active_count

    console = Console(stderr=True)
    console.print(f"[bold green]Runtime protection engine starting ({mode} mode)[/bold green]")

    async def _run() -> None:
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _signal_handler() -> None:
            console.print("\n[yellow]Shutting down...[/yellow]")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)

        if mode == "http":
            task = asyncio.create_task(run_http_mode(engine, host, port))
        else:
            task = asyncio.create_task(run_stdin_mode(engine))

        # Wait for stop signal or task completion
        done = asyncio.create_task(stop_event.wait())
        await asyncio.wait([task, done], return_when=asyncio.FIRST_COMPLETED)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        engine.stop()
        stats = engine.status()
        console.print(f"[dim]Tool calls analyzed: {stats['tool_calls_analyzed']}, Alerts: {stats['alerts_generated']}[/dim]")

    asyncio.run(_run())


class _NoOpDetector:
    """Stub detector that does nothing — used when a detector is disabled."""

    def check(self, *args, **kwargs):  # noqa: N805
        return []

    def record(self, *args, **kwargs):
        return []


@main.command("watch")
@click.option("--webhook", default=None, help="Webhook URL for alerts (Slack/Teams/PagerDuty)")
@click.option("--log", "alert_log", default=None, help="Alert log file (JSONL)")
@click.option("--interval", default=2.0, type=float, help="Debounce interval in seconds")
def watch_cmd(webhook, alert_log, interval):
    """Watch MCP configs for changes and alert on new risks.

    \b
    Continuously monitors MCP client configuration files. On change:
    - Re-scans the affected config
    - Diffs against the last scan
    - Alerts if new vulnerabilities or risks are introduced

    \b
    Requires: pip install 'agent-bom[watch]'

    \b
    Usage:
      agent-bom watch
      agent-bom watch --webhook https://hooks.slack.com/services/...
      agent-bom watch --log alerts.jsonl
    """
    from agent_bom.watch import (
        ConsoleAlertSink,
        FileAlertSink,
        WebhookAlertSink,
        discover_config_dirs,
        start_watching,
    )

    console = Console()
    console.print(BANNER, style="bold blue")

    sinks = [ConsoleAlertSink()]
    if webhook:
        sinks.append(WebhookAlertSink(webhook))
    if alert_log:
        sinks.append(FileAlertSink(alert_log))

    dirs = discover_config_dirs()
    if not dirs:
        console.print("[yellow]No MCP config directories found to watch.[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold blue]Watching {len(dirs)} config director{'ies' if len(dirs) > 1 else 'y'}...[/bold blue]")
    for d in dirs:
        console.print(f"  [dim]{d}[/dim]")
    console.print("\n  [dim]Press Ctrl+C to stop.[/dim]\n")

    start_watching(sinks, debounce_seconds=interval)


@main.command("analytics")
@click.argument("query_type", type=click.Choice(["trends", "posture", "events", "top-cves"]))
@click.option("--days", default=30, type=int, help="Lookback window in days (default: 30)")
@click.option("--hours", default=24, type=int, help="Lookback window in hours for events (default: 24)")
@click.option("--agent", default=None, help="Filter by agent name")
@click.option("--limit", "top_limit", default=20, type=int, help="Limit for top-cves (default: 20)")
@click.option("--clickhouse-url", default=None, envvar="AGENT_BOM_CLICKHOUSE_URL", metavar="URL", help="ClickHouse HTTP URL")
def analytics_cmd(query_type, days, hours, agent, top_limit, clickhouse_url):
    """Query vulnerability trends, posture history, and runtime events from ClickHouse.

    \b
    Usage:
      agent-bom analytics trends [--days 30] [--agent NAME]
      agent-bom analytics posture [--days 90] [--agent NAME]
      agent-bom analytics events [--hours 24]
      agent-bom analytics top-cves [--limit 20]
    """
    from rich.console import Console
    from rich.table import Table

    from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

    console = Console()

    if not clickhouse_url:
        console.print("[red]ClickHouse URL required.[/red] Set --clickhouse-url or AGENT_BOM_CLICKHOUSE_URL env var.")
        sys.exit(1)

    try:
        store = ClickHouseAnalyticsStore(url=clickhouse_url)
    except Exception as exc:
        console.print(f"[red]ClickHouse connection error:[/red] {exc}")
        sys.exit(1)

    if query_type == "trends":
        rows = store.query_vuln_trends(days=days, agent=agent)
        table = Table(title=f"Vulnerability Trends (last {days} days)")
        table.add_column("Day", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Count", style="bold")
        for r in rows:
            table.add_row(str(r.get("day", "")), r.get("severity", ""), str(r.get("cnt", 0)))
        console.print(table)

    elif query_type == "posture":
        rows = store.query_posture_history(agent=agent, days=days)
        table = Table(title=f"Posture History (last {days} days)")
        table.add_column("Day", style="cyan")
        table.add_column("Agent", style="blue")
        table.add_column("Grade", style="bold")
        table.add_column("Risk Score", style="yellow")
        table.add_column("Compliance", style="green")
        for r in rows:
            table.add_row(
                str(r.get("day", "")),
                r.get("agent_name", ""),
                r.get("posture_grade", ""),
                str(r.get("risk_score", "")),
                str(r.get("compliance_score", "")),
            )
        console.print(table)

    elif query_type == "events":
        rows = store.query_event_summary(hours=hours)
        table = Table(title=f"Runtime Events (last {hours} hours)")
        table.add_column("Event Type", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Count", style="bold")
        for r in rows:
            table.add_row(r.get("event_type", ""), r.get("severity", ""), str(r.get("cnt", 0)))
        console.print(table)

    elif query_type == "top-cves":
        rows = store.query_top_cves(limit=top_limit)
        table = Table(title=f"Top {top_limit} CVEs")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Count", style="bold")
        table.add_column("Max CVSS", style="red")
        for r in rows:
            table.add_row(r.get("cve_id", ""), str(r.get("cnt", 0)), str(r.get("max_cvss", "")))
        console.print(table)

    if not rows:
        console.print("[dim]No data found. Run scans with --clickhouse-url to populate analytics.[/dim]")


@main.command("graph")
@click.argument("scan_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "dot", "mermaid"]), default="json", show_default=True, help="Output format."
)
@click.option("--output", "-o", "output_path", default=None, help="Write to file instead of stdout.")
def graph_cmd(scan_file: str, fmt: str, output_path: Optional[str]) -> None:
    """Export the transitive dependency graph from a saved JSON scan report.

    \b
    SCAN_FILE  Path to a JSON file produced by: agent-bom scan --format json

    \b
    Examples:
        agent-bom scan --format json --output report.json
        agent-bom graph report.json --format dot --output deps.dot
        dot -Tsvg deps.dot -o deps.svg

        agent-bom graph report.json --format mermaid

    Closes #292.
    """
    from rich.console import Console as _Console

    from agent_bom.output.graph_export import load_graph_from_scan, to_dot, to_json, to_mermaid

    _con = _Console()

    try:
        graph = load_graph_from_scan(scan_file)
    except (ValueError, KeyError) as exc:
        _con.print(f"[red]Error loading scan file:[/red] {exc}")
        raise SystemExit(1) from exc

    if fmt == "dot":
        output = to_dot(graph)
    elif fmt == "mermaid":
        output = to_mermaid(graph)
    else:
        output = json.dumps(to_json(graph), indent=2)

    if output_path:
        Path(output_path).write_text(output)
        _con.print(f"[green]Graph exported[/green] ({graph.node_count()} nodes, {graph.edge_count()} edges) → {output_path}")
    else:
        click.echo(output)


@main.command("dashboard")
@click.option("--report", type=click.Path(exists=True), default=None, help="Path to agent-bom JSON report file.")
@click.option("--port", default=8501, show_default=True, help="Streamlit server port.")
def dashboard_cmd(report: Optional[str], port: int):
    """Launch the interactive Streamlit dashboard.

    \b
    Requires:  pip install 'agent-bom[dashboard]'

    \b
    Usage:
      agent-bom dashboard                        # Upload or live-scan from UI
      agent-bom dashboard --report scan.json     # Pre-load a report
      agent-bom scan -f json -o r.json && agent-bom dashboard --report r.json
    """
    import shutil
    import subprocess

    if not shutil.which("streamlit"):
        click.echo("Error: streamlit not found. Install with: pip install 'agent-bom[dashboard]'", err=True)
        sys.exit(1)

    app_path = Path(__file__).parent.parent.parent / "dashboard" / "app.py"
    if not app_path.exists():
        # Fallback: installed package location
        import importlib.resources

        try:
            ref = importlib.resources.files("dashboard") / "app.py"
            app_path = Path(str(ref))
        except (ModuleNotFoundError, TypeError):
            click.echo("Error: dashboard/app.py not found. Run from the agent-bom repo root.", err=True)
            sys.exit(1)

    cmd = ["streamlit", "run", str(app_path), "--server.port", str(port)]
    if report:
        cmd += ["--", "--report", report]

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as exc:
        click.echo(f"Dashboard exited with code {exc.returncode}", err=True)
        sys.exit(exc.returncode)


@main.command("introspect")
@click.option("--command", "server_command", default=None, help="MCP server command to introspect (e.g. 'npx @mcp/server-filesystem /')")
@click.option("--url", "server_url", default=None, help="MCP server SSE/HTTP URL to introspect")
@click.option("--timeout", "timeout", default=10.0, show_default=True, type=float, help="Connection timeout per server (seconds)")
@click.option("--all", "introspect_all", is_flag=True, help="Introspect all discovered MCP servers (auto-discovery)")
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True),
    default=None,
    help="JSON baseline of expected tools — report drift against it",
)
@click.option("--format", "output_format", type=click.Choice(["console", "json"]), default="console", show_default=True)
@click.option("--no-color", is_flag=True, help="Disable ANSI color output")
def introspect_cmd(server_command, server_url, timeout, introspect_all, baseline_path, output_format, no_color):
    """Connect to live MCP servers and show their actual tools and resources.

    \b
    Read-only — only calls initialize, tools/list, resources/list.
    Never calls tools/call.  Detects drift against config-declared tools.

    \b
    Usage:
      agent-bom introspect --command "npx @mcp/server-filesystem /"
      agent-bom introspect --url http://localhost:8080/sse
      agent-bom introspect --all                           # all discovered servers
      agent-bom introspect --all --baseline baseline.json  # drift report
      agent-bom introspect --all --format json             # machine-readable

    \b
    Requires: pip install 'agent-bom[mcp-server]'  (for MCP SDK)
    """
    import json as _json

    from rich.console import Console
    from rich.table import Table

    from agent_bom.mcp_introspect import introspect_servers_sync

    con = Console(no_color=no_color)

    if not server_command and not server_url and not introspect_all:
        con.print("[red]Error:[/red] Provide --command, --url, or --all")
        sys.exit(1)

    # Build server list
    if introspect_all:
        from agent_bom.discovery import discover_all

        con.print("[dim]Discovering MCP servers...[/dim]", highlight=False)
        agents = discover_all()
        servers = [s for a in agents for s in a.mcp_servers]
        if not servers:
            con.print("[yellow]No MCP servers discovered.[/yellow]")
            sys.exit(0)
    else:
        from agent_bom.models import MCPServer, TransportType

        if server_command:
            parts = server_command.split()
            srv = MCPServer(
                name=parts[0],
                command=parts[0],
                args=parts[1:],
                transport=TransportType.STDIO,
            )
        else:
            srv = MCPServer(
                name=server_url or "server",
                url=server_url,
                transport=TransportType.SSE,
            )
        servers = [srv]

    # Load baseline if provided
    baseline: dict[str, list[str]] = {}
    if baseline_path:
        try:
            baseline = _json.loads(Path(baseline_path).read_text())
        except Exception as e:  # noqa: BLE001
            con.print(f"[yellow]Warning: could not load baseline: {e}[/yellow]")

    # Introspect
    try:
        results = introspect_servers_sync(servers, timeout=timeout)
    except ImportError:
        con.print("[red]MCP SDK not installed.[/red] Run: pip install 'agent-bom[mcp-server]'")
        sys.exit(1)

    if output_format == "json":
        output = []
        for r in results:
            entry = {
                "server": r.server_name,
                "success": r.success,
                "tools": [t.name for t in r.runtime_tools],
                "resources": [res.name for res in r.runtime_resources],
                "error": r.error,
            }
            if baseline:
                expected = baseline.get(r.server_name, [])
                entry["drift_added"] = [t for t in entry["tools"] if t not in expected]
                entry["drift_removed"] = [t for t in expected if t not in entry["tools"]]
            output.append(entry)
        click.echo(_json.dumps(output, indent=2))
        sys.exit(0)

    # Console output
    any_drift = False
    for r in results:
        status = "[green]✓[/green]" if r.success else "[red]✗[/red]"
        con.print(f"\n{status} [bold]{r.server_name}[/bold]", highlight=False)
        if not r.success:
            con.print(f"  [red]{r.error}[/red]")
            continue

        if r.protocol_version:
            con.print(f"  Protocol: {r.protocol_version}")

        if r.runtime_tools:
            tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
            tbl.add_column("Tool")
            tbl.add_column("Description")
            for t in r.runtime_tools:
                desc = (t.description or "")[:80]
                expected_tools = baseline.get(r.server_name, [])
                marker = ""
                if expected_tools and t.name not in expected_tools:
                    marker = " [yellow](NEW)[/yellow]"
                    any_drift = True
                tbl.add_row(f"  {t.name}{marker}", desc)
            con.print(tbl)
        else:
            con.print("  [dim]No tools[/dim]")

        if r.runtime_resources:
            con.print(f"  Resources: {', '.join(res.name for res in r.runtime_resources)}")

        if baseline:
            expected_tools = baseline.get(r.server_name, [])
            removed = [t for t in expected_tools if t not in {x.name for x in r.runtime_tools}]
            if removed:
                con.print(f"  [red]Removed tools: {', '.join(removed)}[/red]")
                any_drift = True

    if any_drift:
        con.print("\n[yellow]⚠ Drift detected — tools differ from baseline.[/yellow]")
        sys.exit(1)


@main.command("audit-replay")
@click.argument("log_path", type=click.Path(exists=True))
@click.option("--tool", default=None, help="Filter entries by tool name (substring match)")
@click.option("--type", "entry_type", default=None, help="Filter by entry type (tools/call, relay_error, …)")
@click.option("--blocked-only", is_flag=True, help="Show only blocked tool calls")
@click.option("--alerts-only", is_flag=True, help="Show only runtime detector alerts")
@click.option(
    "--sign-key",
    default=None,
    envvar="AGENT_BOM_RESPONSE_SIGN_KEY",
    help="Secret key used when the proxy was started with --response-sign-key",
)
@click.option("--verify-hmac", is_flag=True, help="Verify HMAC-SHA256 response signatures in the log")
@click.option("--json", "as_json", is_flag=True, help="Output machine-readable JSON summary (for CI)")
def audit_replay_cmd(log_path, tool, entry_type, blocked_only, alerts_only, sign_key, verify_hmac, as_json):
    """View and analyse a proxy audit JSONL log.

    \b
    Renders a colour-coded summary of all recorded tool calls, alerts,
    relay errors, and optional HMAC response signatures.

    \b
    Exits 1 when the log contains blocked calls or relay errors (useful
    as a CI gate after running a test suite through the proxy).

    \b
    Examples:
      agent-bom audit-replay audit.jsonl
      agent-bom audit-replay audit.jsonl --blocked-only
      agent-bom audit-replay audit.jsonl --alerts-only
      agent-bom audit-replay audit.jsonl --tool read_file
      agent-bom audit-replay audit.jsonl --sign-key $SECRET --verify-hmac
      agent-bom audit-replay audit.jsonl --json
    """
    from agent_bom.audit_replay import replay

    exit_code = replay(
        log_path,
        tool=tool,
        entry_type=entry_type,
        blocked_only=blocked_only,
        alerts_only=alerts_only,
        sign_key=sign_key,
        verify_hmac=verify_hmac,
        as_json=as_json,
    )
    sys.exit(exit_code)


def cli_main() -> None:
    """Entry point with clean top-level error handling and update check.

    Catches unhandled Python exceptions and prints a user-friendly message
    instead of a raw traceback.  Pass --verbose to see the full traceback.
    Starts a background thread to check for newer versions on PyPI.
    """
    # Start update check in background — never blocks the scan
    _t = threading.Thread(target=_check_for_update_bg, daemon=True)
    _t.start()

    try:
        main(standalone_mode=True)
    except SystemExit as exc:
        # Print update notice before exit (if available quickly)
        if exc.code == 0:
            _print_update_notice(Console(stderr=True))
        raise
    except KeyboardInterrupt:
        click.echo("\nInterrupted.", err=True)
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        verbose = "--verbose" in sys.argv or "-v" in sys.argv
        err_console = Console(stderr=True)
        err_console.print(f"\n[bold red]Error:[/bold red] {exc}")
        if verbose:
            err_console.print_exception(show_locals=False)
        else:
            err_console.print("[dim]Run with --verbose for full traceback.[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    cli_main()  # pragma: no cover
