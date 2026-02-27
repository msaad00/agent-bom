"""CLI entry point for agent-bom."""

from __future__ import annotations

import json
import sys
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


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="agent-bom", message="agent-bom %(version)s")
def main():
    """agent-bom — AI Bill of Materials for agents, MCP servers, containers & IaC.

    \b
    Maps the full trust chain: agent → MCP server → packages → CVEs → blast radius.

    \b
    Quick start:
      agent-bom scan                        auto-discover local agents
      agent-bom scan -f html -o report.html open dashboard
      agent-bom scan --enrich               add NVD CVSS + EPSS + CISA KEV
      agent-bom api                         start REST API (port 8422)
      agent-bom serve                       API + dashboard (port 8422)

    \b
    Docs:  https://github.com/msaad00/agent-bom
    """
    pass


@main.command()
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan")
@click.option("--config-dir", type=click.Path(exists=True), help="Custom agent config directory to scan")
@click.option("--inventory", type=click.Path(exists=True), help="Manual inventory JSON file")
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
    "--image", "images", multiple=True, metavar="IMAGE", help="Docker image to scan (e.g. nginx:1.25). Repeatable for multiple images."
)
@click.option("--k8s", is_flag=True, help="Discover container images from a Kubernetes cluster via kubectl")
@click.option("--namespace", default="default", show_default=True, help="Kubernetes namespace (used with --k8s)")
@click.option("--all-namespaces", "-A", is_flag=True, help="Scan all Kubernetes namespaces (used with --k8s)")
@click.option("--context", "k8s_context", default=None, help="kubectl context to use (used with --k8s)")
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
@click.option("--aws", is_flag=True, help="Discover AI agents from AWS Bedrock, Lambda, and ECS")
@click.option("--aws-region", default=None, metavar="REGION", help="AWS region (default: AWS_DEFAULT_REGION)")
@click.option("--aws-profile", default=None, metavar="PROFILE", help="AWS credential profile")
@click.option("--azure", "azure_flag", is_flag=True, help="Discover agents from Azure AI Foundry and Container Apps")
@click.option("--azure-subscription", default=None, metavar="ID", envvar="AZURE_SUBSCRIPTION_ID", help="Azure subscription ID")
@click.option("--gcp", "gcp_flag", is_flag=True, help="Discover agents from Google Cloud Vertex AI and Cloud Run")
@click.option("--gcp-project", default=None, metavar="PROJECT", envvar="GOOGLE_CLOUD_PROJECT", help="GCP project ID")
@click.option("--databricks", "databricks_flag", is_flag=True, help="Discover agents from Databricks clusters and model serving")
@click.option("--snowflake", "snowflake_flag", is_flag=True, help="Discover Cortex agents and Snowpark apps from Snowflake")
@click.option("--nebius", "nebius_flag", is_flag=True, help="Discover AI workloads from Nebius GPU cloud")
@click.option("--nebius-api-key", default=None, envvar="NEBIUS_API_KEY", metavar="KEY", help="Nebius API key")
@click.option("--nebius-project-id", default=None, envvar="NEBIUS_PROJECT_ID", metavar="ID", help="Nebius project ID")
@click.option("--aws-include-lambda", is_flag=True, help="Discover standalone Lambda functions (used with --aws)")
@click.option("--aws-include-eks", is_flag=True, help="Discover EKS cluster workloads via kubectl (used with --aws)")
@click.option("--aws-include-step-functions", is_flag=True, help="Discover Step Functions workflows (used with --aws)")
@click.option("--aws-include-ec2", is_flag=True, help="Discover EC2 instances by tag (used with --aws)")
@click.option("--aws-ec2-tag", default=None, metavar="KEY=VALUE", help="EC2 tag filter for --aws-include-ec2 (e.g. 'Environment=ai-prod')")
@click.option("--huggingface", "hf_flag", is_flag=True, help="Discover models, Spaces, and endpoints from Hugging Face Hub")
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
@click.option(
    "--vanta-token", default=None, envvar="VANTA_API_TOKEN", metavar="TOKEN", help="Vanta API token for compliance evidence upload"
)
@click.option("--drata-token", default=None, envvar="DRATA_API_TOKEN", metavar="TOKEN", help="Drata API token for GRC evidence upload")
@click.option(
    "--verbose", "-v", is_flag=True, help="Full output — dependency tree, all findings, severity chart, threat frameworks, debug logging"
)
@click.option("--no-color", is_flag=True, help="Disable colored output (useful for piping, CI logs, accessibility)")
@click.option(
    "--preset",
    type=click.Choice(["ci", "enterprise", "quick"]),
    default=None,
    help="Scan preset: ci (quiet, json, fail-on-critical), enterprise (enrich, introspect, transitive, verify-integrity), quick (no transitive, no enrich)",
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
    images: tuple,
    k8s: bool,
    namespace: str,
    all_namespaces: bool,
    k8s_context: Optional[str],
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
    jupyter_dirs: tuple,
    model_dirs: tuple,
    model_provenance: bool,
    hf_models: tuple,
    introspect: bool,
    introspect_timeout: float,
    enforce: bool,
    verify_integrity: bool,
    ai_enrich: bool,
    ai_model: str,
    aws: bool,
    aws_region: Optional[str],
    aws_profile: Optional[str],
    azure_flag: bool,
    azure_subscription: Optional[str],
    gcp_flag: bool,
    gcp_project: Optional[str],
    databricks_flag: bool,
    snowflake_flag: bool,
    nebius_flag: bool,
    nebius_api_key: Optional[str],
    nebius_project_id: Optional[str],
    aws_include_lambda: bool,
    aws_include_eks: bool,
    aws_include_step_functions: bool,
    aws_include_ec2: bool,
    aws_ec2_tag: Optional[str],
    hf_flag: bool,
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
    jira_url: Optional[str],
    jira_user: Optional[str],
    jira_token: Optional[str],
    jira_project: Optional[str],
    slack_webhook: Optional[str],
    vanta_token: Optional[str],
    drata_token: Optional[str],
    verbose: bool,
    no_color: bool,
    preset: Optional[str],
    open_report: bool,
):
    """Discover agents, extract dependencies, scan for vulnerabilities.

    \b
    Exit codes:
      0  Clean — no violations, no vulnerabilities at or above threshold
      1  Fail — policy failure, or vulnerabilities found at or above
                --fail-on-severity / --fail-on-kev / --fail-if-ai-risk
    """
    import logging as _logging
    import time as _time

    _scan_start = _time.monotonic()

    # Verbose mode: set root logging to DEBUG
    if verbose:
        _logging.basicConfig(level=_logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")

    # Apply presets (override defaults, don't override explicit flags)
    if preset == "ci":
        quiet = True
        output_format = output_format if output_format != "console" else "json"
        fail_on_severity = fail_on_severity or "critical"
    elif preset == "enterprise":
        enrich = True
        introspect = True
        transitive = True
        verify_integrity = True
    elif preset == "quick":
        transitive = False
        enrich = False

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
        for tf_dir in tf_dirs:
            reads.append(f"  [green]Would read:[/green]   {tf_dir}  (Terraform .tf files)")
        for ap in agent_projects:
            reads.append(f"  [green]Would read:[/green]   {ap}  (Python agent project)")
        for jdir in jupyter_dirs:
            reads.append(f"  [green]Would read:[/green]   {jdir}  (Jupyter notebooks *.ipynb)")
        for mdir in model_dirs:
            reads.append(f"  [green]Would read:[/green]   {mdir}  (ML model files .gguf, .safetensors, .onnx, .pt, etc.)")
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
        con.print(f"\n[bold blue]Loading inventory from {inventory}...[/bold blue]\n")
        from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

        with open(inventory) as f:
            inventory_data = json.load(f)

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
                        # Accept "name@version" shorthand
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
                config_path=agent_data.get("config_path", inventory),
                mcp_servers=mcp_servers,
                version=agent_data.get("version"),
                source=agent_data.get("source", inventory_data.get("source")),
            )
            agents.append(agent)

        con.print(f"  [green]✓[/green] Loaded {len(agents)} agent(s) from inventory")
    elif not skill_only and config_dir:
        con.print(f"\n[bold blue]Scanning config directory: {config_dir}...[/bold blue]\n")
        agents = discover_all(project_dir=config_dir)
    elif not skill_only:
        agents = discover_all(project_dir=project)

    any_cloud = (
        aws
        or azure_flag
        or gcp_flag
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
        and not tf_dirs
        and not gha_path
        and not agent_projects
        and not jupyter_dirs
        and not any_cloud
    ):
        con.print("\n[yellow]No MCP configurations found.[/yellow]")
        con.print(
            "  Use --project, --config-dir, --inventory, --image, --k8s, "
            "--tf-dir, --gha, --agent-project, --jupyter, --aws, --azure, --gcp, "
            "--databricks, --snowflake, --nebius, --huggingface, --wandb, "
            "--mlflow, --openai, --ollama, or --scan-prompts to specify a target."
        )
        sys.exit(0)

    # Step 1b: Load SBOM packages if provided
    sbom_packages: list = []
    if not skill_only and sbom_file:
        from agent_bom.sbom import load_sbom

        try:
            sbom_packages, sbom_fmt = load_sbom(sbom_file)
            con.print(f"\n[bold blue]Loaded SBOM ({sbom_fmt}): {len(sbom_packages)} package(s) from {sbom_file}[/bold blue]\n")
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
                img_packages, strategy = scan_image(image_ref)
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
    if not skill_only and databricks_flag:
        cloud_providers.append(("databricks", {}))
    if not skill_only and snowflake_flag:
        cloud_providers.append(("snowflake", {}))
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
                # Keep pre-populated packages from inventory, merge with discovered ones
                pre_populated = list(server.packages)
                _smithery_tok = smithery_token if smithery_flag else None
                discovered = extract_packages(
                    server, resolve_transitive=transitive, max_depth=max_depth, smithery_token=_smithery_tok, mcp_registry=mcp_registry_flag
                )

                # Merge: discovered + pre-populated + SBOM packages (deduplicated)
                discovered_names = {(p.name, p.ecosystem) for p in discovered}
                merged = discovered + [p for p in pre_populated if (p.name, p.ecosystem) not in discovered_names]
                if sbom_packages:
                    existing_names = {(p.name, p.ecosystem) for p in merged}
                    merged += [p for p in sbom_packages if (p.name, p.ecosystem) not in existing_names]
                    sbom_packages = []  # Attach to first server only, avoid duplication
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
        if not no_scan and total_packages > 0:
            with con.status("[bold]Querying OSV + NVD + KEV + EPSS...[/bold]", spinner="dots"):
                blast_radii = scan_agents_sync(agents, enable_enrichment=enrich, nvd_api_key=nvd_api_key)
            con.print(f"  [green]✓[/green] Scan complete — {len(blast_radii)} finding(s)")

        # Step 4a: Snyk vulnerability enrichment (optional)
        if snyk_flag and not no_scan and total_packages > 0:
            all_pkgs_for_snyk = [p for a in agents for s in a.mcp_servers for p in s.packages]
            if snyk_token:
                try:
                    from agent_bom.snyk import enrich_with_snyk_sync

                    con.print("\n[bold blue]Enriching with Snyk vulnerability data...[/bold blue]\n")
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

    # Build report
    report = AIBOMReport(agents=agents, blast_radii=blast_radii)
    if _skill_audit_data:
        report.skill_audit_data = _skill_audit_data
    if _trust_assessment_data:
        report.trust_assessment_data = _trust_assessment_data
    if _prompt_scan_data:
        report.prompt_scan_data = _prompt_scan_data
    if _enforcement_data:
        report.enforcement_data = _enforcement_data

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
            print_compact_blast_radius(report, limit=5)

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
            print_compact_remediation(report, limit=3)
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

    # Step 6: Save report to history
    current_report_json = to_json(report)
    if save_report:
        from agent_bom.history import save_report as _save

        saved_path = _save(current_report_json)
        con.print(f"\n  [green]✓[/green] Report saved to history: {saved_path}")

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
        except (FileNotFoundError, ValueError) as e:
            con.print(f"\n  [red]Policy error: {e}[/red]")
            sys.exit(1)

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

    # Step 9: Exit code based on policy flags
    exit_code = 0

    if fail_on_severity and blast_radii:
        threshold = SEVERITY_ORDER.get(fail_on_severity, 0)
        for br in blast_radii:
            sev = br.vulnerability.severity.value.lower()
            if SEVERITY_ORDER.get(sev, 0) >= threshold:
                if not quiet:
                    con.print(f"\n  [red]Exiting with code 1: found {sev} vulnerability ({br.vulnerability.id})[/red]")
                exit_code = 1
                break

    if fail_on_kev and blast_radii:
        kev_findings = [br for br in blast_radii if br.vulnerability.is_kev]
        if kev_findings:
            if not quiet:
                con.print(
                    f"\n  [red bold]Exiting with code 1: {len(kev_findings)} CISA KEV "
                    f"finding(s) found (use --enrich if not already)[/red bold]"
                )
            exit_code = 1

    if fail_if_ai_risk and blast_radii:
        ai_findings = [br for br in blast_radii if br.ai_risk_context and br.exposed_credentials]
        if ai_findings:
            if not quiet:
                con.print(
                    f"\n  [red bold]Exiting with code 1: {len(ai_findings)} AI framework "
                    f"package(s) with vulnerabilities and exposed credentials[/red bold]"
                )
            exit_code = 1

    if not policy_passed:
        exit_code = 1

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

        resolved = asyncio.run(_resolve())
        if resolved:
            console.print(f"  [green]✓ Resolved @latest → {pkg.version}[/green]")
            version = pkg.version
        else:
            console.print(f"[yellow]⚠ Could not resolve latest version for {name} ({ecosystem})[/yellow]")
            console.print("  Provide an explicit version: agent-bom check name@1.2.3 -e ecosystem")
            sys.exit(0)

    console.print(f"\n[bold blue]🔍 Checking {name}@{version} ({ecosystem})[/bold blue]\n")

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
            table.add_row(
                v.id,
                f"[{style} reverse] {v.severity.value.upper()} [/{style} reverse]",
                f"{v.cvss_score:.1f}" if v.cvss_score else "—",
                fix_display,
                (v.summary or "")[:80],
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
def serve_cmd(host: str, port: int, persist: Optional[str], cors_allow_all: bool, reload: bool):
    """Start the API server + Next.js dashboard.

    \b
    Requires:  pip install 'agent-bom[ui]'

    \b
    Usage:
      agent-bom serve
      agent-bom serve --port 8422 --persist jobs.db
    """
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

    click.echo(f"\n  API server  →  http://{host}:{port}")
    click.echo(f"  API docs    →  http://{host}:{port}/docs")
    click.echo("  Dashboard   →  http://localhost:3000  (run: cd ui && npm run dev)")
    click.echo("  Press Ctrl+C to stop.\n")

    import uvicorn as _uvicorn

    _uvicorn.run(
        "agent_bom.api.server:app",
        host=host,
        port=port,
        reload=reload,
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
    try:
        import uvicorn
    except ImportError:
        click.echo(
            "ERROR: uvicorn is required for `agent-bom api`.\nInstall it with:  pip install 'agent-bom[api]'",
            err=True,
        )
        sys.exit(1)

    from agent_bom import __version__ as _ver
    from agent_bom.api.server import configure_api, set_job_store

    origins = cors_origins.split(",") if cors_origins else None
    configure_api(
        cors_origins=origins,
        cors_allow_all=cors_allow_all,
        api_key=api_key,
        rate_limit_rpm=rate_limit_rpm,
    )

    if persist:
        from agent_bom.api.store import SQLiteJobStore

        set_job_store(SQLiteJobStore(db_path=persist))

    click.echo(f"  agent-bom API v{_ver}")
    click.echo(f"  Listening on http://{host}:{port}")
    click.echo(f"  Docs:         http://{host}:{port}/docs")
    if api_key:
        click.echo("  Auth:         API key required (Bearer / X-API-Key)")
    if persist:
        click.echo(f"  Storage:      SQLite ({persist})")
    click.echo("  Press Ctrl+C to stop.\n")

    uvicorn.run(
        "agent_bom.api.server:app",
        host=host,
        port=port,
        reload=reload,
        workers=1 if reload else workers,
        log_level="info",
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
def mcp_server_cmd(transport: str, port: int, host: str):
    """Start agent-bom as an MCP server.

    \b
    Requires:  pip install 'agent-bom[mcp-server]'

    \b
    Exposes 13 security tools via MCP protocol:
      scan              Full scan — CVEs, config security, blast radius, compliance
      check             Check a specific package for CVEs before installing
      blast_radius      Look up blast radius for a specific CVE
      policy_check      Evaluate policy rules against scan findings
      registry_lookup   Query the MCP server threat intelligence registry
      generate_sbom     Generate CycloneDX or SPDX SBOM
      compliance        OWASP / MITRE ATLAS / NIST AI RMF posture
      remediate         Generate actionable remediation plan
      skill_trust       ClawHub-style trust assessment for SKILL.md files
      verify            Package integrity + SLSA provenance verification
      where             Show all MCP discovery paths + existence status
      inventory         List agents/servers without CVE scanning
      diff              Compare scan against baseline for new/resolved vulns

    \b
    Usage:
      agent-bom mcp-server                                # stdio (Claude Desktop, Cursor)
      agent-bom mcp-server --transport sse                # SSE (remote clients)
      agent-bom mcp-server --transport streamable-http    # Streamable HTTP (Smithery, etc.)

    \b
    Claude Desktop config (~/.claude/claude_desktop_config.json):
      {"mcpServers": {"agent-bom": {"command": "agent-bom", "args": ["mcp-server"]}}}
    """
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
    except Exception as exc:  # noqa: BLE001
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
def apply_command(scan_json, project_dir, dry_run, no_backup):
    """Apply remediation fixes from a scan result JSON file.

    Reads vulnerability fixes from a previous scan output and modifies
    package.json / requirements.txt with fixed versions.

    \b
    Example:
        agent-bom scan --format json --output scan.json
        agent-bom apply scan.json --dir ./my-project --dry-run
        agent-bom apply scan.json --dir ./my-project
    """
    from rich.console import Console

    from agent_bom.remediate import apply_fixes_from_json

    con = Console(stderr=True)
    con.print(f"\n  Applying fixes from [bold]{scan_json}[/bold] to [bold]{project_dir}[/bold]")

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
@click.argument("server_cmd", nargs=-1, required=True)
def proxy_cmd(policy, log_path, block_undeclared, detect_credentials, rate_limit_threshold, log_only, alert_webhook, server_cmd):
    """Run an MCP server through agent-bom's security proxy.

    \b
    Intercepts JSON-RPC messages between client and server:
    - Logs every tools/call invocation to an audit trail
    - Optionally enforces policy rules in real-time
    - Blocks undeclared tools (not in tools/list response)
    - Detects tool drift (rug pull), dangerous arguments, credential leaks
    - Rate limiting and suspicious sequence detection

    \b
    Usage:
      agent-bom proxy -- npx @modelcontextprotocol/server-filesystem /tmp
      agent-bom proxy --log audit.jsonl -- npx @mcp/server-github
      agent-bom proxy --policy policy.json --block-undeclared -- npx @mcp/server-postgres
      agent-bom proxy --detect-credentials --log-only -- npx @mcp/server-github

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

    from agent_bom.proxy import run_proxy

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
        )
    )
    sys.exit(exit_code)


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


if __name__ == "__main__":
    main()
