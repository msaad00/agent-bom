"""Click option decorators for the ``scan`` command, grouped by category.

Instead of a 517-line decorator pyramid on the scan function, options are
organized into logical groups.  The :func:`scan_options` composite decorator
applies all groups in a single ``@scan_options`` call.

Usage::

    from agent_bom.cli.options import scan_options

    @click.command()
    @scan_options
    def scan(**kwargs):
        ...
"""

from __future__ import annotations

import click

# ── helpers ──────────────────────────────────────────────────────────────────


def _apply(decorators):
    """Apply a list of click decorators bottom-up (last in list = outermost)."""

    def wrapper(fn):
        for dec in reversed(decorators):
            fn = dec(fn)
        return fn

    return wrapper


# ── 1. Input sources ────────────────────────────────────────────────────────


def input_options(fn):
    """Project directory, config, inventory, SBOM, images, filesystem."""
    return _apply(
        [
            click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan"),
            click.option("--config-dir", type=click.Path(exists=True), help="Custom agent config directory to scan"),
            click.option("--inventory", type=str, default=None, help="Inventory file (JSON or CSV). Use '-' for stdin."),
            click.option(
                "--sbom",
                "sbom_file",
                type=click.Path(exists=True),
                help="Existing SBOM file to ingest (CycloneDX or SPDX JSON from Syft/Grype/Trivy)",
            ),
            click.option(
                "--sbom-name",
                "sbom_name",
                default=None,
                metavar="NAME",
                help="Label for the SBOM resource (e.g. 'prod-api-01', 'nginx:1.25'). Auto-detected from SBOM metadata if omitted.",
            ),
            click.option(
                "--image",
                "images",
                multiple=True,
                metavar="IMAGE",
                help="Docker image to scan (e.g. nginx:1.25). Repeatable for multiple images.",
            ),
            click.option(
                "--image-tar",
                "image_tars",
                multiple=True,
                metavar="TAR",
                help="OCI image tarball to scan without Docker/Syft/Grype (e.g. image.tar from 'docker save'). Repeatable.",
            ),
            click.option(
                "--filesystem",
                "filesystem_paths",
                multiple=True,
                type=click.Path(exists=True),
                metavar="PATH",
                help="Filesystem directory or tar archive to scan for packages via Syft (e.g. mounted VM disk snapshot). Repeatable.",
            ),
            click.option(
                "--correlate",
                "correlate_log",
                type=click.Path(exists=True),
                default=None,
                metavar="AUDIT_LOG",
                help="Cross-reference scan results with proxy audit log (JSONL) to identify which vulnerable tools were actually called.",
            ),
            click.option(
                "--self-scan",
                "self_scan",
                is_flag=True,
                default=False,
                help="Scan agent-bom's own installed dependencies for vulnerabilities.",
            ),
            click.option(
                "--demo", is_flag=True, default=False, help="Run a demo scan with bundled inventory containing known-vulnerable packages."
            ),
            click.option(
                "--external-scan",
                "external_scan_path",
                type=click.Path(exists=True),
                default=None,
                help="Path to Trivy, Grype, or Syft JSON output. Ingests findings and adds blast radius analysis.",
            ),
            click.option(
                "--os-packages",
                "os_packages",
                is_flag=True,
                default=False,
                help="Scan the host OS for installed system packages (dpkg/rpm/apk) and check them for CVEs.",
            ),
        ]
    )(fn)


# ── 2. Output & formatting ─────────────────────────────────────────────────


def output_options(fn):
    """Output path, format, display controls, telemetry endpoints."""
    return _apply(
        [
            click.option("--output", "-o", type=str, help="Output file path (use '-' for stdout)"),
            click.option(
                "--open",
                "open_report",
                is_flag=True,
                default=False,
                help="Auto-open HTML/graph-html report in default browser after generation",
            ),
            click.option(
                "--format",
                "-f",
                "output_format",
                type=click.Choice(
                    [
                        "console",
                        "json",
                        "html",
                        "sarif",
                        "cyclonedx",
                        "spdx",
                        "junit",
                        "csv",
                        "markdown",
                        "plain",
                        "text",
                        "prometheus",
                        "graph",
                        "graph-html",
                        "mermaid",
                        "svg",
                        "badge",
                    ]
                ),
                default="console",
                help=(
                    "Output format.\n\n"
                    "Core: console (default, colored terminal), json, html, sarif (GitHub/GitLab Security tab), cyclonedx (SBOM).\n"
                    "SBOM: spdx (alternate SBOM standard).\n"
                    "CI/CD: junit (JUnit XML for Jenkins/GitLab/Azure DevOps), csv (spreadsheet/SIEM), markdown (PR comments/wiki).\n"
                    "Plain: plain (no color, for piping/logging) — alias: text.\n"
                    "Monitoring: prometheus (Prometheus exposition format).\n"
                    "Visualization: mermaid, graph-html (interactive), svg.\n"
                    "Other: graph (raw graph JSON), badge (single-line status)."
                ),
            ),
            click.option(
                "--mermaid-mode",
                type=click.Choice(["supply-chain", "attack-flow", "lifecycle"]),
                default="supply-chain",
                help="Mermaid diagram mode: supply-chain (full hierarchy), attack-flow (CVE blast radius), or lifecycle (gantt timeline)",
            ),
            click.option(
                "--push-gateway",
                "push_gateway",
                default=None,
                metavar="URL",
                help="Prometheus Pushgateway URL to push metrics after scan (e.g. http://localhost:9091)",
            ),
            click.option(
                "--otel-endpoint",
                "otel_endpoint",
                default=None,
                metavar="URL",
                help="OpenTelemetry OTLP/HTTP collector endpoint (e.g. http://localhost:4318). Requires pip install 'agent-bom[otel]'",
            ),
            click.option(
                "--verbose",
                "-v",
                is_flag=True,
                help="Full output — dependency tree, all findings, severity chart, threat frameworks, debug logging",
            ),
            click.option(
                "--log-level",
                "log_level",
                type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
                default=None,
                help="Set log level (overrides --verbose). Env: AGENT_BOM_LOG_LEVEL",
            ),
            click.option("--log-json", "log_json", is_flag=True, help="Emit structured JSON logs to stderr (for SIEM ingestion)"),
            click.option("--log-file", "log_file", type=click.Path(), default=None, help="Write JSON logs to file"),
            click.option("--no-color", is_flag=True, help="Disable colored output (useful for piping, CI logs, accessibility)"),
            click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results (for scripting)"),
            click.option(
                "--exclude-unfixable",
                is_flag=True,
                default=False,
                help="Exclude findings with no available fix from SARIF output (reduces GitHub Security tab noise)",
            ),
            click.option(
                "--fixable-only",
                "fixable_only",
                is_flag=True,
                default=False,
                help="Show only vulnerabilities with available fixes.",
            ),
            click.option(
                "--posture",
                is_flag=True,
                default=False,
                help="Show a concise 5-line workstation posture summary.",
            ),
        ]
    )(fn)


# ── 3. Scan control ────────────────────────────────────────────────────────


def scan_control_options(fn):
    """Scan behavior: dry-run, skip flags, depth, presets."""
    return _apply(
        [
            click.option("--dry-run", is_flag=True, help="Show what files and APIs would be accessed without scanning, then exit 0"),
            click.option(
                "--offline",
                is_flag=True,
                envvar="AGENT_BOM_OFFLINE",
                help="Scan only against local DB — skip all network calls. Use after 'db update'.",
            ),
            click.option("--no-scan", is_flag=True, help="Skip vulnerability scanning (inventory only)"),
            click.option(
                "--blast-radius-depth",
                type=int,
                default=1,
                show_default=True,
                metavar="N",
                help=(
                    "Multi-hop blast radius depth (1-5). Traces agent-to-agent delegation chains "
                    "through shared MCP servers. Higher values reveal transitive risk but increase "
                    "analysis time. Default 1 = direct impact only."
                ),
            ),
            click.option("--no-tree", is_flag=True, help="Skip dependency tree output"),
            click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages"),
            click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution"),
            click.option(
                "--preset",
                type=click.Choice(["ci", "enterprise", "quick"]),
                default=None,
                help=(
                    "Scan preset: ci (quiet, json, fail-on-critical), enterprise (enrich, introspect,"
                    " transitive, verify-integrity, verify-instructions), quick (no transitive, no enrich)"
                ),
            ),
        ]
    )(fn)


# ── 4. Enrichment ──────────────────────────────────────────────────────────


def enrichment_options(fn):
    """NVD, EPSS, KEV, Scorecard, deps.dev, license, Snyk."""
    return _apply(
        [
            click.option("--enrich", is_flag=True, help="Enrich vulnerabilities with NVD, EPSS, and CISA KEV data"),
            click.option("--compliance", is_flag=True, help="Tag findings with compliance frameworks (OWASP, NIST, CIS, ISO, SOC2, CMMC)"),
            click.option(
                "--auto-update-db/--no-auto-update-db",
                "auto_update_db",
                default=True,
                envvar="AGENT_BOM_AUTO_UPDATE_DB",
                show_default=True,
                help="Auto-refresh local vuln DB if stale (>7 days). --no-auto-update-db to disable.",
            ),
            click.option(
                "--db-source",
                "db_sources",
                type=str,
                default=None,
                envvar="AGENT_BOM_DB_SOURCES",
                help="Comma-separated DB sources to sync before scanning (e.g. nvd,ghsa,osv,epss,kev).",
            ),
            click.option("--nvd-api-key", envvar="NVD_API_KEY", help="NVD API key for higher rate limits"),
            click.option("--scorecard", "scorecard_flag", is_flag=True, help="Enrich packages with OpenSSF Scorecard scores"),
            click.option(
                "--deps-dev",
                "deps_dev",
                is_flag=True,
                help="Use deps.dev for transitive dependency resolution and license enrichment (all ecosystems)",
            ),
            click.option(
                "--license-check",
                "license_check",
                is_flag=True,
                help="Evaluate package licenses against compliance policy (block GPL/AGPL, warn copyleft)",
            ),
            click.option("--snyk", "snyk_flag", is_flag=True, help="Enrich vulnerabilities with Snyk intelligence (requires SNYK_TOKEN)"),
            click.option(
                "--snyk-token", default=None, envvar="SNYK_TOKEN", metavar="KEY", help="Snyk API token (or set SNYK_TOKEN env var)"
            ),
            click.option(
                "--snyk-org", default=None, envvar="SNYK_ORG_ID", metavar="ORG", help="Snyk organization ID (or set SNYK_ORG_ID env var)"
            ),
        ]
    )(fn)


# ── 5. VEX ──────────────────────────────────────────────────────────────────


def vex_options(fn):
    """OpenVEX document loading and generation."""
    return _apply(
        [
            click.option(
                "--vex",
                "vex_path",
                type=click.Path(exists=True),
                default=None,
                metavar="PATH",
                help="Apply a VEX document (OpenVEX JSON) to suppress resolved vulnerabilities",
            ),
            click.option(
                "--generate-vex",
                "generate_vex_flag",
                is_flag=True,
                help="Auto-generate a VEX document from scan results (KEV → affected, rest → under_investigation)",
            ),
            click.option(
                "--vex-output",
                "vex_output_path",
                type=str,
                default=None,
                metavar="PATH",
                help="Write generated VEX document to this file (default: agent-bom.vex.json)",
            ),
            click.option(
                "--ignore-file",
                "ignore_file",
                type=click.Path(),
                default=None,
                metavar="PATH",
                help=(
                    "Path to ignore/allowlist file (default: .agent-bom-ignore.yaml). "
                    "Suppress known false positives by CVE ID, package, or finding type."
                ),
            ),
        ]
    )(fn)


# ── 6. Policy & CI gates ───────────────────────────────────────────────────


def policy_options(fn):
    """Failure thresholds, policy files, baselines, history."""
    return _apply(
        [
            click.option(
                "--fail-on-severity",
                type=click.Choice(["critical", "high", "medium", "low"]),
                help="Exit 1 if vulnerabilities of this severity or higher are found",
            ),
            click.option(
                "--warn-on",
                "warn_on_severity",
                type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
                default=None,
                help=(
                    "Warn (exit 0) when findings at or above this severity exist. "
                    "Use with --fail-on-severity for two-tier CI gates (e.g. --warn-on medium --fail-on-severity critical)."
                ),
            ),
            click.option("--fail-on-kev", is_flag=True, help="Exit 1 if any finding appears in CISA KEV (must use --enrich)"),
            click.option("--fail-if-ai-risk", is_flag=True, help="Exit 1 if an AI framework package with credentials has vulnerabilities"),
            click.option("--save", "save_report", is_flag=True, help="Save this scan to ~/.agent-bom/history/ for future diffing"),
            click.option("--baseline", type=click.Path(exists=True), help="Path to a baseline report JSON to diff against current scan"),
            click.option(
                "--delta",
                "delta_mode",
                is_flag=True,
                default=False,
                help=(
                    "Delta mode: report only new findings vs baseline (--baseline). "
                    "Exit code is based on new findings only — pre-existing are suppressed. "
                    "Use in CI to surface only what the current PR introduced."
                ),
            ),
            click.option("--policy", type=click.Path(exists=True), help="Policy file (JSON/YAML) with declarative security rules"),
        ]
    )(fn)


# ── 7. Discovery sources ───────────────────────────────────────────────────


def discovery_options(fn):
    """Agent frameworks, skills, browser extensions, Jupyter, model files, datasets, training pipelines, prompts."""
    return _apply(
        [
            click.option(
                "--agent-project",
                "agent_projects",
                multiple=True,
                type=click.Path(exists=True),
                metavar="DIR",
                help="Python project using an agent framework (OpenAI Agents SDK, Google ADK, LangChain, AutoGen, "
                "CrewAI, LlamaIndex, Pydantic AI, smolagents, Semantic Kernel, Haystack). Repeatable.",
            ),
            click.option(
                "--skill",
                "skill_paths",
                multiple=True,
                type=click.Path(exists=True),
                metavar="PATH",
                help="Skill/instruction file to scan (CLAUDE.md, .cursorrules, skill.md). "
                "Extracts MCP server refs, packages, and credential env vars. Repeatable.",
            ),
            click.option(
                "--no-skill", is_flag=True, help="Skip all skill/instruction file scanning (auto-discovery + explicit --skill paths)"
            ),
            click.option("--skill-only", is_flag=True, help="Scan ONLY skill/instruction files; skip agent/package/CVE scanning"),
            click.option(
                "--scan-prompts", is_flag=True, help="Scan prompt template files (.prompt, system_prompt.*, prompts/) for security risks"
            ),
            click.option(
                "--browser-extensions",
                "browser_extensions",
                is_flag=True,
                help="Scan installed browser extensions (Chrome, Brave, Edge, Firefox) for dangerous permissions "
                "that could expose AI assistant sessions or MCP tool calls.",
            ),
            click.option(
                "--jupyter",
                "jupyter_dirs",
                multiple=True,
                type=click.Path(exists=True),
                metavar="DIR",
                help="Scan Jupyter notebooks (.ipynb) for AI library imports, model references, and credentials. Repeatable.",
            ),
            click.option(
                "--model-files",
                "model_dirs",
                multiple=True,
                type=click.Path(exists=True),
                metavar="DIR",
                help="Scan for ML model binary files (.gguf, .safetensors, .onnx, .pt, .pkl, etc.). Repeatable.",
            ),
            click.option(
                "--model-provenance", is_flag=True, help="Enable SHA-256 hash and Sigstore signature checks for --model-files scans"
            ),
            click.option(
                "--ai-inventory",
                "ai_inventory_paths",
                multiple=True,
                type=click.Path(exists=True),
                metavar="DIR",
                help="Scan source code for AI SDK imports, model references, API keys, and shadow AI. Repeatable.",
            ),
            click.option(
                "--dataset-cards",
                "dataset_dirs",
                multiple=True,
                type=click.Path(exists=True),
                metavar="DIR",
                help="Scan for dataset cards (dataset_info.json, README.md frontmatter, .dvc files). Repeatable.",
            ),
            click.option(
                "--training-pipelines",
                "training_dirs",
                multiple=True,
                type=click.Path(exists=True),
                metavar="DIR",
                help="Scan for ML training pipeline metadata (MLflow runs, Kubeflow pipelines, W&B logs). Repeatable.",
            ),
            click.option(
                "--hf-model",
                "hf_models",
                multiple=True,
                metavar="NAME",
                help="Check HuggingFace model provenance (org/model format, e.g. meta-llama/Llama-3.1-8B). Repeatable.",
            ),
        ]
    )(fn)


# ── 8. Runtime & enforcement ───────────────────────────────────────────────


def runtime_options(fn):
    """Introspect, enforce, verify, context graph, dynamic discovery, processes, containers, health check."""
    return _apply(
        [
            click.option(
                "--introspect",
                is_flag=True,
                help="Connect to live MCP servers to discover runtime tools/resources (read-only, requires mcp SDK)",
            ),
            click.option(
                "--introspect-timeout",
                type=float,
                default=10.0,
                show_default=True,
                help="Timeout per MCP server for --introspect (seconds)",
            ),
            click.option(
                "--enforce",
                is_flag=True,
                help="Run tool poisoning detection and enforcement checks (description injection, capability combos, CVE exposure, drift)",
            ),
            click.option(
                "--verify-integrity", is_flag=True, help="Verify package integrity (SHA256/SRI) and SLSA provenance against registries"
            ),
            click.option(
                "--verify-instructions",
                is_flag=True,
                help="Verify instruction file provenance (CLAUDE.md, .cursorrules, SKILL.md) via Sigstore bundles",
            ),
            click.option(
                "--context-graph", "context_graph_flag", is_flag=True, help="Compute agent context graph with lateral movement analysis"
            ),
            click.option(
                "--graph-backend",
                "graph_backend",
                type=click.Choice(["auto", "memory", "networkx"]),
                default="auto",
                show_default=True,
                help="Graph backend for context graph analysis (auto tries networkx, falls back to memory)",
            ),
            click.option(
                "--dynamic-discovery", is_flag=True, help="Enable dynamic content-based MCP config discovery beyond known clients"
            ),
            click.option(
                "--dynamic-max-depth",
                type=int,
                default=4,
                show_default=True,
                help="Max directory depth for dynamic discovery filesystem scanning",
            ),
            click.option(
                "--include-processes",
                is_flag=True,
                help="Scan running host processes for MCP servers (requires psutil: pip install psutil)",
            ),
            click.option(
                "--include-containers", is_flag=True, help="Scan running Docker containers for MCP servers (requires docker CLI on PATH)"
            ),
            click.option(
                "--k8s-mcp",
                "k8s_mcp",
                is_flag=True,
                help="Scan Kubernetes cluster for MCP pods, services, and CRDs (requires kubectl on PATH)",
            ),
            click.option("--k8s-namespace", default="default", show_default=True, help="Kubernetes namespace for --k8s-mcp"),
            click.option("--k8s-all-namespaces", "k8s_all_namespaces", is_flag=True, help="Scan all Kubernetes namespaces for --k8s-mcp"),
            click.option(
                "--k8s-context", "k8s_mcp_context", default=None, help="kubectl context for --k8s-mcp (uses current context if omitted)"
            ),
            click.option(
                "--health-check",
                "health_check",
                is_flag=True,
                help="Probe discovered MCP servers for liveness (reachability + tool count, requires mcp SDK)",
            ),
            click.option(
                "--hc-timeout", type=float, default=5.0, show_default=True, help="Timeout per server for --health-check (seconds)"
            ),
        ]
    )(fn)


# ── 9. Kubernetes (image scanning) ─────────────────────────────────────────


def kubernetes_options(fn):
    """K8s cluster image discovery for vulnerability scanning."""
    return _apply(
        [
            click.option("--k8s", is_flag=True, help="Discover container images from a Kubernetes cluster via kubectl"),
            click.option("--namespace", default="default", show_default=True, help="Kubernetes namespace (used with --k8s)"),
            click.option("--all-namespaces", "-A", is_flag=True, help="Scan all Kubernetes namespaces (used with --k8s)"),
            click.option("--context", "k8s_context", default=None, help="kubectl context to use (used with --k8s)"),
            click.option(
                "--registry-user", default=None, envvar="AGENT_BOM_REGISTRY_USER", help="Registry username for private image scanning"
            ),
            click.option(
                "--registry-pass", default=None, envvar="AGENT_BOM_REGISTRY_PASS", help="Registry password for private image scanning"
            ),
            click.option(
                "--platform", "image_platform", default=None, help="Image platform for multi-arch manifests (e.g. linux/amd64, linux/arm64)"
            ),
        ]
    )(fn)


# ── 10. Cloud providers ────────────────────────────────────────────────────


def cloud_options(fn):
    """AWS, Azure, GCP, CoreWeave, Databricks, Snowflake, Nebius."""
    return _apply(
        [
            # AWS
            click.option("--aws", is_flag=True, help="Discover AI agents from AWS Bedrock, Lambda, and ECS"),
            click.option("--aws-region", default=None, metavar="REGION", help="AWS region (default: AWS_DEFAULT_REGION)"),
            click.option("--aws-profile", default=None, metavar="PROFILE", help="AWS credential profile"),
            click.option("--aws-include-lambda", is_flag=True, help="Discover standalone Lambda functions (used with --aws)"),
            click.option("--aws-include-eks", is_flag=True, help="Discover EKS cluster workloads via kubectl (used with --aws)"),
            click.option("--aws-include-step-functions", is_flag=True, help="Discover Step Functions workflows (used with --aws)"),
            click.option("--aws-include-ec2", is_flag=True, help="Discover EC2 instances by tag (used with --aws)"),
            click.option(
                "--aws-ec2-tag", default=None, metavar="KEY=VALUE", help="EC2 tag filter for --aws-include-ec2 (e.g. 'Environment=ai-prod')"
            ),
            # Azure
            click.option("--azure", "azure_flag", is_flag=True, help="Discover agents from Azure AI Foundry and Container Apps"),
            click.option("--azure-subscription", default=None, metavar="ID", envvar="AZURE_SUBSCRIPTION_ID", help="Azure subscription ID"),
            # GCP
            click.option("--gcp", "gcp_flag", is_flag=True, help="Discover agents from Google Cloud Vertex AI and Cloud Run"),
            click.option("--gcp-project", default=None, metavar="PROJECT", envvar="GOOGLE_CLOUD_PROJECT", help="GCP project ID"),
            # CoreWeave
            click.option(
                "--coreweave",
                "coreweave_flag",
                is_flag=True,
                help="Discover GPU VMs, NVIDIA NIM inference, and InfiniBand training from CoreWeave",
            ),
            click.option("--coreweave-context", default=None, metavar="CTX", help="kubectl context for CoreWeave cluster"),
            click.option("--coreweave-namespace", default=None, metavar="NS", help="Limit CoreWeave discovery to a namespace"),
            # Databricks
            click.option(
                "--databricks", "databricks_flag", is_flag=True, help="Discover agents from Databricks clusters and model serving"
            ),
            # Snowflake
            click.option("--snowflake", "snowflake_flag", is_flag=True, help="Discover Cortex agents and Snowpark apps from Snowflake"),
            click.option(
                "--snowflake-authenticator",
                default=None,
                envvar="SNOWFLAKE_AUTHENTICATOR",
                metavar="METHOD",
                help="Snowflake auth method: externalbrowser (SSO, default), snowflake_jwt (key-pair), oauth. No passwords stored.",
            ),
            click.option(
                "--cortex-observability", is_flag=True, help="Include Cortex agent observability telemetry (requires --snowflake)"
            ),
            # Nebius
            click.option("--nebius", "nebius_flag", is_flag=True, help="Discover AI workloads from Nebius GPU cloud"),
            click.option("--nebius-api-key", default=None, envvar="NEBIUS_API_KEY", metavar="KEY", help="Nebius API key"),
            click.option("--nebius-project-id", default=None, envvar="NEBIUS_PROJECT_ID", metavar="ID", help="Nebius project ID"),
        ]
    )(fn)


# ── 11. ML platform providers ──────────────────────────────────────────────


def ml_platform_options(fn):
    """HuggingFace, W&B, MLflow, OpenAI, Ollama, Smithery, MCP Registry."""
    return _apply(
        [
            click.option("--huggingface", "hf_flag", is_flag=True, help="Discover models, Spaces, and endpoints from Hugging Face Hub"),
            click.option(
                "--verify-model-hashes",
                "verify_model_hashes",
                is_flag=True,
                help="Verify SHA-256 of local model weight files against HuggingFace Hub metadata",
            ),
            click.option("--hf-token", default=None, envvar="HF_TOKEN", metavar="TOKEN", help="Hugging Face API token"),
            click.option("--hf-username", default=None, metavar="USER", help="Hugging Face username to scope discovery"),
            click.option("--hf-organization", default=None, metavar="ORG", help="Hugging Face organization to scope discovery"),
            click.option("--wandb", "wandb_flag", is_flag=True, help="Discover runs and artifacts from Weights & Biases"),
            click.option("--wandb-api-key", default=None, envvar="WANDB_API_KEY", metavar="KEY", help="W&B API key"),
            click.option("--wandb-entity", default=None, envvar="WANDB_ENTITY", metavar="ENTITY", help="W&B entity (team or user)"),
            click.option("--wandb-project", default=None, metavar="PROJECT", help="W&B project name"),
            click.option("--mlflow", "mlflow_flag", is_flag=True, help="Discover models and experiments from MLflow"),
            click.option(
                "--mlflow-tracking-uri", default=None, envvar="MLFLOW_TRACKING_URI", metavar="URI", help="MLflow tracking server URI"
            ),
            click.option("--openai", "openai_flag", is_flag=True, help="Discover assistants and fine-tuned models from OpenAI"),
            click.option("--openai-api-key", default=None, envvar="OPENAI_API_KEY", metavar="KEY", help="OpenAI API key"),
            click.option("--openai-org-id", default=None, envvar="OPENAI_ORG_ID", metavar="ORG", help="OpenAI organization ID"),
            click.option("--ollama", "ollama_flag", is_flag=True, help="Discover locally downloaded Ollama models"),
            click.option(
                "--ollama-host", default=None, envvar="OLLAMA_HOST", metavar="URL", help="Ollama API host (default: http://localhost:11434)"
            ),
            click.option(
                "--smithery",
                "smithery_flag",
                is_flag=True,
                help="Use Smithery.ai registry as fallback for unknown MCP servers (extends coverage from 112 to 2800+ servers)",
            ),
            click.option(
                "--smithery-token",
                default=None,
                envvar="SMITHERY_API_KEY",
                metavar="KEY",
                help="Smithery API key (or set SMITHERY_API_KEY env var)",
            ),
            click.option(
                "--mcp-registry",
                "mcp_registry_flag",
                is_flag=True,
                help="Use Official MCP Registry as fallback for unknown MCP servers (free, no auth)",
            ),
        ]
    )(fn)


# ── 12. IaC & SAST ─────────────────────────────────────────────────────────


def iac_sast_options(fn):
    """Terraform, GitHub Actions, code scanning (Semgrep)."""
    return _apply(
        [
            click.option(
                "--tf-dir",
                "tf_dirs",
                multiple=True,
                type=click.Path(exists=True),
                metavar="DIR",
                help="Terraform directory to scan for AI resources, providers, and hardcoded secrets. Repeatable.",
            ),
            click.option(
                "--gha",
                "gha_path",
                type=click.Path(exists=True),
                metavar="REPO",
                help="Repository root to scan GitHub Actions workflows for AI usage and credential exposure.",
            ),
            click.option(
                "--code",
                "code_paths",
                multiple=True,
                type=click.Path(exists=True),
                metavar="PATH",
                help="Source code directory to scan for security flaws via Semgrep (SAST). Repeatable.",
            ),
            click.option(
                "--sast-config",
                default="auto",
                show_default=True,
                metavar="CONFIG",
                help="Semgrep config for --code scans (e.g. 'p/security-audit'). Default: auto.",
            ),
            click.option(
                "--iac",
                "iac_paths",
                multiple=True,
                type=click.Path(exists=True),
                metavar="PATH",
                help="Scan IaC files for misconfigurations (Dockerfile, K8s YAML, Terraform). Repeatable.",
            ),
        ]
    )(fn)


# ── 13. Compliance & benchmarks ─────────────────────────────────────────────


def compliance_options(fn):
    """CIS benchmarks, AISVS, vector DB, GPU scan, compliance export."""
    return _apply(
        [
            click.option("--aws-cis-benchmark", is_flag=True, help="Run CIS AWS Foundations Benchmark v3.0 checks (used with --aws)"),
            click.option("--snowflake-cis-benchmark", is_flag=True, help="Run CIS Snowflake Benchmark v1.0 checks (used with --snowflake)"),
            click.option(
                "--azure-cis-benchmark", is_flag=True, help="Run CIS Azure Security Benchmark v3.0 checks (requires AZURE_SUBSCRIPTION_ID)"
            ),
            click.option(
                "--gcp-cis-benchmark", is_flag=True, help="Run CIS GCP Foundation Benchmark v3.0 checks (requires GOOGLE_CLOUD_PROJECT)"
            ),
            click.option(
                "--databricks-security", is_flag=True, help="Run Databricks Security Best Practices checks (used with --databricks)"
            ),
            click.option(
                "--aisvs",
                "aisvs_flag",
                is_flag=True,
                help="Run AISVS v1.0 compliance checks (model safety, vector store auth, inference exposure)",
            ),
            click.option(
                "--vector-db-scan",
                "vector_db_scan",
                is_flag=True,
                help="Scan for running vector databases (Qdrant, Weaviate, Chroma, Milvus) and assess security",
            ),
            click.option(
                "--gpu-scan",
                "gpu_scan_flag",
                is_flag=True,
                help=(
                    "Discover GPU-enabled containers and K8s nodes (NVIDIA base images, CUDA versions,"
                    " DCGM endpoints). Requires docker/kubectl on PATH."
                ),
            ),
            click.option(
                "--gpu-k8s-context",
                "gpu_k8s_context",
                default=None,
                metavar="CTX",
                help="kubectl context for --gpu-scan K8s node discovery",
            ),
            click.option("--no-dcgm-probe", "no_dcgm_probe", is_flag=True, help="Skip DCGM exporter endpoint probing during --gpu-scan"),
            click.option(
                "--compliance-export",
                "compliance_export",
                type=click.Choice(["cmmc", "fedramp", "nist-ai-rmf"]),
                default=None,
                help="Export compliance evidence bundle (ZIP) for CMMC, FedRAMP, or NIST AI RMF audits",
            ),
        ]
    )(fn)


# ── 14. AI enrichment & remediation ─────────────────────────────────────────


def ai_remediation_options(fn):
    """LLM enrichment, remediation generation, auto-apply fixes."""
    return _apply(
        [
            click.option(
                "--ai-enrich",
                is_flag=True,
                help=(
                    "Enrich findings with LLM-generated risk narratives, executive summary, and threat chains."
                    " Auto-detects Ollama (free, local) or uses litellm (pip install 'agent-bom[ai-enrich]')"
                ),
            ),
            click.option(
                "--ai-model",
                default="openai/gpt-4o-mini",
                show_default=True,
                metavar="MODEL",
                help=(
                    "LLM model for --ai-enrich. Auto-detects Ollama if running."
                    " Examples: ollama/llama3.2 (free, local), ollama/mistral, openai/gpt-4o-mini"
                ),
            ),
            click.option(
                "--remediate",
                "remediate_path",
                type=str,
                default=None,
                metavar="PATH",
                help="Generate remediation.md with fix commands for all findings",
            ),
            click.option(
                "--remediate-sh",
                "remediate_sh_path",
                type=str,
                default=None,
                metavar="PATH",
                help="Generate remediation.sh script with package upgrade commands",
            ),
            click.option(
                "--apply",
                "apply_fixes_flag",
                is_flag=True,
                help="Auto-apply package version fixes to dependency files (package.json, requirements.txt)",
            ),
            click.option("--apply-dry-run", is_flag=True, help="Preview what --apply would change without modifying files"),
        ]
    )(fn)


# ── 15. Integrations ───────────────────────────────────────────────────────


def integration_options(fn):
    """Jira, Slack, ServiceNow, push, Vanta, Drata, SIEM, ClickHouse."""
    return _apply(
        [
            click.option(
                "--jira-url",
                default=None,
                envvar="JIRA_URL",
                metavar="URL",
                help="Jira base URL for ticket creation (e.g. https://company.atlassian.net)",
            ),
            click.option(
                "--jira-user", default=None, envvar="JIRA_USER", metavar="EMAIL", help="Jira user email (or set JIRA_USER env var)"
            ),
            click.option(
                "--jira-token",
                default=None,
                envvar="JIRA_API_TOKEN",
                metavar="TOKEN",
                help="Jira API token (or set JIRA_API_TOKEN env var)",
            ),
            click.option("--jira-project", default=None, envvar="JIRA_PROJECT", metavar="KEY", help="Jira project key (e.g. SEC)"),
            click.option(
                "--slack-webhook",
                default=None,
                envvar="SLACK_WEBHOOK_URL",
                metavar="URL",
                help="Slack incoming webhook URL for scan alerts",
            ),
            click.option("--jira-discover", is_flag=True, help="Discover AI agents from Jira automation rules and installed apps"),
            click.option(
                "--servicenow", "servicenow_flag", is_flag=True, help="Discover AI agents from ServiceNow Flow Designer and IntegrationHub"
            ),
            click.option(
                "--servicenow-instance", default=None, envvar="SERVICENOW_INSTANCE", metavar="URL", help="ServiceNow instance URL"
            ),
            click.option("--servicenow-user", default=None, envvar="SERVICENOW_USER", metavar="USER", help="ServiceNow username"),
            click.option("--servicenow-password", default=None, envvar="SERVICENOW_PASSWORD", metavar="PWD", help="ServiceNow password"),
            click.option("--slack-discover", is_flag=True, help="Discover installed Slack apps and bots in workspace"),
            click.option(
                "--slack-bot-token", default=None, envvar="SLACK_BOT_TOKEN", metavar="TOKEN", help="Slack bot token for app discovery"
            ),
            click.option(
                "--push-url", default=None, envvar="AGENT_BOM_PUSH_URL", metavar="URL", help="Push scan results to central dashboard URL"
            ),
            click.option(
                "--push-api-key", default=None, envvar="AGENT_BOM_PUSH_API_KEY", metavar="KEY", help="API key for push authentication"
            ),
            click.option(
                "--vanta-token",
                default=None,
                envvar="VANTA_API_TOKEN",
                metavar="TOKEN",
                help="Vanta API token for compliance evidence upload",
            ),
            click.option(
                "--drata-token", default=None, envvar="DRATA_API_TOKEN", metavar="TOKEN", help="Drata API token for GRC evidence upload"
            ),
            click.option(
                "--siem",
                "siem_type",
                default=None,
                envvar="AGENT_BOM_SIEM_TYPE",
                type=click.Choice(["splunk", "datadog", "elasticsearch", "opensearch"], case_sensitive=False),
                metavar="TYPE",
                help="Push findings to SIEM: splunk | datadog | elasticsearch | opensearch",
            ),
            click.option(
                "--siem-url",
                default=None,
                envvar="AGENT_BOM_SIEM_URL",
                metavar="URL",
                help="SIEM endpoint URL (e.g. https://splunk.corp:8088)",
            ),
            click.option(
                "--siem-token", default=None, envvar="AGENT_BOM_SIEM_TOKEN", metavar="TOKEN", help="SIEM authentication token / API key"
            ),
            click.option(
                "--siem-index",
                default=None,
                envvar="AGENT_BOM_SIEM_INDEX",
                metavar="INDEX",
                help="SIEM index / sourcetype (e.g. main, agent-bom-alerts)",
            ),
            click.option(
                "--siem-format",
                default="ocsf",
                envvar="AGENT_BOM_SIEM_FORMAT",
                type=click.Choice(["raw", "ocsf"], case_sensitive=False),
                show_default=True,
                help="Event format for SIEM push: ocsf (default) or raw",
            ),
            click.option(
                "--clickhouse-url",
                default=None,
                envvar="AGENT_BOM_CLICKHOUSE_URL",
                metavar="URL",
                help="ClickHouse HTTP URL for analytics (e.g. http://localhost:8123)",
            ),
        ]
    )(fn)


# ── Composite decorator ────────────────────────────────────────────────────

# Order matters: click applies decorators bottom-up, so the first group
# listed here will have its options appear *last* in --help.  We list them
# in a logical reading order; the actual CLI help grouping is not affected
# since click sorts options alphabetically by default.

_ALL_GROUPS = [
    input_options,
    output_options,
    scan_control_options,
    enrichment_options,
    vex_options,
    policy_options,
    discovery_options,
    runtime_options,
    kubernetes_options,
    cloud_options,
    ml_platform_options,
    iac_sast_options,
    compliance_options,
    ai_remediation_options,
    integration_options,
]


def scan_options(fn):
    """Apply all scan CLI options in one decorator: ``@scan_options``."""
    for group in reversed(_ALL_GROUPS):
        fn = group(fn)
    return fn
