"""Scan option groups for discovery, runtime, cloud, compliance, and integrations."""

from __future__ import annotations

import click

from agent_bom.cli.options_helpers import _apply


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
            click.option(
                "--skill-only",
                is_flag=True,
                help="Scan ONLY skill/instruction files; skip agent/package/CVE scanning (focused workflow: `agent-bom skills scan`)",
            ),
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
                "--model-policy-mode",
                type=click.Choice(["off", "warn", "enforce"]),
                default="off",
                show_default=True,
                help="Evaluate model artifact provenance policy without changing local scan defaults.",
            ),
            click.option(
                "--require-model-signatures",
                is_flag=True,
                help="Warn or fail, based on --model-policy-mode, when model files lack Sigstore/cosign-compatible signature evidence.",
            ),
            click.option(
                "--block-unsafe-model-formats",
                is_flag=True,
                help="Warn or fail, based on --model-policy-mode, for executable-on-load model formats such as pickle, PyTorch, and .bin.",
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
                "--scan-pii",
                "scan_pii",
                is_flag=True,
                default=False,
                help="Scan CSV/JSON/JSONL dataset files for PII/PHI content (emails, SSNs, credit cards, medical data).",
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
                help="Verify instruction file provenance via Sigstore bundles (dedicated workflow: `agent-bom skills verify`)",
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


def cloud_options(fn):
    """AWS, Azure, GCP, CoreWeave, Databricks, Snowflake, Nebius."""
    return _apply(
        [
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
            click.option("--azure", "azure_flag", is_flag=True, help="Discover agents from Azure AI Foundry and Container Apps"),
            click.option("--azure-subscription", default=None, metavar="ID", envvar="AZURE_SUBSCRIPTION_ID", help="Azure subscription ID"),
            click.option("--gcp", "gcp_flag", is_flag=True, help="Discover agents from Google Cloud Vertex AI and Cloud Run"),
            click.option("--gcp-project", default=None, metavar="PROJECT", envvar="GOOGLE_CLOUD_PROJECT", help="GCP project ID"),
            click.option(
                "--coreweave",
                "coreweave_flag",
                is_flag=True,
                help="Discover GPU VMs, NVIDIA NIM inference, and InfiniBand training from CoreWeave",
            ),
            click.option("--coreweave-context", default=None, metavar="CTX", help="kubectl context for CoreWeave cluster"),
            click.option("--coreweave-namespace", default=None, metavar="NS", help="Limit CoreWeave discovery to a namespace"),
            click.option(
                "--databricks", "databricks_flag", is_flag=True, help="Discover agents from Databricks clusters and model serving"
            ),
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
            click.option("--nebius", "nebius_flag", is_flag=True, help="Discover AI workloads from Nebius GPU cloud"),
            click.option("--nebius-api-key", default=None, envvar="NEBIUS_API_KEY", metavar="KEY", help="Nebius API key"),
            click.option("--nebius-project-id", default=None, envvar="NEBIUS_PROJECT_ID", metavar="ID", help="Nebius project ID"),
        ]
    )(fn)


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
                "--rules",
                default="auto",
                show_default=True,
                metavar="CONFIG",
                help=(
                    "Semgrep config for --code scans. Use 'auto', 'default' (local rules + auto), "
                    "'p/<ruleset>', a local file/directory, ~/.agent-bom/rules/, or a comma-separated list."
                ),
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
                help="Export compliance evidence bundle (ZIP). Accepted values: cmmc, fedramp, nist-ai-rmf.",
            ),
        ]
    )(fn)


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
                help=(
                    "Event format for SIEM push: ocsf (standardized for enterprise SIEM ingestion) or raw (canonical agent-bom event shape)"
                ),
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
