"""The main `scan` command — discover, resolve, scan, report."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

import click

from agent_bom.cli._common import (
    BANNER,
    SEVERITY_ORDER,
    _build_agents_from_inventory,
    _make_console,
    logger,
)
from agent_bom.cli.options import scan_options
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


@click.command()
@scan_options
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
    warn_on_severity: Optional[str],
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
    external_scan_path: Optional[str],
):
    """Discover agents, extract dependencies, scan for vulnerabilities.

    \b
    Exit codes:
      0  Clean — no violations, no vulnerabilities at or above threshold
           (also exits 0 when only --warn-on threshold is breached)
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

    # Step 1b2: Ingest external scanner report (--external-scan)
    if not skill_only and external_scan_path:
        import json as _json

        from agent_bom.models import Agent, AgentType, MCPServer, TransportType
        from agent_bom.parsers.external_scanners import detect_and_parse

        try:
            with open(external_scan_path) as _ext_f:
                _ext_data = _json.load(_ext_f)
            _ext_packages = detect_and_parse(_ext_data)
            _ext_resource_name = Path(external_scan_path).stem
            con.print(f"\n  [green]✓[/green] Ingested {len(_ext_packages)} packages from Trivy/Grype/Syft report\n")
            _ext_server = MCPServer(
                name=_ext_resource_name,
                command="external-scan",
                args=[external_scan_path],
                transport=TransportType.STDIO,
                packages=_ext_packages,
            )
            _ext_agent = Agent(
                name=f"external-scan:{_ext_resource_name}",
                agent_type=AgentType.CUSTOM,
                config_path=external_scan_path,
                source="external-scan",
                mcp_servers=[_ext_server],
            )
            agents.append(_ext_agent)
        except (FileNotFoundError, ValueError, _json.JSONDecodeError) as e:
            con.print(f"\n  [red]External scan error: {e}[/red]")
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
                if verbose:
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

        # Console output: trust assessment
        verdict_styles = {
            Verdict.BENIGN: "green",
            Verdict.SUSPICIOUS: "yellow",
            Verdict.MALICIOUS: "red bold",
        }
        vstyle = verdict_styles.get(trust_result.verdict, "white")

        if verbose:
            # Full trust panel (--verbose only)
            from rich.panel import Panel as TrustPanel
            from rich.table import Table as TrustTable

            level_icons = {
                TrustLevel.PASS: "[green]✓[/green]",
                TrustLevel.INFO: "[blue]ℹ[/blue]",
                TrustLevel.WARN: "[yellow]⚠[/yellow]",
                TrustLevel.FAIL: "[red]✗[/red]",
            }
            trust_table = TrustTable(expand=True, padding=(0, 1), show_header=True)
            trust_table.add_column("", justify="center", no_wrap=True, width=3)
            trust_table.add_column("Category", no_wrap=True, width=24)
            trust_table.add_column("Summary", ratio=3)

            for cat in trust_result.categories:
                icon = level_icons.get(cat.level, "?")
                trust_table.add_row(icon, f"[bold]{cat.name}[/bold]", cat.summary)

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
        else:
            # Compact one-liner (default mode)
            fail_count = sum(1 for c in trust_result.categories if c.level == TrustLevel.FAIL)
            warn_count = sum(1 for c in trust_result.categories if c.level == TrustLevel.WARN)
            fname = Path(trust_result.source_file).name
            verdict_text = f"[{vstyle}]{trust_result.verdict.value.upper()}[/{vstyle}]"
            issues = []
            if fail_count:
                issues.append(f"[red]{fail_count} fail[/red]")
            if warn_count:
                issues.append(f"[yellow]{warn_count} warn[/yellow]")
            issues_str = f" ({', '.join(issues)})" if issues else ""
            con.print(f"  Trust: {fname} → {verdict_text}{issues_str}")

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

                for prompt_finding in prompt_result.findings:
                    style = sev_colors.get(prompt_finding.severity, "white")
                    icon = sev_icons.get(prompt_finding.severity, "⚪")
                    sev_cell = f"{icon} [{style}]{prompt_finding.severity.upper()}[/{style}]"
                    cat_cell = f"[cyan]{prompt_finding.category}[/cyan]"
                    detail_parts = [f"[bold]{prompt_finding.title}[/bold]"]
                    detail_parts.append(f"[dim]{prompt_finding.detail}[/dim]")
                    if prompt_finding.recommendation:
                        detail_parts.append(f"[green]→ {prompt_finding.recommendation}[/green]")
                    detail_cell = "\n".join(detail_parts)
                    file_info = Path(prompt_finding.source_file).name
                    if prompt_finding.line_number:
                        file_info += f":{prompt_finding.line_number}"
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
                            f"    [red]✗[/red] {r.filename}"
                            f"  expected={(r.expected_sha256 or '?')[:16]}…"
                            f"  got={r.actual_sha256[:16] if r.actual_sha256 else '?'}…"
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
                for vdb_r in vector_db_results:
                    tbl.add_row(
                        vdb_r.db_type,
                        f"{vdb_r.host}:{vdb_r.port}",
                        "[green]yes[/]" if vdb_r.requires_auth else "[red]NO[/]",
                        _vdb_risk.get(vdb_r.risk_level, vdb_r.risk_level),
                        ", ".join(vdb_r.risk_flags) or "-",
                    )
                for pine_r in pinecone_results:
                    tbl.add_row(
                        "pinecone",
                        pine_r.index_name,
                        "[green]API key[/]",
                        _vdb_risk.get(pine_r.risk_level, pine_r.risk_level),
                        ", ".join(pine_r.risk_flags) or "-",
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
        blast_radii: list[Any] = []
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
                for intro_r in intro_report.results:
                    if intro_r.success:
                        drift_str = ""
                        if intro_r.has_drift:
                            parts = []
                            if intro_r.tools_added:
                                parts.append(f"+{len(intro_r.tools_added)} tools")
                            if intro_r.tools_removed:
                                parts.append(f"-{len(intro_r.tools_removed)} tools")
                            if intro_r.resources_added:
                                parts.append(f"+{len(intro_r.resources_added)} resources")
                            if intro_r.resources_removed:
                                parts.append(f"-{len(intro_r.resources_removed)} resources")
                            drift_str = f" [yellow]drift: {', '.join(parts)}[/yellow]"
                        con.print(
                            f"  [green]✓[/green] {intro_r.server_name}:"
                            f" {intro_r.tool_count} tools, {intro_r.resource_count} resources{drift_str}"
                        )
                    else:
                        con.print(f"  [dim]  {intro_r.server_name}: {intro_r.error}[/dim]")
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
                instr_paths: list[str | Path] = list(instr_files)
                verifications = verify_instruction_files_batch(instr_paths)
                _instruction_provenance_data = []
                for verification in verifications:
                    rel_path = (
                        str(Path(verification.file_path).relative_to(project_root))
                        if verification.file_path.startswith(str(project_root))
                        else verification.file_path
                    )
                    if verification.verified:
                        con.print(f"  [green]✓[/green] {rel_path} — provenance verified ({verification.reason})")
                    elif verification.has_sigstore_bundle:
                        con.print(f"  [yellow]⚠[/yellow] {rel_path} — bundle found but invalid ({verification.reason})")
                    else:
                        con.print(f"  [dim]  {rel_path} — unsigned (sha256: {verification.sha256[:12]}...)[/dim]")
                    _instruction_provenance_data.append(
                        {
                            "file": rel_path,
                            "sha256": verification.sha256,
                            "verified": verification.verified,
                            "has_bundle": verification.has_sigstore_bundle,
                            "signer": verification.signer_identity,
                            "rekor_index": verification.rekor_log_index,
                            "reason": verification.reason,
                        }
                    )
            else:
                con.print("\n  [dim]No instruction files found to verify.[/dim]")

        # Step 4e: Cortex agent observability (optional)
        _cortex_telemetry_data = None
        if cortex_observability and snowflake_flag:
            try:
                from agent_bom.cloud.snowflake import _get_connection  # type: ignore[attr-defined]
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
    if external_scan_path:
        _scan_sources.append("external_scan")
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
    # Dual-write: populate unified findings stream alongside blast_radii (#566 Phase 1)
    from agent_bom.finding import blast_radius_to_finding

    _findings = [blast_radius_to_finding(br) for br in blast_radii]
    report = AIBOMReport(
        agents=agents,
        blast_radii=blast_radii,
        findings=_findings,
        scan_sources=_scan_sources,
    )
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
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                logger.debug("Could not load license policy file, using defaults: %s", exc)
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
        from agent_bom.parsers.dataset_cards import DatasetInfo, scan_dataset_directory

        all_datasets: list[DatasetInfo] = []
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
            project_dirs: list[Path] = []
            for agent in agents:
                if agent.config_path:
                    agent_config_dir = Path(agent.config_path).parent
                    # Walk up to find package.json or requirements.txt
                    for candidate_dir in [agent_config_dir, agent_config_dir.parent, agent_config_dir.parent.parent]:
                        if (candidate_dir / "package.json").exists() or (candidate_dir / "requirements.txt").exists():
                            if candidate_dir not in project_dirs:
                                project_dirs.append(candidate_dir)
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
            adjusted = [sk_f for sk_f in _skill_audit_obj.findings if sk_f.ai_adjusted_severity]
            if adjusted:
                for sk_f in adjusted:
                    if sk_f.ai_adjusted_severity == "false_positive":
                        con.print(f"  [green]✓ FP[/green] {sk_f.title}")
                        con.print(f"    [dim]{sk_f.ai_analysis}[/dim]")
                    else:
                        con.print(f"  [yellow]↕ ADJ[/yellow] {sk_f.title}: {sk_f.severity} → {sk_f.ai_adjusted_severity}")
                        if sk_f.ai_analysis:
                            con.print(f"    [dim]{sk_f.ai_analysis}[/dim]")

            # Show AI-detected new findings
            ai_detected = [sk_f for sk_f in _skill_audit_obj.findings if sk_f.context == "ai_analysis"]
            if ai_detected:
                con.print(f"\n  [bold yellow]AI-Detected Threats ({len(ai_detected)})[/bold yellow]")
                for sk_f in ai_detected:
                    style = sev_colors.get(sk_f.severity, "white")
                    con.print(f"    [{style}]\\[{sk_f.severity.upper()}][/{style}] {sk_f.title}")
                    con.print(f"      [dim]{sk_f.detail}[/dim]")
                    if sk_f.recommendation:
                        con.print(f"      [green]→ {sk_f.recommendation}[/green]")

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
        except Exception as exc:
            # Asset tracking is best-effort; don't fail the scan
            logger.debug("Asset tracking failed: %s", exc, exc_info=True)

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

                _asyncio_int.run(upload_evidence(vanta_token, findings))  # type: ignore[arg-type]
                con.print("  [green]✓[/green] Vanta: evidence uploaded")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Vanta upload failed: {exc}")

        if drata_token and findings:
            try:
                from agent_bom.integrations.drata import upload_evidence as upload_evidence_drata

                _asyncio_int.run(upload_evidence_drata(drata_token, findings))  # type: ignore[arg-type]
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

    # Two-tier: warn-on threshold (exit 0 with banner) — only fires when exit_code is still 0
    if warn_on_severity and _active_blast_radii and exit_code == 0:
        warn_threshold = SEVERITY_ORDER.get(warn_on_severity.lower(), 0)
        warn_matches = [
            br for br in _active_blast_radii if SEVERITY_ORDER.get(br.vulnerability.severity.value.lower(), 0) >= warn_threshold
        ]
        if warn_matches:
            if not quiet:
                con.print(
                    f"\n  [yellow]⚠[/yellow]  {len(warn_matches)} finding(s) at or above "
                    f"{warn_on_severity.upper()} severity (--warn-on threshold). "
                    f"Upgrade to --fail-on-severity to enforce."
                )

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
