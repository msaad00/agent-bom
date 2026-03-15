"""The main `scan` command — discover, resolve, scan, report.

This package replaces the monolithic cli/scan.py. The public interface is
identical: ``from agent_bom.cli.scan import scan`` still works, and all
``patch("agent_bom.cli.scan.<symbol>", ...)`` targets remain importable from
this namespace.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

import click

from agent_bom.cli._common import (
    SEVERITY_ORDER,
    _build_agents_from_inventory,
    _make_console,
    logger,
)
from agent_bom.cli.options import scan_options
from agent_bom.cli.scan._cloud import run_benchmarks, run_cloud_discovery
from agent_bom.cli.scan._context import ScanContext
from agent_bom.cli.scan._discovery import run_local_discovery
from agent_bom.cli.scan._output import _format_text, render_output
from agent_bom.cli.scan._post import compute_exit_code, run_integrations
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
    offline: bool,
    no_scan: bool,
    blast_radius_depth: int,
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
    delta_mode: bool,
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
    auto_update_db: bool,
    db_sources: Optional[str],
    snyk_flag: bool,
    snyk_token: Optional[str],
    snyk_org: Optional[str],
    remediate_path: Optional[str],
    remediate_sh_path: Optional[str],
    apply_fixes_flag: bool,
    apply_dry_run: bool,
    code_paths: tuple,
    sast_config: str,
    ai_inventory_paths: tuple,
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
    os_packages: bool,
    iac_paths: tuple = (),
    ignore_file: Optional[str] = None,
):
    """Discover agents, extract dependencies, scan for vulnerabilities.

    \b
    Exit codes:
      0  Clean — no violations, no vulnerabilities at or above threshold
           (also exits 0 when only --warn threshold is breached)
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
        warn_on_severity = warn_on_severity or "high"
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

    if demo:
        con.print("\n[bold yellow]Demo mode[/bold yellow] — scanning bundled inventory with known-vulnerable packages.\n")

    # ── Offline mode: disable all network calls ──────────────────────────────
    if offline:
        import agent_bom.scanners as _scanners_mod

        _scanners_mod.offline_mode = True
        auto_update_db = False
        enrich = False
        scorecard_flag = False
        deps_dev = False
        snyk_flag = False
        if not quiet:
            from agent_bom.db.schema import db_freshness_days as _offline_freshness

            days = _offline_freshness()
            if days is None:
                con.print(
                    "[bold yellow]⚠ Offline mode[/bold yellow] — no local DB found. Run 'agent-bom db update' first for vulnerability data."
                )
            elif days > 7:
                con.print(f"[bold yellow]⚠ Offline mode[/bold yellow] — local DB is {days} days old. Run 'agent-bom db update' to refresh.")
            else:
                con.print("[dim]Offline mode — scanning against local DB only[/dim]")

    # ── Auto-offline: use local DB if synced recently (saves ~10s network) ──
    if not offline:
        try:
            import os
            import time

            from agent_bom.db.schema import DB_PATH

            if DB_PATH.exists():
                _age_days = (time.time() - os.path.getmtime(DB_PATH)) / 86400
                if _age_days <= 1:
                    import agent_bom.scanners as _scanners_auto

                    _scanners_auto.prefer_local_db = True
                    logger.debug("Local DB is %.1f day(s) old — preferring local DB over network", _age_days)
        except Exception:
            pass  # DB not available, will use network

    # ── Auto-refresh stale DB if requested ───────────────────────────────────
    if auto_update_db:
        from agent_bom.db.schema import db_freshness_days
        from agent_bom.db.sync import sync_db

        freshness = db_freshness_days()
        source_list = [s.strip() for s in db_sources.split(",")] if db_sources else None
        if freshness is None or freshness > 7 or source_list:
            if not quiet:
                src_msg = f" (sources: {', '.join(source_list)})" if source_list else ""
                con.print(f"[dim]Refreshing local vuln DB{src_msg} …[/dim]")
            try:
                sync_db(sources=source_list)
            except Exception as _db_exc:
                logger.warning("Auto DB refresh failed: %s", _db_exc)

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
        for aip in ai_inventory_paths:
            reads.append(f"  [green]Would scan:[/green]   {aip}  (AI component source scan)")
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

    # Pre-scan: local DB freshness check
    if not no_scan:
        try:
            from agent_bom.db.schema import db_freshness_days

            _db_age = db_freshness_days()
            if _db_age is None:
                if not quiet:
                    con.print(
                        "[yellow]⚠ No local vulnerability DB found.[/yellow] "
                        "Falling back to OSV API (slower). "
                        "Run [bold]agent-bom db update[/bold] to build a local cache."
                    )
            elif _db_age > 14:
                if not quiet:
                    con.print(
                        f"[red]⚠ Local vulnerability DB is {_db_age} days old.[/red] "
                        "Scan results may be incomplete. "
                        "Run [bold]agent-bom db update[/bold] before scanning."
                    )
            elif _db_age > 7:
                if not quiet:
                    con.print(
                        f"[yellow]⚠ Local vulnerability DB is {_db_age} days old.[/yellow] "
                        "Consider running [bold]agent-bom db update[/bold]."
                    )
        except Exception:
            pass  # Never block a scan due to freshness check failure

    # Create shared context object
    ctx = ScanContext(con=con)

    # Compute any_cloud for early no-agent check in _discovery
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

    # Step 1–1g4: Local discovery
    _step_t0 = _time.monotonic()
    run_local_discovery(
        ctx,
        project=project,
        config_dir=config_dir,
        inventory=inventory,
        skill_only=skill_only,
        dynamic_discovery=dynamic_discovery,
        dynamic_max_depth=dynamic_max_depth,
        include_processes=include_processes,
        include_containers=include_containers,
        introspect=introspect,
        introspect_timeout=introspect_timeout,
        enforce=enforce,
        health_check=health_check,
        hc_timeout=hc_timeout,
        k8s_mcp=k8s_mcp,
        k8s_namespace=k8s_namespace,
        k8s_all_namespaces=k8s_all_namespaces,
        k8s_mcp_context=k8s_mcp_context,
        no_skill=no_skill,
        skill_paths=skill_paths,
        skill_only_mode=skill_only,
        ai_enrich=ai_enrich,
        ai_model=ai_model,
        sbom_file=sbom_file,
        sbom_name=sbom_name,
        external_scan_path=external_scan_path,
        k8s=k8s,
        namespace=namespace,
        all_namespaces=all_namespaces,
        k8s_context=k8s_context,
        registry_user=registry_user,
        registry_pass=registry_pass,
        image_platform=image_platform,
        images=images,
        image_tars=image_tars,
        filesystem_paths=filesystem_paths,
        code_paths=code_paths,
        sast_config=sast_config,
        ai_inventory_paths=ai_inventory_paths,
        tf_dirs=tf_dirs,
        gha_path=gha_path,
        agent_projects=agent_projects,
        scan_prompts=scan_prompts,
        browser_extensions=browser_extensions,
        jupyter_dirs=jupyter_dirs,
        verbose=verbose,
        quiet=quiet,
        smithery_token=smithery_token,
        smithery_flag=smithery_flag,
        mcp_registry_flag=mcp_registry_flag,
        os_packages=os_packages,
        iac_paths=iac_paths,
        _any_cloud=any_cloud,
        _discover_all=discover_all,  # pass patchable reference — tests patch agent_bom.cli.scan.discover_all
    )

    ctx.step_timings["discovery"] = _time.monotonic() - _step_t0

    # Re-bind the (possibly updated) agents list
    agents = ctx.agents

    # Step 1h + 1y + 1z: Cloud discovery, SaaS connectors, correlation
    _step_t0 = _time.monotonic()
    run_cloud_discovery(
        ctx,
        skill_only=skill_only,
        aws=aws,
        aws_region=aws_region,
        aws_profile=aws_profile,
        aws_include_lambda=aws_include_lambda,
        aws_include_eks=aws_include_eks,
        aws_include_step_functions=aws_include_step_functions,
        aws_include_ec2=aws_include_ec2,
        aws_ec2_tag=aws_ec2_tag,
        azure_flag=azure_flag,
        azure_subscription=azure_subscription,
        gcp_flag=gcp_flag,
        gcp_project=gcp_project,
        coreweave_flag=coreweave_flag,
        coreweave_context=coreweave_context,
        coreweave_namespace=coreweave_namespace,
        databricks_flag=databricks_flag,
        snowflake_flag=snowflake_flag,
        snowflake_authenticator=snowflake_authenticator,
        nebius_flag=nebius_flag,
        nebius_api_key=nebius_api_key,
        nebius_project_id=nebius_project_id,
        hf_flag=hf_flag,
        hf_token=hf_token,
        hf_username=hf_username,
        hf_organization=hf_organization,
        wandb_flag=wandb_flag,
        wandb_api_key=wandb_api_key,
        wandb_entity=wandb_entity,
        wandb_project=wandb_project,
        mlflow_flag=mlflow_flag,
        mlflow_tracking_uri=mlflow_tracking_uri,
        openai_flag=openai_flag,
        openai_api_key=openai_api_key,
        openai_org_id=openai_org_id,
        ollama_flag=ollama_flag,
        ollama_host=ollama_host,
        jira_discover=jira_discover,
        jira_url=jira_url,
        jira_user=jira_user,
        jira_token=jira_token,
        servicenow_flag=servicenow_flag,
        servicenow_instance=servicenow_instance,
        servicenow_user=servicenow_user,
        servicenow_password=servicenow_password,
        slack_discover=slack_discover,
        slack_bot_token=slack_bot_token,
    )

    # Steps 1x–1z: Benchmarks
    run_benchmarks(
        ctx,
        skill_only=skill_only,
        verify_model_hashes=verify_model_hashes,
        project=project,
        hf_token=hf_token,
        aws_cis_benchmark=aws_cis_benchmark,
        aws_region=aws_region,
        aws_profile=aws_profile,
        snowflake_cis_benchmark=snowflake_cis_benchmark,
        snowflake_authenticator=snowflake_authenticator,
        azure_cis_benchmark=azure_cis_benchmark,
        azure_subscription=azure_subscription,
        gcp_cis_benchmark=gcp_cis_benchmark,
        gcp_project=gcp_project,
        databricks_security=databricks_security,
        aisvs_flag=aisvs_flag,
        vector_db_scan=vector_db_scan,
        gpu_scan_flag=gpu_scan_flag,
        gpu_k8s_context=gpu_k8s_context,
        no_dcgm_probe=no_dcgm_probe,
        smithery_flag=smithery_flag,
        smithery_token=smithery_token,
        mcp_registry_flag=mcp_registry_flag,
        snyk_flag=snyk_flag,
        snyk_token=snyk_token,
        snyk_org=snyk_org,
        cortex_observability=cortex_observability,
        snowflake_flag=snowflake_flag,
    )

    # Keep local reference up-to-date (cloud discovery may have extended agents)
    agents = ctx.agents
    ctx.step_timings["cloud"] = _time.monotonic() - _step_t0

    # Step 2: Extract packages
    _step_t0 = _time.monotonic()
    total_packages = 0
    if skill_only:
        blast_radii: list[Any] = []
    else:
        from rich.rule import Rule

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
                    continue
                pre_populated = list(server.packages)
                _smithery_tok = smithery_token if smithery_flag else None
                discovered = extract_packages(
                    server, resolve_transitive=transitive, max_depth=max_depth, smithery_token=_smithery_tok, mcp_registry=mcp_registry_flag
                )

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

                all_pkgs_updated = [pkg for agent in agents for server in agent.mcp_servers for pkg in server.packages]
                lic_count = _asyncio_dd.run(enrich_licenses_deps_dev(all_pkgs_updated))
                if lic_count:
                    con.print(f"  [green]✓[/green] deps.dev: {lic_count} package license(s) enriched")

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
                    pass

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
            ctx.enforcement_data = _enforcement_data

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

        ctx.step_timings["extraction"] = _time.monotonic() - _step_t0

        # Step 4: Vulnerability scan
        from rich.rule import Rule

        con.print()
        con.print(Rule("Vulnerability Scan", style="red"))
        con.print()
        _step_t0 = _time.monotonic()
        blast_radii = []
        if no_scan:
            con.print("  [dim]Vulnerability scanning skipped (--no-scan)[/dim]")
        elif total_packages == 0:
            con.print("  [dim]No packages to scan[/dim]")
        else:
            _unique_pkgs = len({(p.name, p.version, p.ecosystem) for a in agents for s in a.mcp_servers for p in s.packages})
            from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold]{task.description}[/bold]"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TextColumn("[dim]{task.fields[phase]}[/dim]"),
                TimeElapsedColumn(),
                console=con,
                transient=True,
            ) as progress:
                scan_task = progress.add_task(
                    f"Scanning {_unique_pkgs} packages",
                    total=4,
                    phase="local DB + OSV + GHSA",
                )
                progress.update(scan_task, completed=1, phase="querying vulnerability databases...")
                blast_radii = scan_agents_sync(
                    agents,
                    enable_enrichment=enrich,
                    nvd_api_key=nvd_api_key,
                    blast_radius_depth=blast_radius_depth,
                )
                progress.update(scan_task, completed=3, phase="building blast radius analysis")
                progress.update(scan_task, completed=4, phase="done")
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
        _instruction_provenance_data: list = []
        if verify_instructions:
            from agent_bom.integrity import discover_instruction_files, verify_instruction_files_batch

            project_root = Path(project or ".").resolve()
            instr_files = discover_instruction_files(project_root)
            if instr_files:
                con.print(f"\n[bold blue]🔏 Verifying instruction file provenance ({len(instr_files)} file(s))...[/bold blue]\n")
                instr_paths: list[str | Path] = list(instr_files)
                verifications = verify_instruction_files_batch(instr_paths)
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
        _scan_sources.append("agent_discovery")

    from agent_bom.finding import blast_radius_to_finding

    _findings = [blast_radius_to_finding(br) for br in blast_radii]
    report = AIBOMReport(
        agents=agents,
        blast_radii=blast_radii,
        findings=_findings,
        scan_sources=_scan_sources,
    )

    # Attach skill/trust/prompt/enforcement data from context
    if ctx.skill_audit_data:
        report.skill_audit_data = ctx.skill_audit_data
    if ctx.trust_assessment_data:
        report.trust_assessment_data = ctx.trust_assessment_data
    if ctx.prompt_scan_data:
        report.prompt_scan_data = ctx.prompt_scan_data
    if ctx.enforcement_data:
        report.enforcement_data = ctx.enforcement_data
    if ctx.sast_data:
        report.sast_data = ctx.sast_data
    if ctx.ai_inventory_data:
        report.ai_inventory_data = ctx.ai_inventory_data

    # Attach benchmark reports
    if ctx.cis_benchmark_report is not None:
        report.cis_benchmark_data = ctx.cis_benchmark_report.to_dict()
    if ctx.sf_cis_benchmark_report is not None:
        report.snowflake_cis_benchmark_data = ctx.sf_cis_benchmark_report.to_dict()
    if ctx.azure_cis_benchmark_report is not None:
        report.azure_cis_benchmark_data = ctx.azure_cis_benchmark_report.to_dict()
    if ctx.gcp_cis_benchmark_report is not None:
        report.gcp_cis_benchmark_data = ctx.gcp_cis_benchmark_report.to_dict()
    if ctx.databricks_security_report is not None:
        report.databricks_cis_benchmark_data = ctx.databricks_security_report.to_dict()
    if ctx.aisvs_report is not None:
        report.aisvs_benchmark_data = ctx.aisvs_report.to_dict()
    if ctx.vector_db_results:
        report.vector_db_scan_data = [r.to_dict() for r in ctx.vector_db_results]
    if ctx.gpu_infra_report is not None:
        report.gpu_infra_data = ctx.gpu_infra_report.risk_summary

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
    if ctx._browser_ext_results is not None:
        report.browser_extensions = ctx._browser_ext_results

    # Step 4c: AI-powered enrichment (optional)
    _skill_result_obj = ctx._skill_result_obj
    _skill_audit_obj = ctx._skill_audit_obj
    if ai_enrich:
        from agent_bom.ai_enrich import run_ai_enrichment_sync

        run_ai_enrichment_sync(
            report,
            model=ai_model,
            skill_result=_skill_result_obj,
            skill_audit=_skill_audit_obj,
        )

        if _skill_audit_obj:
            ctx.skill_audit_data = {
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
            report.skill_audit_data = ctx.skill_audit_data

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
            project_dirs: list[Path] = []
            for agent in agents:
                if agent.config_path:
                    agent_config_dir = Path(agent.config_path).parent
                    for candidate_dir in [agent_config_dir, agent_config_dir.parent, agent_config_dir.parent.parent]:
                        if (candidate_dir / "package.json").exists() or (candidate_dir / "requirements.txt").exists():
                            if candidate_dir not in project_dirs:
                                project_dirs.append(candidate_dir)
                            break
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

    # Apply ignore/allowlist file (.agent-bom-ignore.yaml or --ignore-file)
    from agent_bom.ignores import apply_ignores, load_ignore_file

    _ignore_entries = load_ignore_file(ignore_file)
    if _ignore_entries:
        blast_radii, _suppressed = apply_ignores(blast_radii, _ignore_entries)
        if _suppressed and not quiet:
            con.print(f"\n  [dim]Suppressed {_suppressed} finding(s) via ignore file[/dim]")
        # Rebuild report.blast_radii to reflect suppressions
        report.blast_radii = blast_radii

    ctx.step_timings["scanning"] = _time.monotonic() - _step_t0

    # Attach blast_radii and report to context for downstream phases
    ctx.blast_radii = blast_radii
    ctx.report = report

    # Step 5: Output
    _step_t0 = _time.monotonic()
    render_output(
        ctx,
        output=output,
        output_format=output_format,
        no_tree=no_tree,
        quiet=quiet,
        no_color=no_color,
        open_report=open_report,
        compliance_export=compliance_export,
        mermaid_mode=mermaid_mode,
        push_gateway=push_gateway,
        otel_endpoint=otel_endpoint,
        baseline=baseline,
        delta_mode=delta_mode,
        verbose=verbose,
    )

    # Step 6: Save report to history + asset tracking
    current_report_json = to_json(report)
    if save_report:
        from agent_bom.history import save_report as _save

        saved_path = _save(current_report_json)
        con.print(f"\n  [green]✓[/green] Report saved to history: {saved_path}")

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
            logger.debug("Asset tracking failed: %s", exc, exc_info=True)

    # Step 7: Diff against baseline
    if baseline:
        from agent_bom.history import diff_reports, load_report

        baseline_data = load_report(Path(baseline))
        diff = diff_reports(baseline_data, current_report_json)
        print_diff(diff)

    # Step 7a: Delta mode — exit code based on new findings only
    if delta_mode:
        from agent_bom.scan_delta import compute_delta, load_baseline

        _baseline_path = baseline
        if not _baseline_path:
            from agent_bom.scan_delta import _DEFAULT_BASELINE_PATH

            if _DEFAULT_BASELINE_PATH.exists():
                _baseline_path = str(_DEFAULT_BASELINE_PATH)
            else:
                logger.warning(
                    "Delta mode requested but no --baseline file specified and no auto-baseline found at %s. Skipping delta filter.",
                    _DEFAULT_BASELINE_PATH,
                )

        if _baseline_path:
            try:
                _baseline_data = load_baseline(_baseline_path)
                _delta_result = compute_delta(current_report_json, _baseline_data)
                _delta_result.baseline_path = _baseline_path
                ctx.delta_result = _delta_result
                if not quiet:
                    from rich.console import Console as _Console

                    _Console().print(f"\n[bold]Delta:[/bold] {_delta_result.summary_line()} (baseline: {_baseline_path})\n")
                from agent_bom.scan_delta import apply_delta_to_scan

                current_report_json = apply_delta_to_scan(current_report_json, _delta_result)
            except (FileNotFoundError, ValueError) as exc:
                logger.warning("Delta baseline error: %s — skipping delta filter", exc)

    ctx.step_timings["output"] = _time.monotonic() - _step_t0

    # Scan completion divider
    _elapsed = _time.monotonic() - _scan_start
    if output_format == "console" and not output and not quiet:
        from rich.rule import Rule

        con.print()
        con.print(Rule(f"Scan Complete — {_elapsed:.1f}s", style="green" if not blast_radii else "yellow"))

        # Per-step timing breakdown
        _timings = ctx.step_timings
        _timing_parts = []
        for _step_name in ("discovery", "cloud", "extraction", "scanning", "output"):
            _t = _timings.get(_step_name, 0.0)
            if _t >= 0.1:
                _timing_parts.append(f"{_step_name}: {_t:.1f}s")
        if _timing_parts:
            _breakdown = " · ".join(_timing_parts)
            con.print(f"  [dim]{_breakdown}[/dim]")

        # Next-steps suggestions based on findings
        _next_steps: list[str] = []
        if blast_radii:
            _crit_count = sum(1 for br in blast_radii if br.vulnerability.severity.value == "critical")
            _high_count = sum(1 for br in blast_radii if br.vulnerability.severity.value == "high")
            _kev_count = sum(1 for br in blast_radii if getattr(br.vulnerability, "kev", False))
            _fixable = sum(1 for br in blast_radii if br.vulnerability.fixed_version)

            if _crit_count or _high_count:
                _next_steps.append(
                    f"[red bold]→[/red bold] {_crit_count} critical + {_high_count} high — "
                    "run [bold]agent-bom scan --fail-on critical[/bold] in CI to gate deployments"
                )
            if _fixable:
                _next_steps.append(
                    f"[green]→[/green] {_fixable} fixable — run [bold]agent-bom scan --remediate plan.md[/bold] for upgrade steps"
                )
            if not enrich:
                _next_steps.append("[cyan]→[/cyan] run with [bold]--enrich[/bold] for EPSS exploit probability + KEV + CVSS v4 data")
            _next_steps.append(
                "[blue]→[/blue] export: [bold]-f html[/bold] (interactive report) · "
                "[bold]-f sarif[/bold] (GitHub Security) · [bold]-f cyclonedx[/bold] (SBOM)"
            )
        elif not no_scan and total_packages > 0:
            _next_steps.append("[green]→[/green] no vulnerabilities found — your supply chain looks clean")
            _next_steps.append("[cyan]→[/cyan] run [bold]agent-bom scan --enrich --transitive[/bold] for deeper analysis")

        if _next_steps:
            con.print()
            con.print("  [bold]Next steps:[/bold]")
            for _ns in _next_steps:
                con.print(f"    {_ns}")

    # Step 8: Enterprise integrations + SIEM + policy (post-scan)
    run_integrations(
        ctx,
        quiet=quiet,
        jira_url=jira_url,
        jira_user=jira_user,
        jira_token=jira_token,
        jira_project=jira_project,
        slack_webhook=slack_webhook,
        jira_discover=jira_discover,
        servicenow_flag=servicenow_flag,
        servicenow_instance=servicenow_instance,
        servicenow_user=servicenow_user,
        servicenow_password=servicenow_password,
        slack_discover=slack_discover,
        slack_bot_token=slack_bot_token,
        vanta_token=vanta_token,
        drata_token=drata_token,
        siem_type=siem_type,
        siem_url=siem_url,
        siem_token=siem_token,
        siem_index=siem_index,
        siem_format=siem_format,
        clickhouse_url=clickhouse_url,
        policy=policy,
    )

    # Step 9: Exit code
    exit_code = compute_exit_code(
        ctx,
        fail_on_severity=fail_on_severity,
        warn_on_severity=warn_on_severity,
        fail_on_kev=fail_on_kev,
        fail_if_ai_risk=fail_if_ai_risk,
        push_url=push_url,
        push_api_key=push_api_key,
        quiet=quiet,
    )

    if exit_code:
        sys.exit(exit_code)


def _print_text(report: AIBOMReport, blast_radii: list) -> None:
    """Print plain text to stdout."""
    import sys

    sys.stdout.write(_format_text(report, blast_radii))
