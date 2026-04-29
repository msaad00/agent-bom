"""Preflight helpers extracted from the main scan command.

These helpers keep the public ``agent_bom.cli.agents`` interface stable while
pulling the high-branching preflight stages out of the main command body:

- dry-run access/data audit rendering
- IaC-only fast path execution
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._output import render_output
from agent_bom.models import AIBOMReport


def emit_dry_run_plan(
    con: Any,
    *,
    inventory: str | None,
    project: str | None,
    config_dir: str | None,
    code_paths: tuple,
    ai_inventory_paths: tuple,
    tf_dirs: tuple,
    agent_projects: tuple,
    jupyter_dirs: tuple,
    model_dirs: tuple,
    dataset_dirs: tuple,
    training_dirs: tuple,
    gha_path: str | None,
    skill_paths: tuple,
    no_skill: bool,
    skill_only: bool,
    images: tuple,
    aws: bool,
    aws_region: str | None,
    aws_include_lambda: bool,
    aws_include_eks: bool,
    aws_include_step_functions: bool,
    aws_include_ec2: bool,
    azure_flag: bool,
    gcp_flag: bool,
    gcp_project: str | None,
    databricks_flag: bool,
    snowflake_flag: bool,
    coreweave_flag: bool,
    nebius_flag: bool,
    hf_flag: bool,
    wandb_flag: bool,
    mlflow_flag: bool,
    openai_flag: bool,
    ollama_flag: bool,
    ollama_host: str | None,
    mcp_registry_flag: bool,
    snyk_flag: bool,
    enrich: bool,
) -> None:
    """Render the dry-run access plan and data-audit block."""
    from agent_bom.discovery import get_all_discovery_paths

    con.print("\n[bold cyan]🔍 Dry-run — access plan (no files read, no queries made)[/bold cyan]\n")
    reads: list[str] = []
    if inventory:
        reads.append(f"  [green]Would read:[/green]   {inventory}")
    if project:
        reads.append(f"  [green]Would read:[/green]   {project}  (agent configs)")
    if config_dir:
        reads.append(f"  [green]Would read:[/green]   {config_dir}  (config directory)")
    if not reads:
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
        reads.append("  [green]Would query:[/green]  CoreWeave VirtualServer/InferenceService CRDs, GPU pods, InfiniBand jobs via kubectl")
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
        host = ollama_host or "http://localhost:11434"
        reads.append(f"  [green]Would query:[/green]  Ollama API ({host}/api/tags) + ~/.ollama/models manifests")
    if mcp_registry_flag:
        reads.append("  [green]Would query:[/green]  https://registry.modelcontextprotocol.io/v0/servers  (Official MCP Registry, no auth)")
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


def run_iac_only_scan(
    *,
    con: Any,
    iac_paths: tuple,
    k8s_live: bool,
    k8s_live_namespace: str,
    k8s_live_all_namespaces: bool,
    k8s_live_context: str | None,
    output: str | None,
    output_format: str,
    no_tree: bool,
    quiet: bool,
    no_color: bool,
    open_report: bool,
    compliance_export: str | None,
    mermaid_mode: str,
    push_gateway: str | None,
    otel_endpoint: str | None,
    baseline: str | None,
    delta_mode: bool,
    verbose: bool,
    exclude_unfixable: bool,
    fixable_only: bool,
    fail_on_severity: str | None,
) -> None:
    """Execute the dedicated IaC-only scan path and exit from the main command."""
    from agent_bom.iac import scan_iac_directory
    from agent_bom.k8s import K8sDiscoveryError, scan_live_cluster_posture

    iac_ctx = ScanContext(con=con)
    all_iac_findings: list = []

    if iac_paths:
        con.print(f"\n[bold blue]Scanning {len(iac_paths)} path(s) for IaC misconfigurations...[/bold blue]\n")
        for iac_path in iac_paths:
            iac_findings = scan_iac_directory(iac_path)
            all_iac_findings.extend(iac_findings)
            if iac_findings:
                from collections import Counter

                severity_counts = Counter(f.severity for f in iac_findings)
                severity_parts = [
                    f"[red]{severity_counts.get('critical', 0)} critical[/red]",
                    f"[yellow]{severity_counts.get('high', 0)} high[/yellow]",
                ]
                con.print(f"  [red]⚠[/red]  {iac_path}: {len(iac_findings)} finding(s) ({', '.join(severity_parts)})")
            else:
                con.print(f"  [green]✓[/green] {iac_path}: no misconfigurations")

    if k8s_live:
        con.print("\n[bold blue]Inspecting live Kubernetes cluster posture...[/bold blue]\n")
        try:
            k8s_live_findings = scan_live_cluster_posture(
                namespace=k8s_live_namespace,
                all_namespaces=k8s_live_all_namespaces,
                context=k8s_live_context,
            )
        except K8sDiscoveryError as exc:
            con.print(f"  [red]✗[/red] live cluster scan failed: {exc}")
            raise SystemExit(1) from exc
        all_iac_findings.extend(k8s_live_findings)
        if k8s_live_findings:
            from collections import Counter

            severity_counts = Counter(f.severity for f in k8s_live_findings)
            severity_parts = [
                f"[red]{severity_counts.get('critical', 0)} critical[/red]",
                f"[yellow]{severity_counts.get('high', 0)} high[/yellow]",
            ]
            con.print(f"  [red]⚠[/red]  live cluster posture: {len(k8s_live_findings)} finding(s) ({', '.join(severity_parts)})")
        else:
            con.print("  [green]✓[/green] live cluster posture: no runtime misconfigurations")

    iac_report = AIBOMReport(agents=[], blast_radii=[])
    iac_report.iac_findings_data = {
        "total": len(all_iac_findings),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "title": finding.title,
                "message": finding.message,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "category": finding.category,
                "compliance": finding.compliance,
                "attack_techniques": finding.attack_techniques,
                "remediation": finding.remediation,
            }
            for finding in all_iac_findings
        ],
    }
    iac_ctx.report = iac_report
    iac_ctx.iac_findings_data = iac_report.iac_findings_data

    if output_format == "json" or (output and output_format == "console"):
        out_data = json.dumps(iac_report.iac_findings_data, indent=2)
        if output and output != "-":
            Path(output).write_text(out_data)
            con.print(f"\n[green]IaC report written[/green] → {output}")
        else:
            click.echo(out_data)
    elif output_format != "console":
        render_output(
            iac_ctx,
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
            exclude_unfixable=exclude_unfixable,
            fixable_only=fixable_only,
        )

    if fail_on_severity and all_iac_findings:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_order.get(fail_on_severity, 99)
        if any(severity_order.get(finding.severity, 99) <= threshold for finding in all_iac_findings):
            sys.exit(1)
