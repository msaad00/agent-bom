"""Cloud command group — scan cloud infrastructure.

Cloud providers: AWS, Azure, GCP (real infrastructure with fleets, IAM, services).
AI platforms (Snowflake, Databricks, HuggingFace, etc.) are separate — not cloud infra.

Usage::

    agent-bom cloud aws                   # AWS discovery + CIS benchmark
    agent-bom cloud azure                 # Azure discovery + CIS benchmark
    agent-bom cloud gcp                   # GCP discovery + CIS benchmark
"""

from __future__ import annotations

from typing import Optional

import click

from agent_bom.cli._grouped_help import SuggestingGroup


@click.group("cloud", cls=SuggestingGroup, invoke_without_command=True)
@click.pass_context
def cloud_group(ctx: click.Context) -> None:
    """Scan cloud infrastructure — AWS, Azure, GCP.

    Requires cloud provider credentials (AWS CLI, Azure CLI, or gcloud).
    Discovers AI workloads, runs CIS benchmark checks, and assesses security posture.

    \b
    No credentials needed for:
      agent-bom image ecr.aws/app    scan cloud container images
      agent-bom iac infra/           scan Terraform/CloudFormation
      agent-bom fs .                 scan packages locally

    \b
    Subcommands (require credentials):
      aws          AWS — Bedrock, Lambda, ECS, EKS + CIS v3.0 (60 checks)
      azure        Azure — AI Foundry, Container Apps + CIS v2.0 (95 checks)
      gcp          GCP — Vertex AI, Cloud Run + CIS v3.0 (59 checks)
      resilience   Provider pagination/retry/partial-failure evidence
    """
    if ctx.invoked_subcommand is None:
        # Check if any cloud credentials are configured before running all
        import shutil

        providers = []
        if shutil.which("aws"):
            providers.append("aws")
        if shutil.which("az"):
            providers.append("azure")
        if shutil.which("gcloud"):
            providers.append("gcp")

        if not providers:
            from rich.console import Console

            con = Console(stderr=True)
            con.print("\n[yellow]No cloud CLI tools found (aws, az, gcloud).[/yellow]")
            con.print("  Install and configure credentials for your provider:")
            con.print("  [cyan]agent-bom cloud aws[/cyan]     requires: aws configure")
            con.print("  [cyan]agent-bom cloud azure[/cyan]   requires: az login")
            con.print("  [cyan]agent-bom cloud gcp[/cyan]     requires: gcloud auth login")
            con.print()
            con.print("  [dim]No credentials needed for:[/dim]")
            con.print("  [cyan]agent-bom image[/cyan] · [cyan]agent-bom iac[/cyan] · [cyan]agent-bom fs[/cyan]")
            return

        from agent_bom.cli.agents import scan

        ctx.invoke(
            scan,
            aws="aws" in providers,
            azure_flag="azure" in providers,
            gcp_flag="gcp" in providers,
            aws_cis_benchmark="aws" in providers,
            azure_cis_benchmark="azure" in providers,
            gcp_cis_benchmark="gcp" in providers,
            auto_update_db=False,
        )


@click.command("aws")
@click.option("--region", default=None, help="AWS region")
@click.option("--profile", default=None, help="AWS credential profile")
@click.option("--include-lambda", is_flag=True, help="Include Lambda functions")
@click.option("--include-eks", is_flag=True, help="Include EKS workloads")
@click.option("--include-ec2", is_flag=True, help="Include EC2 instances")
@click.option("--include-iam", is_flag=True, help="Enrich identity graph with IAM role policies and trust principals")
@click.option("--cis", is_flag=True, default=True, help="Run CIS benchmark (default: on)")
@click.option("--no-cis", is_flag=True, help="Skip CIS benchmark")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def aws_cmd(
    region: Optional[str],
    profile: Optional[str],
    include_lambda: bool,
    include_eks: bool,
    include_ec2: bool,
    include_iam: bool,
    cis: bool,
    no_cis: bool,
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
) -> None:
    """Scan AWS for AI agents, infrastructure, and CIS compliance."""
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        aws=True,
        aws_region=region,
        aws_profile=profile,
        aws_include_lambda=include_lambda,
        aws_include_eks=include_eks,
        aws_include_ec2=include_ec2,
        aws_include_iam=include_iam,
        aws_cis_benchmark=cis and not no_cis,
        auto_update_db=False,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


@click.command("azure")
@click.option("--subscription", default=None, help="Azure subscription ID")
@click.option("--cis", is_flag=True, default=True, help="Run CIS benchmark (default: on)")
@click.option("--no-cis", is_flag=True, help="Skip CIS benchmark")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def azure_cmd(
    subscription: Optional[str],
    cis: bool,
    no_cis: bool,
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
) -> None:
    """Scan Azure for AI agents, infrastructure, and CIS compliance."""
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        azure_flag=True,
        azure_subscription=subscription,
        azure_cis_benchmark=cis and not no_cis,
        auto_update_db=False,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


@click.command("gcp")
@click.option("--project", default=None, help="GCP project ID")
@click.option("--cis", is_flag=True, default=True, help="Run CIS benchmark (default: on)")
@click.option("--no-cis", is_flag=True, help="Skip CIS benchmark")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def gcp_cmd(
    project: Optional[str],
    cis: bool,
    no_cis: bool,
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
) -> None:
    """Scan GCP for AI agents, infrastructure, and CIS compliance."""
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        gcp_flag=True,
        gcp_project=project,
        gcp_cis_benchmark=cis and not no_cis,
        auto_update_db=False,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


# Register standalone commands on the cloud group
cloud_group.add_command(aws_cmd, "aws")
cloud_group.add_command(azure_cmd, "azure")
cloud_group.add_command(gcp_cmd, "gcp")


@click.command("resilience")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console")
def resilience_cmd(output_format: str) -> None:
    """Show cloud provider pagination, retry, and partial-failure posture."""
    from agent_bom.cloud.resilience import provider_resilience_summary

    summary = provider_resilience_summary()
    if output_format == "json":
        import json

        click.echo(json.dumps(summary, indent=2, sort_keys=True))
        return

    from rich.console import Console
    from rich.table import Table

    table = Table(title="Cloud provider resilience")
    table.add_column("Provider")
    table.add_column("Status")
    table.add_column("Pagination")
    table.add_column("Partial failure")
    for profile in summary["providers"]:
        table.add_row(
            profile["provider"],
            profile["status"],
            profile["pagination"],
            profile["partial_failure"],
        )
    Console().print(table)


cloud_group.add_command(resilience_cmd, "resilience")


@click.command("inventory")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "gcp", "all"]),
    default="all",
    show_default=True,
    help="Restrict the estate inventory to one cloud provider.",
)
@click.option("--region", default=None, help="AWS region (aws only).")
@click.option("--profile", default=None, help="AWS credential profile (aws only).")
@click.option("--subscription", default=None, help="Azure subscription id (azure only).")
@click.option("--project", default=None, help="GCP project id (gcp only).")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console")
def inventory_cmd(
    provider: str,
    region: Optional[str],
    profile: Optional[str],
    subscription: Optional[str],
    project: Optional[str],
    output_format: str,
) -> None:
    """Show an estate-wide AWS / Azure / GCP asset summary (read-only).

    Gated by ``AGENT_BOM_CLOUD_INVENTORY`` (AWS), ``AGENT_BOM_AZURE_INVENTORY``
    (Azure), and ``AGENT_BOM_GCP_INVENTORY`` (GCP). A disabled provider reports a
    ``disabled`` status and runs no network call. Reference only.
    """
    import json as _json

    from agent_bom.cloud import aws_inventory, azure_inventory, gcp_inventory

    reports: list[dict] = []
    if provider in ("aws", "all"):
        reports.append(aws_inventory.discover_inventory(region=region, profile=profile))
    if provider in ("azure", "all"):
        reports.append(azure_inventory.discover_inventory(subscription_id=subscription))
    if provider in ("gcp", "all"):
        reports.append(gcp_inventory.discover_inventory(project_id=project))

    if output_format == "json":
        click.echo(_json.dumps({"providers": reports}, indent=2, sort_keys=True, default=str))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    con.print("\n  [bold]Cloud estate inventory[/bold] [dim]· read-only[/dim]")

    table = Table()
    table.add_column("Provider")
    table.add_column("Status")
    table.add_column("Assets")
    table.add_column("Warnings", justify="right")
    any_disabled = False
    for rep in reports:
        status = str(rep.get("status", "unknown"))
        if status == "disabled":
            any_disabled = True
        style = {"ok": "green", "disabled": "yellow"}.get(status, "dim")
        table.add_row(
            str(rep.get("provider", "—")),
            f"[{style}]{status}[/{style}]",
            _asset_summary(rep),
            str(len(rep.get("warnings") or [])),
        )
    con.print(table)
    if any_disabled:
        con.print(
            "  [dim]Disabled providers run no network call. Enable with[/dim] "
            "[cyan]AGENT_BOM_CLOUD_INVENTORY=1[/cyan] [dim]·[/dim] "
            "[cyan]AGENT_BOM_AZURE_INVENTORY=1[/cyan] [dim]·[/dim] [cyan]AGENT_BOM_GCP_INVENTORY=1[/cyan]"
        )
    con.print()


# Report keys that are lists but NOT asset collections — excluded from the count
# so the summary auto-includes every resource type a provider adds without drift.
_INVENTORY_NON_ASSET_KEYS = frozenset({"warnings", "discovery_envelope", "permissions_used", "discovery_scope", "errors"})


def _asset_summary(report: dict) -> str:
    """Compact ``key=N`` summary of every non-empty asset collection in a report.

    Counts all list-valued keys (minus envelope/warning metadata) so any new
    resource type a provider's inventory adds appears here automatically — no
    hardcoded allowlist to drift out of sync with the discovery layer.
    """
    bits = []
    for key, value in report.items():
        if key in _INVENTORY_NON_ASSET_KEYS:
            continue
        if isinstance(value, list) and value:
            bits.append(f"{key}={len(value)}")
    return ", ".join(bits) if bits else "[dim]none[/dim]"


cloud_group.add_command(inventory_cmd, "inventory")
