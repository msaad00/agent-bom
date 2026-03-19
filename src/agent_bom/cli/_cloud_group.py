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


@click.group("cloud", invoke_without_command=True)
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

        from agent_bom.cli.scan import scan

        ctx.invoke(
            scan,
            aws="aws" in providers,
            azure_flag="azure" in providers,
            gcp_flag="gcp" in providers,
            aws_cis_benchmark="aws" in providers,
            azure_cis_benchmark="azure" in providers,
            gcp_cis_benchmark="gcp" in providers,
        )


@click.command("aws")
@click.option("--region", default=None, help="AWS region")
@click.option("--profile", default=None, help="AWS credential profile")
@click.option("--include-lambda", is_flag=True, help="Include Lambda functions")
@click.option("--include-eks", is_flag=True, help="Include EKS workloads")
@click.option("--include-ec2", is_flag=True, help="Include EC2 instances")
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
    cis: bool,
    no_cis: bool,
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
) -> None:
    """Scan AWS for AI agents, infrastructure, and CIS compliance."""
    from agent_bom.cli.scan import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        aws=True,
        aws_region=region,
        aws_profile=profile,
        aws_include_lambda=include_lambda,
        aws_include_eks=include_eks,
        aws_include_ec2=include_ec2,
        aws_cis_benchmark=cis and not no_cis,
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
    from agent_bom.cli.scan import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        azure_flag=True,
        azure_subscription=subscription,
        azure_cis_benchmark=cis and not no_cis,
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
    from agent_bom.cli.scan import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        gcp_flag=True,
        gcp_project=project,
        gcp_cis_benchmark=cis and not no_cis,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


# Register standalone commands on the cloud group
cloud_group.add_command(aws_cmd, "aws")
cloud_group.add_command(azure_cmd, "azure")
cloud_group.add_command(gcp_cmd, "gcp")
