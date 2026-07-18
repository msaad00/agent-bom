"""Cloud command group — scan cloud infrastructure.

Cloud providers: AWS, Azure, GCP (real infrastructure with fleets, IAM, services).
AI platforms (Snowflake, Databricks, HuggingFace, etc.) are separate — not cloud infra.

One cloud-aware command spans every provider — ``cloud scan`` auto-detects which
clouds are configured and runs the same CIS + discovery work across them, instead
of asking the user to remember a separate subcommand per cloud. The per-cloud
``aws`` / ``azure`` / ``gcp`` commands remain as thin aliases that scope the
unified path to a single provider, so existing invocations keep working.

Usage::

    agent-bom cloud scan                  # every configured cloud (auto-detect)
    agent-bom cloud scan --provider aws   # one cloud, same as `cloud aws`
    agent-bom cloud aws                   # alias → scan --provider aws
    agent-bom cloud azure                 # alias → scan --provider azure
    agent-bom cloud gcp                   # alias → scan --provider gcp
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Optional

import click

from agent_bom.cli._grouped_help import SuggestingGroup


def _auto_update_db_default() -> bool:
    """Cloud scans refresh the vuln DB to latest by default, matching ``agent-bom scan``.

    Honors ``AGENT_BOM_AUTO_UPDATE_DB`` (set falsy to pin the DB for reproducible
    CI). Offline runs skip the refresh downstream regardless of this value.
    """
    raw = os.environ.get("AGENT_BOM_AUTO_UPDATE_DB")
    if raw is None:
        return True
    return raw.strip().lower() not in ("0", "false", "no", "off")

if TYPE_CHECKING:  # pragma: no cover - typing only
    from rich.console import Console

    from agent_bom.cloud.side_scan import SideScanResult

# Deterministic provider catalogue. The order here drives auto-detect ordering,
# per-provider sectioning, and `--provider all` fan-out so the same configuration
# always produces the same output.
_PROVIDER_ORDER: tuple[str, ...] = ("aws", "azure", "gcp")

# How a provider's credentials are set up, so the friendly skip note points the
# user at the exact thing to configure.
_PROVIDER_HINT = {
    "aws": "aws configure  (or IRSA / AWS_PROFILE / AWS_ACCESS_KEY_ID)",
    "azure": "az login  (or service principal / workload identity)",
    "gcp": "gcloud auth application-default login  (or GOOGLE_APPLICATION_CREDENTIALS)",
}


def _provider_configured(provider: str) -> bool:
    """Return True when *provider* has resolvable credentials (not just a CLI).

    Detection is by actual credential SOURCE — env vars, IRSA / workload-identity
    token files, shared config/credentials files, or a locally resolvable SDK
    session — never by a CLI binary on ``PATH``. A CLI binary with no credentials
    (CloudShell, CI images) is no longer a false positive, and an IRSA-backed
    collector with no CLI installed is no longer a false negative. No network
    call is made here.
    """
    from agent_bom.cloud.auth_probe import provider_has_credentials

    has, _source = provider_has_credentials(provider)
    return has


def _provider_status(provider: str) -> tuple[bool, str]:
    """Return ``(has_credentials, source)`` for *provider* — local checks only."""
    from agent_bom.cloud.auth_probe import provider_has_credentials

    return provider_has_credentials(provider)


def _detect_configured_providers() -> list[str]:
    """Configured providers in deterministic order (unconfigured ones dropped)."""
    return [p for p in _PROVIDER_ORDER if _provider_configured(p)]


def _resolve_scan_providers(provider: str) -> tuple[list[str], list[str]]:
    """Resolve ``--provider`` into (selected, skipped) provider lists.

    ``all`` expands to every configured cloud (auto-detect); unconfigured clouds
    are returned as ``skipped`` so the caller can surface a friendly note instead
    of failing. A single named provider is always selected even when its CLI is
    absent — the underlying scan emits its own credential guidance — so the alias
    commands keep their existing behaviour.
    """
    if provider == "all":
        selected = _detect_configured_providers()
        skipped = [p for p in _PROVIDER_ORDER if p not in selected]
        return selected, skipped
    return [provider], []


def _verify_provider(provider: str) -> tuple[bool, str]:
    """Opt-in network confirmation that *provider* credentials authenticate."""
    from agent_bom.cloud.auth_probe import verify_credentials

    return verify_credentials(provider)


def _run_cloud_scan(
    providers: list[str],
    *,
    skipped: Optional[list[str]] = None,
    verify: bool = False,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    aws_include_lambda: bool = True,
    aws_include_eks: bool = False,
    aws_include_ec2: bool = False,
    aws_include_iam: bool = False,
    azure_subscription: Optional[str] = None,
    gcp_project: Optional[str] = None,
    cis: bool = True,
    show_passed: bool = False,
    output_format: str = "console",
    output_path: Optional[str] = None,
    quiet: bool = False,
    verbose: bool = False,
) -> None:
    """Run the shared cloud-scan body across one or more providers.

    Single code path behind both the unified ``cloud scan`` command and the
    per-cloud aliases. The selected providers are enabled together in a single
    ``scan`` invocation; ``scan`` already discovers and benchmarks each provider
    under its own ``try``/``except`` so one provider failing or being
    unconfigured never aborts the others. Provider order is deterministic.
    """
    from rich.console import Console

    from agent_bom.cli.agents import scan

    providers = [p for p in _PROVIDER_ORDER if p in providers]

    # Per-provider status: say exactly what was detected and why, so the operator
    # (or a collector) knows which clouds are scanning and how their credentials
    # were resolved. Only surfaced on console output and when not quiet.
    show_status = not quiet and output_format == "console"
    if show_status and (providers or skipped):
        con = Console(stderr=True)
        for prov in providers:
            _has, source = _provider_status(prov)
            line = f"  [green]{prov}[/green]: scanning [dim](creds via {source})[/dim]"
            if verify:
                ok, detail = _verify_provider(prov)
                mark = "[green]verified[/green]" if ok else "[yellow]unverified[/yellow]"
                line += f" · {mark} [dim]({detail})[/dim]"
            con.print(line)
        for prov in skipped or []:
            con.print(f"  [yellow]{prov}[/yellow]: skipped — no credentials [dim](set up: {_PROVIDER_HINT[prov]})[/dim]")

    if not providers:
        con = Console(stderr=True)
        con.print("\n[yellow]No configured cloud providers to scan.[/yellow]")
        con.print("  Configure credentials for at least one provider and retry:")
        for prov in _PROVIDER_ORDER:
            con.print(f"  [cyan]{prov}[/cyan] → {_PROVIDER_HINT[prov]}")
        return

    aws_on = "aws" in providers
    azure_on = "azure" in providers
    gcp_on = "gcp" in providers

    if not quiet and output_format == "console" and len(providers) > 1:
        Console(stderr=True).print(
            f"\n[bold]Cloud scan[/bold] [dim]· {', '.join(p.upper() for p in providers)} · {'CIS + ' if cis else ''}discovery[/dim]"
        )

    # Pass --show-passed through to the grouped CIS renderer at report time.
    # click.Context.meta is shared across the whole context stack, so it survives
    # the invoke into `scan`.
    from agent_bom.cli.agents._cloud import CIS_SHOW_PASSED_META

    ctx = click.get_current_context()
    ctx.meta[CIS_SHOW_PASSED_META] = show_passed
    ctx.invoke(
        scan,
        aws=aws_on,
        aws_region=aws_region,
        aws_profile=aws_profile,
        # The target ``scan`` command exposes lambda discovery as the negative
        # flag ``no_aws_lambda`` (--no-aws-lambda), not ``aws_include_lambda`` —
        # passing the wrong keyword raised TypeError and broke every
        # ``cloud scan/aws/azure/gcp`` invocation.
        no_aws_lambda=not aws_include_lambda,
        aws_include_eks=aws_include_eks,
        aws_include_ec2=aws_include_ec2,
        aws_include_iam=aws_include_iam,
        azure_flag=azure_on,
        azure_subscription=azure_subscription,
        gcp_flag=gcp_on,
        gcp_project=gcp_project,
        aws_cis_benchmark=aws_on and cis,
        azure_cis_benchmark=azure_on and cis,
        gcp_cis_benchmark=gcp_on and cis,
        auto_update_db=_auto_update_db_default(),
        output_format=output_format,
        output=output_path,
        quiet=quiet,
        verbose=verbose,
    )


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
      scan         One cloud-aware scan across every configured provider
      aws          Alias — scan --provider aws (Bedrock, Lambda, ECS, EKS + CIS)
      azure        Alias — scan --provider azure (AI Foundry, Container Apps + CIS)
      gcp          Alias — scan --provider gcp (Vertex AI, Cloud Run + CIS)
      resilience   Provider pagination/retry/partial-failure evidence
    """
    if ctx.invoked_subcommand is None:
        providers = _detect_configured_providers()

        if not providers:
            from rich.console import Console

            con = Console(stderr=True)
            con.print("\n[yellow]No cloud credentials detected (aws, azure, gcp).[/yellow]")
            con.print("  Configure credentials for your provider:")
            con.print("  [cyan]agent-bom cloud aws[/cyan]     requires: aws configure / IRSA / AWS_PROFILE")
            con.print("  [cyan]agent-bom cloud azure[/cyan]   requires: az login / service principal")
            con.print("  [cyan]agent-bom cloud gcp[/cyan]     requires: gcloud ADC / GOOGLE_APPLICATION_CREDENTIALS")
            con.print()
            con.print("  [dim]No credentials needed for:[/dim]")
            con.print("  [cyan]agent-bom image[/cyan] · [cyan]agent-bom iac[/cyan] · [cyan]agent-bom fs[/cyan]")
            return

        # Bare `cloud` runs the unified scan across whatever is configured.
        _run_cloud_scan(providers)


@click.command("scan")
@click.option(
    "--provider",
    type=click.Choice(["all", *_PROVIDER_ORDER]),
    default="all",
    show_default=True,
    help="Cloud(s) to scan. 'all' auto-detects every configured provider and skips the rest.",
)
@click.option("--region", default=None, help="AWS region (aws only).")
@click.option("--profile", default=None, help="AWS credential profile (aws only).")
@click.option("--no-lambda", "skip_lambda", is_flag=True, help="Skip Lambda function discovery (aws only).")
@click.option("--include-eks", is_flag=True, help="Include EKS workloads (aws only).")
@click.option("--include-ec2", is_flag=True, help="Include EC2 instances (aws only).")
@click.option("--include-iam", is_flag=True, help="Enrich identity graph with IAM (aws only).")
@click.option(
    "--aws-deep",
    is_flag=True,
    help="Full AWS scan: enable EKS, EC2, and IAM discovery at once (convenience alias, aws only).",
)
@click.option("--subscription", default=None, help="Azure subscription ID (azure only).")
@click.option("--project", default=None, help="GCP project ID (gcp only).")
@click.option("--cis/--no-cis", default=True, show_default=True, help="Run CIS benchmark for each selected provider.")
@click.option(
    "--show-passed",
    is_flag=True,
    help="List passed CIS checks in the posture report instead of collapsing them into a count.",
)
@click.option(
    "--verify",
    is_flag=True,
    help="Confirm detected credentials authenticate (STS/whoami). Opt-in — makes a network call.",
)
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
@click.option("--verbose", "-v", is_flag=True, help="Expanded terminal output (full CIS plan, detail tables).")
def scan_cmd(
    provider: str,
    region: Optional[str],
    profile: Optional[str],
    skip_lambda: bool,
    include_eks: bool,
    include_ec2: bool,
    include_iam: bool,
    aws_deep: bool,
    subscription: Optional[str],
    project: Optional[str],
    cis: bool,
    show_passed: bool,
    verify: bool,
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
    verbose: bool,
) -> None:
    """Scan one or every configured cloud — AI agents, infra, and CIS compliance.

    A single cloud-aware command instead of one subcommand per provider. With the
    default ``--provider all`` it auto-detects which clouds are configured, scans
    each, and skips the rest with a note — never failing the whole run because one
    cloud is unconfigured. Provider-scoped flags apply only to their cloud.

    \b
    Examples:
      agent-bom cloud scan                       every configured cloud
      agent-bom cloud scan --provider aws        AWS only (same as `cloud aws`)
      agent-bom cloud scan --provider gcp --project my-proj
      agent-bom cloud scan --no-cis              discovery only, skip CIS
    """
    selected, skipped = _resolve_scan_providers(provider)
    _run_cloud_scan(
        selected,
        skipped=skipped,
        verify=verify,
        aws_region=region,
        aws_profile=profile,
        aws_include_lambda=not skip_lambda,
        aws_include_eks=include_eks or aws_deep,
        aws_include_ec2=include_ec2 or aws_deep,
        aws_include_iam=include_iam or aws_deep,
        azure_subscription=subscription,
        gcp_project=project,
        cis=cis,
        show_passed=show_passed,
        output_format=output_format,
        output_path=output_path,
        quiet=quiet,
        verbose=verbose,
    )


@click.command("aws")
@click.option("--region", default=None, help="AWS region")
@click.option("--profile", default=None, help="AWS credential profile")
@click.option("--no-lambda", "skip_lambda", is_flag=True, help="Skip Lambda function discovery")
@click.option("--include-eks", is_flag=True, help="Include EKS workloads")
@click.option("--include-ec2", is_flag=True, help="Include EC2 instances")
@click.option("--include-iam", is_flag=True, help="Enrich identity graph with IAM role policies and trust principals")
@click.option(
    "--aws-deep",
    is_flag=True,
    help="Full AWS scan: enable EKS, EC2, and IAM discovery at once (convenience alias).",
)
@click.option("--cis", is_flag=True, default=True, help="Run CIS benchmark (default: on)")
@click.option("--no-cis", is_flag=True, help="Skip CIS benchmark")
@click.option("--show-passed", is_flag=True, help="List passed CIS checks instead of collapsing them into a count.")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
@click.option("--verbose", "-v", is_flag=True, help="Expanded terminal output (full CIS plan, detail tables).")
def aws_cmd(
    region: Optional[str],
    profile: Optional[str],
    skip_lambda: bool,
    include_eks: bool,
    include_ec2: bool,
    include_iam: bool,
    aws_deep: bool,
    cis: bool,
    no_cis: bool,
    show_passed: bool,
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
    verbose: bool,
) -> None:
    """Scan AWS for AI agents, infrastructure, and CIS compliance.

    Alias for ``cloud scan --provider aws`` — kept for back-compat.
    Bedrock, Lambda, and ECS are discovered automatically; CIS runs by default.
    """
    _run_cloud_scan(
        ["aws"],
        aws_region=region,
        aws_profile=profile,
        aws_include_lambda=not skip_lambda,
        aws_include_eks=include_eks or aws_deep,
        aws_include_ec2=include_ec2 or aws_deep,
        aws_include_iam=include_iam or aws_deep,
        cis=cis and not no_cis,
        show_passed=show_passed,
        output_format=output_format,
        output_path=output_path,
        quiet=quiet,
        verbose=verbose,
    )


@click.command("azure")
@click.option("--subscription", default=None, help="Azure subscription ID")
@click.option("--cis", is_flag=True, default=True, help="Run CIS benchmark (default: on)")
@click.option("--no-cis", is_flag=True, help="Skip CIS benchmark")
@click.option("--show-passed", is_flag=True, help="List passed CIS checks instead of collapsing them into a count.")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
@click.option("--verbose", "-v", is_flag=True, help="Expanded terminal output (full CIS plan, detail tables).")
def azure_cmd(
    subscription: Optional[str],
    cis: bool,
    no_cis: bool,
    show_passed: bool,
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
    verbose: bool,
) -> None:
    """Scan Azure for AI agents, infrastructure, and CIS compliance.

    Alias for ``cloud scan --provider azure`` — kept for back-compat.
    """
    _run_cloud_scan(
        ["azure"],
        azure_subscription=subscription,
        cis=cis and not no_cis,
        show_passed=show_passed,
        output_format=output_format,
        output_path=output_path,
        quiet=quiet,
    )


@click.command("gcp")
@click.option("--project", default=None, help="GCP project ID")
@click.option("--cis", is_flag=True, default=True, help="Run CIS benchmark (default: on)")
@click.option("--no-cis", is_flag=True, help="Skip CIS benchmark")
@click.option("--show-passed", is_flag=True, help="List passed CIS checks instead of collapsing them into a count.")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
@click.option("--verbose", "-v", is_flag=True, help="Expanded terminal output (full CIS plan, detail tables).")
def gcp_cmd(
    project: Optional[str],
    cis: bool,
    no_cis: bool,
    show_passed: bool,
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
    verbose: bool,
) -> None:
    """Scan GCP for AI agents, infrastructure, and CIS compliance.

    Alias for ``cloud scan --provider gcp`` — kept for back-compat.
    """
    _run_cloud_scan(
        ["gcp"],
        gcp_project=project,
        cis=cis and not no_cis,
        show_passed=show_passed,
        output_format=output_format,
        output_path=output_path,
        quiet=quiet,
        verbose=verbose,
    )


# Register the unified command + the per-cloud aliases on the cloud group.
cloud_group.add_command(scan_cmd, "scan")
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


@click.command("registry-scan")
@click.option(
    "--provider",
    type=click.Choice(["ecr", "acr", "gar"]),
    required=True,
    help="Container registry to sweep: ecr (AWS), acr (Azure), gar (GCP Artifact Registry).",
)
@click.option("--region", default=None, help="AWS region (ecr only).")
@click.option("--profile", default=None, help="AWS credential profile (ecr only).")
@click.option("--registry", default=None, help="ACR login server, e.g. myacr.azurecr.io (acr only).")
@click.option("--project", default=None, help="GCP project id (gar only).")
@click.option("--location", default=None, help="GAR multi-region/location, e.g. us (gar only; all common ones by default).")
@click.option("--max-images", type=int, default=None, help="Cap on images scanned (default: AGENT_BOM_REGISTRY_MAX_IMAGES or 50).")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console")
def registry_scan_cmd(
    provider: str,
    region: Optional[str],
    profile: Optional[str],
    registry: Optional[str],
    project: Optional[str],
    location: Optional[str],
    max_images: Optional[int],
    output_format: str,
) -> None:
    """Sweep an entire cloud container registry — enumerate every repo+tag, scan each (read-only).

    Enumerates all repositories and tags in the registry, dedupes images by
    content digest, caps the work list (newest first), and runs the native image
    scanner on each. Read-only throughout — only registry read APIs and image
    pulls. A registry the role cannot read, or a single image that fails to pull,
    degrades to a warning and the sweep continues.

    \b
    Examples:
      agent-bom cloud registry-scan --provider ecr --region us-east-1
      agent-bom cloud registry-scan --provider acr --registry myacr.azurecr.io
      agent-bom cloud registry-scan --provider gar --project my-proj --location us
    """
    import json as _json

    from agent_bom.cloud.registry_sweep import sweep_registry

    report = sweep_registry(
        provider=provider,
        region=region,
        profile=profile,
        registry=registry,
        project=project,
        location=location,
        max_images=max_images,
    )

    if output_format == "json":
        click.echo(_json.dumps(report, indent=2, sort_keys=True, default=str))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    con.print(f"\n  [bold]Registry sweep[/bold] [dim]· {report['provider']} · read-only · {report['registry'] or '—'}[/dim]")

    status = str(report.get("status", "unknown"))
    if status != "ok":
        style = {"no_images": "yellow", "invalid_provider": "red", "all_failed": "red"}.get(status, "yellow")
        con.print(f"  status: [{style}]{status}[/{style}]")

    con.print(
        f"  discovered=[cyan]{report['discovered_count']}[/cyan] "
        f"scanned=[green]{report['scanned_count']}[/green] "
        f"skipped_by_cap=[yellow]{report['skipped_by_cap']}[/yellow] "
        f"failed=[red]{report['failed_count']}[/red] "
        f"cap={report['max_images']}"
    )

    if report["images"]:
        table = Table()
        table.add_column("Image")
        table.add_column("Packages", justify="right")
        table.add_column("Vuln pkgs", justify="right")
        table.add_column("Max severity")
        for img in report["images"]:
            table.add_row(
                str(img["reference"]),
                str(img["package_count"]),
                str(img["vulnerable_package_count"]),
                str(img["max_severity"]),
            )
        con.print(table)

    for warning in report["warnings"]:
        con.print(f"  [yellow]![/yellow] [dim]{warning}[/dim]")
    con.print()


cloud_group.add_command(registry_scan_cmd, "registry-scan")


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

    Gated by ``AGENT_BOM_AWS_INVENTORY`` (AWS), ``AGENT_BOM_AZURE_INVENTORY``
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

    reports = [_project_authorization_posture(report) for report in reports]

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
    table.add_column("Authorization")
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
            str((rep.get("authorization_evidence") or {}).get("status", "not_applicable")),
        )
    con.print(table)
    if any_disabled:
        con.print(
            "  [dim]Disabled providers run no network call. Enable with[/dim] "
            "[cyan]AGENT_BOM_AWS_INVENTORY=1[/cyan] [dim]·[/dim] "
            "[cyan]AGENT_BOM_AZURE_INVENTORY=1[/cyan] [dim]·[/dim] [cyan]AGENT_BOM_GCP_INVENTORY=1[/cyan]"
        )
    con.print()


def _project_authorization_posture(report: dict) -> dict:
    """Expose bounded authorization posture without policy or diagnostic data."""
    projected = dict(report)
    provider = str(projected.get("provider", "unknown"))
    evidence = projected.pop("authorization_evidence", None)
    if provider not in {"azure", "gcp"}:
        if evidence is not None:
            projected["authorization_evidence"] = evidence
        return projected

    from agent_bom.cloud.authorization_evidence import authorization_evidence_gap_reason_codes, summarize_authorization_evidence

    evidence_payload = evidence if isinstance(evidence, dict) else {}
    summary = summarize_authorization_evidence(evidence_payload)
    projected["authorization_evidence"] = summary.to_dict()
    reason_codes = authorization_evidence_gap_reason_codes(evidence_payload)

    from agent_bom.api.metrics import record_authorization_evidence

    record_authorization_evidence(provider=provider, status=summary.status.value, reason_codes=reason_codes)
    return projected

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


@click.command("side-scan")
@click.option("--instance-id", default=None, help="EC2 instance whose attached EBS volumes to scan.")
@click.option("--volume-id", default=None, help="A specific EBS volume to scan (takes precedence over --instance-id).")
@click.option(
    "--collector-instance-id",
    default=None,
    help="In-account collector EC2 instance the temp volume is attached to (no block data leaves the account).",
)
@click.option("--availability-zone", default=None, help="AZ to create the temp volume in (must match the collector).")
@click.option("--region", default=None, help="AWS region.")
@click.option("--no-secrets", is_flag=True, help="Skip the redacted secret scan (SBOM + CVEs only).")
@click.option("--no-sweep-orphans", is_flag=True, help="Skip the pre-run sweep of snapshots stranded by an earlier crash.")
def side_scan_cmd(
    instance_id: Optional[str],
    volume_id: Optional[str],
    collector_instance_id: Optional[str],
    availability_zone: Optional[str],
    region: Optional[str],
    no_secrets: bool,
    no_sweep_orphans: bool,
) -> None:
    """Agentless EBS disk side-scan — snapshot, mount read-only, SBOM + CVEs + redacted secrets.

    The single opt-in, non-read-only capability in agent-bom: it takes an EBS
    snapshot, attaches a temp volume to an *in-account collector* instance, mounts
    it read-only, parses the package SBOM + secret type/location (never values,
    never file contents), and tears everything down in a guaranteed cleanup. No
    disk image or block data ever leaves the account.

    Requires the scoped snapshot role (deploy/terraform/connect-aws-sidescan) and
    an in-account collector instance. Gated by ``AGENT_BOM_SIDESCAN`` — OFF by
    default; an unset flag prints how to enable it and exits non-zero.

    \b
    Examples:
      AGENT_BOM_SIDESCAN=1 agent-bom cloud side-scan \\
        --volume-id vol-0abc --collector-instance-id i-0def \\
        --availability-zone us-east-1a --region us-east-1
    """
    import asyncio

    from rich.console import Console

    from agent_bom.cloud.base import CloudDiscoveryError
    from agent_bom.cloud.side_scan import run_side_scan

    con = Console()
    try:
        results: list[SideScanResult] = asyncio.run(
            run_side_scan(
                instance_id=instance_id,
                volume_id=volume_id,
                collector_instance_id=collector_instance_id,
                availability_zone=availability_zone,
                region=region,
                scan_secrets_enabled=not no_secrets,
                sweep_orphans=not no_sweep_orphans,
            )
        )
    except CloudDiscoveryError as exc:
        # Actionable, user-safe message (opt-in / config guidance). The message
        # text is authored in the side-scan module and carries no exception
        # internals, so it is safe to surface directly.
        con.print(f"\n  [yellow]side-scan unavailable:[/yellow] {exc}\n")
        raise SystemExit(1) from None

    _render_side_scan_results(con, results)


def _render_side_scan_results(con: Console, results: list[SideScanResult]) -> None:
    """Render side-scan results in Rich tables — metadata only, no overflow."""
    from rich.table import Table

    con.print("\n  [bold]EBS side-scan[/bold] [dim]· agentless · read-only output · auto-cleaned[/dim]")

    if not results:
        con.print("  [yellow]No target volumes resolved.[/yellow] [dim]Pass --volume-id or --instance-id.[/dim]\n")
        return

    summary = Table()
    summary.add_column("Volume")
    summary.add_column("Instance")
    summary.add_column("Snapshot")
    summary.add_column("Packages", justify="right")
    summary.add_column("Vuln pkgs", justify="right")
    summary.add_column("Secrets", justify="right")
    summary.add_column("Cleaned up")
    for res in results:
        summary.add_row(
            str(res.volume_id or "—"),
            str(res.instance_id or "—"),
            str(res.snapshot_id or "—"),
            str(len(res.packages)),
            str(res.vulnerability_count),
            str(len(res.secrets)),
            "[green]yes[/green]" if res.cleaned_up else "[yellow]partial[/yellow]",
        )
    con.print(summary)

    for res in results:
        if res.secrets:
            secrets = Table(title=f"Secrets · {res.volume_id} [dim](type + location only)[/dim]")
            secrets.add_column("Type")
            secrets.add_column("File", overflow="fold")
            secrets.add_column("Line", justify="right")
            secrets.add_column("Severity")
            for sec in res.secrets:
                secrets.add_row(sec.secret_type, sec.file_path, str(sec.line_number), sec.severity)
            con.print(secrets)
        for warning in res.warnings:
            con.print(f"  [yellow]![/yellow] [dim]{warning}[/dim]")
    con.print()


cloud_group.add_command(side_scan_cmd, "side-scan")
