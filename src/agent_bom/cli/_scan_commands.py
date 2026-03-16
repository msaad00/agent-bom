"""Focused scan commands — Trivy-style top-level commands.

Each command is a focused, fast path for a specific scan type.
They all produce the same AIBOMReport model and support the same
output formats (--format, --output, --fail-on-severity).

Usage::

    agent-bom image nginx:latest          # container image scan
    agent-bom fs /mnt/snapshot            # filesystem / VM scan
    agent-bom iac Dockerfile k8s/         # IaC misconfiguration scan
    agent-bom sbom bom.json               # ingest + scan SBOM
"""

from __future__ import annotations

from typing import Optional

import click


@click.command("image")
@click.argument("image_ref")
@click.option("--platform", help="Target platform (e.g. linux/amd64)")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--fail-on-severity", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--enrich", is_flag=True, help="Add NVD CVSS + EPSS + KEV enrichment")
@click.option("--offline", is_flag=True, help="Scan against local DB only")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def image_cmd(
    image_ref: str,
    platform: Optional[str],
    output_format: str,
    output_path: Optional[str],
    fail_on_severity: Optional[str],
    enrich: bool,
    offline: bool,
    quiet: bool,
) -> None:
    """Scan a container image for vulnerabilities.

    \b
    Examples:
      agent-bom image nginx:latest
      agent-bom image myapp:v2.1 --enrich --fail-on-severity high
      agent-bom image ghcr.io/org/app:sha256-abc -f sarif -o results.sarif
    """
    from agent_bom.cli.scan import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        images=(image_ref,),
        image_platform=platform,
        output_format=output_format,
        output=output_path,
        fail_on_severity=fail_on_severity,
        enrich=enrich,
        offline=offline,
        quiet=quiet,
    )


@click.command("fs")
@click.argument("path")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--fail-on-severity", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--enrich", is_flag=True, help="Add NVD CVSS + EPSS + KEV enrichment")
@click.option("--offline", is_flag=True, help="Scan against local DB only")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def fs_cmd(
    path: str,
    output_format: str,
    output_path: Optional[str],
    fail_on_severity: Optional[str],
    enrich: bool,
    offline: bool,
    quiet: bool,
) -> None:
    """Scan a filesystem directory or mounted VM disk snapshot.

    \b
    Examples:
      agent-bom fs .
      agent-bom fs /mnt/vm-snapshot --offline
      agent-bom fs /app --fail-on-severity high -f sarif -o results.sarif
    """
    from agent_bom.cli.scan import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        filesystem_paths=(path,),
        output_format=output_format,
        output=output_path,
        fail_on_severity=fail_on_severity,
        enrich=enrich,
        offline=offline,
        quiet=quiet,
    )


@click.command("iac")
@click.argument("paths", nargs=-1, required=True)
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def iac_cmd(
    paths: tuple[str, ...],
    output_format: str,
    output_path: Optional[str],
    quiet: bool,
) -> None:
    """Scan infrastructure-as-code files for misconfigurations.

    Supports: Dockerfile, Kubernetes YAML, Terraform (.tf), CloudFormation (.json/.yaml)

    \b
    Examples:
      agent-bom iac Dockerfile
      agent-bom iac Dockerfile k8s/ infra/main.tf
      agent-bom iac . -f sarif -o iac-results.sarif
    """
    from agent_bom.cli.scan import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        iac_paths=paths,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


@click.command("sbom")
@click.argument("path")
@click.option("--name", "sbom_name", help="Label for the SBOM resource")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--fail-on-severity", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--enrich", is_flag=True, help="Add NVD CVSS + EPSS + KEV enrichment")
@click.option("--offline", is_flag=True, help="Scan against local DB only")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def sbom_cmd(
    path: str,
    sbom_name: Optional[str],
    output_format: str,
    output_path: Optional[str],
    fail_on_severity: Optional[str],
    enrich: bool,
    offline: bool,
    quiet: bool,
) -> None:
    """Ingest an existing SBOM (CycloneDX/SPDX) and scan for vulnerabilities.

    \b
    Examples:
      agent-bom sbom vendor-bom.json
      agent-bom sbom bom.cdx.json --enrich --fail-on-severity critical
    """
    from agent_bom.cli.scan import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        sbom_file=path,
        sbom_name=sbom_name,
        output_format=output_format,
        output=output_path,
        fail_on_severity=fail_on_severity,
        enrich=enrich,
        offline=offline,
        quiet=quiet,
    )
