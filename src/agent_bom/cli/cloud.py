"""agent-cloud — Cloud infrastructure scanning for AI workloads.

Discovers AI agents, models, and services across cloud providers.
Runs CIS benchmarks, verifies model provenance, and assesses security posture.

Entry point: ``agent-cloud`` (registered in pyproject.toml).
"""

from __future__ import annotations

import sys
from collections import OrderedDict
from typing import Optional

import click

from agent_bom import __version__
from agent_bom.cli._entry import make_entry_point
from agent_bom.cli._grouped_help import GroupedGroup

# ── Help categories ──────────────────────────────────────────────────────────

CLOUD_CATEGORIES: OrderedDict[str, list[str]] = OrderedDict(
    [
        ("Cloud Providers", ["aws", "azure", "gcp"]),
        ("AI Platforms", ["snowflake", "databricks", "huggingface", "ollama"]),
        ("Posture", ["posture"]),
    ]
)

# ── Click group ──────────────────────────────────────────────────────────────


@click.group(
    cls=GroupedGroup,
    command_categories=CLOUD_CATEGORIES,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(
    version=__version__,
    prog_name="agent-cloud",
    message=(f"agent-cloud {__version__}\nPython {sys.version.split()[0]} · {sys.platform}\nPart of: https://github.com/msaad00/agent-bom"),
)
def cloud():
    """agent-cloud — Cloud infrastructure scanning for AI workloads.

    \b
    Discovers AI agents, models, and services across cloud providers.
    Runs CIS benchmarks and assesses security posture.

    \b
    Quick start:
      agent-cloud aws                    AWS Bedrock/Lambda/EKS + CIS v3.0
      agent-cloud azure                  Azure AI Foundry + CIS v2.0
      agent-cloud gcp                    GCP Vertex AI + CIS v3.0
      agent-cloud snowflake              Cortex Agents/MCP + CIS
      agent-cloud huggingface            Model provenance + hash verify
      agent-cloud posture                Unified cross-cloud summary

    \b
    Docs: https://github.com/msaad00/agent-bom
    """
    pass


# ── Register cloud provider commands (reuse from _cloud_group.py) ────────────

from agent_bom.cli._cloud_group import aws_cmd, azure_cmd, gcp_cmd  # noqa: E402

cloud.add_command(aws_cmd, "aws")
cloud.add_command(azure_cmd, "azure")
cloud.add_command(gcp_cmd, "gcp")

# ── Thin commands for AI platforms (delegate to scan with flags) ─────────────


@click.command("snowflake")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--cis", is_flag=True, default=True, help="Run CIS benchmark (default: on)")
@click.option("--no-cis", is_flag=True, help="Skip CIS benchmark")
@click.option("--quiet", "-q", is_flag=True)
def snowflake_cmd(output_format: str, output_path: Optional[str], cis: bool, no_cis: bool, quiet: bool) -> None:
    """Scan Snowflake for Cortex Agents, MCP servers, and CIS compliance."""
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        snowflake_flag=True,
        snowflake_cis_benchmark=cis and not no_cis,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


@click.command("databricks")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def databricks_cmd(output_format: str, output_path: Optional[str], quiet: bool) -> None:
    """Scan Databricks for clusters, libraries, and security best practices."""
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        databricks_flag=True,
        databricks_security=True,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


@click.command("huggingface")
@click.option("--verify-hashes", is_flag=True, default=True, help="Verify model file hashes")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def huggingface_cmd(verify_hashes: bool, output_format: str, output_path: Optional[str], quiet: bool) -> None:
    """Scan HuggingFace for model provenance, hash verification, and licensing."""
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        hf_flag=True,
        verify_model_hashes=verify_hashes,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


@click.command("ollama")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def ollama_cmd(output_format: str, output_path: Optional[str], quiet: bool) -> None:
    """Scan Ollama for local model registry and provenance."""
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        ollama_flag=True,
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


@click.command("posture")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def posture_cmd(output_format: str, output_path: Optional[str], quiet: bool) -> None:
    """Unified cross-cloud AI security posture summary.

    Auto-detects available cloud credentials and scans all configured providers.
    """
    import shutil

    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        aws=bool(shutil.which("aws")),
        azure_flag=bool(shutil.which("az")),
        gcp_flag=bool(shutil.which("gcloud")),
        aws_cis_benchmark=bool(shutil.which("aws")),
        azure_cis_benchmark=bool(shutil.which("az")),
        gcp_cis_benchmark=bool(shutil.which("gcloud")),
        output_format=output_format,
        output=output_path,
        quiet=quiet,
    )


cloud.add_command(snowflake_cmd, "snowflake")
cloud.add_command(databricks_cmd, "databricks")
cloud.add_command(huggingface_cmd, "huggingface")
cloud.add_command(ollama_cmd, "ollama")
cloud.add_command(posture_cmd, "posture")

# ── Entry point ──────────────────────────────────────────────────────────────

cloud_main = make_entry_point(cloud, "agent-cloud")
