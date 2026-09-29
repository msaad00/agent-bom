"""Pre-install check, integrity verification, and guard commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from agent_bom import __version__
from agent_bom.cli._check_command import run_check
from agent_bom.cli._check_support import (
    _check_agent_confidence,
    _check_agent_summary,
    _check_payload_to_sarif,
    _check_result_payload,
    _check_severity_counts,
    _detect_ecosystem,
    _format_vulnerability_count,
    _maven_coordinate_error,
    _package_spec_error,
    _parse_package_spec,
    _render_provenance_check,
    _resolve_check_ecosystems,
    _response_has_version,
    _vulns_at_or_above,
    _write_check_output,
    _write_json_output,
    _write_sarif_output,
)
from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEMS

__all__ = [
    "_check_agent_confidence",
    "_check_agent_summary",
    "_check_payload_to_sarif",
    "_check_result_payload",
    "_check_severity_counts",
    "_detect_ecosystem",
    "_format_vulnerability_count",
    "_maven_coordinate_error",
    "_package_spec_error",
    "_parse_package_spec",
    "_render_provenance_check",
    "_resolve_check_ecosystems",
    "_response_has_version",
    "_vulns_at_or_above",
    "_write_check_output",
    "_write_json_output",
    "_write_sarif_output",
    "check",
    "guard_cmd",
    "verify",
]


def _exit_model_verification(
    model_dir: Path,
    repo_id: str | None,
    hf_token: str | None,
    as_json: bool,
    quiet: bool,
) -> None:
    """Verify local model weight files against upstream metadata."""
    from agent_bom.model_hash import verify_model_hashes

    console = Console()
    report = verify_model_hashes(model_dir, token=hf_token, repo_id=repo_id)
    summary = report.summary()

    if report.scanned == 0:
        if as_json:
            click.echo(
                json.dumps(
                    {
                        "scan_root": str(model_dir),
                        "repo_id": repo_id or "",
                        "verdict": "error",
                        "error": "No model weight files found",
                        "summary": summary,
                    },
                    indent=2,
                )
            )
        else:
            console.print(f"[red]Error: no model weight files found under {model_dir}[/red]")
        sys.exit(2)

    exit_code = 0 if report.verified == report.scanned else 1
    verdict = "verified" if exit_code == 0 else "unverified"

    if as_json:
        click.echo(
            json.dumps(
                {
                    "scan_root": str(model_dir),
                    "repo_id": repo_id or "",
                    "verdict": verdict,
                    "summary": summary,
                    "has_tampering": report.has_tampering,
                    "results": [result.to_dict() for result in report.results],
                },
                indent=2,
            )
        )
        sys.exit(exit_code)

    if quiet:
        console.print(
            f"{model_dir}: {'VERIFIED' if exit_code == 0 else 'UNVERIFIED'} "
            f"({report.verified}/{report.scanned} verified, {report.tampered} tampered, "
            f"{report.unverified} unverified, {report.offline} offline)"
        )
        sys.exit(exit_code)

    from rich.table import Table

    console.print(f"\n[bold blue]Verifying model weight files in {model_dir}[/bold blue]\n")
    table = Table(title=f"{model_dir} ({repo_id or 'repo auto-detect'})", show_header=True)
    table.add_column("Check", width=26)
    table.add_column("Status", width=10, justify="center")
    table.add_column("Detail", max_width=72)
    table.add_row(
        "Model hash verification",
        "[green]PASS[/green]" if exit_code == 0 else "[red]FAIL[/red]",
        (
            f"{report.verified}/{report.scanned} verified · "
            f"{report.tampered} tampered · "
            f"{report.unverified} unverified · "
            f"{report.offline} offline"
        ),
    )
    if report.has_tampering:
        tampered = [result.filename for result in report.results if result.status == "tampered"]
        table.add_row("Tampered files", "[red]FAIL[/red]", ", ".join(tampered[:3]))
    elif report.offline:
        table.add_row("Hub reachability", "[yellow]UNKNOWN[/yellow]", "HuggingFace Hub unreachable during verification")
    elif report.unverified:
        unverified = [result.filename for result in report.results if result.status == "unverified"]
        table.add_row("Missing metadata", "[yellow]UNKNOWN[/yellow]", ", ".join(unverified[:3]))
    console.print(table)

    if exit_code == 0:
        console.print(f"\n  [bold green]VERIFIED[/bold green] — {report.verified} model file(s) matched expected hashes\n")
    else:
        console.print("\n  [bold red]UNVERIFIED[/bold red] — one or more model files could not be trusted\n")
    sys.exit(exit_code)


@click.command()
@click.argument("package_spec")
@click.option(
    "--ecosystem",
    "-e",
    type=click.Choice(SUPPORTED_PACKAGE_ECOSYSTEMS),
    help="Package ecosystem (inferred from name/command if omitted)",
)
@click.option("--quiet", "-q", is_flag=True, help="Only print the final verdict, no details")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["console", "json", "sarif"], case_sensitive=False),
    default="console",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", "output_path", type=str, default=None, help="Write machine-readable output to a file (use '-' for stdout).")
@click.option(
    "--exit-zero",
    is_flag=True,
    help="Exit 0 even when vulnerabilities are found (useful for exploratory or parallel checks)",
)
@click.option("--enrich", is_flag=True, help="Add NVD CVSS, EPSS, and CISA KEV enrichment to matched vulnerabilities.")
@click.option("--offline", is_flag=True, help="Scan against the local vulnerability database only.")
@click.option(
    "--fail-on-severity",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Exit 1 only when vulnerabilities at this severity or higher are found.",
)
@click.option("--nvd-api-key", envvar="NVD_API_KEY", default=None, help="NVD API key for higher rate limits when using --enrich.")
@click.pass_context
def check(
    ctx: click.Context,
    package_spec: str,
    ecosystem: Optional[str],
    quiet: bool,
    no_color: bool,
    output_format: str,
    output_path: str | None,
    exit_zero: bool,
    enrich: bool,
    offline: bool,
    fail_on_severity: str | None,
    nvd_api_key: str | None,
):
    """Check a package for known vulnerabilities before installing.

    \b
    Examples:
      agent-bom check express@4.18.2 --ecosystem npm
      agent-bom check requests@2.28.0 --ecosystem pypi
      agent-bom check ncurses-bin@6.5+20250216-2 --ecosystem deb
      agent-bom check "npx @modelcontextprotocol/server-filesystem"

    \b
    Exit codes:
      0  Clean — no known vulnerabilities
      1  Unsafe — vulnerabilities found, or package flagged as malicious
      2  Incomplete — insufficient context for a trustworthy clean verdict
         (missing version, OS package metadata, or offline scan of an
         ecosystem the local DB carries no advisories for)

    \b
    Notes:
      `check` supports terminal output by default and `--format json`
      or `--format sarif` for machine-readable pre-install verdicts.
      Use `--enrich` when the verdict needs CVSS, EPSS, KEV, or NVD
      status evidence for triage or CI policy.
      For HTML, PDF, or SBOM output, use `agent-bom agents` (or
      `agent-bom scan`) with `--format/--output`.
      Use --exit-zero for exploratory or parallel workflows where findings
      should be reported without failing the command.
      Use --fail-on-severity to make CI fail only at the selected threshold.
    """
    run_check(
        ctx,
        package_spec=package_spec,
        ecosystem=ecosystem,
        quiet=quiet,
        no_color=no_color,
        output_format=output_format,
        output_path=output_path,
        exit_zero=exit_zero,
        enrich=enrich,
        offline=offline,
        fail_on_severity=fail_on_severity,
        nvd_api_key=nvd_api_key,
    )


@click.command()
@click.argument("package_spec", required=False, default=None)
@click.option(
    "--ecosystem",
    "-e",
    type=click.Choice(["npm", "pypi"]),
    help="Package ecosystem (default: pypi for self-verify)",
)
@click.option(
    "--model-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Verify local model weight files under this directory",
)
@click.option(
    "--repo-id",
    help="HuggingFace repo ID override for model verification, e.g. mistralai/Mistral-7B-v0.1",
)
@click.option(
    "--hf-token",
    envvar="HF_TOKEN",
    help="Optional HuggingFace token for private model metadata",
)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Only print verdict, no details")
def verify(
    package_spec: Optional[str],
    ecosystem: Optional[str],
    model_dir: Path | None,
    repo_id: str | None,
    hf_token: str | None,
    as_json: bool,
    quiet: bool,
):
    """Verify package integrity and provenance against registries.

    \b
    Self-verify (no arguments or explicit package name):
      agent-bom verify              check THIS installation of agent-bom
      agent-bom verify agent-bom    same as above

    \b
    Verify any package:
      agent-bom verify requests@2.28.0 -e pypi
      agent-bom verify @modelcontextprotocol/server-filesystem@2025.1.14 -e npm
      agent-bom verify --model-dir ./models --repo-id org/model

    \b
    Exit codes:
      0  Verified — integrity and provenance checks passed
      1  Unverified — one or more checks failed
      2  Error — could not complete verification
    """
    if model_dir is not None:
        if package_spec is not None:
            console = Console()
            console.print("[red]Error: choose either package verification or --model-dir, not both.[/red]")
            sys.exit(2)
        _exit_model_verification(model_dir, repo_id, hf_token, as_json, quiet)

    import asyncio

    from agent_bom.http_client import create_client
    from agent_bom.integrity import (
        check_package_provenance,
        fetch_pypi_release_metadata,
        verify_installed_record,
        verify_package_integrity,
    )
    from agent_bom.models import Package

    console = Console()

    # Determine target
    self_verify = package_spec is None or (
        package_spec is not None and package_spec.strip() in {"agent-bom", "agent_bom"} and ecosystem in (None, "pypi")
    )

    if self_verify:
        name, version, eco = "agent-bom", __version__, "pypi"
        if not quiet and not as_json:
            console.print(f"\n[bold blue]Verifying agent-bom {version} installation...[/bold blue]\n")
        record_result = verify_installed_record("agent-bom")
    else:
        assert package_spec is not None
        name, version, eco = _parse_package_spec(package_spec, ecosystem)
        record_result = None
        if not quiet and not as_json:
            console.print(f"\n[bold blue]Verifying {name}@{version} ({eco})...[/bold blue]\n")

    if version in ("unknown", ""):
        if name in {"agent-bom", "agent_bom"}:
            console.print(
                f"[red]Error: use `agent-bom verify` to self-verify this installation, or pass a version like "
                f"`agent-bom verify agent-bom@{__version__} -e pypi`.[/red]"
            )
        else:
            console.print(
                "[red]Error: version required. Use name@version format, "
                "for example requests@2.33.0 or @modelcontextprotocol/server-filesystem@2025.1.14.[/red]"
            )
        sys.exit(2)

    checks: dict[str, dict] = {}
    exit_code = 0

    # RECORD check (self-verify only)
    if record_result is not None:
        if record_result["installed_version"] is None:
            console.print("[red]Error: agent-bom is not installed as a package.[/red]")
            sys.exit(2)
        if not record_result["record_available"]:
            checks["record_integrity"] = {
                "status": "unknown",
                "detail": "RECORD not available (editable install?)",
            }
        elif record_result["record_intact"]:
            checks["record_integrity"] = {
                "status": "pass",
                "detail": f"{record_result['verified_files']}/{record_result['total_files']} files verified",
            }
        else:
            failed = record_result["failed_files"]
            checks["record_integrity"] = {
                "status": "fail",
                "detail": f"{len(failed)} file(s) tampered: {', '.join(failed[:3])}",
            }
            exit_code = 1

    # Registry + provenance checks (async)
    async def _verify():
        async with create_client(timeout=15.0) as client:
            pkg = Package(name=name, version=version, ecosystem=eco)
            integrity = await verify_package_integrity(pkg, client)
            provenance = await check_package_provenance(pkg, client)
            pypi_meta = None
            if eco == "pypi":
                pypi_meta = await fetch_pypi_release_metadata(name, version, client)
            return integrity, provenance, pypi_meta

    try:
        integrity, provenance, pypi_meta = asyncio.run(_verify())
    except Exception as exc:
        console.print(f"[red]Error during verification: {exc}[/red]")
        sys.exit(2)

    # Registry hash check
    if integrity and integrity.get("verified"):
        hash_val = integrity.get("sha256") or integrity.get("sha512_sri") or "present"
        checks["registry_hash"] = {
            "status": "pass",
            "detail": f"sha256:{hash_val[:16]}..." if len(str(hash_val)) > 16 else str(hash_val),
        }
    elif integrity:
        checks["registry_hash"] = {"status": "fail", "detail": "No hash found on registry"}
        exit_code = 1
    else:
        checks["registry_hash"] = {"status": "unknown", "detail": "Could not reach registry"}

    # Provenance check
    checks["provenance"] = _render_provenance_check(provenance)
    if checks["provenance"]["status"] != "pass":
        exit_code = 1

    # Metadata consistency (self-verify with pypi_meta only)
    if pypi_meta and record_result:
        local_meta = record_result.get("metadata", {})
        mismatches = []
        if pypi_meta.get("version") != version:
            mismatches.append("version")
        pypi_repo = pypi_meta.get("source_repo", "")
        local_repo = local_meta.get("source_repo", "")
        if pypi_repo and local_repo and pypi_repo != local_repo:
            mismatches.append("source_repo")
        if mismatches:
            checks["metadata_match"] = {
                "status": "fail",
                "detail": f"Mismatch: {', '.join(mismatches)}",
            }
            exit_code = 1
        else:
            checks["metadata_match"] = {"status": "pass", "detail": "version, source match PyPI"}

    # JSON output
    if as_json:
        output = {
            "package": name,
            "version": version,
            "ecosystem": eco,
            "checks": checks,
            "verdict": "verified" if exit_code == 0 else "unverified",
        }
        if pypi_meta:
            output["source_repo"] = pypi_meta.get("source_repo", "")
            output["license"] = pypi_meta.get("license", "")
        click.echo(json.dumps(output, indent=2))
        sys.exit(exit_code)

    # Quiet output
    if quiet:
        verdict = "VERIFIED" if exit_code == 0 else "UNVERIFIED"
        console.print(f"{name}@{version}: {verdict}")
        sys.exit(exit_code)

    # Rich table output
    from rich.table import Table

    status_icons = {
        "pass": "[green]PASS[/green]",
        "fail": "[red]FAIL[/red]",
        "missing": "[dim]MISSING[/dim]",
        "unavailable": "[yellow]UNAVAILABLE[/yellow]",
        "unknown": "[yellow]UNKNOWN[/yellow]",
    }
    check_labels = {
        "record_integrity": "RECORD integrity",
        "registry_hash": "Registry SHA-256",
        "provenance": "Provenance attestation",
        "metadata_match": "Metadata consistency",
    }

    table = Table(title=f"{name}@{version} ({eco})", show_header=True)
    table.add_column("Check", width=25)
    table.add_column("Status", width=10, justify="center")
    table.add_column("Detail", max_width=60)

    for key in ["record_integrity", "registry_hash", "provenance", "metadata_match"]:
        if key in checks:
            c = checks[key]
            table.add_row(check_labels[key], status_icons[c["status"]], c["detail"])

    console.print(table)

    # Source info
    if pypi_meta:
        console.print(f"\n  Source:  {pypi_meta.get('source_repo', 'N/A')}")
        console.print(f"  License: {pypi_meta.get('license', 'N/A')}")

    if exit_code == 0:
        console.print(f"\n  [bold green]VERIFIED[/bold green] — {name}@{version} integrity and provenance confirmed\n")
    else:
        console.print("\n  [bold red]UNVERIFIED[/bold red] — one or more checks failed\n")

    sys.exit(exit_code)


@click.command("guard", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("tool", type=click.Choice(["pip", "npm", "npx"]))
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.option("--min-severity", default="high", type=click.Choice(["critical", "high", "medium"]), help="Minimum severity to block")
@click.option("--allow-risky", is_flag=True, help="Warn but don't block risky packages")
def guard_cmd(tool: str, args: tuple, min_severity: str, allow_risky: bool):
    """Pre-install security guard — scan packages before installing.

    \b
    Wraps pip/npm install to check each package against OSV and NVD
    for known vulnerabilities before allowing installation.

    \b
    Usage:
      agent-bom guard pip install requests flask
      agent-bom guard npm install express

    \b
    Shell alias (recommended):
      alias pip='agent-bom guard pip'
      alias npm='agent-bom guard npm'

    \b
    Blocks install if any package has critical/high CVEs.
    Use --allow-risky to install anyway (with warnings).
    """
    from agent_bom.guard import run_guarded_install
    from agent_bom.logging_config import setup_logging

    setup_logging(level="INFO")

    exit_code = run_guarded_install(
        tool=tool,
        args=list(args),
        min_severity=min_severity,
        allow_risky=allow_risky,
    )
    sys.exit(exit_code)
