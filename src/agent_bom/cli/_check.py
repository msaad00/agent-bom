"""Pre-install check, integrity verification, and guard commands."""

from __future__ import annotations

import json
import sys
from typing import Optional

import click
from rich.console import Console

from agent_bom import __version__


def _detect_ecosystem(name: str) -> Optional[str]:
    """Detect ecosystem by checking if package exists on PyPI or npm.

    Returns the ecosystem name, or None if ambiguous (exists on both
    or network unavailable) — caller should scan both.
    """
    try:
        from agent_bom.http_client import sync_get

        on_pypi = False
        on_npm = False

        pypi_resp = sync_get(f"https://pypi.org/pypi/{name}/json", timeout=3)
        if pypi_resp and pypi_resp.status_code == 200:
            on_pypi = True

        npm_resp = sync_get(f"https://registry.npmjs.org/{name}", timeout=3)
        if npm_resp and npm_resp.status_code == 200:
            on_npm = True

        if on_pypi and not on_npm:
            return "pypi"
        if on_npm and not on_pypi:
            return "npm"
        return None  # ambiguous — scan both
    except Exception:
        return None


def _parse_package_spec(
    package_spec: str,
    ecosystem: Optional[str] = None,
) -> tuple[str, str, str]:
    """Parse a package spec into (name, version, ecosystem).

    Handles npx/uvx prefixes, scoped npm packages, and name@version.
    Auto-detects ecosystem when not specified.
    """
    spec = package_spec.strip()
    # Accept both pip (pkg==1.0) and universal (pkg@1.0) syntax
    if "==" in spec and "@" not in spec:
        spec = spec.replace("==", "@", 1)
    if spec.startswith("npx ") or spec.startswith("uvx "):
        parts = spec.split()
        pkg_args = [p for p in parts[1:] if not p.startswith("-")]
        spec = pkg_args[0] if pkg_args else spec
        if not ecosystem:
            ecosystem = "pypi" if package_spec.startswith("uvx") else "npm"

    if "@" in spec and not spec.startswith("@"):
        name, version = spec.rsplit("@", 1)
    elif spec.startswith("@") and spec.count("@") > 1:
        last_at = spec.rindex("@")
        name, version = spec[:last_at], spec[last_at + 1 :]
    else:
        name, version = spec, "unknown"

    if not ecosystem:
        if name.startswith("@"):
            ecosystem = "npm"
        elif "." in name or "_" in name:
            ecosystem = "pypi"
        else:
            # Ambiguous — try to detect, default to pypi
            ecosystem = _detect_ecosystem(name) or "pypi"

    return name, version, ecosystem


@click.command()
@click.argument("package_spec")
@click.option(
    "--ecosystem",
    "-e",
    type=click.Choice(["npm", "pypi", "go", "cargo", "maven", "nuget"]),
    help="Package ecosystem (inferred from name/command if omitted)",
)
@click.option("--quiet", "-q", is_flag=True, help="Only print vuln count, no details")
@click.option("--no-color", is_flag=True, help="Disable colored output")
def check(package_spec: str, ecosystem: Optional[str], quiet: bool, no_color: bool):
    """Check a package for known vulnerabilities before installing.

    \b
    Examples:
      agent-bom check express@4.18.2 --ecosystem npm
      agent-bom check requests@2.28.0 --ecosystem pypi
      agent-bom check "npx @modelcontextprotocol/server-filesystem"

    \b
    Exit codes:
      0  Clean — no known vulnerabilities
      1  Unsafe — vulnerabilities found
    """
    import asyncio

    console = Console(no_color=no_color)

    name, version, detected_eco = _parse_package_spec(package_spec, ecosystem)

    from agent_bom.models import Package, normalize_package_name
    from agent_bom.scanners import build_vulnerabilities, query_osv_batch

    if version == "unknown":
        console.print(f"[yellow]⚠ No version specified for {name} — skipping OSV lookup.[/yellow]")
        console.print("  Provide a version: agent-bom check name@version --ecosystem ecosystem")
        sys.exit(0)

    # Scan both pypi+npm for ambiguous packages (no dots, no underscores, no @)
    # This catches packages like lodash that exist on both registries
    if not ecosystem and not name.startswith("@") and "." not in name and "_" not in name:
        ecosystems: list[str] = ["pypi", "npm"]
    else:
        ecosystems = [detected_eco]
    pkgs = [Package(name=name, version=version, ecosystem=eco) for eco in ecosystems]

    # Resolve "latest" / empty version from registry
    if version in ("latest", ""):
        from agent_bom.http_client import create_client
        from agent_bom.resolver import resolve_package_version

        async def _resolve() -> bool:
            async with create_client(timeout=15.0) as client:
                for p in pkgs:
                    if await resolve_package_version(p, client):
                        return True
                return False

        with console.status("[bold]Resolving version from registry...[/bold]", spinner="dots"):
            resolved = asyncio.run(_resolve())
        if resolved:
            version = next((p.version for p in pkgs if p.version not in ("unknown", "latest", "")), version)
            for p in pkgs:
                p.version = version
            console.print(f"  [green]✓ Resolved @latest → {version}[/green]")
        else:
            eco_str = "/".join(ecosystems)
            console.print(f"[yellow]⚠ Could not resolve latest version for {name} ({eco_str})[/yellow]")
            console.print("  Provide an explicit version: agent-bom check name@1.2.3 -e ecosystem")
            sys.exit(0)

    eco_display = "/".join(ecosystems)
    console.print(f"\n[bold blue]🔍 Checking {name}@{version} ({eco_display})[/bold blue]\n")

    with console.status("[bold]Querying OSV...[/bold]", spinner="dots"):
        results = asyncio.run(query_osv_batch(pkgs))

    # Merge results from all ecosystems
    vuln_data: list[dict] = []
    matched_eco = ecosystems[0]
    for eco in ecosystems:
        key = f"{eco}:{normalize_package_name(name, eco)}@{version}"
        eco_vulns = results.get(key, [])
        if eco_vulns:
            vuln_data.extend(eco_vulns)
            matched_eco = eco

    ecosystem = matched_eco
    pkg = Package(name=name, version=version, ecosystem=ecosystem)

    if not vuln_data:
        console.print(f"  [green]✓ No known vulnerabilities in {name}@{version}[/green]\n")
        sys.exit(0)

    vulns = build_vulnerabilities(vuln_data, pkg)

    if not quiet:
        from rich.table import Table

        table = Table(title=f"{name}@{version} — {len(vulns)} vulnerability/ies found")
        table.add_column("ID", width=20)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6, justify="right")
        table.add_column("Fix", width=15)
        table.add_column("Summary", max_width=50)

        severity_styles = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
        }
        for v in vulns:
            sev = v.severity.value.lower()
            style = severity_styles.get(sev, "white")
            fix_display = f"[green]✓ {v.fixed_version}[/green]" if v.fixed_version else "[red dim]No fix[/red dim]"
            # Show summary; fall back to aliases list if empty
            summary_text = v.summary or ""
            if not summary_text or summary_text == "No description available":
                aliases_str = ", ".join(v.aliases[:3]) if v.aliases else ""
                summary_text = f"[dim]See {aliases_str}[/dim]" if aliases_str else "[dim]No description[/dim]"
            table.add_row(
                v.id,
                f"[{style} reverse] {v.severity.value.upper()} [/{style} reverse]",
                f"{v.cvss_score:.1f}" if v.cvss_score else "—",
                fix_display,
                summary_text[:100],
            )
        console.print(table)
        console.print()

    console.print(f"  [red]✗ {len(vulns)} vulnerability/ies found — do not install without review.[/red]\n")
    sys.exit(1)


@click.command()
@click.argument("package_spec", required=False, default=None)
@click.option(
    "--ecosystem",
    "-e",
    type=click.Choice(["npm", "pypi"]),
    help="Package ecosystem (default: pypi for self-verify)",
)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Only print verdict, no details")
def verify(package_spec: Optional[str], ecosystem: Optional[str], as_json: bool, quiet: bool):
    """Verify package integrity and provenance against registries.

    \b
    Self-verify (no arguments):
      agent-bom verify              check THIS installation of agent-bom

    \b
    Verify any package:
      agent-bom verify requests@2.28.0 -e pypi
      agent-bom verify @modelcontextprotocol/server-filesystem@2025.1.14 -e npm

    \b
    Exit codes:
      0  Verified — integrity and provenance checks passed
      1  Unverified — one or more checks failed
      2  Error — could not complete verification
    """
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
    if package_spec is None:
        name, version, eco = "agent-bom", __version__, "pypi"
        if not quiet:
            console.print(f"\n[bold blue]Verifying agent-bom {version} installation...[/bold blue]\n")
        record_result = verify_installed_record("agent-bom")
    else:
        name, version, eco = _parse_package_spec(package_spec, ecosystem)
        record_result = None
        if not quiet:
            console.print(f"\n[bold blue]Verifying {name}@{version} ({eco})...[/bold blue]\n")

    if version in ("unknown", ""):
        console.print("[red]Error: version required. Use name@version format.[/red]")
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
    if provenance and provenance.get("has_provenance"):
        att_count = provenance.get("attestation_count", 0)
        checks["provenance"] = {
            "status": "pass",
            "detail": f"Attestation found ({att_count} attestation(s))",
        }
    elif provenance:
        checks["provenance"] = {"status": "unknown", "detail": "No provenance attestation"}
    else:
        checks["provenance"] = {"status": "unknown", "detail": "Could not check provenance"}

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

    status_icons = {"pass": "[green]PASS[/green]", "fail": "[red]FAIL[/red]", "unknown": "[yellow]UNKNOWN[/yellow]"}
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
        console.print(f"\n  [bold green]VERIFIED[/bold green] — {name}@{version} integrity confirmed\n")
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
