"""Pre-install check, integrity verification, and guard commands."""

from __future__ import annotations

import json
import sys
from typing import Optional

import click
from rich.console import Console

from agent_bom import __version__
from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEMS


def _response_has_version(response, ecosystem: str, version: str) -> bool:
    """Return True when a registry response contains the requested version."""
    if response is None or response.status_code != 200:
        return False
    if version in {"unknown", "", "latest"}:
        return True
    try:
        payload = response.json()
    except Exception:
        return False
    if ecosystem == "pypi":
        return version in (payload.get("releases") or {})
    return version in (payload.get("versions") or {})


def _detect_ecosystem(name: str, version: str = "unknown") -> Optional[str]:
    """Detect ecosystem by checking package and version presence on PyPI or npm."""
    try:
        from agent_bom.http_client import sync_get

        pypi_resp = sync_get(f"https://pypi.org/pypi/{name}/json", timeout=3)
        npm_resp = sync_get(f"https://registry.npmjs.org/{name}", timeout=3)
        on_pypi = _response_has_version(pypi_resp, "pypi", version)
        on_npm = _response_has_version(npm_resp, "npm", version)

        if on_pypi and not on_npm:
            return "pypi"
        if on_npm and not on_pypi:
            return "npm"
        return None
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
            ecosystem = _detect_ecosystem(name, version) or "pypi"

    return name, version, ecosystem


def _resolve_check_ecosystems(name: str, version: str, ecosystem: Optional[str], detected_eco: str) -> list[str]:
    """Return the ecosystems that `check` should scan."""
    if ecosystem:
        return [detected_eco]
    if name.startswith("@") or "." in name or "_" in name:
        return [detected_eco]

    resolved = _detect_ecosystem(name, version)
    if resolved:
        return [resolved]

    error = click.ClickException(f"Ambiguous package name '{name}'. Specify --ecosystem pypi or --ecosystem npm for a trustworthy verdict.")
    error.exit_code = 2
    raise error


@click.command()
@click.argument("package_spec")
@click.option(
    "--ecosystem",
    "-e",
    type=click.Choice(SUPPORTED_PACKAGE_ECOSYSTEMS),
    help="Package ecosystem (inferred from name/command if omitted)",
)
@click.option("--quiet", "-q", is_flag=True, help="Only print vuln count, no details")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option(
    "--exit-zero",
    is_flag=True,
    help="Exit 0 even when vulnerabilities are found (useful for exploratory or parallel checks)",
)
def check(package_spec: str, ecosystem: Optional[str], quiet: bool, no_color: bool, exit_zero: bool):
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
      1  Unsafe — vulnerabilities found
      2  Incomplete — OS package context insufficient for a trustworthy verdict

    \b
    Notes:
      Use --exit-zero for exploratory or parallel workflows where findings
      should be reported without failing the command.
    """
    console = Console(no_color=no_color)

    name, version, detected_eco = _parse_package_spec(package_spec, ecosystem)

    from agent_bom.models import Package
    from agent_bom.parsers.os_parsers import enrich_os_package_context

    if version == "unknown":
        console.print(f"[yellow]⚠ No version specified for {name} — skipping OSV lookup.[/yellow]")
        console.print("  Provide a version: agent-bom check name@version --ecosystem ecosystem")
        sys.exit(0)

    ecosystems = _resolve_check_ecosystems(name, version, ecosystem, detected_eco)
    pkgs = [Package(name=name, version=version, ecosystem=eco) for eco in ecosystems]
    os_context_complete = True
    for pkg in pkgs:
        if pkg.ecosystem in {"deb", "apk", "rpm"}:
            os_context_complete = enrich_os_package_context(pkg) and os_context_complete

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
            import asyncio

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

    with console.status("[bold]Scanning package risk...[/bold]", spinner="dots"):
        import asyncio

        from agent_bom.scanners import IncompleteScanError, consume_scan_warnings, scan_packages

        try:
            asyncio.run(scan_packages(pkgs))
        except IncompleteScanError as exc:
            console.print(f"  [yellow]⚠[/yellow] {exc}")
            sys.exit(2)

    scan_warnings = consume_scan_warnings()
    if scan_warnings:
        console.print(f"  [yellow]⚠[/yellow] Scan completed with {len(scan_warnings)} warning(s); results may be incomplete.")

    matched_pkg = next((p for p in pkgs if p.vulnerabilities), pkgs[0])
    vulns = matched_pkg.vulnerabilities

    if not vulns and matched_pkg.ecosystem in {"deb", "apk", "rpm"} and not os_context_complete:
        console.print(f"  [yellow]⚠ Incomplete OS package context for {name}@{version}[/yellow]")
        console.print(
            "  Best-effort matching found no vulnerabilities, but source/distro metadata was "
            "insufficient for a trustworthy clean verdict.\n"
        )
        sys.exit(2)

    if not vulns:
        console.print(f"  [green]✓ No known vulnerabilities in {name}@{version}[/green]\n")
        sys.exit(0)

    if not quiet:
        from rich.table import Table

        from agent_bom.cwe_impact import classify_cwe_impact

        table = Table(title=f"{name}@{version} — {len(vulns)} vulnerability/ies found")
        table.add_column("Sev", width=10, no_wrap=True)
        table.add_column("ID", width=20, no_wrap=True)
        table.add_column("Impact", width=14, no_wrap=True)
        table.add_column("Fix", width=10)
        table.add_column("Summary", max_width=38)

        severity_styles = {
            "critical": "red bold",
            "high": "#e67e22 bold",
            "medium": "yellow",
            "low": "dim",
        }
        _impact_styles = {
            "code-execution": "red",
            "credential-access": "red",
            "file-access": "#e67e22",
            "injection": "#e67e22",
            "ssrf": "#e67e22",
            "data-leak": "yellow",
            "availability": "dim",
            "client-side": "dim",
        }
        for v in vulns:
            sev = v.severity.value.lower()
            style = severity_styles.get(sev, "white")
            fix_display = f"[green]{v.fixed_version}[/green]" if v.fixed_version else "[dim]no fix[/dim]"
            # CWE impact category
            impact = classify_cwe_impact(v.cwe_ids)
            impact_style = _impact_styles.get(impact, "dim")
            impact_label = impact.replace("-", " ").replace("code execution", "RCE")
            # KEV badge
            kev = " [red bold]KEV[/red bold]" if v.is_kev else ""
            # Concise summary — truncate to keep table compact
            summary_text = v.summary or ""
            if not summary_text or summary_text == "No description available":
                aliases_str = ", ".join(v.aliases[:3]) if v.aliases else ""
                summary_text = f"[dim]See {aliases_str}[/dim]" if aliases_str else "[dim]—[/dim]"
            elif len(summary_text) > 50:
                summary_text = summary_text[:47] + "..."
            table.add_row(
                f"[{style}]{v.severity.value.upper()}[/{style}]{kev}",
                v.id,
                f"[{impact_style}]{impact_label}[/{impact_style}]",
                fix_display,
                summary_text,
            )
        console.print(table)
        console.print()

    if exit_zero:
        console.print(f"  [yellow]⚠ {len(vulns)} vulnerability/ies found — reported without failing due to --exit-zero.[/yellow]\n")
        sys.exit(0)

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
