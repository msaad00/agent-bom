"""Operator trust and data-boundary CLI surface."""

from __future__ import annotations

import json
from typing import Any

import click

from agent_bom.data_boundaries import describe_data_access_boundaries


def _comma(values: object) -> str:
    if isinstance(values, list):
        return ", ".join(str(value) for value in values)
    return str(values)


@click.command("trust")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    show_default=True,
    help="Output format.",
)
def trust_cmd(output_format: str) -> None:
    """Show data access, network, auth, and storage boundaries."""
    contract = describe_data_access_boundaries()
    if output_format == "json":
        click.echo(json.dumps(contract, indent=2, sort_keys=True))
        return

    posture = contract["default_posture"]
    if not isinstance(posture, dict):
        raise click.ClickException("data boundary contract is malformed")

    click.echo("Data access boundaries")
    click.echo(f"- hidden telemetry: {posture['hidden_telemetry']}")
    click.echo(f"- hosted control plane required: {posture['mandatory_hosted_control_plane']}")
    click.echo(f"- credential values stored: {posture['credential_values_stored']}")
    click.echo(f"- credential values transmitted: {posture['credential_values_transmitted']}")
    click.echo(f"- credential values validated by default: {posture['credential_values_validated_by_default']}")

    credential_evidence = contract["credential_evidence"]
    if isinstance(credential_evidence, dict):
        click.echo("\nCredential evidence")
        click.echo(f"- config env vars: {credential_evidence['config_env_vars']}")
        click.echo(f"- project secret scan: {credential_evidence['project_secret_scan']}")
        click.echo(f"- stores matched prefix: {credential_evidence['stores_matched_prefix']}")

    for section_name in ("network_boundaries", "storage_boundaries", "auth_boundaries", "extension_boundaries"):
        section = contract.get(section_name)
        if not isinstance(section, dict):
            continue
        click.echo(f"\n{section_name.replace('_', ' ').title()}")
        for key, value in section.items():
            if isinstance(value, dict):
                nested = ", ".join(f"{nested_key}={_comma(nested_value)}" for nested_key, nested_value in value.items())
                click.echo(f"- {key}: {nested}")
            else:
                click.echo(f"- {key}: {_comma(value)}")

    modes = contract.get("modes")
    if isinstance(modes, list):
        click.echo("\nScan modes")
        for mode in modes:
            if not isinstance(mode, dict):
                continue
            label = str(mode.get("mode", "unknown")).replace("_", " ")
            reads = _comma(mode.get("reads", []))
            mode_controls = _comma(mode.get("operator_controls") or mode.get("controls") or [])
            click.echo(f"- {label}: reads {reads}; controls {mode_controls}")

    operator_controls = contract.get("operator_controls")
    if isinstance(operator_controls, dict):
        click.echo("\nOperator controls")
        for key in (
            "scope_preview",
            "project_scope",
            "config_scope",
            "disable_vulnerability_network",
            "disable_scan_network_and_vuln_lookup",
        ):
            control_value: Any = operator_controls.get(key)
            if control_value is not None:
                click.echo(f"- {key}: {_comma(control_value)}")
