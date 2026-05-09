"""`agent-bom firewall` CLI: validate and inspect inter-agent firewall policies.

Foundation only (#982 PR 1). Enforcement at the gateway and proxy is wired up
in subsequent PRs.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from agent_bom.firewall import (
    FirewallDecision,
    FirewallPolicyError,
    FirewallRule,
    evaluate,
    load_firewall_policy_file,
)


@click.group("firewall", invoke_without_command=False)
def firewall_group() -> None:
    """Inter-agent firewall policy tooling.

    \b
    Subcommands:
      validate    Validate a firewall policy file
      list        List rules in a firewall policy file
      check       Test a source → target pair against a policy

    \b
    Policy file format (JSON):
      {
        "version": 1,
        "tenant_id": "acme",
        "enforcement_mode": "enforce" | "dry_run",
        "default_decision": "allow" | "deny" | "warn",
        "rules": [
          {"source": "cursor", "target": "snowflake-cli",
           "decision": "deny", "description": "..."},
          {"source": "role:trusted", "target": "role:data-plane", "decision": "allow"}
        ]
      }
    """


@firewall_group.command("validate")
@click.argument("policy_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate_cmd(policy_file: Path) -> None:
    """Validate a firewall policy file. Exits non-zero on schema errors."""
    try:
        policy = load_firewall_policy_file(policy_file)
    except FirewallPolicyError as exc:
        click.secho(f"invalid: {exc}", fg="red", err=True)
        raise SystemExit(2)
    click.secho(
        f"valid · {len(policy.rules)} rule(s) · default={policy.default_decision.value} · mode={policy.enforcement_mode.value}",
        fg="green",
    )


@firewall_group.command("list")
@click.argument("policy_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a human-readable table.")
def list_cmd(policy_file: Path, as_json: bool) -> None:
    """List rules in a firewall policy file."""
    try:
        policy = load_firewall_policy_file(policy_file)
    except FirewallPolicyError as exc:
        click.secho(f"invalid: {exc}", fg="red", err=True)
        raise SystemExit(2)

    if as_json:
        click.echo(
            json.dumps(
                {
                    "version": policy.version,
                    "tenant_id": policy.tenant_id,
                    "enforcement_mode": policy.enforcement_mode.value,
                    "default_decision": policy.default_decision.value,
                    "rules": [
                        {
                            "source": r.source,
                            "target": r.target,
                            "decision": r.decision.value,
                            "description": r.description,
                        }
                        for r in policy.rules
                    ],
                },
                indent=2,
            )
        )
        return

    click.echo(
        f"firewall · tenant={policy.tenant_id or '*'} · mode={policy.enforcement_mode.value} · default={policy.default_decision.value}"
    )
    if not policy.rules:
        click.echo("(no rules)")
        return
    for rule in policy.rules:
        color = {"allow": "green", "deny": "red", "warn": "yellow"}.get(rule.decision.value, "white")
        click.echo(
            f"  {rule.source:<24} -> {rule.target:<24}  "
            + click.style(rule.decision.value.upper(), fg=color)
            + (f"  · {rule.description}" if rule.description else "")
        )


def _rule_payload(rule: FirewallRule | None) -> dict[str, str | None] | None:
    if rule is None:
        return None
    return {
        "source": rule.source,
        "target": rule.target,
        "decision": rule.decision.value,
        "description": rule.description,
    }


def _check_exit_code(decision: FirewallDecision) -> int:
    if decision is FirewallDecision.ALLOW:
        return 0
    if decision is FirewallDecision.WARN:
        return 1
    return 2


@firewall_group.command("check")
@click.argument("policy_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("source")
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON and exit 0=allow, 1=warn, 2=deny.")
@click.option(
    "--source-role",
    "source_roles",
    multiple=True,
    help="Role tag for the source agent (repeatable).",
)
@click.option(
    "--target-role",
    "target_roles",
    multiple=True,
    help="Role tag for the target agent (repeatable).",
)
def check_cmd(
    policy_file: Path,
    source: str,
    target: str,
    as_json: bool,
    source_roles: tuple[str, ...],
    target_roles: tuple[str, ...],
) -> None:
    """Test a source → target pair against the policy.

    Exit codes are scriptable for CI and deployment gates:
    0 = allow, 1 = warn, 2 = deny or invalid policy.
    """
    try:
        policy = load_firewall_policy_file(policy_file)
    except FirewallPolicyError as exc:
        click.secho(f"invalid: {exc}", fg="red", err=True)
        raise SystemExit(2)

    result = evaluate(
        policy,
        source_agent=source,
        target_agent=target,
        source_roles=set(source_roles),
        target_roles=set(target_roles),
    )
    if as_json:
        click.echo(
            json.dumps(
                {
                    "source_agent": source,
                    "target_agent": target,
                    "source_roles": list(source_roles),
                    "target_roles": list(target_roles),
                    "decision": result.decision.value,
                    "effective_decision": result.effective_decision.value,
                    "matched_rule": _rule_payload(result.matched_rule),
                    "policy": {
                        "source": str(policy_file),
                        "tenant_id": policy.tenant_id,
                        "default_decision": policy.default_decision.value,
                        "enforcement_mode": policy.enforcement_mode.value,
                    },
                },
                indent=2,
            )
        )
        raise SystemExit(_check_exit_code(result.effective_decision))

    color = {"allow": "green", "deny": "red", "warn": "yellow"}[result.effective_decision.value]
    click.echo(f"{source} -> {target}: " + click.style(result.effective_decision.value.upper(), fg=color, bold=True))
    if result.matched_rule is not None:
        click.echo(
            f"  matched: {result.matched_rule.source} -> {result.matched_rule.target} "
            f"({result.matched_rule.decision.value})"
            + (f"  · {result.matched_rule.description}" if result.matched_rule.description else "")
        )
    else:
        click.echo(f"  no rule matched · default = {policy.default_decision.value}")
    if result.decision != result.effective_decision:
        click.echo(f"  note: dry_run mode converted {result.decision.value} -> {result.effective_decision.value}")
    raise SystemExit(_check_exit_code(result.effective_decision))
