"""Canonical front-door verbs for the human CLI.

agent-bom exposes a deep command catalog (scanning, runtime, MCP, reporting,
governance, plus every cloud/identity/cost surface). For a first-time human the
breadth is the problem, not the depth. This module adds a *narrow front door* —
five canonical verbs that read like a story:

    connect → scan → graph → report     (and `up` to run the platform locally)

Nothing here removes or rewrites an existing command. ``scan``, ``graph`` and
``report`` already exist and are simply surfaced as the primary verbs in
``--help``. This module contributes the two genuinely new verbs:

* ``connect`` — read-only onboarding guidance for a cloud/source. It points at
  the per-cloud read-only Terraform module under ``deploy/terraform/connect-*``
  and the opt-in inventory env var, then reports whether local credentials are
  already detectable so the next ``scan`` will have something to read.
* ``up`` (alias of ``serve``) — run the platform locally. It delegates to the
  existing ``serve`` command and points at the full-stack docker compose file.

Every flag/behavior of the underlying commands is preserved; these verbs are
additive aliases and guidance, not a restructure.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import click

# ---------------------------------------------------------------------------
# `connect` — read-only onboarding guidance + credential detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ConnectSource:
    """Static description of one connectable cloud/source.

    All values are documentation pointers — ``connect`` never mutates anything
    and never calls a cloud API. ``cred_env_vars`` are the standard provider
    credential variables we look for to report whether a local scan will have
    something to read.
    """

    name: str
    title: str
    terraform_module: str
    inventory_env: str
    inventory_value: str
    cred_env_vars: tuple[str, ...]
    scan_command: str
    role_summary: str
    audit_trail_note: str = ""


# Ordered to match the documented onboarding story (cloud → data platforms).
_CONNECT_SOURCES: dict[str, _ConnectSource] = {
    "aws": _ConnectSource(
        name="aws",
        title="Amazon Web Services",
        terraform_module="deploy/terraform/connect-aws",
        inventory_env="AGENT_BOM_AWS_INVENTORY",
        inventory_value="1",
        cred_env_vars=("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"),
        scan_command="agent-bom scan --aws",
        role_summary="IAM principal with AWS-managed SecurityAudit (+ ViewOnlyAccess). List/Describe/Get only.",
        audit_trail_note=(
            "Reuses this SAME SecurityAudit role — no new role. cloudtrail:LookupEvents is "
            "already granted by the AWS-managed SecurityAudit policy, so enabling it adds zero new permission."
        ),
    ),
    "azure": _ConnectSource(
        name="azure",
        title="Microsoft Azure",
        terraform_module="deploy/terraform/connect-azure",
        inventory_env="AGENT_BOM_AZURE_INVENTORY",
        inventory_value="1",
        cred_env_vars=("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"),
        scan_command="agent-bom scan --azure",
        role_summary="Service principal with the built-in Reader role. Read-only; no write/delete grants.",
        audit_trail_note=(
            "Reuses this SAME Reader/Security Reader role — no new role. The Activity Log read "
            "(Microsoft.Insights/eventtypes/values/read) sits inside the existing Reader grant in standard setups."
        ),
    ),
    "gcp": _ConnectSource(
        name="gcp",
        title="Google Cloud Platform",
        terraform_module="deploy/terraform/connect-gcp",
        inventory_env="AGENT_BOM_GCP_INVENTORY",
        inventory_value="1",
        cred_env_vars=("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"),
        scan_command="agent-bom scan --gcp",
        role_summary="Service account with roles/viewer (+ roles/iam.securityReviewer). Read-only.",
        audit_trail_note=(
            "Reuses this SAME roles/viewer role — no new role. The audit-log read "
            "(logging.logEntries.list) sits inside the existing roles/viewer grant in standard setups."
        ),
    ),
    "snowflake": _ConnectSource(
        name="snowflake",
        title="Snowflake",
        terraform_module="deploy/terraform/connect-snowflake",
        inventory_env="SNOWFLAKE_ACCOUNT",
        inventory_value="<your-account-locator>",
        cred_env_vars=("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PRIVATE_KEY_PATH"),
        scan_command="agent-bom cloud snowflake",
        role_summary="Read-only role (warehouse USAGE + governance views). No DML/DDL grants.",
    ),
}


def _detected_cred_vars(source: _ConnectSource) -> list[str]:
    """Return the subset of the source's credential env vars currently set."""
    return [name for name in source.cred_env_vars if os.environ.get(name)]


def _render_connect_guidance(con: object, source: _ConnectSource) -> None:
    """Print the deterministic read-only setup for one source.

    Output is fixed for a given environment (only the credential-detection line
    reflects the current env), so it is safe to snapshot in tests.
    """
    printer = con.print  # type: ignore[attr-defined]
    printer()
    printer(f"  [bold]Connect {source.title}[/bold] [dim](read-only)[/dim]")
    printer(f"  [dim]{source.role_summary}[/dim]")
    printer()
    printer("  [bold]1. Provision the read-only grant[/bold]")
    printer(f"     [cyan]terraform -chdir={source.terraform_module} init && terraform -chdir={source.terraform_module} apply[/cyan]")
    printer("     [dim]Module mints exactly the read-only role agent-bom needs — nothing is created or modified in your account.[/dim]")
    printer()
    printer("  [bold]2. Opt in to inventory[/bold] [dim](default-off; agent-bom does zero network I/O until set)[/dim]")
    printer(f"     [cyan]export {source.inventory_env}={source.inventory_value}[/cyan]")
    printer()
    printer("  [bold]3. Scan[/bold]")
    printer(f"     [cyan]{source.scan_command}[/cyan]")
    printer()

    if source.audit_trail_note:
        printer("  [bold]Optional: audit-trail behavioral edges[/bold] [dim](opt-in, read-only)[/dim]")
        printer("     [cyan]export AGENT_BOM_AUDIT_TRAIL=1[/cyan]")
        printer(f"     [dim]{source.audit_trail_note}[/dim]")
        printer()

    detected = _detected_cred_vars(source)
    if detected:
        printer(f"  [green]Credentials detected:[/green] {', '.join(detected)}")
    else:
        expected = ", ".join(source.cred_env_vars)
        printer(f"  [yellow]No credentials detected.[/yellow] Set one of: [dim]{expected}[/dim]")
    printer()


def _list_connect_sources() -> None:
    """Print the supported `connect` sources (shown when no source is given)."""
    from rich.console import Console

    con = Console()
    con.print()
    con.print("  [bold]agent-bom connect[/bold] [dim]— read-only onboarding[/dim]")
    con.print("  [dim]Pick a source; agent-bom prints the exact read-only setup and verifies detection.[/dim]")
    con.print()
    for source in _CONNECT_SOURCES.values():
        con.print(f"    [cyan]>[/cyan] [bold]agent-bom connect {source.name}[/bold]   {source.title}")
    con.print()


@click.group(
    "connect",
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.pass_context
def connect_group(ctx: click.Context) -> None:
    """Read-only onboard a cloud or data source.

    \b
    Prints the exact read-only setup for a source (Terraform module + opt-in
    inventory env var), then reports whether local credentials are already
    detectable. agent-bom never mutates the target and does no network I/O
    until you opt in.

    \b
    Sources:
      agent-bom connect aws         IAM SecurityAudit/ViewOnly role (read-only)
      agent-bom connect azure       Reader-role service principal (read-only)
      agent-bom connect gcp         roles/viewer service account (read-only)
      agent-bom connect snowflake   read-only governance role

    \b
    Then:  agent-bom scan   ->   agent-bom graph   ->   agent-bom report
    """
    if ctx.invoked_subcommand is None:
        _list_connect_sources()


def _make_connect_subcommand(source: _ConnectSource) -> click.Command:
    @click.command(
        source.name,
        help=(
            f"Read-only onboarding for {source.title}.\n\n"
            f"Prints the read-only Terraform module ({source.terraform_module}), the "
            f"opt-in inventory env var ({source.inventory_env}), and the scan command, "
            f"then reports whether local credentials are detectable. Read-only — nothing "
            f"is created or modified in your account."
        ),
    )
    def _cmd() -> None:
        from rich.console import Console

        _render_connect_guidance(Console(), source)

    return _cmd


for _source in _CONNECT_SOURCES.values():
    connect_group.add_command(_make_connect_subcommand(_source))


# ---------------------------------------------------------------------------
# `up` — run the platform locally (alias of `serve`)
# ---------------------------------------------------------------------------

_FULLSTACK_COMPOSE = "deploy/docker-compose.fullstack.yml"


def make_up_command(serve_cmd: click.Command) -> click.Command:
    """Build the ``up`` verb as a thin pass-through to the existing ``serve``.

    ``up`` keeps every flag ``serve`` accepts (host/port/persist/…) by reusing
    ``serve``'s parameters and forwarding to its callback. The only addition is
    an epilog pointing at the full-stack docker compose file for users who want
    the complete UI + API + datastores rather than the single-process server.
    """

    @click.command(
        "up",
        context_settings={"help_option_names": ["-h", "--help"]},
        params=list(serve_cmd.params),
        short_help="Run the platform locally (alias of `serve`).",
    )
    @click.pass_context
    def up_cmd(ctx: click.Context, **kwargs: object) -> None:
        """Run the agent-bom platform locally (API + dashboard).

        \b
        Alias of `agent-bom serve` — accepts the same flags (--host, --port,
        --persist, ...). Starts the single-process server with the bundled UI.

        \b
        For the full stack (UI + API + Postgres + graph store), use docker:
          docker compose -f deploy/docker-compose.fullstack.yml up

        \b
        Needs: an open port (default 8422). No cloud credentials required to boot.
        """
        ctx.invoke(serve_cmd, **kwargs)

    up_cmd.epilog = f"Full stack (UI + API + datastores):  docker compose -f {_FULLSTACK_COMPOSE} up"
    return up_cmd


__all__ = ["connect_group", "make_up_command"]
