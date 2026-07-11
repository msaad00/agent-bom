"""Canonical front-door verbs for the human CLI.

agent-bom exposes a deep command catalog (scanning, runtime, MCP, reporting,
governance, plus every cloud/identity/cost surface). For a first-time human the
breadth is the problem, not the depth. This module adds a *narrow front door* —
five canonical verbs that read like a story:

    connect → scan → graph → report     (and `up` to run the platform locally)

Nothing here removes or rewrites an existing command. ``scan``, ``graph`` and
``report`` already exist and are simply surfaced as the primary verbs in
``--help``. This module contributes the two genuinely new verbs:

* ``connect`` — read-only onboarding guidance for a cloud/source. It prints
  CLI, CloudShell, and Terraform grant options (pick what your rights allow),
  points at ``scripts/provision/`` and ``deploy/terraform/connect-*``, and
  reports whether local credentials are already detectable so the next
  ``scan`` will have something to read.
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
    provision_path: str
    cli_hint: str
    cloudshell_hint: str
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
        provision_path="scripts/provision/aws_readonly_policy.json",
        cli_hint="aws iam create-policy/role + SecurityAudit (see scripts/provision/README.md)",
        cloudshell_hint="Open AWS CloudShell → paste the CLI grant (no local Terraform required)",
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
        provision_path="scripts/provision/azure_readonly_role.json",
        cli_hint="az ad sp create-for-rbac --role Reader (see scripts/provision/README.md)",
        cloudshell_hint="Open Azure Cloud Shell → paste the az grant (no local Terraform required)",
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
        provision_path="scripts/provision/gcp_readonly_role.yaml",
        cli_hint="gcloud iam service-accounts create + roles/viewer (see scripts/provision/README.md)",
        cloudshell_hint="Open Google Cloud Shell → paste the gcloud grant (no local Terraform required)",
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
        provision_path="scripts/provision/snowflake_readonly.sql",
        cli_hint="snow sql -f scripts/provision/snowflake_readonly.sql",
        cloudshell_hint="Snowsight SQL worksheet → paste snowflake_readonly.sql",
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
    from agent_bom.cli._terminal_sections import render_connect_card

    body_lines = [
        "[bold]1. Provision the read-only grant[/bold] [dim]— pick one path based on your rights[/dim]",
        "   [bold]CLI[/bold]",
        f"   [cyan]{source.cli_hint}[/cyan]",
        f"   [dim]Recipe + policy: {source.provision_path}[/dim]",
        "   [bold]CloudShell / console[/bold]",
        f"   [cyan]{source.cloudshell_hint}[/cyan]",
        "   [bold]Terraform[/bold] [dim](when IaC owns apply rights)[/dim]",
        f"   [cyan]terraform -chdir={source.terraform_module} init && terraform -chdir={source.terraform_module} apply[/cyan]",
        "   [dim]Read-only role only — agent-bom never writes to your account.[/dim]",
        "",
        "[bold]2. Opt in to inventory[/bold] [dim](default-off)[/dim]",
        f"   [cyan]export {source.inventory_env}={source.inventory_value}[/cyan]",
        "",
        "[bold]3. Scan[/bold]",
        f"   [cyan]{source.scan_command}[/cyan]",
    ]
    if source.audit_trail_note:
        body_lines.extend(
            [
                "",
                "[bold]Optional: audit-trail edges[/bold] [dim](opt-in)[/dim]",
                "   [cyan]export AGENT_BOM_AUDIT_TRAIL=1[/cyan]",
                f"   [dim]{source.audit_trail_note}[/dim]",
            ]
        )

    detected = _detected_cred_vars(source)
    if detected:
        body_lines.extend(["", f"[green]Credentials detected:[/green] {', '.join(detected)}"])
    else:
        expected = ", ".join(source.cred_env_vars)
        body_lines.extend(["", f"[yellow]No credentials detected.[/yellow] Set one of: [dim]{expected}[/dim]"])

    render_connect_card(
        con,  # type: ignore[arg-type]
        title=source.title,
        role_summary=f"{source.role_summary} (read-only)",
        body="\n".join(body_lines),
        next_command=source.scan_command,
    )


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
    """Read-only onboard a cloud or data source — describe, or establish + verify.

    \b
    With no connection flags, `connect <source>` prints the exact read-only
    setup (CLI, CloudShell, or Terraform grant + opt-in inventory env var) and
    reports whether local credentials are detectable — no network I/O.

    \b
    Given connection params (e.g. aws --role-arn/--external-id/--region) it goes
    further and actually establishes + verifies a read-only connection using the
    SAME broker and schema as the API:
      * locally (default): broker a short-lived read-only credential and run a
        trivial read-only probe (e.g. AWS sts:GetCallerIdentity) to prove it;
      * with --server/--api-key: register the connection with a running control
        plane (POST /v1/cloud/connections) and run its /test — the identical
        connection the UI/API create.
    The secret (--external-id / client secret / key) is write-only: never
    printed, never logged.

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


# ── Establish + verify: shared schema (CloudConnectionCreate) + shared broker ──
#
# Each provider exposes provider-appropriate flags that map onto the *canonical*
# ``CloudConnectionCreate`` fields (role_ref / external_id / regions / auth_params)
# so the CLI never invents a divergent connection shape. ``secret`` fields carry
# the single write-only secret and are never echoed.


@dataclass(frozen=True)
class _ConnectField:
    """One provider flag and how it maps onto the canonical connection schema.

    ``kind`` selects the canonical target: ``role_ref`` and ``secret`` set the
    two required columns, ``secret_file`` reads the secret from a file path,
    ``regions`` is a repeatable list, and ``auth_param`` writes into the
    non-secret ``auth_params`` blob under ``auth_key``.
    """

    flag: str
    param: str
    kind: str
    help: str
    auth_key: str = ""


_CONNECT_FIELDS: dict[str, tuple[_ConnectField, ...]] = {
    "aws": (
        _ConnectField("--role-arn", "role_arn", "role_ref", "IAM role ARN to assume, read-only (the connection role_ref)."),
        _ConnectField("--external-id", "external_id", "secret", "STS ExternalId — write-only secret; never printed or logged."),
        _ConnectField("--region", "regions", "regions", "Region to scan (repeatable)."),
    ),
    "azure": (
        _ConnectField("--client-id", "client_id", "role_ref", "App/service-principal client id (the connection role_ref)."),
        _ConnectField("--client-secret", "client_secret", "secret", "Client secret — write-only; never printed or logged."),
        _ConnectField("--tenant-id", "tenant_id", "auth_param", "Azure AD tenant id.", auth_key="tenant_id"),
        _ConnectField("--subscription-id", "subscription_id", "auth_param", "Azure subscription id.", auth_key="subscription_id"),
    ),
    "gcp": (
        _ConnectField("--service-account", "service_account", "role_ref", "Service-account email (the connection role_ref)."),
        _ConnectField("--key-file", "key_file", "secret_file", "Path to the service-account key JSON — write-only; never printed."),
        _ConnectField("--project", "project", "auth_param", "GCP project id.", auth_key="project_id"),
    ),
    "snowflake": (
        _ConnectField("--account", "account", "role_ref", "Snowflake account or account/user (the connection role_ref)."),
        _ConnectField("--private-key-file", "private_key_file", "secret_file", "Path to the PEM private key — write-only; never printed."),
        _ConnectField("--user", "user", "auth_param", "Snowflake user.", auth_key="user"),
        _ConnectField("--role", "role", "auth_param", "Snowflake role.", auth_key="role"),
        _ConnectField("--warehouse", "warehouse", "auth_param", "Snowflake warehouse.", auth_key="warehouse"),
    ),
}


def _connect_options(source: _ConnectSource) -> list[click.Option]:
    """Build the Click options for one provider's establish + verify flags."""
    options: list[click.Option] = []
    for field in _CONNECT_FIELDS[source.name]:
        decls = [field.flag, field.param]
        if field.kind == "regions":
            options.append(click.Option(decls, multiple=True, help=field.help))
        elif field.kind == "secret_file":
            options.append(click.Option(decls, type=click.Path(exists=True, dir_okay=False), help=field.help))
        else:
            options.append(click.Option(decls, help=field.help))
    options.extend(
        [
            click.Option(["--display-name"], help="Human label for the connection (defaults to the provider name)."),
            click.Option(["--server"], help="Control-plane base URL to register the connection with (uses the API)."),
            click.Option(["--api-key"], help="API key for --server registration."),
            click.Option(["--tenant"], help="Control-plane tenant id for --server registration."),
            click.Option(
                ["--scan", "do_scan"],
                is_flag=True,
                help="After establishing, trigger a scan (server /scan, else local scan guidance).",
            ),
        ]
    )
    return options


def _resolve_connect_inputs(source: _ConnectSource, kwargs: dict[str, object]) -> tuple[str, str, list[str], dict[str, str], bool]:
    """Map raw Click kwargs onto canonical (role_ref, external_id, regions, auth_params).

    Returns the four canonical pieces plus ``supplied`` — whether any connection
    param was given at all (if not, the caller keeps the informational default).
    ``secret_file`` fields are read from disk here; the secret content is never
    returned to the caller as anything but the ``external_id`` value.
    """
    role_ref = ""
    external_id = ""
    regions: list[str] = []
    auth_params: dict[str, str] = {}
    supplied = False
    for field in _CONNECT_FIELDS[source.name]:
        value = kwargs.get(field.param)
        if field.kind == "regions":
            if value:
                regions = [str(item) for item in value]  # type: ignore[union-attr]
                supplied = True
            continue
        if not value:
            continue
        supplied = True
        if field.kind == "role_ref":
            role_ref = str(value)
        elif field.kind == "secret":
            external_id = str(value)
        elif field.kind == "secret_file":
            from pathlib import Path

            external_id = Path(str(value)).read_text(encoding="utf-8")
        elif field.kind == "auth_param":
            auth_params[field.auth_key] = str(value)
    return role_ref, external_id, regions, auth_params, supplied


def _readonly_probe(provider: str, brokered: object, regions: list[str]) -> str:
    """Run a trivial, bounded, read-only call against a brokered credential.

    Proves the read-only credential actually works. Returns a short, non-secret
    description of what the probe saw (e.g. the AWS account id) — never the
    connection secret.
    """
    if provider == "aws":
        identity = brokered.client("sts").get_caller_identity()  # type: ignore[attr-defined]
        account = str(identity.get("Account") or "").strip()
        return f"AWS account {account}" if account else "AWS caller identity confirmed"
    if provider == "azure":
        # Bounded token acquisition against ARM — read-only, no resource calls.
        brokered.get_token("https://management.azure.com/.default")  # type: ignore[attr-defined]
        return "Azure Reader credential acquired a management token"
    if provider == "gcp":
        import google.auth.transport.requests as _ga_requests

        brokered.refresh(_ga_requests.Request())  # type: ignore[attr-defined]
        return "GCP read-only service-account credential refreshed"
    if provider == "snowflake":
        try:
            cursor = brokered.cursor()  # type: ignore[attr-defined]
            cursor.execute("SELECT CURRENT_VERSION()")
            cursor.fetchone()
        finally:
            try:
                brokered.close()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 - close best-effort
                pass
        return "Snowflake read-only key-pair connection opened"
    return "credential brokered"


def _local_verify(
    con: object,
    source: _ConnectSource,
    *,
    role_ref: str,
    external_id: str,
    regions: list[str],
    auth_params: dict[str, str],
    display_name: str,
    do_scan: bool,
) -> None:
    """Broker a read-only credential in-process and prove it with a bounded probe.

    Standalone — needs no control plane. Degrades gracefully with an install hint
    when the provider SDK extra is missing. The secret is never printed.
    """
    from rich.markup import escape

    from agent_bom.cloud.base import CloudDiscoveryError
    from agent_bom.cloud.connection_broker import ConnectionBrokerError, broker_session
    from agent_bom.cloud.connection_request import ephemeral_connection_record

    con.print(f"[dim]Verifying a read-only {source.title} connection locally (no server)...[/dim]")  # type: ignore[attr-defined]
    try:
        with ephemeral_connection_record(
            provider=source.name,
            display_name=display_name,
            role_ref=role_ref,
            external_id=external_id,
            regions=regions,
            auth_params=auth_params,
        ) as record:
            brokered = broker_session(record, session_name="agent-bom-cli-verify")
            detail = _readonly_probe(source.name, brokered, regions)
    except CloudDiscoveryError as exc:
        # Missing SDK extra — the broker's own install hint is already actionable.
        # Escape so the ``[extra]`` in the hint is not swallowed as rich markup.
        con.print(f"[yellow]Cannot verify locally:[/yellow] {escape(str(exc))}")  # type: ignore[attr-defined]
        return
    except (ConnectionBrokerError, Exception) as exc:  # noqa: BLE001 - broker/provider failure
        from agent_bom.security import sanitize_error

        con.print(f"[red]Verification failed:[/red] {escape(sanitize_error(exc, generic=True))}")  # type: ignore[attr-defined]
        return

    con.print(f"[green]Verified[/green] read-only credentials — {escape(detail)}.")  # type: ignore[attr-defined]
    if do_scan:
        con.print(f"[dim]Next, run the read-only scan:[/dim] [cyan]{source.scan_command}[/cyan]")  # type: ignore[attr-defined]


def _register_via_server(
    con: object,
    source: _ConnectSource,
    *,
    role_ref: str,
    external_id: str,
    regions: list[str],
    auth_params: dict[str, str],
    display_name: str,
    server: str,
    api_key: str,
    tenant: str,
    do_scan: bool,
) -> None:
    """Register the connection with a control plane, then run its /test (and /scan).

    Uses the API client + the SAME ``CloudConnectionCreate`` schema, so this is
    the identical connection the UI/API create. The secret is sent for at-rest
    encryption server-side and is never printed by the CLI.
    """
    from agent_bom.client import AgentBomApiError, AgentBomClient

    client = AgentBomClient(base_url=server, api_key=api_key, tenant_id=tenant or None)
    try:
        created = client.create_cloud_connection(
            provider=source.name,
            display_name=display_name,
            role_ref=role_ref,
            external_id=external_id,
            regions=regions,
            auth_params=auth_params,
        )
        connection_id = str(created.get("id") or "")
        con.print(f"[green]Registered[/green] {source.title} connection [bold]{connection_id}[/bold] on {server}.")  # type: ignore[attr-defined]
        test = client.test_cloud_connection(connection_id)
        con.print(f"[green]Test:[/green] read-only broker check -> {test.get('status', 'ok')}.")  # type: ignore[attr-defined]
        if do_scan:
            scan = client.scan_cloud_connection(connection_id)
            con.print(f"[green]Scan:[/green] launched (scan_id {scan.get('scan_id', '?')}).")  # type: ignore[attr-defined]
    except AgentBomApiError as exc:
        con.print(f"[red]Control plane rejected the request ({exc.status_code}).[/red] See server logs for detail.")  # type: ignore[attr-defined]
    finally:
        client.close()


def _make_connect_subcommand(source: _ConnectSource) -> click.Command:
    def _cmd(**kwargs: object) -> None:
        from rich.console import Console

        con = Console()
        role_ref, external_id, regions, auth_params, supplied = _resolve_connect_inputs(source, kwargs)
        if not supplied:
            # Back-compat: no connection flags -> unchanged informational output.
            _render_connect_guidance(con, source)
            return

        display_name = str(kwargs.get("display_name") or "").strip() or f"{source.title} (read-only)"
        server = str(kwargs.get("server") or "").strip()
        api_key = str(kwargs.get("api_key") or "").strip()
        tenant = str(kwargs.get("tenant") or "").strip()
        do_scan = bool(kwargs.get("do_scan"))

        if not role_ref or not external_id:
            secret_flag = next(f.flag for f in _CONNECT_FIELDS[source.name] if f.kind in ("secret", "secret_file"))
            role_flag = next(f.flag for f in _CONNECT_FIELDS[source.name] if f.kind == "role_ref")
            con.print(f"[red]To establish a connection, provide both {role_flag} and {secret_flag}.[/red]")
            raise click.exceptions.Exit(2)

        if server or api_key:
            if not server or not api_key:
                con.print("[red]--server and --api-key are both required to register with a control plane.[/red]")
                raise click.exceptions.Exit(2)
            _register_via_server(
                con,
                source,
                role_ref=role_ref,
                external_id=external_id,
                regions=regions,
                auth_params=auth_params,
                display_name=display_name,
                server=server,
                api_key=api_key,
                tenant=tenant,
                do_scan=do_scan,
            )
        else:
            _local_verify(
                con,
                source,
                role_ref=role_ref,
                external_id=external_id,
                regions=regions,
                auth_params=auth_params,
                display_name=display_name,
                do_scan=do_scan,
            )

    command = click.Command(
        source.name,
        callback=_cmd,
        params=_connect_options(source),
        help=(
            f"Read-only onboarding for {source.title}.\n\n"
            f"With no connection flags: prints CLI, CloudShell, and Terraform grant "
            f"options ({source.terraform_module} / {source.provision_path}), the opt-in "
            f"inventory env var ({source.inventory_env}), and the scan command, then reports "
            f"whether local credentials are detectable.\n\n"
            f"With connection flags (e.g. {_CONNECT_FIELDS[source.name][0].flag} + the write-only "
            f"secret): establishes + verifies a read-only connection using the same broker and "
            f"CloudConnectionCreate schema as the API — locally by default, or against a control "
            f"plane with --server/--api-key. Read-only; nothing is created or modified in your account."
        ),
        context_settings={"help_option_names": ["-h", "--help"]},
    )
    return command


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
