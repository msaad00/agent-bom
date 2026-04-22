"""Deployment lifecycle helper commands."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from agent_bom.deploy_teardown import (
    DEFAULT_STATE_DIR,
    build_reference_teardown_plan,
    execute_teardown_plan,
    format_teardown_plan,
    resolve_terraform_bin,
    validate_teardown_plan,
)


@click.command("teardown")
@click.option("--cluster-name", default="agent-bom", show_default=True, help="EKS cluster name used for local state resolution")
@click.option("--region", default="us-east-1", show_default=True, help="AWS region shown in the operator summary")
@click.option("--namespace", default="agent-bom", show_default=True, help="Kubernetes namespace containing the release")
@click.option("--release", "release_name", default="agent-bom", show_default=True, help="Helm release name")
@click.option(
    "--state-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_STATE_DIR,
    show_default=True,
    help="Local state root used by the AWS/EKS reference installer",
)
@click.option("--delete-namespace", is_flag=True, help="Delete the namespace after Helm uninstall completes")
@click.option("--delete-local-state", is_flag=True, help="Delete the generated local state after teardown")
@click.option("--skip-helm-uninstall", is_flag=True, help="Skip the Helm uninstall phase")
@click.option("--skip-terraform-destroy", is_flag=True, help="Skip the Terraform destroy phase")
@click.option("--wait-timeout-seconds", type=int, default=180, show_default=True, help="How long kubectl wait should block")
@click.option("--dry-run", is_flag=True, help="Print the teardown plan without changing anything")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip the interactive confirmation prompt")
def teardown_cmd(
    cluster_name: str,
    region: str,
    namespace: str,
    release_name: str,
    state_dir: Path,
    delete_namespace: bool,
    delete_local_state: bool,
    skip_helm_uninstall: bool,
    skip_terraform_destroy: bool,
    wait_timeout_seconds: int,
    dry_run: bool,
    assume_yes: bool,
) -> None:
    """Tear down the AWS/EKS reference install owned by agent-bom.

    This command intentionally removes only product-owned surfaces:
    - Helm release resources
    - product-owned AWS baseline resources managed by Terraform
    - optional local generated installer state

    It does not delete the EKS cluster, VPC, ingress controller, DNS, or
    other platform-owned shared infrastructure.
    """

    plan = build_reference_teardown_plan(
        cluster_name=cluster_name,
        region=region,
        namespace=namespace,
        release_name=release_name,
        state_dir=state_dir,
        delete_namespace=delete_namespace,
        delete_local_state=delete_local_state,
        skip_helm_uninstall=skip_helm_uninstall,
        skip_terraform_destroy=skip_terraform_destroy,
        wait_timeout_seconds=wait_timeout_seconds,
        terraform_bin=resolve_terraform_bin(),
    )
    errors = validate_teardown_plan(plan, dry_run=dry_run)
    if errors:
        raise click.ClickException("\n".join(errors))

    summary = format_teardown_plan(plan)
    click.echo(summary)

    if dry_run:
        execute_teardown_plan(plan, dry_run=True)
        return

    if not assume_yes and not click.confirm("\nProceed with the agent-bom teardown plan?", default=False):
        raise click.ClickException("teardown aborted")

    execute_teardown_plan(plan, dry_run=False)
    if delete_local_state:
        click.echo("\nTeardown completed. Local generated state was deleted after execution.")
    else:
        click.echo(f"\nTeardown summary written to {plan.summary_path}")


@click.command("sidecar-injector")
@click.option(
    "--host",
    default="0.0.0.0",  # nosec B104 - intended for in-cluster ClusterIP admission webhook serving
    show_default=True,
    help="Host for the admission webhook listener.",
)
@click.option("--port", default=8443, show_default=True, type=int, help="TLS port for the admission webhook listener.")
@click.option("--tls-cert-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="TLS certificate file.")
@click.option("--tls-key-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="TLS private key file.")
@click.option(
    "--proxy-image",
    envvar="AGENT_BOM_SIDECAR_PROXY_IMAGE",
    required=True,
    help="Container image injected as the agent-bom proxy sidecar.",
)
@click.option(
    "--control-plane-url",
    envvar="AGENT_BOM_API_URL",
    required=True,
    help="Control-plane API base URL the injected sidecar uses for policy pull and audit push.",
)
@click.option(
    "--control-plane-token-secret-name",
    envvar="AGENT_BOM_SIDECAR_TOKEN_SECRET_NAME",
    required=True,
    help="Secret name injected into the sidecar as AGENT_BOM_API_TOKEN.",
)
@click.option(
    "--control-plane-token-secret-key",
    envvar="AGENT_BOM_SIDECAR_TOKEN_SECRET_KEY",
    default="token",
    show_default=True,
    help="Secret key holding the control-plane API token.",
)
@click.option(
    "--default-mcp-port",
    default=3000,
    show_default=True,
    type=int,
    help="Fallback localhost MCP port when no explicit mcp-url annotation is set.",
)
@click.option("--metrics-port", default=8422, show_default=True, type=int, help="Metrics port exposed by the injected proxy sidecar.")
@click.option("--policy-refresh-seconds", default=30, show_default=True, type=int, help="Policy pull interval for the injected sidecar.")
@click.option("--audit-push-interval", default=10, show_default=True, type=int, help="Audit push interval for the injected sidecar.")
@click.option(
    "--detect-credentials/--no-detect-credentials",
    default=True,
    show_default=True,
    help="Enable credential detection in the injected sidecar.",
)
@click.option(
    "--block-undeclared/--no-block-undeclared",
    default=True,
    show_default=True,
    help="Enable undeclared-tool blocking in the injected sidecar.",
)
@click.option(
    "--policy-configmap-name",
    default=None,
    help="Default ConfigMap name mounted at /etc/agent-bom/policy.json inside injected sidecars.",
)
@click.option(
    "--tenant-label-key",
    default="agent-bom.io/tenant",
    show_default=True,
    help="Pod label or annotation key used to stamp tenant_id into injection audit records.",
)
@click.option(
    "--log-level",
    type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False),
    default="info",
    show_default=True,
)
def sidecar_injector_cmd(
    host: str,
    port: int,
    tls_cert_file: Path,
    tls_key_file: Path,
    proxy_image: str,
    control_plane_url: str,
    control_plane_token_secret_name: str,
    control_plane_token_secret_key: str,
    default_mcp_port: int,
    metrics_port: int,
    policy_refresh_seconds: int,
    audit_push_interval: int,
    detect_credentials: bool,
    block_undeclared: bool,
    policy_configmap_name: str | None,
    tenant_label_key: str,
    log_level: str,
) -> None:
    """Run the TLS admission webhook that auto-injects proxy sidecars."""
    try:
        import uvicorn
    except ImportError:
        click.echo(
            "ERROR: uvicorn is required for `agent-bom sidecar-injector`.\nInstall it with:  pip install 'agent-bom[api]'",
            err=True,
        )
        sys.exit(1)

    from agent_bom.sidecar_injector import SidecarInjectorSettings, create_sidecar_injector_app

    settings = SidecarInjectorSettings(
        proxy_image=proxy_image,
        control_plane_url=control_plane_url,
        control_plane_token_secret_name=control_plane_token_secret_name,
        control_plane_token_secret_key=control_plane_token_secret_key,
        default_mcp_port=max(default_mcp_port, 1),
        metrics_port=max(metrics_port, 1),
        policy_refresh_seconds=max(policy_refresh_seconds, 1),
        audit_push_interval=max(audit_push_interval, 1),
        detect_credentials=detect_credentials,
        block_undeclared=block_undeclared,
        policy_configmap_name=policy_configmap_name,
        tenant_label_key=tenant_label_key,
    )
    app = create_sidecar_injector_app(settings)
    click.echo(f"agent-bom sidecar injector serving on https://{host}:{port}")
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level.lower(),
        ssl_certfile=str(tls_cert_file),
        ssl_keyfile=str(tls_key_file),
    )
