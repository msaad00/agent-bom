"""Deployment lifecycle helper commands."""

from __future__ import annotations

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
