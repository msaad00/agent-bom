"""Helpers for tearing down the self-hosted AWS/EKS reference install."""

from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STATE_DIR = Path.home() / ".agent-bom" / "eks-reference"
PLATFORM_OWNED_SURFACES = (
    "EKS cluster and node groups",
    "VPC, subnets, route tables, and security baselines",
    "Ingress controller, DNS, and TLS/cert-manager",
    "Shared controllers such as ExternalSecrets and OTLP collectors",
)


@dataclass(frozen=True)
class CommandStep:
    label: str
    command: tuple[str, ...]
    required: bool = True
    timeout_seconds: int = 600


@dataclass(frozen=True)
class TeardownPlan:
    cluster_name: str
    region: str
    namespace: str
    release_name: str
    state_root: Path
    terraform_root: Path
    generated_dir: Path
    summary_path: Path
    helm_uninstall: CommandStep | None
    helm_wait: CommandStep | None
    namespace_delete: CommandStep | None
    terraform_destroy: CommandStep | None
    local_state_delete: CommandStep | None
    platform_owned_surfaces: tuple[str, ...]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_terraform_bin() -> str | None:
    return shutil.which("terraform") or shutil.which("tofu")


def build_reference_teardown_plan(
    *,
    cluster_name: str,
    region: str,
    namespace: str,
    release_name: str,
    state_dir: Path = DEFAULT_STATE_DIR,
    delete_namespace: bool = False,
    delete_local_state: bool = False,
    skip_helm_uninstall: bool = False,
    skip_terraform_destroy: bool = False,
    wait_timeout_seconds: int = 180,
    terraform_bin: str | None = None,
) -> TeardownPlan:
    """Build a teardown plan for the AWS/EKS reference deployment."""

    state_root = state_dir / cluster_name
    terraform_root = state_root / "terraform"
    generated_dir = state_root / "generated"
    summary_path = generated_dir / "teardown-summary.txt"

    helm_uninstall = None
    helm_wait = None
    namespace_delete_step = None
    terraform_destroy = None
    local_state_delete_step = None

    if not skip_helm_uninstall:
        helm_uninstall = CommandStep(
            label="Uninstall the Helm release",
            command=("helm", "uninstall", release_name, "--namespace", namespace),
        )
        helm_wait = CommandStep(
            label="Wait for pods and jobs in the namespace to disappear",
            command=(
                "kubectl",
                "wait",
                "--for=delete",
                "pod,job",
                "--all",
                "--namespace",
                namespace,
                f"--timeout={max(1, wait_timeout_seconds)}s",
            ),
            required=False,
            timeout_seconds=max(1, wait_timeout_seconds) + 30,
        )
        if delete_namespace:
            namespace_delete_step = CommandStep(
                label="Delete the dedicated namespace after Helm resources are gone",
                command=("kubectl", "delete", "namespace", namespace, "--ignore-not-found=true"),
                required=False,
                timeout_seconds=600,
            )

    if not skip_terraform_destroy:
        terraform_exec = terraform_bin or "terraform"
        terraform_destroy = CommandStep(
            label="Destroy the product-owned AWS baseline",
            command=(terraform_exec, f"-chdir={terraform_root}", "destroy", "-auto-approve"),
            required=True,
            timeout_seconds=3600,
        )

    if delete_local_state:
        local_state_delete_step = CommandStep(
            label="Delete the local generated state and summaries",
            command=("rm", "-rf", str(state_root)),
            required=False,
            timeout_seconds=300,
        )

    return TeardownPlan(
        cluster_name=cluster_name,
        region=region,
        namespace=namespace,
        release_name=release_name,
        state_root=state_root,
        terraform_root=terraform_root,
        generated_dir=generated_dir,
        summary_path=summary_path,
        helm_uninstall=helm_uninstall,
        helm_wait=helm_wait,
        namespace_delete=namespace_delete_step,
        terraform_destroy=terraform_destroy,
        local_state_delete=local_state_delete_step,
        platform_owned_surfaces=PLATFORM_OWNED_SURFACES,
    )


def _format_step(step: CommandStep | None) -> list[str]:
    if step is None:
        return []
    rendered = shlex.join(step.command)
    suffix = "" if step.required else " (best effort)"
    return [f"- {step.label}{suffix}", f"  {rendered}"]


def format_teardown_plan(plan: TeardownPlan) -> str:
    """Render the teardown plan for operators."""

    lines = [
        "agent-bom teardown plan",
        "",
        f"cluster: {plan.cluster_name}",
        f"region: {plan.region}",
        f"namespace: {plan.namespace}",
        f"release: {plan.release_name}",
        f"terraform dir: {plan.terraform_root}",
        f"summary: {plan.summary_path}",
        "",
        "Will remove:",
    ]
    for step in (
        plan.helm_uninstall,
        plan.helm_wait,
        plan.namespace_delete,
        plan.terraform_destroy,
        plan.local_state_delete,
    ):
        lines.extend(_format_step(step))
    lines.extend(
        [
            "",
            "Platform-owned surfaces left untouched:",
        ]
    )
    for item in plan.platform_owned_surfaces:
        lines.append(f"- {item}")
    return "\n".join(lines)


def validate_teardown_plan(plan: TeardownPlan, *, dry_run: bool = False) -> list[str]:
    """Return a list of plan validation errors."""

    errors: list[str] = []
    if not dry_run:
        if plan.helm_uninstall is not None and shutil.which("helm") is None:
            errors.append("helm is required to uninstall the release")
        if (plan.helm_wait is not None or plan.namespace_delete is not None) and shutil.which("kubectl") is None:
            errors.append("kubectl is required for namespace wait/delete operations")
        if plan.terraform_destroy is not None:
            terraform_exec = plan.terraform_destroy.command[0]
            if shutil.which(terraform_exec) is None:
                errors.append(f"{terraform_exec} is required to destroy the AWS baseline")
            if not plan.terraform_root.exists():
                errors.append(f"terraform root does not exist: {plan.terraform_root}")
    return errors


def _run_step(step: CommandStep, *, dry_run: bool) -> None:
    if dry_run:
        sys.stdout.write(f"+ {shlex.join(step.command)}\n")
        return
    subprocess.run(step.command, check=step.required, timeout=step.timeout_seconds)


def execute_teardown_plan(plan: TeardownPlan, *, dry_run: bool = False) -> str:
    """Execute or print the teardown plan and return the rendered summary."""

    summary = format_teardown_plan(plan)
    plan.generated_dir.mkdir(parents=True, exist_ok=True)
    plan.summary_path.write_text(summary + "\n", encoding="utf-8")
    for step in (
        plan.helm_uninstall,
        plan.helm_wait,
        plan.namespace_delete,
        plan.terraform_destroy,
        plan.local_state_delete,
    ):
        if step is not None:
            _run_step(step, dry_run=dry_run)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-name", default="agent-bom", help="EKS cluster name (used to resolve local state)")
    parser.add_argument("--region", default="us-east-1", help="AWS region for operator context (summary only)")
    parser.add_argument("--namespace", default="agent-bom", help="Kubernetes namespace containing the release")
    parser.add_argument("--release", default="agent-bom", help="Helm release name")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR, help="Local state root used by the reference installer")
    parser.add_argument("--delete-namespace", action="store_true", help="Delete the namespace after Helm uninstall")
    parser.add_argument("--delete-local-state", action="store_true", help="Delete local generated state after teardown")
    parser.add_argument("--skip-helm-uninstall", action="store_true", help="Skip the Helm uninstall phase")
    parser.add_argument("--skip-terraform-destroy", action="store_true", help="Skip the Terraform destroy phase")
    parser.add_argument("--wait-timeout-seconds", type=int, default=180, help="How long kubectl wait should block")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan and commands without running them")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    plan = build_reference_teardown_plan(
        cluster_name=args.cluster_name,
        region=args.region,
        namespace=args.namespace,
        release_name=args.release,
        state_dir=args.state_dir,
        delete_namespace=args.delete_namespace,
        delete_local_state=args.delete_local_state,
        skip_helm_uninstall=args.skip_helm_uninstall,
        skip_terraform_destroy=args.skip_terraform_destroy,
        wait_timeout_seconds=args.wait_timeout_seconds,
        terraform_bin=resolve_terraform_bin(),
    )
    errors = validate_teardown_plan(plan, dry_run=args.dry_run)
    if errors:
        for error in errors:
            sys.stderr.write(f"error: {error}\n")
        return 1
    sys.stdout.write(f"{format_teardown_plan(plan)}\n")
    execute_teardown_plan(plan, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
