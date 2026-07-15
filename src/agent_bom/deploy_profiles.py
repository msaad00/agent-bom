"""Canonical Helm chart profiles for shipped deployment examples."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class HelmValidationProfile:
    """A named Helm profile backed by shipped chart examples."""

    name: str
    description: str
    values_files: tuple[Path, ...] = field(default_factory=tuple)
    set_arguments: tuple[str, ...] = field(default_factory=tuple)
    set_file_arguments: tuple[tuple[str, Path], ...] = field(default_factory=tuple)


def helm_chart_dir(repo_root: Path) -> Path:
    return repo_root / "deploy" / "helm" / "agent-bom"


def helm_example_dir(repo_root: Path) -> Path:
    return helm_chart_dir(repo_root) / "examples"


def ingress_hosts_missing_paths(rendered: str) -> list[str]:
    """Return ``host`` values whose rendered Ingress rule carries no HTTP paths.

    A rule that renders ``http.paths`` as ``null``/empty is an invalid Ingress: it
    binds a hostname but routes nowhere. This guards against example values files
    that override ``ingress.hosts`` without carrying ``apiPaths``/``uiPaths`` — a
    render that exits 0 yet produces an ingress that cannot route traffic.
    """

    offenders: list[str] = []
    for document in rendered.split("\n---"):
        if "kind: Ingress" not in document:
            continue

        manifest = None
        try:
            import yaml

            manifest = yaml.safe_load(document)
        except Exception:
            manifest = None

        if isinstance(manifest, dict):
            rules = (manifest.get("spec") or {}).get("rules") or []
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                paths = ((rule.get("http") or {}).get("paths")) or []
                if not paths:
                    offenders.append(str(rule.get("host", "<no-host>")))
            continue

        # Fallback text scan when PyYAML is unavailable (bare CI python): every
        # rendered ``paths:`` line must be immediately followed by a ``- path:``
        # list item, otherwise the rule routes nowhere.
        lines = document.splitlines()
        current_host = "<no-host>"
        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("host:"):
                current_host = stripped.split("host:", 1)[1].strip().strip('"')
            if stripped == "paths:":
                following = next(
                    (nxt.strip() for nxt in lines[index + 1 :] if nxt.strip()),
                    "",
                )
                if not following.startswith("- path:"):
                    offenders.append(current_host)
    return offenders


def helm_validation_profiles(repo_root: Path) -> list[HelmValidationProfile]:
    """Return the canonical shipped Helm profile matrix."""

    examples = helm_example_dir(repo_root)
    return [
        HelmValidationProfile(
            name="scanner-only",
            description="Default scanner-only render (controlPlane.enabled=false).",
        ),
        HelmValidationProfile(
            name="sqlite-pilot",
            description="Single-node SQLite demo control plane for fast packaged pilots.",
            values_files=(examples / "eks-control-plane-sqlite-pilot-values.yaml",),
        ),
        HelmValidationProfile(
            name="focused-pilot",
            description="Focused EKS pilot with control plane, scanner, and narrowed ingress.",
            values_files=(examples / "eks-mcp-pilot-values.yaml",),
        ),
        HelmValidationProfile(
            name="enterprise-demo",
            description="Focused EKS pilot with scheduled AWS estate inventory via IRSA.",
            values_files=(
                examples / "eks-mcp-pilot-values.yaml",
                examples / "eks-enterprise-demo-overlay.yaml",
            ),
        ),
        HelmValidationProfile(
            name="focused-pilot-byo-postgres",
            description="Focused EKS pilot plus operator-owned Postgres-compatible control-plane database.",
            values_files=(
                examples / "eks-mcp-pilot-values.yaml",
                examples / "byo-postgres-values.yaml",
            ),
        ),
        HelmValidationProfile(
            name="production",
            description="Postgres-backed production EKS defaults with autoscaling and backups.",
            values_files=(examples / "eks-production-values.yaml",),
        ),
        HelmValidationProfile(
            name="keda-autoscaling",
            description="Production EKS defaults with KEDA-backed API and gateway autoscaling.",
            values_files=(
                examples / "eks-production-values.yaml",
                examples / "eks-keda-values.yaml",
            ),
            set_arguments=("gateway.enabled=true",),
            set_file_arguments=(("gateway.upstreamsYaml", examples / "gateway-upstreams.example.yaml"),),
        ),
        HelmValidationProfile(
            name="eks-vanilla",
            description="Production EKS profile using ALB, IRSA, Kubernetes Secrets, and RDS/Postgres.",
            values_files=(examples / "eks-vanilla-values.yaml",),
        ),
        HelmValidationProfile(
            name="mesh-hardening",
            description="Istio and Kyverno hardening overlay for operator-managed clusters.",
            values_files=(examples / "eks-istio-kyverno-values.yaml",),
        ),
        HelmValidationProfile(
            name="snowflake-backend",
            description="Warehouse export/backend overlay for Snowflake-integrated deployments.",
            values_files=(examples / "eks-snowflake-values.yaml",),
        ),
        HelmValidationProfile(
            name="gateway-runtime",
            description="Focused pilot plus central gateway rendering with shipped upstream example.",
            values_files=(examples / "eks-mcp-pilot-values.yaml",),
            set_arguments=("gateway.enabled=true",),
            set_file_arguments=(("gateway.upstreamsYaml", examples / "gateway-upstreams.example.yaml"),),
        ),
    ]


def build_helm_profile_command(
    repo_root: Path,
    profile_name: str,
    *,
    release_name: str = "agent-bom",
    namespace: str = "agent-bom",
    create_namespace: bool = True,
    extra_values_files: tuple[Path, ...] = (),
    extra_set_arguments: tuple[str, ...] = (),
    extra_set_file_arguments: tuple[tuple[str, Path], ...] = (),
) -> list[str]:
    """Build the canonical Helm upgrade/install command for a shipped profile."""

    profiles = {profile.name: profile for profile in helm_validation_profiles(repo_root)}
    try:
        profile = profiles[profile_name]
    except KeyError as exc:
        available = ", ".join(sorted(profiles))
        raise KeyError(f"unknown Helm profile '{profile_name}' (available: {available})") from exc

    cmd = [
        "helm",
        "upgrade",
        "--install",
        release_name,
        str(helm_chart_dir(repo_root)),
        "--namespace",
        namespace,
    ]
    if create_namespace:
        cmd.append("--create-namespace")

    for values_file in (*profile.values_files, *extra_values_files):
        cmd.extend(["-f", str(values_file)])
    for set_argument in (*profile.set_arguments, *extra_set_arguments):
        cmd.extend(["--set", set_argument])
    for key, path in (*profile.set_file_arguments, *extra_set_file_arguments):
        cmd.extend(["--set-file", f"{key}={path}"])
    return cmd
