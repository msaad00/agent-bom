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


def helm_validation_profiles(repo_root: Path) -> list[HelmValidationProfile]:
    """Return the canonical shipped Helm profile matrix."""

    examples = helm_example_dir(repo_root)
    return [
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
            name="production",
            description="Postgres-backed production EKS defaults with autoscaling and backups.",
            values_files=(examples / "eks-production-values.yaml",),
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
