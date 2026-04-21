"""Canonical Helm chart validation profiles for shipped deployment examples."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class HelmValidationProfile:
    """A named Helm render profile backed by shipped chart examples."""

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
    """Return the canonical validation matrix for shipped Helm examples."""

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
