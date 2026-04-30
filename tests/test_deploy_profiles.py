"""Tests for canonical Helm deployment validation profiles."""

from __future__ import annotations

import subprocess
from pathlib import Path

from agent_bom.deploy_profiles import build_helm_profile_command, helm_chart_dir, helm_validation_profiles


def test_helm_validation_profiles_reference_existing_chart_assets():
    repo_root = Path(__file__).resolve().parent.parent
    chart_dir = helm_chart_dir(repo_root)
    assert chart_dir.exists()
    profiles = helm_validation_profiles(repo_root)
    assert [profile.name for profile in profiles] == [
        "sqlite-pilot",
        "focused-pilot",
        "focused-pilot-byo-postgres",
        "production",
        "eks-vanilla",
        "mesh-hardening",
        "snowflake-backend",
        "gateway-runtime",
    ]
    for profile in profiles:
        for values_file in profile.values_files:
            assert values_file.exists(), f"{profile.name} missing values file {values_file}"
        for _key, file_path in profile.set_file_arguments:
            assert file_path.exists(), f"{profile.name} missing set-file input {file_path}"


def test_gateway_runtime_profile_uses_shipped_upstreams_example():
    repo_root = Path(__file__).resolve().parent.parent
    profiles = {profile.name: profile for profile in helm_validation_profiles(repo_root)}
    gateway = profiles["gateway-runtime"]
    assert gateway.set_arguments == ("gateway.enabled=true",)
    assert gateway.set_file_arguments == (
        ("gateway.upstreamsYaml", repo_root / "deploy" / "helm" / "agent-bom" / "examples" / "gateway-upstreams.example.yaml"),
    )


def test_postgres_secret_example_documents_byo_postgres_contract():
    repo_root = Path(__file__).resolve().parent.parent
    chart = repo_root / "deploy" / "helm" / "agent-bom" / "Chart.yaml"
    postgres_secret = repo_root / "deploy" / "helm" / "agent-bom" / "examples" / "postgres-secret.example.yaml"
    docs = repo_root / "site-docs" / "deployment" / "postgres-provisioning.md"

    assert "dependencies:" not in chart.read_text()
    assert "AGENT_BOM_POSTGRES_URL" in postgres_secret.read_text()
    byo_values = repo_root / "deploy" / "helm" / "agent-bom" / "examples" / "byo-postgres-values.yaml"
    byo_body = byo_values.read_text()
    assert "AGENT_BOM_POSTGRES_URL" in byo_body
    assert "Snowflake Postgres" in byo_body
    assert "smoke-test required" in byo_body
    docs_body = docs.read_text()
    assert "no Postgres subchart dependency" in docs_body
    assert "provision Postgres/RDS with your platform tooling" in docs_body


def test_build_helm_profile_command_uses_shipped_profile_stack():
    repo_root = Path(__file__).resolve().parent.parent
    cmd = build_helm_profile_command(repo_root, "focused-pilot")
    assert cmd[:6] == [
        "helm",
        "upgrade",
        "--install",
        "agent-bom",
        str(repo_root / "deploy" / "helm" / "agent-bom"),
        "--namespace",
    ]
    assert "agent-bom" in cmd
    assert "--create-namespace" in cmd
    assert str(repo_root / "deploy" / "helm" / "agent-bom" / "examples" / "eks-mcp-pilot-values.yaml") in cmd


def test_byo_postgres_profile_layers_focused_pilot_with_database_overlay():
    repo_root = Path(__file__).resolve().parent.parent
    cmd = build_helm_profile_command(repo_root, "focused-pilot-byo-postgres")
    assert str(repo_root / "deploy" / "helm" / "agent-bom" / "examples" / "eks-mcp-pilot-values.yaml") in cmd
    assert str(repo_root / "deploy" / "helm" / "agent-bom" / "examples" / "byo-postgres-values.yaml") in cmd


def test_install_helm_profile_script_prints_packaged_command():
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [
            "python3",
            "scripts/install_helm_profile.py",
            "focused-pilot",
            "--print-command",
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    stdout = result.stdout.strip()
    assert stdout.startswith("helm upgrade --install agent-bom ")
    assert "deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml" in stdout
