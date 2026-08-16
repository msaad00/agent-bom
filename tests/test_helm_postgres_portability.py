"""Contracts for provider-neutral Postgres Helm deployment verification."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
HELM_DIR = REPO_ROOT / "deploy" / "helm" / "agent-bom"


def _render(*args: str) -> list[dict]:
    result = subprocess.run(
        ["helm", "template", "agent-bom", str(HELM_DIR), *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [doc for doc in yaml.safe_load_all(result.stdout) if isinstance(doc, dict)]


def _component(docs: list[dict], *, kind: str, component: str) -> dict:
    return next(
        doc
        for doc in docs
        if doc.get("kind") == kind and doc.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") == component
    )


def test_chart_defaults_define_postgres_provider_and_verification_contract() -> None:
    values = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    postgres = values["controlPlane"]["postgres"]

    assert postgres["provider"] == "auto"
    assert postgres["verification"] == {
        "enabled": True,
        "hooks": "post-install,post-upgrade",
        "hookWeight": "10",
        "deletePolicy": "before-hook-creation",
        "backoffLimit": 0,
        "ttlSecondsAfterFinished": 600,
        "resources": {
            "requests": {"cpu": "25m", "memory": "64Mi"},
            "limits": {"cpu": "200m", "memory": "256Mi"},
        },
    }


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not available")
def test_byo_postgres_render_injects_provider_and_fails_closed_verification() -> None:
    docs = _render(
        "--values",
        str(HELM_DIR / "examples" / "eks-mcp-pilot-values.yaml"),
        "--values",
        str(HELM_DIR / "examples" / "byo-postgres-values.yaml"),
        "--set",
        "controlPlane.postgres.provider=snowflake-pg",
    )
    api = _component(docs, kind="Deployment", component="api")
    verification = _component(docs, kind="Job", component="postgres-verification")

    api_env = {entry["name"]: entry for entry in api["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert api_env["AGENT_BOM_POSTGRES_PROVIDER"]["value"] == "snowflake-pg"

    annotations = verification["metadata"]["annotations"]
    assert annotations["helm.sh/hook"] == "post-install,post-upgrade"
    assert annotations["helm.sh/hook-weight"] == "10"

    container = verification["spec"]["template"]["spec"]["containers"][0]
    env = {entry["name"]: entry for entry in container["env"]}
    assert env["AGENT_BOM_POSTGRES_PROVIDER"]["value"] == "snowflake-pg"
    assert env["AGENT_BOM_POSTGRES_URL"]["valueFrom"]["secretKeyRef"]["name"] == "agent-bom-control-plane-db"
    assert env["AGENT_BOM_POSTGRES_MAINTENANCE_URL"]["valueFrom"]["secretKeyRef"]["name"] == "agent-bom-control-plane-maintenance"
    assert "ALEMBIC_DATABASE_URL" not in env

    command = "\n".join([*container.get("command", []), *container.get("args", [])])
    assert "probe_postgres_portability" in command
    assert 'result.status == "ready"' in command
    assert "result.to_dict()" in command


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not available")
def test_sqlite_pilot_does_not_render_postgres_verification() -> None:
    docs = _render("--values", str(HELM_DIR / "examples" / "eks-control-plane-sqlite-pilot-values.yaml"))
    components = {doc.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") for doc in docs if doc.get("kind") == "Job"}
    assert "postgres-verification" not in components


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not available")
def test_chart_rejects_provider_override_when_canonical_postgres_wiring_is_enabled() -> None:
    result = subprocess.run(
        [
            "helm",
            "template",
            "agent-bom",
            str(HELM_DIR),
            "--values",
            str(HELM_DIR / "examples" / "eks-mcp-pilot-values.yaml"),
            "--set",
            "controlPlane.api.env[0].name=AGENT_BOM_POSTGRES_PROVIDER",
            "--set",
            "controlPlane.api.env[0].value=other",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "cannot override canonical Postgres" in result.stderr


def test_byo_postgres_example_documents_provider_hint_and_live_verification() -> None:
    body = (HELM_DIR / "examples" / "byo-postgres-values.yaml").read_text()

    assert "controlPlane.postgres.provider" in body
    assert "agent-bom doctor" in body
    assert "postgres-verification" in body
    assert "compatible_unverified" in body


def test_packaged_postgres_secret_examples_require_tls() -> None:
    documents = [
        doc for doc in yaml.safe_load_all((HELM_DIR / "examples" / "postgres-secret.example.yaml").read_text()) if isinstance(doc, dict)
    ]
    database_urls = [
        value
        for document in documents
        for key, value in (document.get("stringData") or {}).items()
        if key in {"AGENT_BOM_POSTGRES_URL", "AGENT_BOM_POSTGRES_MAINTENANCE_URL", "ALEMBIC_DATABASE_URL"}
    ]

    assert len(database_urls) == 3
    assert all("sslmode=require" in url for url in database_urls)
