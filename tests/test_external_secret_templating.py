"""The control-plane database URL must assemble without a manual step.

The EKS root wires an ExternalSecret that reads ``AGENT_BOM_POSTGRES_URL`` from
a Secrets Manager entry Terraform creates *empty*, so a documented
``terraform apply`` produced a control plane whose pre-install migration Job
had no database URL.

RDS manages the master password itself, and reading it in Terraform would put
a plaintext credential in state. Instead the chart lets an ExternalSecret
compose the URL from the AWS-managed secret's own fields, so the password
travels Secrets Manager to Kubernetes and never through Terraform.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

HELM_DIR = Path(__file__).parent.parent / "deploy" / "helm" / "agent-bom"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")

_TEMPLATED_SECRET = {
    "controlPlane": {
        "enabled": True,
        # This fixture verifies only ExternalSecret rendering. Postgres
        # migrations have their own contract tests and now require a distinct
        # migration/admin credential rather than inheriting the API secret.
        "migrations": {"enabled": False},
        # The API reference keeps this fixture representative of a consumer of
        # the rendered runtime secret.
        "api": {"envFrom": [{"secretRef": {"name": "abom-control-plane-db"}}]},
        "externalSecrets": {
            "enabled": True,
            "secretStoreRef": {"kind": "ClusterSecretStore", "name": "aws-secrets-manager"},
            "secrets": [
                {
                    "nameSuffix": "control-plane-db",
                    "target": {"name": "abom-control-plane-db"},
                    "template": {
                        "engineVersion": "v2",
                        "data": {
                            "AGENT_BOM_POSTGRES_URL": "postgresql://{{ .username }}:{{ .password }}@db.example:5432/agent_bom",
                        },
                    },
                    "data": [
                        {"secretKey": "username", "remoteRef": {"key": "rds!cluster-x", "property": "username"}},
                        {"secretKey": "password", "remoteRef": {"key": "rds!cluster-x", "property": "password"}},
                    ],
                }
            ],
        },
    }
}


def _render(values: dict) -> list[dict]:
    proc = subprocess.run(
        ["helm", "template", "abom", str(HELM_DIR), "--values", "-"],
        input=json.dumps(values),
        capture_output=True,
        text=True,
        check=True,
    )
    return [doc for doc in yaml.safe_load_all(proc.stdout) if doc]


def _render_result(values: dict) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "abom", str(HELM_DIR), "--values", "-"],
        input=json.dumps(values),
        capture_output=True,
        text=True,
        check=False,
    )


def _external_secrets(docs: list[dict]) -> list[dict]:
    return [doc for doc in docs if doc.get("kind") == "ExternalSecret"]


def _render_value_files(*value_files: Path) -> list[dict]:
    command = ["helm", "template", "agent-bom-secrets", str(HELM_DIR)]
    for value_file in value_files:
        command.extend(["--values", str(value_file)])
    proc = subprocess.run(command, capture_output=True, text=True, check=True)
    return [doc for doc in yaml.safe_load_all(proc.stdout) if doc]


def test_preinstall_migration_rejects_same_release_external_secret_sync() -> None:
    """A pre-install hook cannot depend on a normal resource in its release."""
    values = {
        "controlPlane": {
            "enabled": True,
            "api": {"envFrom": [{"secretRef": {"name": "abom-control-plane-db"}}]},
            "externalSecrets": {
                "enabled": True,
                "secretStoreRef": {"kind": "ClusterSecretStore", "name": "aws-secrets-manager"},
                "secrets": [
                    {
                        "nameSuffix": "control-plane-db",
                        "target": {"name": "abom-control-plane-db"},
                        "data": [
                            {
                                "secretKey": "AGENT_BOM_POSTGRES_URL",
                                "remoteRef": {"key": "agent-bom/db", "property": "url"},
                            }
                        ],
                    }
                ],
            },
            "migrations": {
                "envFrom": [{"secretRef": {"name": "abom-control-plane-db"}}],
            },
        }
    }

    result = _render_result(values)

    assert result.returncode != 0
    assert "separate secret-sync release" in result.stderr


def test_preupgrade_only_migration_also_rejects_same_release_external_secret_sync() -> None:
    """Changing hook phases must not reopen the normal-resource race."""
    values = {
        "controlPlane": {
            "enabled": True,
            "api": {"envFrom": [{"secretRef": {"name": "abom-control-plane-db"}}]},
            "externalSecrets": {
                "enabled": True,
                "secretStoreRef": {"kind": "ClusterSecretStore", "name": "aws-secrets-manager"},
                "secrets": [
                    {
                        "nameSuffix": "control-plane-db",
                        "target": {"name": "abom-control-plane-db"},
                        "data": [
                            {
                                "secretKey": "AGENT_BOM_POSTGRES_URL",
                                "remoteRef": {"key": "agent-bom/db", "property": "url"},
                            }
                        ],
                    }
                ],
            },
            "migrations": {
                "hooks": "pre-upgrade",
                "envFrom": [{"secretRef": {"name": "abom-control-plane-db"}}],
            },
        }
    }

    result = _render_result(values)

    assert result.returncode != 0
    assert "separate secret-sync release" in result.stderr


def test_external_secret_sync_only_renders_without_control_plane() -> None:
    """The first stage creates only ExternalSecret resources, never workloads."""
    values = {
        "scanner": {"enabled": False},
        "rbac": {"create": False},
        "serviceAccount": {"create": False},
        "networkPolicy": {"enabled": False},
        "teardownHooks": {"enabled": False},
        "controlPlane": {
            "enabled": False,
            "externalSecrets": {
                "enabled": True,
                "syncOnly": True,
                "secretStoreRef": {"kind": "ClusterSecretStore", "name": "aws-secrets-manager"},
                "secrets": [
                    {
                        "nameSuffix": "control-plane-db",
                        "target": {"name": "abom-control-plane-db"},
                        "data": [
                            {
                                "secretKey": "AGENT_BOM_POSTGRES_URL",
                                "remoteRef": {"key": "agent-bom/db", "property": "url"},
                            }
                        ],
                    }
                ],
            },
        },
    }

    docs = _render(values)

    assert [doc["kind"] for doc in docs] == ["ExternalSecret"]


def test_production_secret_sync_stage_renders_only_four_external_secrets() -> None:
    """The shipped bootstrap overlay cannot start workloads or migrations."""
    examples = HELM_DIR / "examples"

    docs = _render_value_files(
        examples / "eks-production-values.yaml",
        examples / "eks-production-secret-sync-values.yaml",
    )

    assert {doc["kind"] for doc in docs} == {"ExternalSecret"}
    assert {doc["spec"]["target"]["name"] for doc in docs} == {
        "agent-bom-control-plane-db",
        "agent-bom-control-plane-maintenance",
        "agent-bom-control-plane-admin",
        "agent-bom-control-plane-auth",
    }


def test_production_workload_stage_never_renders_external_secrets() -> None:
    """The migration release consumes pre-created Secrets from the sync stage."""
    docs = _render_value_files(HELM_DIR / "examples" / "eks-production-values.yaml")

    assert not _external_secrets(docs)
    assert any(
        doc.get("kind") == "Job" and doc.get("metadata", {}).get("name") == "agent-bom-postgres-migrate"
        for doc in docs
    )
    teardown_jobs = [
        doc
        for doc in docs
        if doc.get("kind") == "Job"
        and doc.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") == "teardown-hook"
    ]
    teardown_args = [
        arg
        for job in teardown_jobs
        for arg in job["spec"]["template"]["spec"]["containers"][0]["command"]
    ]
    assert "agent-bom-control-plane-db" not in teardown_args
    assert "agent-bom-control-plane-maintenance" not in teardown_args
    assert "agent-bom-control-plane-admin" not in teardown_args
    assert "agent-bom-control-plane-auth" not in teardown_args


def test_external_secret_renders_the_composed_url_template() -> None:
    """A templated secret must emit target.template.data, not just labels."""
    secrets = _external_secrets(_render(_TEMPLATED_SECRET))

    assert secrets, "no ExternalSecret rendered"
    template = secrets[0]["spec"]["target"]["template"]
    assert template["engineVersion"] == "v2"
    assert "AGENT_BOM_POSTGRES_URL" in template["data"]
    assert "{{ .username }}" in template["data"]["AGENT_BOM_POSTGRES_URL"]


def test_composed_secret_pulls_both_credential_fields() -> None:
    """Both halves of the credential must be requested from the managed secret."""
    secrets = _external_secrets(_render(_TEMPLATED_SECRET))

    keys = {entry["secretKey"] for entry in secrets[0]["spec"]["data"]}
    assert keys == {"username", "password"}


def test_untemplated_secret_keeps_working() -> None:
    """Secrets that map a stored value directly must be unaffected."""
    values = {
        "controlPlane": {
            "enabled": True,
            "migrations": {"enabled": False},
            "api": {"envFrom": [{"secretRef": {"name": "abom-control-plane-db"}}]},
            "externalSecrets": {
                "enabled": True,
                "secretStoreRef": {"kind": "ClusterSecretStore", "name": "aws-secrets-manager"},
                "secrets": [
                    {
                        "nameSuffix": "control-plane-auth",
                        "target": {"name": "abom-control-plane-auth"},
                        "data": [
                            {
                                "secretKey": "AGENT_BOM_OIDC_ISSUER",
                                "remoteRef": {"key": "agent-bom/auth", "property": "OIDC_ISSUER"},
                            }
                        ],
                    }
                ],
            },
        }
    }

    secrets = _external_secrets(_render(values))

    assert secrets[0]["spec"]["data"][0]["secretKey"] == "AGENT_BOM_OIDC_ISSUER"
    # No template data means ExternalSecrets copies the stored value verbatim.
    assert "data" not in secrets[0]["spec"]["target"].get("template", {})
