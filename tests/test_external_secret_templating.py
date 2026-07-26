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
        # The chart refuses to render migrations without a database URL source.
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


def _external_secrets(docs: list[dict]) -> list[dict]:
    return [doc for doc in docs if doc.get("kind") == "ExternalSecret"]


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
