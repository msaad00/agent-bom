"""Non-secret secret-manager rotation adapter metadata.

These adapters intentionally do not generate, read, or write secret values.
They describe the operator-controlled rotation path for the configured
customer secret manager so posture endpoints can produce stable evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SecretRotationAdapter:
    """Describe one supported customer-secret-manager rotation path."""

    name: str
    tool: str
    aliases: tuple[str, ...]
    custody: str
    rotation_model: str
    command_template: str
    timestamp_template: str
    evidence: tuple[str, ...]

    def command(self, *, secret_name: str, source_env: str | None) -> str:
        label = source_env or secret_name
        return self.command_template.format(label=label, secret_name=secret_name)

    def timestamp_command(self, *, last_rotated_env: str) -> str:
        return self.timestamp_template.format(last_rotated_env=last_rotated_env)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tool": self.tool,
            "aliases": list(self.aliases),
            "custody": self.custody,
            "rotation_model": self.rotation_model,
            "secret_values_included": False,
            "evidence": list(self.evidence),
        }

    def rotation_step(
        self,
        *,
        secret_name: str,
        source_env: str | None,
        last_rotated_env: str,
    ) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "tool": self.tool,
            "custody": self.custody,
            "rotation_model": self.rotation_model,
            "secret_values_included": False,
            "command": self.command(secret_name=secret_name, source_env=source_env),
            "timestamp_command": self.timestamp_command(last_rotated_env=last_rotated_env),
            "evidence": list(self.evidence),
        }


_AWS = SecretRotationAdapter(
    name="aws_secrets_manager",
    tool="aws-secrets-manager",
    aliases=("aws_secrets_manager", "aws-secrets-manager", "aws", "secretsmanager"),
    custody="customer_aws_account",
    rotation_model="put-secret-value_then_rollout_restart",
    command_template=("aws secretsmanager put-secret-value --secret-id <secret-id-for-{label}> --secret-string file://<new-secret-file>"),
    timestamp_template=(
        "aws secretsmanager put-secret-value --secret-id <secret-id-for-{last_rotated_env}> --secret-string '<iso-8601-utc-timestamp>'"
    ),
    evidence=(
        "Secrets Manager version ID for the rotated secret",
        "CloudTrail PutSecretValue event ID",
        "Kubernetes rollout restart and rollout status output",
        "/v1/auth/secrets/lifecycle response after rotation",
    ),
)

_VAULT = SecretRotationAdapter(
    name="hashicorp_vault",
    tool="vault",
    aliases=("hashicorp_vault", "vault", "hashicorp-vault"),
    custody="customer_vault_cluster",
    rotation_model="kv_write_then_rollout_restart",
    command_template="vault kv put <mount/path/agent-bom> {label}=@<new-secret-file>",
    timestamp_template="vault kv put <mount/path/agent-bom> {last_rotated_env}=<iso-8601-utc-timestamp>",
    evidence=(
        "Vault write response or audit device request ID",
        "Vault secret version for the rotated key",
        "Kubernetes rollout restart and rollout status output",
        "/v1/auth/secrets/lifecycle response after rotation",
    ),
)

_EXTERNAL_SECRETS = SecretRotationAdapter(
    name="external_secrets",
    tool="external-secrets",
    aliases=("external_secrets", "external-secrets", "eso", "csi"),
    custody="customer_external_provider",
    rotation_model="rotate_upstream_provider_then_wait_for_secret_sync",
    command_template=(
        "rotate {label} in the upstream provider, then wait for External Secrets or CSI to refresh the mounted Kubernetes Secret"
    ),
    timestamp_template=(
        "set {last_rotated_env}=<iso-8601-utc-timestamp> in the upstream provider and wait for External Secrets or CSI sync"
    ),
    evidence=(
        "ExternalSecret or SecretProviderClass sync condition",
        "Kubernetes Secret resourceVersion after sync",
        "Kubernetes rollout restart and rollout status output",
        "/v1/auth/secrets/lifecycle response after rotation",
    ),
)

_KUBERNETES_SECRET = SecretRotationAdapter(
    name="kubernetes_secret",
    tool="kubectl",
    aliases=("kubernetes_secret", "kubernetes", "k8s", "k8s_secret"),
    custody="customer_kubernetes_secret",
    rotation_model="apply_secret_manifest_then_rollout_restart",
    command_template=(
        "kubectl create secret generic agent-bom-control-plane-auth "
        "--from-env-file=<rotated-env-file> -n agent-bom --dry-run=client -o yaml | kubectl apply -f -"
    ),
    timestamp_template=(
        "set {last_rotated_env}=<iso-8601-utc-timestamp> in <rotated-env-file>, then re-apply the Kubernetes Secret manifest"
    ),
    evidence=(
        "Kubernetes Secret resourceVersion after apply",
        "Kubernetes rollout restart and rollout status output",
        "/v1/auth/secrets/lifecycle response after rotation",
    ),
)

_GENERIC = SecretRotationAdapter(
    name="operator_secret_manager",
    tool="operator-secret-manager",
    aliases=("operator_secret_manager", "generic", "customer_secret_manager"),
    custody="customer_secret_manager",
    rotation_model="operator_controlled_secret_swap_then_rollout_restart",
    command_template="update {label} in the customer secret manager; do not put raw secret values in Git or Helm values",
    timestamp_template="record {last_rotated_env}=<iso-8601-utc-timestamp> next to the rotated secret metadata",
    evidence=(
        "customer change ticket or secret-manager audit event",
        "Kubernetes rollout restart and rollout status output",
        "/v1/auth/secrets/lifecycle response after rotation",
    ),
)

_ADAPTERS = (_AWS, _VAULT, _EXTERNAL_SECRETS, _KUBERNETES_SECRET, _GENERIC)
_BY_ALIAS = {alias: adapter for adapter in _ADAPTERS for alias in adapter.aliases}


def supported_secret_rotation_adapters() -> list[dict[str, Any]]:
    """Return the non-secret supported adapter catalog."""

    return [adapter.describe() for adapter in _ADAPTERS]


def resolve_secret_rotation_adapter(provider: str | None) -> SecretRotationAdapter:
    """Resolve a configured provider to a supported adapter."""

    normalized = (provider or "").strip().lower().replace("-", "_")
    return _BY_ALIAS.get(normalized, _GENERIC)
