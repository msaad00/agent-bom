"""Explicit, tenant-bound workload credential adapters for stored connections.

Only operators configure token files and trust audiences. API callers select an
opaque binding, which is revalidated on every use; there is no ambient fallback.
Provider token exchanges verify trust. Parsing configuration is not proof of
successful authentication or of read-only IAM grants.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.cloud.connection_broker import ConnectionBrokerError

_MODES = {"azure": {"managed_identity", "workload_identity"}, "gcp": {"workload_identity"}}
_READ_ONLY = "https://www.googleapis.com/auth/cloud-platform.read-only"


class WorkloadBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tenant_id: str
    provider: Literal["azure", "gcp"]
    auth_mode: Literal["managed_identity", "workload_identity"]
    role_ref: str
    scope_id: str
    inventory_scope: Literal["account", "organization"] = "account"
    directory_tenant_id: str = ""
    token_file_path: str = ""
    audience: str = ""
    enabled: bool = True
    expires_at: str


def supported_workload_modes() -> dict[str, list[str]]:
    """Supported adapters only; this does not advertise any tenant's bindings."""
    return {provider: sorted(modes) for provider, modes in _MODES.items()}


def workload_mode(provider: str, params: dict[str, Any]) -> str:
    """Absent mode means legacy; an explicit unknown mode never falls back."""
    mode = str(params.get("auth_mode") or "")
    if mode and mode not in _MODES.get(provider, set()):
        raise ConnectionBrokerError("Unsupported connection authentication mode.")
    if not mode and params.get("credential_binding"):
        raise ConnectionBrokerError("Connection binding requires a workload authentication mode.")
    return mode


def resolve_binding(record: CloudConnectionRecord) -> WorkloadBinding:
    """Resolve fresh operator configuration and check every delegated boundary."""
    try:
        mode = workload_mode(record.provider, record.auth_params)
        ref = record.auth_params.get("credential_binding")
        configured = os.environ.get("AGENT_BOM_CONNECTION_WORKLOAD_BINDINGS_FILE", "")
        if not mode or not isinstance(ref, str) or not ref or not configured or record.external_id_encrypted:
            raise ValueError("invalid workload configuration")
        with Path(configured).open("rb") as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("oversize workload configuration")
        document = json.loads(raw)
        binding = WorkloadBinding.model_validate(document["bindings"][ref])
        expires = datetime.fromisoformat(binding.expires_at.replace("Z", "+00:00"))
        scope_key = "subscription_id" if record.provider == "azure" else "project_id"
        if (
            not binding.enabled
            or expires.tzinfo is None
            or expires <= datetime.now(timezone.utc)
            or binding.tenant_id != record.tenant_id
            or binding.provider != record.provider
            or binding.auth_mode != mode
            or binding.role_ref != record.role_ref
            or not binding.scope_id
            or binding.scope_id != record.auth_params.get(scope_key)
            or binding.inventory_scope != record.inventory_scope
        ):
            raise ValueError("workload binding mismatch")
        if record.provider == "azure":
            if (
                not binding.directory_tenant_id
                or binding.directory_tenant_id != record.auth_params.get("tenant_id")
                or not binding.role_ref
            ):
                raise ValueError("directory mismatch")
            if binding.audience:
                raise ValueError("unexpected Azure audience")
        elif not re.fullmatch(
            r"//iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[^/]+/providers/[^/]+", binding.audience
        ) or not re.fullmatch(r"[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com", binding.role_ref):
            raise ValueError("invalid Google trust target")
        if mode == "workload_identity" and not Path(binding.token_file_path).is_absolute():
            raise ValueError("workload token file must be operator configured")
        return binding
    except Exception as exc:
        raise ConnectionBrokerError("Workload connection binding is unavailable or does not match the connection.") from exc


def broker_workload(record: CloudConnectionRecord) -> Any:
    binding = resolve_binding(record)
    try:
        if binding.provider == "azure":
            if binding.auth_mode == "managed_identity":
                from azure.identity import ManagedIdentityCredential

                return ManagedIdentityCredential(client_id=binding.role_ref)
            from azure.identity import WorkloadIdentityCredential

            return WorkloadIdentityCredential(
                tenant_id=binding.directory_tenant_id, client_id=binding.role_ref, token_file_path=binding.token_file_path
            )
        from google.auth import identity_pool, impersonated_credentials

        source = identity_pool.Credentials(
            audience=binding.audience,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            token_url="https://sts.googleapis.com/v1/token",
            credential_source={"file": binding.token_file_path},
            scopes=["https://www.googleapis.com/auth/iam"],
        )
        return impersonated_credentials.Credentials(
            source_credentials=source, target_principal=binding.role_ref, target_scopes=[_READ_ONLY], lifetime=3600
        )
    except Exception as exc:
        raise ConnectionBrokerError("Workload credential could not be constructed.") from exc
