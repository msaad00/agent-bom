"""Cloud provenance normalization helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.security import sanitize_error, sanitize_text

_LIFECYCLE_STATE_MAPS: dict[tuple[str, str, str], dict[str, str]] = {
    ("aws", "bedrock", "agent"): {
        "PREPARED": "prepared",
        "NOT_PREPARED": "not-prepared",
    },
    ("databricks", "clusters", "cluster"): {
        "RUNNING": "running",
        "RESIZING": "resizing",
        "RESTARTING": "restarting",
        "TERMINATED": "terminated",
    },
    ("databricks", "model-serving", "serving-endpoint"): {
        "READY": "ready",
        "NOT_READY": "not-ready",
    },
}


def normalize_cloud_lifecycle_state(
    *,
    provider: str,
    service: str,
    resource_type: str,
    raw_state: Any,
) -> str | None:
    """Map raw provider lifecycle values to canonical states.

    Returns ``None`` when a source value is not part of the verified mapping.
    That lets discovery code skip unknown states until the mapping is reviewed
    and explicitly added, instead of silently guessing.
    """
    if raw_state in ("", None):
        return None
    mapping = _LIFECYCLE_STATE_MAPS.get((provider, service, resource_type), {})
    return mapping.get(str(raw_state).strip().upper())


def build_cloud_origin(
    *,
    provider: str,
    service: str,
    resource_type: str,
    resource_id: str,
    resource_name: str,
    location: str | None = None,
    account_id: str | None = None,
    subscription_id: str | None = None,
    project_id: str | None = None,
    raw_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a stable cloud-origin envelope for discovered assets.

    The envelope keeps the low-risk identifying fields needed to validate
    provider mappings without dragging full vendor payloads through the core
    product model.
    """
    scope: dict[str, str] = {}
    if account_id:
        scope["account_id"] = account_id
    if subscription_id:
        scope["subscription_id"] = subscription_id
    if project_id:
        scope["project_id"] = project_id

    envelope: dict[str, Any] = {
        "normalization_version": "1",
        "provider": provider,
        "service": service,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_name": resource_name,
    }
    if location:
        envelope["location"] = location
    if scope:
        envelope["scope"] = scope
    if raw_identity:
        envelope["raw_identity"] = {
            key: value for key, value in raw_identity.items() if isinstance(value, (str, int, float, bool)) and value not in ("", None)
        }
    return envelope


def sanitize_discovery_warning(value: Any, *, max_len: int = 500) -> str:
    """Return warning text that is safe to persist or render.

    Cloud and SaaS SDK exceptions often embed request URLs, local paths, or
    credential-like fragments. Discovery warnings are user-facing diagnostics,
    so normalize them through the same redaction path before they leave a
    provider or connector boundary.
    """
    return sanitize_text(sanitize_error(str(value)), max_len=max_len)


def sanitize_discovery_warnings(values: list[Any] | tuple[Any, ...]) -> list[str]:
    """Sanitize a provider/connector warning list."""
    return [sanitize_discovery_warning(value) for value in values if str(value or "").strip()]


def build_cloud_state(
    *,
    provider: str,
    service: str,
    resource_type: str,
    lifecycle_state: str,
    raw_state: str | None = None,
    state_source: str | None = None,
) -> dict[str, Any]:
    """Return a stable cloud-state envelope for provider lifecycle metadata.

    Only use this when the provider exposes a real lifecycle/status field that
    can be normalized without guesswork.
    """
    envelope: dict[str, Any] = {
        "normalization_version": "1",
        "provider": provider,
        "service": service,
        "resource_type": resource_type,
        "lifecycle_state": lifecycle_state,
    }
    if raw_state:
        envelope["raw_state"] = raw_state
    if state_source:
        envelope["state_source"] = state_source
    return envelope


def _normalize_timestamp(value: Any) -> str | None:
    """Normalize provider timestamps into UTC ISO-8601 strings."""
    if value in ("", None):
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        else:
            value = value.astimezone(timezone.utc)
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            return candidate
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    return str(value)


def build_cloud_timestamps(
    *,
    provider: str,
    service: str,
    resource_type: str,
    created_at: Any = None,
    updated_at: Any = None,
    created_source: str | None = None,
    updated_source: str | None = None,
) -> dict[str, Any] | None:
    """Return a stable cloud-timestamps envelope when provider timestamps exist."""
    created = _normalize_timestamp(created_at)
    updated = _normalize_timestamp(updated_at)
    if not created and not updated:
        return None
    envelope: dict[str, Any] = {
        "normalization_version": "1",
        "provider": provider,
        "service": service,
        "resource_type": resource_type,
    }
    if created:
        envelope["created_at"] = created
    if updated:
        envelope["updated_at"] = updated
    sources: dict[str, str] = {}
    if created and created_source:
        sources["created_at"] = created_source
    if updated and updated_source:
        sources["updated_at"] = updated_source
    if sources:
        envelope["sources"] = sources
    return envelope


def build_cloud_principal(
    *,
    provider: str,
    service: str,
    resource_type: str,
    principal_type: str,
    principal_id: str | None = None,
    principal_name: str | None = None,
    tenant_id: str | None = None,
    source_field: str | None = None,
    raw_identity: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a stable execution-principal envelope for discovered resources.

    This models the workload identity attached to the resource itself. It does
    not attempt to infer an actor or event initiator from inventory APIs.
    """
    if not principal_id and not principal_name:
        return None
    envelope: dict[str, Any] = {
        "normalization_version": "1",
        "provider": provider,
        "service": service,
        "resource_type": resource_type,
        "principal_type": principal_type,
    }
    if principal_id:
        envelope["principal_id"] = principal_id
    if principal_name:
        envelope["principal_name"] = principal_name
    if tenant_id:
        envelope["tenant_id"] = tenant_id
    if source_field:
        envelope["source_field"] = source_field
    if raw_identity:
        envelope["raw_identity"] = {
            key: value for key, value in raw_identity.items() if isinstance(value, (str, int, float, bool)) and value not in ("", None)
        }
    return envelope


def build_cloud_scope(
    *,
    provider: str,
    service: str,
    resource_type: str,
    scope_type: str,
    scope_id: str,
    scope_name: str | None = None,
    parent_scope_type: str | None = None,
    parent_scope_id: str | None = None,
    parent_scope_name: str | None = None,
    location: str | None = None,
    source_fields: list[str] | None = None,
) -> dict[str, Any] | None:
    """Return a stable scope/ownership envelope for discovered resources.

    This models where a resource lives in provider hierarchy, for example a
    resource group inside a subscription or a service inside a project.
    """
    if not scope_id:
        return None
    envelope: dict[str, Any] = {
        "normalization_version": "1",
        "provider": provider,
        "service": service,
        "resource_type": resource_type,
        "scope_type": scope_type,
        "scope_id": scope_id,
    }
    if scope_name:
        envelope["scope_name"] = scope_name
    if parent_scope_type and parent_scope_id:
        envelope["parent_scope"] = {
            "type": parent_scope_type,
            "id": parent_scope_id,
        }
        if parent_scope_name:
            envelope["parent_scope"]["name"] = parent_scope_name
    if location:
        envelope["location"] = location
    if source_fields:
        envelope["source_fields"] = [field for field in source_fields if field]
    return envelope
