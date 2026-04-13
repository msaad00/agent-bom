"""Cloud provenance normalization helpers."""

from __future__ import annotations

from typing import Any


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
