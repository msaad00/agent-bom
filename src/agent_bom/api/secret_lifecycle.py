"""Operator-facing secret lifecycle posture for enterprise deployments."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.secret_rotation_adapters import (
    resolve_secret_rotation_adapter,
    supported_secret_rotation_adapters,
)


def _env_enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        parsed = int(raw)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _configured_api_replicas() -> int:
    raw = os.environ.get("AGENT_BOM_CONTROL_PLANE_REPLICAS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


def _browser_signing_key_required() -> bool:
    return _configured_api_replicas() > 1 or _env_enabled("AGENT_BOM_REQUIRE_BROWSER_SESSION_SIGNING_KEY")


def _rotation_posture(
    *,
    configured: bool,
    subject: str,
    last_rotated_env: str,
    rotation_days_env: str,
    max_age_days_env: str,
    not_configured_status: str,
    not_configured_message: str,
) -> dict[str, Any]:
    rotation_days = _env_int(rotation_days_env)
    max_age_days = _env_int(max_age_days_env)
    raw_last_rotated = os.environ.get(last_rotated_env, "").strip()

    if not configured:
        return {
            "rotation_tracking_supported": True,
            "rotation_status": not_configured_status,
            "rotation_method": "secret_manager_swap_and_rollout_restart",
            "rotation_days": rotation_days,
            "max_age_days": max_age_days,
            "last_rotated": None,
            "age_days": None,
            "rotation_message": not_configured_message,
        }

    if not raw_last_rotated:
        return {
            "rotation_tracking_supported": True,
            "rotation_status": "unknown_age",
            "rotation_method": "secret_manager_swap_and_rollout_restart",
            "rotation_days": rotation_days,
            "max_age_days": max_age_days,
            "last_rotated": None,
            "age_days": None,
            "rotation_message": (
                f"{subject} is configured but {last_rotated_env} is unset. Record an ISO-8601 rotation timestamp "
                "when the secret is rotated."
            ),
        }

    try:
        rotated = datetime.fromisoformat(raw_last_rotated)
    except ValueError:
        return {
            "rotation_tracking_supported": True,
            "rotation_status": "unknown_age",
            "rotation_method": "secret_manager_swap_and_rollout_restart",
            "rotation_days": rotation_days,
            "max_age_days": max_age_days,
            "last_rotated": raw_last_rotated,
            "age_days": None,
            "rotation_message": (
                f"{last_rotated_env} is set but is not a valid ISO-8601 timestamp. Use a value like '2026-04-17T00:00:00+00:00'."
            ),
        }

    if rotated.tzinfo is None:
        rotated = rotated.replace(tzinfo=timezone.utc)
    age_days = max(0, int((datetime.now(timezone.utc) - rotated).total_seconds() // 86400))

    if max_age_days is not None and age_days >= max_age_days:
        status = "max_age_exceeded"
        message = f"{subject} is {age_days} days old, exceeding the configured maximum ({max_age_days} days). Rotate it now."
    elif rotation_days is not None and age_days >= rotation_days:
        status = "rotation_due"
        message = f"{subject} is {age_days} days old, past the configured rotation interval ({rotation_days} days)."
    else:
        status = "ok"
        message = (
            f"{subject} is {age_days} days old; configured rotation interval is {rotation_days} days."
            if rotation_days is not None
            else f"{subject} is {age_days} days old. No explicit rotation interval is configured."
        )

    return {
        "rotation_tracking_supported": True,
        "rotation_status": status,
        "rotation_method": "secret_manager_swap_and_rollout_restart",
        "rotation_days": rotation_days,
        "max_age_days": max_age_days,
        "last_rotated": rotated.isoformat(),
        "age_days": age_days,
        "rotation_message": message,
    }


def _env_secret_posture(
    *,
    name: str,
    source_env: str,
    subject: str,
    required_env: str | None = None,
    key_id_env: str | None = None,
) -> dict[str, Any]:
    configured = bool(os.environ.get(source_env, "").strip())
    required = _env_enabled(required_env) if required_env else False
    key_id = os.environ.get(key_id_env, "").strip() if key_id_env else ""
    rotation_days_env = f"{source_env}_ROTATION_DAYS"
    max_age_days_env = f"{source_env}_MAX_AGE_DAYS"
    rotation = _rotation_posture(
        configured=configured,
        subject=subject,
        last_rotated_env=f"{source_env}_LAST_ROTATED",
        rotation_days_env=rotation_days_env,
        max_age_days_env=max_age_days_env,
        not_configured_status="missing_required" if required else "not_configured",
        not_configured_message=(
            f"{subject} is required by {required_env} but {source_env} is not configured."
            if required and required_env
            else f"{subject} is not configured."
        ),
    )
    status = "configured" if configured else ("missing_required" if required else "not_configured")
    return {
        "name": name,
        "status": status,
        "configured": configured,
        "required": required,
        "source": source_env if configured else None,
        "key_id_configured": bool(key_id),
        "key_id": key_id or None,
        **rotation,
    }


def _browser_session_signing_posture() -> dict[str, Any]:
    dedicated = os.environ.get("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "").strip()
    required = _browser_signing_key_required()

    if dedicated:
        source = "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY"
        configured = True
    else:
        source = None
        configured = False

    rotation = _rotation_posture(
        configured=configured,
        subject="Browser session signing secret",
        last_rotated_env="AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_LAST_ROTATED",
        rotation_days_env="AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_ROTATION_DAYS",
        max_age_days_env="AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_MAX_AGE_DAYS",
        not_configured_status="missing_required" if required else "ephemeral",
        not_configured_message=(
            "Browser sessions require AGENT_BOM_BROWSER_SESSION_SIGNING_KEY because the control plane is clustered."
            if required
            else (
                "Browser sessions use a process-ephemeral signing key. Sessions are invalidated on restart and rotation age is not stable."
            )
        ),
    )
    return {
        "name": "browser_session_signing",
        "status": "configured" if configured else ("missing_required" if required else "ephemeral"),
        "configured": configured,
        "required": required,
        "source": source,
        "dedicated_key_configured": bool(dedicated),
        "inherited_from": None,
        "configured_api_replicas": _configured_api_replicas(),
        **rotation,
    }


def _external_secret_provider_posture() -> dict[str, Any]:
    provider = os.environ.get("AGENT_BOM_SECRET_PROVIDER", "").strip()
    external_secrets = _env_enabled("AGENT_BOM_EXTERNAL_SECRETS_ENABLED")
    vault_addr = os.environ.get("VAULT_ADDR", "").strip()
    aws_region = os.environ.get("AWS_REGION", "").strip() or os.environ.get("AWS_DEFAULT_REGION", "").strip()
    configured = bool(provider or external_secrets or vault_addr or aws_region)
    resolved_provider = provider or ("hashicorp_vault" if vault_addr else "aws_environment" if aws_region else None)
    adapter = resolve_secret_rotation_adapter(resolved_provider)
    return {
        "status": "configured" if configured else "not_declared",
        "configured": configured,
        "provider": resolved_provider,
        "rotation_adapter": adapter.describe(),
        "supported_rotation_adapters": supported_secret_rotation_adapters(),
        "external_secrets_enabled": external_secrets,
        "vault_addr_configured": bool(vault_addr),
        "aws_region_configured": bool(aws_region),
        "message": (
            "External secret manager posture is declared. Keep secret values in KMS/Vault/External Secrets and mount only runtime env refs."
            if configured
            else (
                "No external secret manager posture is declared. Production deployments should set "
                "AGENT_BOM_SECRET_PROVIDER or use External Secrets/CSI."
            )
        ),
    }


def _rotation_priority(posture: dict[str, Any]) -> int:
    status = str(posture.get("rotation_status") or posture.get("status") or "")
    return {
        "missing_required": 0,
        "max_age_exceeded": 1,
        "rotation_due": 2,
        "unknown_age": 3,
        "ephemeral": 4,
        "not_configured": 5,
        "ok": 9,
        "configured": 9,
    }.get(status, 6)


def _rotation_action(name: str, posture: dict[str, Any], provider: str | None) -> dict[str, Any]:
    source_env = posture.get("source") if isinstance(posture.get("source"), str) else None
    last_rotated_env = f"{source_env}_LAST_ROTATED" if source_env else f"AGENT_BOM_{name.upper()}_LAST_ROTATED"
    status = str(posture.get("rotation_status") or posture.get("status") or "unknown")
    needs_rotation = status in {"missing_required", "max_age_exceeded", "rotation_due", "unknown_age", "ephemeral"}
    adapter = resolve_secret_rotation_adapter(provider)
    return {
        "name": name,
        "status": status,
        "priority": _rotation_priority(posture),
        "needs_rotation": needs_rotation,
        "source_env": source_env,
        "key_id": posture.get("key_id"),
        "last_rotated_env": last_rotated_env,
        "rotation_days": posture.get("rotation_days"),
        "max_age_days": posture.get("max_age_days"),
        "provider": provider or "operator_secret_manager",
        "provider_rotation": adapter.rotation_step(secret_name=name, source_env=source_env, last_rotated_env=last_rotated_env),
        "rollout": {
            "required": needs_rotation,
            "commands": [
                "kubectl rollout restart deployment/agent-bom-api -n agent-bom",
                "kubectl rollout status deployment/agent-bom-api -n agent-bom",
            ],
        },
        "verification": [
            'curl -fsS "$AGENT_BOM_URL/v1/auth/secrets/lifecycle" -H "Authorization: Bearer $AGENT_BOM_ADMIN_TOKEN"',
            "confirm this secret no longer reports rotation_due, max_age_exceeded, unknown_age, missing_required, or ephemeral",
        ],
        "record_timestamp": {
            "env": last_rotated_env,
            "value_format": "ISO-8601 UTC timestamp, for example 2026-04-24T00:00:00+00:00",
            "adapter_command": adapter.timestamp_command(last_rotated_env=last_rotated_env),
        },
        "notes": posture.get("rotation_message") or posture.get("message") or "",
    }


def build_secret_rotation_plan(posture: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a non-secret operator plan for rotating configured control-plane secrets."""
    lifecycle = posture or describe_secret_lifecycle_posture()
    provider_info = lifecycle.get("external_secret_provider", {})
    provider = provider_info.get("provider") if isinstance(provider_info, dict) else None
    provider_name = str(provider) if provider else None
    secrets = lifecycle.get("secrets", {})
    secret_items = secrets.items() if isinstance(secrets, dict) else ()
    actions = [_rotation_action(name, value, provider_name) for name, value in secret_items if isinstance(value, dict)]
    actions.sort(key=lambda item: (int(item["priority"]), str(item["name"])))
    active_actions = [item for item in actions if item["needs_rotation"]]
    return {
        "status": "action_required" if active_actions else "ok",
        "generated_from": "/v1/auth/secrets/lifecycle",
        "secret_values_included": False,
        "provider": provider_name or "operator_secret_manager",
        "rotation_adapter": resolve_secret_rotation_adapter(provider_name).describe(),
        "supported_rotation_adapters": supported_secret_rotation_adapters(),
        "external_secret_provider_configured": bool(provider_info.get("configured")) if isinstance(provider_info, dict) else False,
        "action_count": len(active_actions),
        "actions": active_actions,
        "all_secrets": actions,
        "operator_sequence": [
            "generate replacement secret in the customer-owned secret manager",
            "update the mounted Kubernetes Secret or external secret provider reference",
            "roll out API and gateway workloads that consume the secret",
            "record the matching *_LAST_ROTATED timestamp",
            "verify /v1/auth/secrets/lifecycle and audit events before closing the change",
        ],
        "message": (
            "Rotation actions are required for one or more control-plane secrets."
            if active_actions
            else "No rotation actions are currently required."
        ),
    }


def describe_secret_lifecycle_posture() -> dict[str, Any]:
    """Return a consolidated, non-secret lifecycle posture surface."""
    from agent_bom.api.audit_log import describe_audit_hmac_status
    from agent_bom.api.compliance_signing import describe_signing_posture
    from agent_bom.api.middleware import get_rate_limit_key_status

    secrets = {
        "audit_hmac": describe_audit_hmac_status(),
        "compliance_signing": describe_signing_posture(),
        "rate_limit_key": get_rate_limit_key_status(),
        "browser_session_signing": _browser_session_signing_posture(),
        "scim_bearer": _env_secret_posture(
            name="scim_bearer",
            source_env="AGENT_BOM_SCIM_BEARER_TOKEN",
            subject="SCIM bearer token",
            required_env="AGENT_BOM_REQUIRE_SCIM",
            key_id_env="AGENT_BOM_SCIM_BEARER_TOKEN_ID",
        ),
        "api_static_key": _env_secret_posture(
            name="api_static_key",
            source_env="AGENT_BOM_API_KEY",
            subject="Static API key",
            required_env=None,
            key_id_env="AGENT_BOM_API_KEY_ID",
        ),
    }
    rotation_statuses = [
        str(value.get("rotation_status") or value.get("status") or "unknown") for value in secrets.values() if isinstance(value, dict)
    ]
    blockers = [
        name
        for name, value in secrets.items()
        if str(value.get("rotation_status") or value.get("status")) in {"max_age_exceeded", "missing_required"}
    ]
    warnings = [
        name
        for name, value in secrets.items()
        if str(value.get("rotation_status") or value.get("status")) in {"unknown_age", "rotation_due", "ephemeral", "not_configured"}
    ]
    return {
        "status": "blocked" if blockers else "attention_required" if warnings else "ok",
        "rotation_statuses": rotation_statuses,
        "blockers": blockers,
        "warnings": warnings,
        "external_secret_provider": _external_secret_provider_posture(),
        "secrets": secrets,
        "message": (
            "One or more required secrets are missing or past max age."
            if blockers
            else "Secret lifecycle posture has warnings that should be closed before enterprise procurement."
            if warnings
            else "Secret lifecycle posture is configured and rotation timestamps are current."
        ),
    }
