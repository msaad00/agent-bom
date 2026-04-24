"""Operator-facing secret lifecycle posture for enterprise deployments."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any


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
    audit = os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY", "").strip()
    static_api = os.environ.get("AGENT_BOM_API_KEY", "").strip()

    if dedicated:
        source = "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY"
        inherited_from = None
        configured = True
    elif audit:
        source = "AGENT_BOM_AUDIT_HMAC_KEY"
        inherited_from = "audit_hmac"
        configured = True
    elif static_api:
        source = "AGENT_BOM_API_KEY"
        inherited_from = "static_api_key"
        configured = True
    else:
        source = None
        inherited_from = None
        configured = False

    rotation = _rotation_posture(
        configured=configured,
        subject="Browser session signing secret",
        last_rotated_env="AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_LAST_ROTATED",
        rotation_days_env="AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_ROTATION_DAYS",
        max_age_days_env="AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_MAX_AGE_DAYS",
        not_configured_status="ephemeral",
        not_configured_message=(
            "Browser sessions use a process-ephemeral signing key. Sessions are invalidated on restart and rotation age is not stable."
        ),
    )
    return {
        "name": "browser_session_signing",
        "status": "configured" if configured else "ephemeral",
        "configured": configured,
        "required": False,
        "source": source,
        "dedicated_key_configured": bool(dedicated),
        "inherited_from": inherited_from,
        **rotation,
    }


def _external_secret_provider_posture() -> dict[str, Any]:
    provider = os.environ.get("AGENT_BOM_SECRET_PROVIDER", "").strip()
    external_secrets = _env_enabled("AGENT_BOM_EXTERNAL_SECRETS_ENABLED")
    vault_addr = os.environ.get("VAULT_ADDR", "").strip()
    aws_region = os.environ.get("AWS_REGION", "").strip() or os.environ.get("AWS_DEFAULT_REGION", "").strip()
    configured = bool(provider or external_secrets or vault_addr or aws_region)
    return {
        "status": "configured" if configured else "not_declared",
        "configured": configured,
        "provider": provider or ("hashicorp_vault" if vault_addr else "aws_environment" if aws_region else None),
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
