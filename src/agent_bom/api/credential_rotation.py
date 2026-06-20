"""Credential rotation and expiry posture from reference-only metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.api.models import CredentialRefRecord

DEFAULT_EXPIRY_WARNING_DAYS = 14
DEFAULT_ROTATION_DAYS_BY_CLASS = {
    "api_key": 90,
    "service_account": 90,
    "role_arn": 180,
    "secret_manager": 90,
    "workload_identity": 180,
    "generic": 90,
}
DEFAULT_MAX_AGE_DAYS_BY_CLASS = {
    "api_key": 180,
    "service_account": 180,
    "role_arn": 365,
    "secret_manager": 180,
    "workload_identity": 365,
    "generic": 180,
}
FINDING_STATUSES = {"unknown_age", "near_expiry", "rotation_due", "max_age_exceeded", "expired"}


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _credential_class(credential: CredentialRefRecord) -> str:
    value = credential.credential_class or credential.mode or "generic"
    return value.strip().lower() or "generic"


def _age_days(started_at: datetime | None, *, now: datetime) -> int | None:
    if started_at is None:
        return None
    return max(0, (now - started_at).days)


def _days_until(expiry_at: datetime | None, *, now: datetime) -> int | None:
    if expiry_at is None:
        return None
    return (expiry_at - now).days


def _status_for_credential(
    credential: CredentialRefRecord,
    *,
    age_days: int | None,
    days_until_expiry: int | None,
    rotation_interval_days: int,
    max_age_days: int,
    expiry_warning_days: int,
) -> tuple[str, str, str]:
    if not credential.enabled:
        return ("disabled", "info", "Credential reference is disabled.")
    if days_until_expiry is not None and days_until_expiry < 0:
        return ("expired", "critical", "Credential reference metadata indicates the credential is expired.")
    if age_days is None:
        return ("unknown_age", "medium", "Credential reference has no last_rotated_at metadata.")
    if age_days > max_age_days:
        return ("max_age_exceeded", "high", "Credential reference exceeds the maximum allowed age.")
    if age_days > rotation_interval_days:
        return ("rotation_due", "high", "Credential reference is past the rotation interval.")
    if days_until_expiry is not None and days_until_expiry <= expiry_warning_days:
        return ("near_expiry", "medium", "Credential reference is near expiry.")
    return ("ok", "info", "Credential reference rotation metadata is within policy.")


def build_credential_rotation_governance(
    credentials: list[CredentialRefRecord],
    *,
    tenant_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build reference-only credential rotation evidence without secret material."""

    measured_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    summary = {
        "total": len(credentials),
        "ok": 0,
        "disabled": 0,
        "unknown_age": 0,
        "near_expiry": 0,
        "rotation_due": 0,
        "max_age_exceeded": 0,
        "expired": 0,
        "findings": 0,
    }
    credential_rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for credential in credentials:
        credential_class = _credential_class(credential)
        rotation_interval_days = credential.rotation_interval_days or DEFAULT_ROTATION_DAYS_BY_CLASS.get(
            credential_class,
            DEFAULT_ROTATION_DAYS_BY_CLASS["generic"],
        )
        max_age_days = credential.max_age_days or DEFAULT_MAX_AGE_DAYS_BY_CLASS.get(
            credential_class,
            DEFAULT_MAX_AGE_DAYS_BY_CLASS["generic"],
        )
        expiry_warning_days = credential.expiry_warning_days or DEFAULT_EXPIRY_WARNING_DAYS
        last_rotated_at = _parse_datetime(credential.last_rotated_at)
        expires_at = _parse_datetime(credential.expires_at)
        credential_age_days = _age_days(last_rotated_at, now=measured_at)
        credential_days_until_expiry = _days_until(expires_at, now=measured_at)
        status, severity, message = _status_for_credential(
            credential,
            age_days=credential_age_days,
            days_until_expiry=credential_days_until_expiry,
            rotation_interval_days=rotation_interval_days,
            max_age_days=max_age_days,
            expiry_warning_days=expiry_warning_days,
        )
        summary[status] += 1

        evidence = {
            "reference_only": True,
            "secret_material_stored": False,
            "external_ref_recorded": bool(credential.external_ref),
        }
        row = {
            "credential_ref_id": credential.credential_ref_id,
            "display_name": credential.display_name,
            "provider": credential.provider,
            "mode": credential.mode,
            "credential_class": credential_class,
            "owner": credential.owner,
            "enabled": credential.enabled,
            "rotation_status": status,
            "severity": severity,
            "age_days": credential_age_days,
            "days_until_expiry": credential_days_until_expiry,
            "last_rotated_at": last_rotated_at.isoformat() if last_rotated_at else None,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "policy": {
                "rotation_interval_days": rotation_interval_days,
                "max_age_days": max_age_days,
                "expiry_warning_days": expiry_warning_days,
            },
            "message": message,
            "evidence": evidence,
        }
        credential_rows.append(row)

        if status in FINDING_STATUSES:
            findings.append(
                {
                    "finding_id": f"credential-rotation:{credential.credential_ref_id}:{status}",
                    "type": "credential_rotation",
                    "severity": severity,
                    "status": status,
                    "credential_ref_id": credential.credential_ref_id,
                    "credential_class": credential_class,
                    "title": f"Credential rotation policy: {status.replace('_', ' ')}",
                    "message": message,
                    "compliance_tags": ["soc2:CC6.1", "iso27001:A.5.17"],
                    "evidence": evidence,
                }
            )

    summary["findings"] = len(findings)
    return {
        "schema_version": "credential.rotation_governance.v1",
        "tenant_id": tenant_id,
        "measured_at": measured_at.isoformat(),
        "policy": {
            "default_expiry_warning_days": DEFAULT_EXPIRY_WARNING_DAYS,
            "default_rotation_days_by_class": DEFAULT_ROTATION_DAYS_BY_CLASS,
            "default_max_age_days_by_class": DEFAULT_MAX_AGE_DAYS_BY_CLASS,
        },
        "summary": summary,
        "credentials": credential_rows,
        "findings": findings,
    }
