"""Tenant data export and deletion endpoints for self-hosted privacy operations."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.audit_log import get_audit_log, log_action
from agent_bom.api.stores import (
    _get_exception_store,
    _get_fleet_store,
    _get_graph_store,
    _get_policy_store,
    _get_schedule_store,
    _get_source_store,
    _get_store,
    _get_tenant_quota_store,
)
from agent_bom.platform_invariants import normalize_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter()
_logger = logging.getLogger(__name__)

_MAX_EXPORT_RECORDS = 500


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _actor(request: Request) -> str:
    return str(getattr(request.state, "api_key_name", None) or getattr(request.state, "auth_method", None) or "system")


def _sanitize_log_value(value: object, max_len: int = 128) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    text = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
    return text[:max_len]


def _request_tenant(request: Request) -> str:
    return normalize_tenant_id(str(getattr(request.state, "tenant_id", "") or "default"))


def _require_same_tenant(request: Request, tenant_id: str) -> None:
    request_tenant = _request_tenant(request)
    if tenant_id != request_tenant:
        raise HTTPException(
            status_code=403,
            detail="Tenant data operations are limited to the authenticated tenant context",
        )


def _dump_record(record: Any) -> dict[str, Any]:
    if hasattr(record, "model_dump"):
        data = record.model_dump(mode="json")
    elif hasattr(record, "to_dict"):
        data = record.to_dict()
    elif hasattr(record, "dict"):
        data = record.dict()
    elif isinstance(record, dict):
        data = dict(record)
    else:
        data = {"value": str(record)}
    return dict(data)


def _redact_source(record: Any) -> dict[str, Any]:
    data = _dump_record(record)
    if data.get("credential_ref"):
        data["credential_ref"] = "[redacted]"
    if data.get("config"):
        data["config"] = {"redacted": True}
    return data


def _try_records(name: str, func: Callable[[], list[Any]], unavailable: dict[str, str]) -> list[Any]:
    try:
        return func()
    except RuntimeError as exc:
        unavailable[name] = str(exc)
        return []


def _policy_audit_count(tenant_id: str) -> int:
    try:
        return len(_get_policy_store().list_audit_entries(limit=100_000, tenant_id=tenant_id))
    except RuntimeError:
        return 0


def _tenant_dataset(tenant_id: str, *, include_records: bool = False, record_limit: int = _MAX_EXPORT_RECORDS) -> dict[str, Any]:
    unavailable: dict[str, str] = {}
    jobs = _try_records("jobs", lambda: _get_store().list_summary(tenant_id=tenant_id), unavailable)
    fleet = _try_records("fleet_agents", lambda: _get_fleet_store().list_by_tenant(tenant_id), unavailable)
    policies = _try_records("gateway_policies", lambda: _get_policy_store().list_policies(tenant_id=tenant_id), unavailable)
    schedules = _try_records("scan_schedules", lambda: _get_schedule_store().list_all(tenant_id=tenant_id), unavailable)
    sources = _try_records("sources", lambda: _get_source_store().list_all(tenant_id=tenant_id), unavailable)
    exceptions = _try_records("exceptions", lambda: _get_exception_store().list_all(tenant_id=tenant_id), unavailable)
    graph_snapshots = _try_records(
        "graph_snapshots",
        lambda: _get_graph_store().list_snapshots(tenant_id=tenant_id, limit=record_limit),
        unavailable,
    )

    quota = None
    try:
        quota = _get_tenant_quota_store().get(tenant_id)
    except RuntimeError as exc:
        unavailable["tenant_quota"] = str(exc)

    counts = {
        "jobs": len(jobs),
        "fleet_agents": len(fleet),
        "gateway_policies": len(policies),
        "scan_schedules": len(schedules),
        "sources": len(sources),
        "exceptions": len(exceptions),
        "graph_snapshots": len(graph_snapshots),
        "tenant_quota_overrides": 1 if quota is not None else 0,
        "audit_log_entries_retained": get_audit_log().count(tenant_id=tenant_id),
        "policy_audit_entries_retained": _policy_audit_count(tenant_id),
    }
    payload: dict[str, Any] = {
        "tenant_id": tenant_id,
        "counts": counts,
        "retention": {
            "audit_log": "retained_immutable_hmac_chain",
            "policy_audit_log": "retained_for_security_evidence",
            "api_keys": "retained_manage_with_api_key_lifecycle",
        },
    }
    if unavailable:
        payload["unavailable"] = unavailable
    if include_records:
        limit = min(max(record_limit, 1), _MAX_EXPORT_RECORDS)
        payload["records"] = {
            "jobs": jobs[:limit],
            "fleet_agents": [_dump_record(record) for record in fleet[:limit]],
            "gateway_policies": [_dump_record(record) for record in policies[:limit]],
            "scan_schedules": [_dump_record(record) for record in schedules[:limit]],
            "sources": [_redact_source(record) for record in sources[:limit]],
            "exceptions": [_dump_record(record) for record in exceptions[:limit]],
            "graph_snapshots": graph_snapshots[:limit],
            "tenant_quota_overrides": quota or {},
        }
    return payload


def _delete_graph_tenant(tenant_id: str) -> int:
    store = _get_graph_store()
    delete_tenant = getattr(store, "delete_tenant", None)
    if not callable(delete_tenant):
        return 0
    return int(delete_tenant(tenant_id=tenant_id))


def _delete_records(tenant_id: str) -> dict[str, int]:
    jobs = _get_store().list_summary(tenant_id=tenant_id)
    fleet = _get_fleet_store().list_by_tenant(tenant_id)
    policies = _get_policy_store().list_policies(tenant_id=tenant_id)
    schedules = _get_schedule_store().list_all(tenant_id=tenant_id)
    sources = _get_source_store().list_all(tenant_id=tenant_id)
    exceptions = _get_exception_store().list_all(tenant_id=tenant_id)

    deleted = {
        "jobs": sum(1 for record in jobs if _get_store().delete(str(record["job_id"]), tenant_id=tenant_id)),
        "fleet_agents": sum(1 for record in fleet if _get_fleet_store().delete(record.agent_id, tenant_id=tenant_id)),
        "gateway_policies": sum(1 for record in policies if _get_policy_store().delete_policy(record.policy_id, tenant_id=tenant_id)),
        "scan_schedules": sum(1 for record in schedules if _get_schedule_store().delete(record.schedule_id, tenant_id=tenant_id)),
        "sources": sum(1 for record in sources if _get_source_store().delete(record.source_id)),
        "exceptions": sum(1 for record in exceptions if _get_exception_store().delete(record.exception_id, tenant_id=tenant_id)),
        "tenant_quota_overrides": 1 if _get_tenant_quota_store().delete(tenant_id) else 0,
        "graph_rows": _delete_graph_tenant(tenant_id),
    }
    return deleted


@router.get("/v1/tenant/{tenant_id}/data", dependencies=[_dep("config")])
def export_tenant_data(
    tenant_id: str,
    request: Request,
    include_records: bool = Query(False),
    record_limit: int = Query(_MAX_EXPORT_RECORDS, ge=1, le=_MAX_EXPORT_RECORDS),
) -> dict[str, Any]:
    """Export a tenant-scoped data inventory without exposing another tenant's data."""
    normalized_tenant = normalize_tenant_id(tenant_id)
    _require_same_tenant(request, normalized_tenant)
    payload = _tenant_dataset(normalized_tenant, include_records=include_records, record_limit=record_limit)
    log_action(
        "privacy.tenant_export",
        actor=_actor(request),
        resource=f"tenant/{normalized_tenant}/data",
        tenant_id=normalized_tenant,
        include_records=include_records,
    )
    return payload


@router.delete("/v1/tenant/{tenant_id}/data", dependencies=[_dep("config")])
def delete_tenant_data(
    tenant_id: str,
    request: Request,
    confirm_tenant_id: str = Query(""),
    dry_run: bool = Query(True),
) -> dict[str, Any]:
    """Delete tenant-scoped operational data after explicit same-tenant confirmation."""
    normalized_tenant = normalize_tenant_id(tenant_id)
    _require_same_tenant(request, normalized_tenant)
    before = _tenant_dataset(normalized_tenant, include_records=False)
    if dry_run:
        log_action(
            "privacy.tenant_delete_dry_run",
            actor=_actor(request),
            resource=f"tenant/{normalized_tenant}/data",
            tenant_id=normalized_tenant,
            counts=before["counts"],
        )
        return {"tenant_id": normalized_tenant, "dry_run": True, "would_delete": before["counts"], "retention": before["retention"]}

    if confirm_tenant_id.strip() != normalized_tenant:
        raise HTTPException(status_code=400, detail="confirm_tenant_id must exactly match tenant_id when dry_run=false")

    deleted = _delete_records(normalized_tenant)
    _logger.info("tenant data deletion completed tenant=%s deleted=%s", _sanitize_log_value(normalized_tenant), deleted)
    log_action(
        "privacy.tenant_delete",
        actor=_actor(request),
        resource=f"tenant/{normalized_tenant}/data",
        tenant_id=normalized_tenant,
        deleted=deleted,
    )
    after = _tenant_dataset(normalized_tenant, include_records=False)
    return {
        "tenant_id": normalized_tenant,
        "dry_run": False,
        "deleted": deleted,
        "remaining": after["counts"],
        "retention": after["retention"],
    }
