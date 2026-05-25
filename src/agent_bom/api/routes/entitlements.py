"""Local entitlement metadata API routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request

from agent_bom.api.audit_log import AuditEntry, get_audit_log
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.entitlements import load_entitlement_state

router = APIRouter()
_logger = logging.getLogger(__name__)


def _audit_entitlement_read(request: Request, *, resource: str, details: dict[str, object]) -> None:
    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", None) or getattr(request.state, "api_key_role", None) or "system"
    try:
        get_audit_log().append(
            AuditEntry(
                action="entitlement_check",
                actor=str(actor),
                resource=resource,
                details={"tenant_id": tenant_id, **details},
            )
        )
    except Exception:
        _logger.exception("Failed to append entitlement audit entry")


@router.get("/v1/entitlements", tags=["enterprise"])
async def get_entitlements(request: Request) -> dict:
    """Return local entitlement metadata for self-hosted packaging.

    This endpoint is metadata-only.  Missing, invalid, or expired entitlement
    state is visible to admins but does not gate current OSS scanner or
    control-plane paths.
    """
    state = load_entitlement_state()
    _audit_entitlement_read(
        request,
        resource="entitlements/local",
        details={
            "status": state.status,
            "lane": state.lane,
            "enabled_feature_count": len(state.enabled_features),
            "metadata_only": state.metadata_only,
        },
    )
    return state.to_dict()


@router.get("/v1/entitlements/check/{feature}", tags=["enterprise"])
async def check_entitlement(feature: str, request: Request) -> dict:
    """Evaluate one feature against local entitlement metadata."""
    state = load_entitlement_state()
    check = state.check(feature)
    _audit_entitlement_read(
        request,
        resource=f"entitlements/local/{check.feature}",
        details={
            "status": state.status,
            "feature": check.feature,
            "enabled": check.enabled,
            "metadata_only": check.metadata_only,
        },
    )
    return {
        "schema_version": "v1",
        "lane": state.lane,
        "metadata_only": state.metadata_only,
        "current_oss_paths_gated": state.current_oss_paths_gated,
        "check": check.to_dict(),
    }
