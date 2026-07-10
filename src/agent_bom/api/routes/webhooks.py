"""Governance webhook subscription API: register, list, disable, delete, test.

Operators subscribe outbound webhook destinations to agent-identity governance
events (budget enforcement, identity lifecycle, JIT grants, conditional-access
denials, drift). Deliveries flow through the durable, HMAC-signed posture
webhook outbox. The signing secret is returned exactly once at registration.
"""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.audit_log import log_action
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.api.webhook_store import (
    GOVERNANCE_EVENT_TYPES,
    create_subscription,
    get_webhook_subscription_store,
    set_subscription_status,
)
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import redact_secret_url, sanitize_error

router = APIRouter(tags=["webhooks"])


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(getattr(request, "state", None), "actor", None) or "api"


def _subscription_for_tenant(request: Request, subscription_id: str):
    subscription = get_webhook_subscription_store().get(subscription_id)
    if subscription is None or subscription.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="Webhook subscription not found")
    return subscription


@router.post("/webhooks", status_code=201, dependencies=[_dep("config")])
async def create_webhook_subscription(request: Request, body: dict) -> dict[str, object]:
    """Register a governance webhook destination. Returns the signing secret once."""
    url = str(body.get("url", "") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="'url' is required")
    raw_events = body.get("event_types", [])
    if not isinstance(raw_events, list):
        raise HTTPException(status_code=400, detail="'event_types' must be a list")
    event_types = [str(e).strip()[:80] for e in raw_events if str(e).strip()][:50]
    unknown = [e for e in event_types if not e.endswith("*") and e not in GOVERNANCE_EVENT_TYPES]
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown event_types {unknown}; valid: {list(GOVERNANCE_EVENT_TYPES)}")
    try:
        subscription = create_subscription(
            get_webhook_subscription_store(),
            tenant_id=_tenant(request),
            url=url,
            event_types=event_types,
            description=str(body.get("description", "") or ""),
            signing_secret=str(body.get("signing_secret", "") or ""),
            allow_private_networks=bool(body.get("allow_private_networks", False)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid webhook URL: {sanitize_error(exc)}") from exc
    log_action(
        "webhook.subscription_created",
        actor=_actor(request),
        resource=f"webhook/{subscription.subscription_id}",
        tenant_id=subscription.tenant_id,
        # A webhook URL can be the secret itself (Slack-style incoming webhooks
        # embed the token in the path), so persist only a redacted fingerprint
        # to the audit log rather than the cleartext destination.
        url=redact_secret_url(subscription.url),
        event_types=subscription.event_types or ["*"],
    )
    return {
        "schema_version": "webhook.subscription.v1",
        "subscription": subscription.to_public_dict(),
        "signing_secret": subscription.signing_secret,
        "secret_notice": "Store this signing secret now; it is not retrievable later.",
    }


@router.get("/webhooks", dependencies=[_dep("read")])
async def list_webhook_subscriptions(request: Request, include_disabled: bool = False, limit: int = 200) -> dict[str, object]:
    """List governance webhook subscriptions for the active tenant."""
    tenant_id = _tenant(request)
    bounded = max(1, min(limit, 1000))
    subs = get_webhook_subscription_store().list(tenant_id, include_disabled=include_disabled, limit=bounded)
    return {
        "schema_version": "webhook.subscription.v1",
        "tenant_id": tenant_id,
        "event_catalog": list(GOVERNANCE_EVENT_TYPES),
        "count": len(subs),
        "subscriptions": [s.to_public_dict() for s in subs],
    }


@router.get("/webhooks/{subscription_id}", dependencies=[_dep("read")])
async def get_webhook_subscription(request: Request, subscription_id: str) -> dict[str, object]:
    """Return one webhook subscription (without the signing secret)."""
    subscription = _subscription_for_tenant(request, subscription_id)
    return {"schema_version": "webhook.subscription.v1", "subscription": subscription.to_public_dict()}


@router.post("/webhooks/{subscription_id}/disable", dependencies=[_dep("config")])
async def disable_webhook_subscription(request: Request, subscription_id: str) -> dict[str, object]:
    """Disable a subscription without deleting it."""
    _subscription_for_tenant(request, subscription_id)
    subscription = set_subscription_status(get_webhook_subscription_store(), subscription_id, status="disabled")
    if subscription is None:
        raise HTTPException(status_code=404, detail="Webhook subscription not found")
    log_action(
        "webhook.subscription_disabled",
        actor=_actor(request),
        resource=f"webhook/{subscription_id}",
        tenant_id=subscription.tenant_id,
    )
    return {"schema_version": "webhook.subscription.v1", "subscription": subscription.to_public_dict()}


@router.post("/webhooks/{subscription_id}/enable", dependencies=[_dep("config")])
async def enable_webhook_subscription(request: Request, subscription_id: str) -> dict[str, object]:
    """Re-enable a disabled subscription."""
    _subscription_for_tenant(request, subscription_id)
    subscription = set_subscription_status(get_webhook_subscription_store(), subscription_id, status="active")
    if subscription is None:
        raise HTTPException(status_code=404, detail="Webhook subscription not found")
    log_action(
        "webhook.subscription_enabled",
        actor=_actor(request),
        resource=f"webhook/{subscription_id}",
        tenant_id=subscription.tenant_id,
    )
    return {"schema_version": "webhook.subscription.v1", "subscription": subscription.to_public_dict()}


@router.delete("/webhooks/{subscription_id}", dependencies=[_dep("config")])
async def delete_webhook_subscription(request: Request, subscription_id: str) -> dict[str, object]:
    """Delete a webhook subscription."""
    _subscription_for_tenant(request, subscription_id)
    deleted = get_webhook_subscription_store().delete(subscription_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook subscription not found")
    log_action(
        "webhook.subscription_deleted",
        actor=_actor(request),
        resource=f"webhook/{subscription_id}",
        tenant_id=_tenant(request),
    )
    return {"schema_version": "webhook.subscription.v1", "deleted": True, "subscription_id": subscription_id}


@router.post("/webhooks/{subscription_id}/test", dependencies=[_dep("config")])
async def test_webhook_subscription(request: Request, subscription_id: str) -> dict[str, object]:
    """Enqueue a synthetic ``webhook.test`` event directly to this destination.

    Bypasses the subscription's event-type filter so an operator can verify
    delivery regardless of which governance events it is subscribed to.
    """
    subscription = _subscription_for_tenant(request, subscription_id)
    from agent_bom.posture_streaming import PostureEvent, WebhookDestination, default_webhook_outbox

    event = PostureEvent(
        event_type="webhook.test",
        tenant_id=subscription.tenant_id,
        source="webhooks.api",
        subject_id=subscription_id,
        payload={"message": "agent-bom governance webhook test", "subscription_id": subscription_id},
    )
    try:
        destination = WebhookDestination(
            destination_id=subscription.subscription_id,
            tenant_id=subscription.tenant_id,
            url=subscription.url,
            signing_secret=subscription.signing_secret,
            allow_private_networks=subscription.allow_private_networks,
        )
        default_webhook_outbox().enqueue(event, destination)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail="failed to enqueue test delivery") from exc
    return {"schema_version": "webhook.subscription.v1", "queued": True, "subscription_id": subscription_id, "event_id": event.event_id}
