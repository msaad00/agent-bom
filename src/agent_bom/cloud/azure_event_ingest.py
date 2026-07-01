"""Event-driven Azure posture ingestion (continuous / change-triggered CNAPP).

The complement to the polling scheduler for Azure, mirroring the AWS lane in
:mod:`agent_bom.cloud.event_ingest`. When a resource changes in a customer
subscription, Azure Monitor emits an Activity Log record that an Event Grid
subscription (or a diagnostic setting) can route to a Storage Queue. The control
plane drains that queue and re-evaluates **only** the Azure CIS rules that apply
to the changed resource's type — so a storage account made public is re-checked
in seconds instead of waiting for the next scheduled full scan. Polling remains
the fallback; this is additive.

Trust posture (non-negotiable, fail-closed):

* **Read-only against the customer.** The changed resource is re-fetched and its
  CIS checks re-run through the SAME brokered read-only Reader credential the
  scheduled scan uses (:func:`agent_bom.cloud.connection_broker.broker_session`).
  No write API is ever called on the customer subscription.
* **Subscription/tenant-bound.** A change event is only dispatched when its
  subscription (and tenant, when present) matches the connection's own
  subscription/tenant (from ``auth_params``). A spoofed / cross-subscription
  event is dropped, never processed — this prevents a confused-deputy where an
  attacker-controlled queue message steers a scan at a subscription the tenant
  does not own.
* **Bounded.** :func:`consume_azure_events` drains at most a configured number of
  messages across a configured number of receive batches and then RETURNS. There
  is no forever loop; an operator (or a scheduler tick) invokes it repeatedly.
* **Crash-proof.** A malformed message is logged and deleted (it can never be
  parsed, so redelivery would only poison the queue); a transient dispatch
  failure is logged and left on the queue for the visibility timeout to
  redeliver. One bad message never sinks the batch.

Opt-in and default OFF: the consumer only runs when ``AGENT_BOM_AZURE_EVENT_QUEUE``
is set (read live) — the full Storage Queue URL the operator wired Event Grid to.
The queue is operator-owned, so the control plane reads it with its OWN ambient
credentials — distinct from the customer read-only Reader credential used for the
posture re-evaluation.

Requires ``azure-storage-queue`` + ``azure-identity`` for the queue consumer.
Install with ``pip install 'agent-bom[azure]'``.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable

from agent_bom import config
from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.cloud.event_ingest import CloudChangeEvent, _default_persist, _now

logger = logging.getLogger(__name__)

# Opt-in gate (read live so operators/tests can toggle it). Absence = disabled.
# The value is the full Azure Storage Queue URL the operator routed Event Grid to.
EVENT_QUEUE_ENV = "AGENT_BOM_AZURE_EVENT_QUEUE"


@dataclass(frozen=True)
class _ResourceRule:
    """How to re-evaluate posture for one Azure resource-type token.

    ``inventory_kwargs`` scopes :func:`azure_inventory.discover_inventory` to just
    the affected resource class (so we re-fetch that resource, not the estate).
    ``check_ids`` is the exact Azure CIS subset re-run for the type. ``locators``
    maps inventory payload list keys to the field that identifies a single
    resource, so the changed resource can be picked out of the class fetch.
    """

    check_ids: tuple[str, ...]
    inventory_kwargs: dict[str, bool]
    locators: tuple[tuple[str, str], ...]


# Only the affected class is fetched; every other include_* flag is forced off.
def _only(**flags: bool) -> dict[str, bool]:
    base = {
        "include_storage": False,
        "include_compute": False,
        "include_identity": False,
        "include_data": False,
        "include_network": False,
        "include_hierarchy": False,
    }
    base.update(flags)
    return base


# Resource-type token → posture re-evaluation rule. Azure Activity Log
# ``operationName`` / Event Grid ``subject`` collapse to these tokens via the ARM
# resource-type segment (see ``_canonical_resource_type``).
_RESOURCE_RULES: dict[str, _ResourceRule] = {
    "storage": _ResourceRule(
        check_ids=("3.1", "3.2", "3.3", "3.7", "3.8", "3.10", "3.11", "3.12"),
        inventory_kwargs=_only(include_storage=True),
        locators=(("storage_accounts", "name"), ("storage_accounts", "id")),
    ),
    "nsg": _ResourceRule(
        check_ids=("6.1", "6.2", "6.4", "6.6"),
        inventory_kwargs=_only(include_compute=True, include_network=True),
        locators=(("security_groups", "group_id"), ("security_groups", "name")),
    ),
    "compute": _ResourceRule(
        check_ids=("7.1", "7.2", "7.3"),
        inventory_kwargs=_only(include_compute=True),
        locators=(("instances", "name"), ("instances", "id")),
    ),
    "keyvault": _ResourceRule(
        check_ids=("8.1", "8.2", "8.4", "8.5", "8.6", "8.7"),
        inventory_kwargs=_only(include_data=True),
        locators=(("key_vaults", "name"), ("key_vaults", "id")),
    ),
    "sql": _ResourceRule(
        check_ids=("4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5", "4.1.6"),
        inventory_kwargs=_only(include_data=True),
        locators=(("databases", "name"), ("databases", "id")),
    ),
    "webapp": _ResourceRule(
        check_ids=("9.1", "9.2", "9.3", "9.4", "9.6"),
        inventory_kwargs=_only(include_compute=True),
        locators=(("app_services", "name"), ("app_services", "id")),
    ),
    "authorization": _ResourceRule(
        check_ids=("1.1", "1.2", "1.5", "1.7", "1.15"),
        inventory_kwargs=_only(include_identity=True),
        locators=(("role_assignments", "id"),),
    ),
}

# ARM resource-type segment (lower-cased, from the provider path) → service token.
_AZURE_RESOURCE_TYPE_TOKENS: dict[str, str] = {
    "storageaccounts": "storage",
    "networksecuritygroups": "nsg",
    "virtualmachines": "compute",
    "disks": "compute",
    "vaults": "keyvault",
    "servers": "sql",
    "databases": "sql",
    "sites": "webapp",
    "roleassignments": "authorization",
}


def event_ingest_enabled() -> bool:
    """Return whether Azure event-driven ingestion is opted in (queue configured).

    Read live so operators and tests can toggle it. Default OFF: with no queue
    URL the consumer is a no-op and only the polling scheduler runs.
    """
    return bool(os.environ.get(EVENT_QUEUE_ENV, "").strip())


def _uri_segments(uri: str) -> list[str]:
    return [seg for seg in (uri or "").split("/") if seg]


def _subscription_from_uri(uri: str) -> str:
    """Pull the subscription id out of an ARM resource id / Event Grid subject.

    Splits WITHOUT collapsing empty segments so ``/subscriptions//providers/...``
    (an absent subscription) resolves to "" rather than mis-reading the next
    keyword segment as the id.
    """
    raw = (uri or "").split("/")
    for idx, seg in enumerate(raw):
        if seg.lower() == "subscriptions" and idx + 1 < len(raw):
            return raw[idx + 1].strip()
    return ""


def _type_and_name_from_uri(uri: str) -> tuple[str, str]:
    """Return (arm_resource_type_segment, resource_name) from an ARM resource id.

    ``/subscriptions/<s>/resourceGroups/<rg>/providers/Microsoft.Storage/
    storageAccounts/<name>`` → (``"storageaccounts"``, ``"<name>"``). The type
    segment is the one immediately after the provider namespace; the name is the
    last segment. Returns ("", "") when the shape is not an ARM resource id.
    """
    segs = _uri_segments(uri)
    for idx, seg in enumerate(segs):
        if seg.lower() == "providers" and idx + 2 < len(segs):
            return segs[idx + 2].lower(), segs[-1]
    return "", ""


def _canonical_resource_type(arm_type: str) -> str:
    """Collapse an ARM resource-type segment to a service token."""
    return _AZURE_RESOURCE_TYPE_TOKENS.get((arm_type or "").strip().lower(), "")


def _operation_value(operation: Any) -> str:
    """Normalize an operationName that may be a string or ``{"value": ...}``."""
    if isinstance(operation, dict):
        return str(operation.get("value") or "").strip()
    return str(operation or "").strip()


def parse_azure_event(message: str | dict[str, Any]) -> CloudChangeEvent | None:
    """Parse an Event Grid / Activity Log message into a :class:`CloudChangeEvent`.

    Accepts either an Event Grid envelope (``{"subject", "eventType", "data":
    {"operationName", "resourceUri", ...}}``) or a bare Azure Monitor Activity Log
    record (``{"resourceId", "operationName", "subscriptionId", ...}``). Returns
    ``None`` for anything malformed or for a resource type with no posture rule —
    the caller treats ``None`` as "skip, do not crash".
    """
    try:
        obj = json.loads(message) if isinstance(message, (str, bytes)) else message
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None

    data = obj.get("data")
    data = data if isinstance(data, dict) else {}

    resource_uri = (
        str(obj.get("subject") or "").strip()
        or str(data.get("resourceUri") or "").strip()
        or str(data.get("resourceId") or "").strip()
        or str(obj.get("resourceId") or "").strip()
        or str(obj.get("resourceUri") or "").strip()
    )

    arm_type, resource_name = _type_and_name_from_uri(resource_uri)
    token = _canonical_resource_type(arm_type)
    if token not in _RESOURCE_RULES:
        return None

    subscription = (
        str(data.get("subscriptionId") or "").strip()
        or str(obj.get("subscriptionId") or "").strip()
        or _subscription_from_uri(resource_uri)
    )
    tenant = str(data.get("tenantId") or "").strip() or str(obj.get("tenantId") or "").strip()
    action = _operation_value(data.get("operationName")) or _operation_value(obj.get("operationName"))

    # Fail closed: without a subscription, an action, and a resource name we
    # cannot safely attribute or scope the re-evaluation.
    if not subscription or not action or not resource_name:
        return None

    return CloudChangeEvent(
        provider="azure",
        account=subscription,
        region=tenant,  # tenant travels in ``region`` for the guard (Azure has no region here).
        resource_type=token,
        resource_id=resource_name,
        action=action,
        arn=resource_uri,
        raw=obj,
    )


def _find_affected_resource(rule: _ResourceRule, inventory: dict[str, Any], resource_id: str) -> dict[str, Any] | None:
    """Return the single inventory entry matching *resource_id*, if present."""
    for list_key, id_field in rule.locators:
        for item in inventory.get(list_key, []) or []:
            if not isinstance(item, dict):
                continue
            if str(item.get(id_field, "")) == resource_id:
                return item
    return None


def dispatch_change_event(
    event: CloudChangeEvent,
    record: CloudConnectionRecord,
    *,
    tenant_id: str | None = None,
    credential: Any = None,
    benchmark_runner: Callable[..., Any] | None = None,
    persist: Callable[[CloudConnectionRecord, str, Any], str] | None = None,
    store: Any = None,
) -> dict[str, Any] | None:
    """Re-evaluate posture for one changed Azure resource and emit the delta.

    Resolves the changed resource via a scoped read-only inventory fetch, re-runs
    ONLY the Azure CIS checks for its resource type against the brokered read-only
    Reader credential, persists the resulting posture through the same scan/graph
    path a full scan uses, and stamps ``last_event_at`` on the connection.

    Fail-closed: the event's provider must be ``azure`` and its subscription (and
    tenant, when both are present) must match the connection's own subscription
    (from ``auth_params``); a mismatch returns ``None`` without touching the
    customer subscription. An unknown resource type also returns ``None``.
    """
    tenant_id = tenant_id or record.tenant_id

    if (event.provider or "").strip().lower() != "azure":
        logger.warning("Dropping non-Azure change event (provider=%s)", event.provider)
        return None
    if (record.provider or "").strip().lower() != "azure":
        logger.warning("Connection %s is not Azure; cannot dispatch Azure change event", record.id)
        return None

    connection_subscription = str(record.auth_params.get("subscription_id") or "").strip()
    if not connection_subscription or event.account != connection_subscription:
        # Confused-deputy guard: never scan a subscription this connection does not own.
        logger.warning(
            "Dropping change event for subscription %s: does not match connection %s subscription",
            event.account,
            record.id,
        )
        return None

    connection_tenant = str(record.auth_params.get("tenant_id") or "").strip()
    if connection_tenant and event.region and event.region != connection_tenant:
        # Tenant is present on both sides and disagrees — a cross-tenant spoof.
        logger.warning(
            "Dropping change event for tenant %s: does not match connection %s tenant",
            event.region,
            record.id,
        )
        return None

    rule = _RESOURCE_RULES.get(event.resource_type)
    if rule is None:
        return None

    from agent_bom.cloud import azure_inventory
    from agent_bom.models import AIBOMReport

    run_cis_benchmark: Callable[..., Any]
    if benchmark_runner is not None:
        run_cis_benchmark = benchmark_runner
    else:
        from agent_bom.cloud.azure_cis_benchmark import run_benchmark

        run_cis_benchmark = run_benchmark

    if credential is None:
        from agent_bom.cloud.connection_broker import broker_session

        credential = broker_session(record, session_name=f"agent-bom-event-{record.id[:8]}")

    inv = rule.inventory_kwargs
    inventory_payload = azure_inventory.discover_inventory(
        subscription_id=connection_subscription,
        credential=credential,
        force=True,
        include_storage=inv["include_storage"],
        include_compute=inv["include_compute"],
        include_identity=inv["include_identity"],
        include_data=inv["include_data"],
        include_network=inv["include_network"],
        include_hierarchy=inv["include_hierarchy"],
    )
    affected = _find_affected_resource(rule, inventory_payload, event.resource_id)

    cis_report = run_cis_benchmark(subscription_id=connection_subscription, credential=credential, checks=list(rule.check_ids))
    cis_dict = cis_report.to_dict()
    findings = [check for check in cis_dict.get("checks", []) if check.get("status") == "fail"]

    import uuid as _uuid

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=str(_uuid.uuid4()))
    report.scan_sources = ["cloud_connection", "cloud:azure", "event:activity_log"]
    report.cloud_inventory_data = inventory_payload
    report.azure_cis_benchmark_data = cis_dict

    persist_fn = persist or _default_persist
    scan_id = persist_fn(record, tenant_id, report)

    # Freshness signal: event-driven re-eval advances last_event_at, NOT
    # last_scan_at (that stays the last full polling scan).
    active_store = store
    if active_store is None:
        from agent_bom.api.connection_store import get_connection_store

        active_store = get_connection_store()
    fresh = active_store.get(tenant_id, record.id) or record
    fresh.last_event_at = _now()
    fresh.updated_at = _now()
    active_store.put(fresh)
    record.last_event_at = fresh.last_event_at

    return {
        "schema_version": "cloud.connections.event.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "azure",
        "scan_id": scan_id,
        "event": {
            "subscription_id": event.account,
            "tenant_id": event.region,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "action": event.action,
        },
        "resource": affected,
        "checks_evaluated": list(rule.check_ids),
        "findings": [
            {
                "check_id": f.get("check_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "resource_ids": f.get("resource_ids", []),
                "evidence": f.get("evidence", ""),
            }
            for f in findings
        ],
        "audit_metadata": {
            "read_only": True,
            "writes_performed": False,
            "note": (
                "Event-driven re-evaluation ran against a short-lived read-only Reader credential brokered from the "
                "stored connection. Only the affected resource type's Azure CIS checks were re-run; no resource is "
                "mutated and no secret value is returned."
            ),
        },
    }


def consume_azure_events(
    record: CloudConnectionRecord,
    *,
    tenant_id: str | None = None,
    queue_url: str | None = None,
    queue_client: Any = None,
    credential: Any = None,
    max_messages: int | None = None,
    max_batches: int | None = None,
    visibility_timeout: int | None = None,
    benchmark_runner: Callable[..., Any] | None = None,
    persist: Callable[[CloudConnectionRecord, str, Any], str] | None = None,
    store: Any = None,
) -> dict[str, Any]:
    """Drain a bounded batch of Azure change events from a Storage Queue.

    Reads the operator-owned Storage Queue (Event Grid→Queue) with the control
    plane's OWN ambient credentials, parses each Activity Log message, and
    dispatches a per-resource posture re-evaluation for events that belong to
    *record*'s subscription. This is a BOUNDED pass: at most ``max_batches``
    receives of ``max_messages`` each, then it returns — there is no forever loop.

    Message lifecycle: a successfully dispatched message is deleted; a malformed
    or foreign-subscription message is logged and deleted (redelivery cannot
    help); a transient dispatch failure is logged and LEFT on the queue for the
    visibility timeout to redeliver. Never raises — one bad message cannot sink
    the batch. With no queue configured it is a no-op (``status="disabled"``).
    """
    tenant_id = tenant_id or record.tenant_id
    queue_url = queue_url or os.environ.get(EVENT_QUEUE_ENV, "").strip()

    summary: dict[str, Any] = {
        "status": "ok",
        "connection_id": record.id,
        "received": 0,
        "processed": 0,
        "deleted": 0,
        "skipped_malformed": 0,
        "skipped_foreign": 0,
        "errors": 0,
        "batches": 0,
    }

    if not queue_url:
        summary["status"] = "disabled"
        return summary

    max_messages = max(1, min(int(max_messages if max_messages is not None else config.AZURE_EVENT_MAX_MESSAGES), 32))
    max_batches = max(1, int(max_batches if max_batches is not None else config.AZURE_EVENT_MAX_BATCHES))
    visibility_timeout = max(0, int(visibility_timeout if visibility_timeout is not None else config.AZURE_EVENT_VISIBILITY_TIMEOUT))

    connection_subscription = str(record.auth_params.get("subscription_id") or "").strip()

    if queue_client is None:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.storage.queue import QueueClient
        except ImportError:
            summary["status"] = "sdk_missing"
            return summary
        try:
            queue_client = QueueClient.from_queue_url(queue_url, credential=DefaultAzureCredential())
        except Exception as exc:  # noqa: BLE001 — control-plane credential/config error must not crash
            logger.warning("Could not create Azure Storage Queue client for event ingestion: %s", type(exc).__name__)
            summary["status"] = "no_credentials"
            return summary

    # Broker one read-only customer credential for the whole batch; every dispatch
    # reuses it. Absent a credential, dispatch would broker per-message.
    if credential is None:
        try:
            from agent_bom.cloud.connection_broker import broker_session

            credential = broker_session(record, session_name=f"agent-bom-event-{record.id[:8]}")
        except Exception as exc:  # noqa: BLE001 — a broker failure is not fatal to the queue drain contract
            logger.warning("Could not broker read-only credential for Azure event ingestion: %s", type(exc).__name__)
            summary["status"] = "broker_failed"
            return summary

    for _ in range(max_batches):  # bounded: always terminates
        summary["batches"] += 1
        try:
            messages = list(queue_client.receive_messages(max_messages=max_messages, visibility_timeout=visibility_timeout))
        except Exception as exc:  # noqa: BLE001 — throttle / transient receive error: stop this pass cleanly
            logger.warning("Azure queue receive failed during event ingestion: %s", type(exc).__name__)
            summary["errors"] += 1
            break

        if not messages:
            break  # empty queue: nothing more to drain this pass

        for message in messages:
            summary["received"] += 1
            body = getattr(message, "content", "") or ""

            event = parse_azure_event(body)
            if event is None:
                summary["skipped_malformed"] += 1
                _delete_message(queue_client, message, summary)  # poison: drop it
                continue

            if event.account != connection_subscription:
                # Not this connection's subscription — never scan a foreign one.
                summary["skipped_foreign"] += 1
                _delete_message(queue_client, message, summary)
                continue

            try:
                dispatch_change_event(
                    event,
                    record,
                    tenant_id=tenant_id,
                    credential=credential,
                    benchmark_runner=benchmark_runner,
                    persist=persist,
                    store=store,
                )
            except Exception as exc:  # noqa: BLE001 — leave on queue for redelivery; never crash the drain
                logger.warning(
                    "Azure event dispatch failed for %s/%s: %s",
                    event.resource_type,
                    event.resource_id,
                    type(exc).__name__,
                )
                summary["errors"] += 1
                continue  # do NOT delete — visibility timeout redelivers

            summary["processed"] += 1
            _delete_message(queue_client, message, summary)

    return summary


def _delete_message(queue_client: Any, message: Any, summary: dict[str, Any]) -> None:
    """Best-effort Storage Queue delete; a delete failure is logged, never raised."""
    try:
        queue_client.delete_message(message)
        summary["deleted"] += 1
    except Exception as exc:  # noqa: BLE001 — delete failure only means one redelivery
        logger.warning("Azure queue delete failed during event ingestion: %s", type(exc).__name__)
