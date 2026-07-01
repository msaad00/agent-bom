"""Event-driven GCP posture ingestion (continuous / change-triggered CNAPP).

The complement to the polling scheduler for GCP, mirroring the AWS lane in
:mod:`agent_bom.cloud.event_ingest`. When a resource changes in a customer
project, Cloud Asset Inventory can publish a feed message (or an audit-log sink
can publish a log entry) to a Pub/Sub topic. The control plane pulls that
subscription and re-evaluates **only** the GCP CIS rules that apply to the
changed resource's type — so a bucket made public is re-checked in seconds
instead of waiting for the next scheduled full scan. Polling remains the
fallback; this is additive.

Trust posture (non-negotiable, fail-closed):

* **Read-only against the customer.** The changed resource is re-fetched and its
  CIS checks re-run through the SAME brokered read-only service-account
  credential (cloud-platform.read-only) the scheduled scan uses
  (:func:`agent_bom.cloud.connection_broker.broker_session`). No write API is ever
  called on the customer project.
* **Project-bound.** A change event is only dispatched when its project matches
  the connection's own project (from ``auth_params``). A spoofed / cross-project
  event is dropped, never processed — this prevents a confused-deputy where an
  attacker-controlled message steers a scan at a project the tenant does not own.
* **Bounded.** :func:`consume_gcp_events` pulls at most a configured number of
  messages across a configured number of pull batches and then RETURNS. There is
  no forever loop; an operator (or a scheduler tick) invokes it repeatedly.
* **Crash-proof.** A malformed message is logged and acked (it can never be
  parsed, so redelivery would only poison the subscription); a transient dispatch
  failure is logged and left un-acked for Pub/Sub to redeliver. One bad message
  never sinks the batch.

Opt-in and default OFF: the consumer only runs when
``AGENT_BOM_GCP_EVENT_SUBSCRIPTION`` is set (read live) — the full Pub/Sub
subscription path the operator wired the feed/sink to. The subscription is
operator-owned, so the control plane reads it with its OWN ambient credentials —
distinct from the customer read-only credential used for the posture re-evaluation.

Requires ``google-cloud-pubsub`` for the subscriber. Install with
``pip install 'agent-bom[gcp]'``.
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
# The value is the full Pub/Sub subscription path the operator routed the feed to.
EVENT_SUBSCRIPTION_ENV = "AGENT_BOM_GCP_EVENT_SUBSCRIPTION"


@dataclass(frozen=True)
class _ResourceRule:
    """How to re-evaluate posture for one GCP resource-type token.

    ``inventory_kwargs`` scopes :func:`gcp_inventory.discover_inventory` to just
    the affected resource class (so we re-fetch that resource, not the estate).
    ``check_ids`` is the exact GCP CIS subset re-run for the type. ``locators``
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
        "include_iam": False,
        "include_containers": False,
        "include_serverless": False,
        "include_databases": False,
        "include_networks": False,
        "include_disks": False,
        "include_messaging": False,
    }
    base.update(flags)
    return base


# Resource-type token → posture re-evaluation rule. Cloud Asset ``assetType`` /
# audit-log ``serviceName`` + ``resourceName`` collapse to these tokens (see
# ``_resolve_token``).
_RESOURCE_RULES: dict[str, _ResourceRule] = {
    "storage": _ResourceRule(
        check_ids=("5.1", "5.2"),
        inventory_kwargs=_only(include_storage=True),
        locators=(("buckets", "name"), ("buckets", "id")),
    ),
    "compute": _ResourceRule(
        check_ids=("4.1", "4.3", "4.5", "4.6", "4.8", "4.9", "4.11"),
        inventory_kwargs=_only(include_compute=True),
        locators=(("instances", "name"), ("instances", "instance_id")),
    ),
    "firewall": _ResourceRule(
        check_ids=("3.6", "3.7", "3.8"),
        inventory_kwargs=_only(include_compute=True),
        locators=(("firewalls", "name"), ("firewalls", "group_id")),
    ),
    "sql": _ResourceRule(
        check_ids=("6.1", "6.2", "6.3"),
        inventory_kwargs=_only(include_databases=True),
        locators=(("cloud_sql_instances", "name"), ("cloud_sql_instances", "id")),
    ),
    "iam": _ResourceRule(
        check_ids=("1.4", "1.5", "1.6", "1.7"),
        inventory_kwargs=_only(include_iam=True),
        locators=(("service_accounts", "email"), ("service_accounts", "name")),
    ),
}

# Cloud Asset ``assetType`` (lower-cased) → service token.
_ASSET_TYPE_TOKENS: dict[str, str] = {
    "storage.googleapis.com/bucket": "storage",
    "compute.googleapis.com/instance": "compute",
    "compute.googleapis.com/firewall": "firewall",
    "sqladmin.googleapis.com/instance": "sql",
    "iam.googleapis.com/serviceaccount": "iam",
}


def event_ingest_enabled() -> bool:
    """Return whether GCP event-driven ingestion is opted in (subscription set).

    Read live so operators and tests can toggle it. Default OFF: with no
    subscription the consumer is a no-op and only the polling scheduler runs.
    """
    return bool(os.environ.get(EVENT_SUBSCRIPTION_ENV, "").strip())


def _uri_segments(uri: str) -> list[str]:
    return [seg for seg in (uri or "").split("/") if seg and seg != ":"]


def _project_from_uri(uri: str) -> str:
    """Pull a concrete project id out of a resource name / asset name.

    ``//compute.googleapis.com/projects/<proj>/zones/.../instances/<n>`` →
    ``<proj>``. Skips the ``_`` placeholder Cloud Storage bucket names use.
    """
    segs = _uri_segments(uri)
    for idx, seg in enumerate(segs):
        if seg.lower() == "projects" and idx + 1 < len(segs):
            candidate = segs[idx + 1]
            if candidate and candidate != "_":
                return candidate
    return ""


def _resource_name(uri: str) -> str:
    """Return the trailing resource name from a resource path / asset name."""
    segs = _uri_segments(uri)
    return segs[-1] if segs else ""


def _resolve_token(asset_type: str, service_name: str, resource_name: str) -> str:
    """Collapse an assetType / serviceName+resourceName to a service token."""
    at = (asset_type or "").strip().lower()
    if at:
        return _ASSET_TYPE_TOKENS.get(at, "")
    sn = (service_name or "").strip().lower()
    rn = (resource_name or "").strip().lower()
    if sn.startswith("storage."):
        return "storage"
    if sn.startswith("sqladmin."):
        return "sql"
    if sn.startswith("iam.") and "serviceaccount" in rn:
        return "iam"
    if sn.startswith("compute."):
        if "/firewalls/" in rn:
            return "firewall"
        if "/instances/" in rn:
            return "compute"
    return ""


def parse_gcp_event(message: str | dict[str, Any]) -> CloudChangeEvent | None:
    """Parse a Cloud Asset feed / audit-log message into a :class:`CloudChangeEvent`.

    Accepts either a Cloud Asset Inventory feed message (``{"asset": {"name",
    "assetType"}, ...}``) or a Pub/Sub-exported audit-log entry
    (``{"protoPayload": {"methodName", "resourceName", "serviceName"}, "resource":
    {"labels": {"project_id"}}}``). Returns ``None`` for anything malformed or for
    a resource type with no posture rule — the caller treats ``None`` as "skip,
    do not crash".
    """
    try:
        obj = json.loads(message) if isinstance(message, (str, bytes)) else message
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None

    asset = obj.get("asset")
    asset = asset if isinstance(asset, dict) else {}
    proto = obj.get("protoPayload")
    proto = proto if isinstance(proto, dict) else {}
    resource = obj.get("resource")
    resource = resource if isinstance(resource, dict) else {}
    labels = resource.get("labels")
    labels = labels if isinstance(labels, dict) else {}

    asset_type = str(asset.get("assetType") or "").strip()
    service_name = str(proto.get("serviceName") or "").strip()
    resource_uri = (
        str(asset.get("name") or "").strip() or str(proto.get("resourceName") or "").strip() or str(obj.get("resourceName") or "").strip()
    )

    token = _resolve_token(asset_type, service_name, resource_uri)
    if token not in _RESOURCE_RULES:
        return None

    resource_name = _resource_name(resource_uri)
    project = str(obj.get("projectId") or "").strip() or str(labels.get("project_id") or "").strip() or _project_from_uri(resource_uri)
    action = str(proto.get("methodName") or "").strip() or str(obj.get("priorAssetState") or "").strip() or "AssetChange"

    # Fail closed: without a project and a resource name we cannot safely
    # attribute or scope the re-evaluation.
    if not project or not resource_name:
        return None

    return CloudChangeEvent(
        provider="gcp",
        account=project,
        region="",
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
    credentials: Any = None,
    benchmark_runner: Callable[..., Any] | None = None,
    persist: Callable[[CloudConnectionRecord, str, Any], str] | None = None,
    store: Any = None,
) -> dict[str, Any] | None:
    """Re-evaluate posture for one changed GCP resource and emit the delta.

    Resolves the changed resource via a scoped read-only inventory fetch, re-runs
    ONLY the GCP CIS checks for its resource type against the brokered read-only
    service-account credential, persists the resulting posture through the same
    scan/graph path a full scan uses, and stamps ``last_event_at``.

    Fail-closed: the event's provider must be ``gcp`` and its project must match
    the connection's own project (from ``auth_params``); a mismatch returns
    ``None`` without touching the customer project. An unknown resource type also
    returns ``None``.
    """
    tenant_id = tenant_id or record.tenant_id

    if (event.provider or "").strip().lower() != "gcp":
        logger.warning("Dropping non-GCP change event (provider=%s)", event.provider)
        return None
    if (record.provider or "").strip().lower() != "gcp":
        logger.warning("Connection %s is not GCP; cannot dispatch GCP change event", record.id)
        return None

    connection_project = str(record.auth_params.get("project_id") or "").strip()
    if not connection_project or event.account != connection_project:
        # Confused-deputy guard: never scan a project this connection does not own.
        logger.warning(
            "Dropping change event for project %s: does not match connection %s project",
            event.account,
            record.id,
        )
        return None

    rule = _RESOURCE_RULES.get(event.resource_type)
    if rule is None:
        return None

    from agent_bom.cloud import gcp_inventory
    from agent_bom.models import AIBOMReport

    run_cis_benchmark: Callable[..., Any]
    if benchmark_runner is not None:
        run_cis_benchmark = benchmark_runner
    else:
        from agent_bom.cloud.gcp_cis_benchmark import run_benchmark

        run_cis_benchmark = run_benchmark

    if credentials is None:
        from agent_bom.cloud.connection_broker import broker_session

        credentials = broker_session(record, session_name=f"agent-bom-event-{record.id[:8]}")

    inv = rule.inventory_kwargs
    inventory_payload = gcp_inventory.discover_inventory(
        project_id=connection_project,
        credentials=credentials,
        force=True,
        include_storage=inv["include_storage"],
        include_compute=inv["include_compute"],
        include_iam=inv["include_iam"],
        include_containers=inv["include_containers"],
        include_serverless=inv["include_serverless"],
        include_databases=inv["include_databases"],
        include_networks=inv["include_networks"],
        include_disks=inv["include_disks"],
        include_messaging=inv["include_messaging"],
    )
    affected = _find_affected_resource(rule, inventory_payload, event.resource_id)

    cis_report = run_cis_benchmark(project_id=connection_project, credentials=credentials, checks=list(rule.check_ids))
    cis_dict = cis_report.to_dict()
    findings = [check for check in cis_dict.get("checks", []) if check.get("status") == "fail"]

    import uuid as _uuid

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=str(_uuid.uuid4()))
    report.scan_sources = ["cloud_connection", "cloud:gcp", "event:asset_feed"]
    report.cloud_inventory_data = inventory_payload
    report.gcp_cis_benchmark_data = cis_dict

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
        "provider": "gcp",
        "scan_id": scan_id,
        "event": {
            "project_id": event.account,
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
                "Event-driven re-evaluation ran against short-lived read-only GCP service-account credentials "
                "(cloud-platform.read-only) brokered from the stored connection. Only the affected resource type's "
                "GCP CIS checks were re-run; no resource is mutated and no secret value is returned."
            ),
        },
    }


def consume_gcp_events(
    record: CloudConnectionRecord,
    *,
    tenant_id: str | None = None,
    subscription: str | None = None,
    subscriber_client: Any = None,
    credentials: Any = None,
    max_messages: int | None = None,
    max_batches: int | None = None,
    benchmark_runner: Callable[..., Any] | None = None,
    persist: Callable[[CloudConnectionRecord, str, Any], str] | None = None,
    store: Any = None,
) -> dict[str, Any]:
    """Pull a bounded batch of GCP change events from a Pub/Sub subscription.

    Pulls the operator-owned Pub/Sub subscription (Cloud Asset feed / audit-log
    sink) with the control plane's OWN ambient credentials, parses each message,
    and dispatches a per-resource posture re-evaluation for events that belong to
    *record*'s project. This is a BOUNDED pass: at most ``max_batches`` pulls of
    ``max_messages`` each, then it returns — there is no forever loop.

    Message lifecycle: a successfully dispatched message is acked; a malformed or
    foreign-project message is logged and acked (redelivery cannot help); a
    transient dispatch failure is logged and LEFT un-acked for Pub/Sub to
    redeliver. Never raises — one bad message cannot sink the batch. With no
    subscription configured it is a no-op (``status="disabled"``).
    """
    tenant_id = tenant_id or record.tenant_id
    subscription = subscription or os.environ.get(EVENT_SUBSCRIPTION_ENV, "").strip()

    summary: dict[str, Any] = {
        "status": "ok",
        "connection_id": record.id,
        "received": 0,
        "processed": 0,
        "acked": 0,
        "skipped_malformed": 0,
        "skipped_foreign": 0,
        "errors": 0,
        "batches": 0,
    }

    if not subscription:
        summary["status"] = "disabled"
        return summary

    max_messages = max(1, min(int(max_messages if max_messages is not None else config.GCP_EVENT_MAX_MESSAGES), 100))
    max_batches = max(1, int(max_batches if max_batches is not None else config.GCP_EVENT_MAX_BATCHES))

    connection_project = str(record.auth_params.get("project_id") or "").strip()

    if subscriber_client is None:
        try:
            from google.cloud import pubsub_v1
        except ImportError:
            summary["status"] = "sdk_missing"
            return summary
        try:
            subscriber_client = pubsub_v1.SubscriberClient()
        except Exception as exc:  # noqa: BLE001 — control-plane credential/config error must not crash
            logger.warning("Could not create Pub/Sub subscriber for event ingestion: %s", type(exc).__name__)
            summary["status"] = "no_credentials"
            return summary

    # Broker one read-only customer credential for the whole batch; every dispatch
    # reuses it. Absent a credential, dispatch would broker per-message.
    if credentials is None:
        try:
            from agent_bom.cloud.connection_broker import broker_session

            credentials = broker_session(record, session_name=f"agent-bom-event-{record.id[:8]}")
        except Exception as exc:  # noqa: BLE001 — a broker failure is not fatal to the pull drain contract
            logger.warning("Could not broker read-only credentials for GCP event ingestion: %s", type(exc).__name__)
            summary["status"] = "broker_failed"
            return summary

    for _ in range(max_batches):  # bounded: always terminates
        summary["batches"] += 1
        try:
            response = subscriber_client.pull(subscription=subscription, max_messages=max_messages)
        except Exception as exc:  # noqa: BLE001 — throttle / transient pull error: stop this pass cleanly
            logger.warning("Pub/Sub pull failed during event ingestion: %s", type(exc).__name__)
            summary["errors"] += 1
            break

        received = list(getattr(response, "received_messages", []) or [])
        if not received:
            break  # empty subscription: nothing more to drain this pass

        for received_message in received:
            summary["received"] += 1
            ack_id = getattr(received_message, "ack_id", None)
            pubsub_message = getattr(received_message, "message", None)
            data = getattr(pubsub_message, "data", b"") or b""
            body = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data)

            event = parse_gcp_event(body)
            if event is None:
                summary["skipped_malformed"] += 1
                _ack_message(subscriber_client, subscription, ack_id, summary)  # poison: drop it
                continue

            if event.account != connection_project:
                # Not this connection's project — never scan a foreign one.
                summary["skipped_foreign"] += 1
                _ack_message(subscriber_client, subscription, ack_id, summary)
                continue

            try:
                dispatch_change_event(
                    event,
                    record,
                    tenant_id=tenant_id,
                    credentials=credentials,
                    benchmark_runner=benchmark_runner,
                    persist=persist,
                    store=store,
                )
            except Exception as exc:  # noqa: BLE001 — leave un-acked for redelivery; never crash the drain
                logger.warning(
                    "GCP event dispatch failed for %s/%s: %s",
                    event.resource_type,
                    event.resource_id,
                    type(exc).__name__,
                )
                summary["errors"] += 1
                continue  # do NOT ack — Pub/Sub redelivers

            summary["processed"] += 1
            _ack_message(subscriber_client, subscription, ack_id, summary)

    return summary


def _ack_message(subscriber_client: Any, subscription: str, ack_id: str | None, summary: dict[str, Any]) -> None:
    """Best-effort Pub/Sub ack; an ack failure is logged, never raised."""
    if not ack_id:
        return
    try:
        subscriber_client.acknowledge(subscription=subscription, ack_ids=[ack_id])
        summary["acked"] += 1
    except Exception as exc:  # noqa: BLE001 — ack failure only means one redelivery
        logger.warning("Pub/Sub ack failed during event ingestion: %s", type(exc).__name__)
