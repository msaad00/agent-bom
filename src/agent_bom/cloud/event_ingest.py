"""Event-driven AWS posture ingestion (continuous / change-triggered CNAPP).

The polling scheduler (:mod:`agent_bom.api.connection_scheduler`) re-scans a
whole connection on an interval. This module adds the complementary, reactive
lane: when a resource changes in a customer account, AWS emits a CloudTrail
management event that EventBridge can route to an SQS queue. The control plane
drains that queue and re-evaluates **only** the CIS rules that apply to the
changed resource's type — so a bucket made public is re-checked in seconds
instead of waiting for the next scheduled full scan. Polling remains the
fallback; this is additive.

Trust posture (non-negotiable, fail-closed):

* **Read-only against the customer.** The changed resource is re-fetched and its
  CIS checks re-run through the SAME brokered, short-lived read-only role the
  scheduled scan uses (:func:`agent_bom.cloud.connection_broker.broker_session`).
  No write API is ever called on the customer account.
* **Account-bound.** A change event is only dispatched when its account matches
  the connection's own account (derived from the connection's ``role_ref`` ARN).
  A spoofed / cross-account event is dropped, never processed — this prevents a
  confused-deputy where an attacker-controlled queue message steers a scan at an
  account the tenant does not own.
* **Bounded.** :func:`consume_aws_events` drains at most a configured number of
  messages across a configured number of receive batches and then RETURNS. There
  is no forever loop; an operator (or a scheduler tick) invokes it repeatedly.
* **Crash-proof.** A malformed message is logged and deleted (it can never be
  parsed, so redelivery would only poison the queue); a transient dispatch/throttle
  failure is logged and left on the queue for the visibility timeout to redeliver.
  One bad message never sinks the batch.

Opt-in and default OFF: the consumer only runs when
``AGENT_BOM_AWS_EVENT_QUEUE_URL`` is set (read live). The queue is operator-owned
(EventBridge→SQS wiring is a deploy step), so the control plane reads it with its
OWN ambient credentials — distinct from the customer read-only role used for the
posture re-evaluation.

Requires ``boto3`` for the SQS consumer. Install with ``pip install 'agent-bom[aws]'``.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from agent_bom import config
from agent_bom.api.connection_store import CloudConnectionRecord

logger = logging.getLogger(__name__)

# Opt-in gate (read live so operators/tests can toggle it). Absence = disabled.
EVENT_QUEUE_URL_ENV = "AGENT_BOM_AWS_EVENT_QUEUE_URL"

# Detail-type EventBridge stamps on CloudTrail-sourced API-call events. Accepted
# as an authenticity signal; a message whose detail-type is present but does not
# match is treated as malformed (not our shape).
_CLOUDTRAIL_DETAIL_TYPE = "AWS API Call via CloudTrail"


@dataclass
class CloudChangeEvent:
    """One normalized cloud resource-change event.

    Provider-neutral shape (AWS is the only producer today). ``resource_type`` is
    the canonical service token (e.g. ``"s3"``, ``"ec2"``, ``"iam"``) the rule
    registry keys off; ``raw`` retains the original event for audit/debugging.
    """

    provider: str
    account: str
    region: str
    resource_type: str
    resource_id: str
    action: str
    arn: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _ResourceRule:
    """How to re-evaluate posture for one resource-type token.

    ``inventory_kwargs`` scopes :func:`aws_inventory.discover_inventory` to just
    the affected resource class (so we re-fetch that resource, not the estate).
    ``check_ids`` is the exact CIS subset re-run for the type. ``locators`` maps
    inventory payload list keys to the field that identifies a single resource,
    so the changed resource can be picked out of the class fetch for the delta.
    """

    check_ids: tuple[str, ...]
    inventory_kwargs: dict[str, bool]
    locators: tuple[tuple[str, str], ...]


# Only the affected class is fetched; every other include_* flag is forced off.
def _only(**flags: bool) -> dict[str, bool]:
    base = {
        "include_s3": False,
        "include_ec2": False,
        "include_iam": False,
        "include_data": False,
        "include_compute": False,
        "include_network": False,
    }
    base.update(flags)
    return base


# Resource-type token → posture re-evaluation rule. CloudTrail ``eventSource`` /
# EventBridge ``source`` collapse to these tokens (see ``_canonical_resource_type``).
_RESOURCE_RULES: dict[str, _ResourceRule] = {
    "s3": _ResourceRule(
        check_ids=("2.1.1", "2.1.2", "2.1.3", "2.1.4", "3.3", "3.6"),
        inventory_kwargs=_only(include_s3=True),
        locators=(("buckets", "name"), ("buckets", "arn")),
    ),
    "ec2": _ResourceRule(
        check_ids=("1.19", "2.2.1", "3.9", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6"),
        inventory_kwargs=_only(include_ec2=True, include_network=True),
        locators=(("security_groups", "group_id"), ("instances", "instance_id")),
    ),
    "iam": _ResourceRule(
        check_ids=(
            "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10", "1.11", "1.12",
            "1.13", "1.14", "1.15", "1.16", "1.17", "1.20", "1.22",
        ),
        inventory_kwargs=_only(include_iam=True),
        locators=(("roles", "name"), ("users", "name"), ("groups", "name")),
    ),
    "rds": _ResourceRule(
        check_ids=("2.3.1", "2.3.2"),
        inventory_kwargs=_only(include_data=True),
        locators=(("rds_instances", "identifier"), ("rds_instances", "name")),
    ),
    "kms": _ResourceRule(
        check_ids=("2.4.1",),
        inventory_kwargs=_only(include_data=True),
        locators=(("kms_keys", "key_id"), ("kms_keys", "arn")),
    ),
    "cloudtrail": _ResourceRule(
        check_ids=("3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.10", "3.11"),
        inventory_kwargs=_only(),
        locators=(),
    ),
}

# CloudTrail requestParameters/responseElements keys that carry the changed
# resource id, tried in order per token. First present wins.
_RESOURCE_ID_KEYS: dict[str, tuple[str, ...]] = {
    "s3": ("bucketName",),
    "ec2": ("groupId", "instanceId", "networkAclId", "routeTableId", "vpcId"),
    "iam": ("roleName", "userName", "groupName", "policyArn", "policyName"),
    "rds": ("dBInstanceIdentifier",),
    "kms": ("keyId",),
    "cloudtrail": ("name", "trailName"),
}


def event_ingest_enabled() -> bool:
    """Return whether event-driven ingestion is opted in (queue URL configured).

    Read live so operators and tests can toggle it. Default OFF: with no queue
    URL the consumer is a no-op and only the polling scheduler runs.
    """
    return bool(os.environ.get(EVENT_QUEUE_URL_ENV, "").strip())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _account_from_role_ref(role_ref: str) -> str:
    """Extract the AWS account id from a connection ``role_ref`` ARN.

    ``arn:aws:iam::123456789012:role/agent-bom-readonly`` → ``123456789012``.
    Returns "" when the ref is not an ARN (defensive; callers fail closed).
    """
    parts = (role_ref or "").split(":")
    return parts[4] if len(parts) > 4 else ""


def _canonical_resource_type(source: str) -> str:
    """Collapse a CloudTrail eventSource / EventBridge source to a service token.

    ``"s3.amazonaws.com"`` → ``"s3"``; ``"aws.s3"`` → ``"s3"``. Lower-cased.
    """
    token = (source or "").strip().lower()
    if token.startswith("aws."):
        token = token[len("aws.") :]
    if token.endswith(".amazonaws.com"):
        token = token[: -len(".amazonaws.com")]
    return token


def _extract_resource_id(token: str, detail: dict[str, Any]) -> str:
    """Pull the changed resource id from a CloudTrail detail's parameters."""
    params: dict[str, Any] = {}
    for key in ("requestParameters", "responseElements"):
        value = detail.get(key)
        if isinstance(value, dict):
            params.update(value)
    for candidate in _RESOURCE_ID_KEYS.get(token, ()):  # first present wins
        value = params.get(candidate)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def parse_cloudtrail_event(message: str | dict[str, Any]) -> CloudChangeEvent | None:
    """Parse an EventBridge/CloudTrail message into a :class:`CloudChangeEvent`.

    Accepts either the EventBridge envelope (``{"detail-type", "source",
    "account", "region", "detail": {...}}``) or a bare CloudTrail record. Returns
    ``None`` for anything malformed or for a resource type with no posture rule —
    the caller treats ``None`` as "skip, do not crash".
    """
    try:
        obj = json.loads(message) if isinstance(message, (str, bytes)) else message
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None

    detail = obj.get("detail")
    if not isinstance(detail, dict):
        detail = obj  # bare CloudTrail record

    # An EventBridge envelope with an unexpected detail-type is not our shape.
    detail_type = obj.get("detail-type")
    if detail_type is not None and detail_type != _CLOUDTRAIL_DETAIL_TYPE:
        return None

    source = obj.get("source") or detail.get("eventSource") or ""
    token = _canonical_resource_type(str(source))
    if token not in _RESOURCE_RULES:
        return None

    user_identity = detail.get("userIdentity")
    account = (
        str(obj.get("account") or "").strip()
        or str(detail.get("recipientAccountId") or "").strip()
        or (str(user_identity.get("accountId") or "").strip() if isinstance(user_identity, dict) else "")
    )
    action = str(detail.get("eventName") or "").strip()
    region = str(obj.get("region") or detail.get("awsRegion") or "").strip()
    resource_id = _extract_resource_id(token, detail)

    # Fail closed: without an account, an action, and a resource id we cannot
    # safely attribute or scope the re-evaluation.
    if not account or not action or not resource_id:
        return None

    return CloudChangeEvent(
        provider="aws",
        account=account,
        region=region,
        resource_type=token,
        resource_id=resource_id,
        action=action,
        arn=str(detail.get("resources", "") or "") if not isinstance(detail.get("resources"), list) else "",
        raw=obj if isinstance(obj, dict) else {},
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


def _default_persist(record: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
    """Persist an event-driven report through the same scan/graph path as a scan.

    Imported lazily so this module (and its unit tests) do not pull the API route
    layer at import time — mirrors the connection scheduler's lazy route import.
    """
    from agent_bom.api.routes.cloud_connections import _persist_connection_report

    return _persist_connection_report(record, tenant_id, report)


def dispatch_change_event(
    event: CloudChangeEvent,
    record: CloudConnectionRecord,
    *,
    tenant_id: str | None = None,
    session: Any = None,
    benchmark_runner: Callable[..., Any] | None = None,
    persist: Callable[[CloudConnectionRecord, str, Any], str] | None = None,
    store: Any = None,
) -> dict[str, Any] | None:
    """Re-evaluate posture for one changed resource and emit the delta.

    Resolves the changed resource via a scoped read-only inventory fetch, re-runs
    ONLY the CIS checks for its resource type against the brokered read-only
    session, persists the resulting posture through the same scan/graph path a
    full scan uses, and stamps ``last_event_at`` on the connection.

    Fail-closed: the event's provider must be ``aws`` and its account must match
    the connection's own account (from ``role_ref``); a mismatch returns ``None``
    without touching the customer account. An unknown resource type also returns
    ``None``. Returns a non-secret delta summary on success.
    """
    tenant_id = tenant_id or record.tenant_id

    if (event.provider or "").strip().lower() != "aws":
        logger.warning("Dropping non-AWS change event (provider=%s)", event.provider)
        return None
    if (record.provider or "").strip().lower() != "aws":
        logger.warning("Connection %s is not AWS; cannot dispatch AWS change event", record.id)
        return None

    connection_account = _account_from_role_ref(record.role_ref)
    if not connection_account or event.account != connection_account:
        # Confused-deputy guard: never scan an account this connection does not own.
        logger.warning(
            "Dropping change event for account %s: does not match connection %s account",
            event.account,
            record.id,
        )
        return None

    rule = _RESOURCE_RULES.get(event.resource_type)
    if rule is None:
        return None

    from agent_bom.cloud import aws_inventory
    from agent_bom.models import AIBOMReport

    run_cis_benchmark: Callable[..., Any]
    if benchmark_runner is not None:
        run_cis_benchmark = benchmark_runner
    else:
        from agent_bom.cloud.aws_cis_benchmark import run_benchmark

        run_cis_benchmark = run_benchmark

    if session is None:
        from agent_bom.cloud.connection_broker import broker_session

        session = broker_session(record, session_name=f"agent-bom-event-{record.id[:8]}")

    region = event.region or (record.regions[0] if record.regions else None)

    inv = rule.inventory_kwargs
    inventory_payload = aws_inventory.discover_inventory(
        region=region,
        force=True,
        session=session,
        include_s3=inv["include_s3"],
        include_ec2=inv["include_ec2"],
        include_iam=inv["include_iam"],
        include_data=inv["include_data"],
        include_compute=inv["include_compute"],
        include_network=inv["include_network"],
    )
    affected = _find_affected_resource(rule, inventory_payload, event.resource_id)

    cis_report = run_cis_benchmark(region=region, session=session, checks=list(rule.check_ids))
    cis_dict = cis_report.to_dict()
    findings = [check for check in cis_dict.get("checks", []) if check.get("status") == "fail"]

    import uuid as _uuid

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=str(_uuid.uuid4()))
    report.scan_sources = ["cloud_connection", "cloud:aws", "event:cloudtrail"]
    report.cloud_inventory_data = inventory_payload
    report.cis_benchmark_data = cis_dict

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
        "provider": "aws",
        "scan_id": scan_id,
        "event": {
            "account": event.account,
            "region": event.region,
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
                "Event-driven re-evaluation ran against a short-lived read-only role assumed from the stored "
                "connection. Only the affected resource type's CIS checks were re-run; no resource is mutated "
                "and no secret value is returned."
            ),
        },
    }


def consume_aws_events(
    record: CloudConnectionRecord,
    *,
    tenant_id: str | None = None,
    queue_url: str | None = None,
    sqs_client: Any = None,
    session: Any = None,
    max_messages: int | None = None,
    max_batches: int | None = None,
    visibility_timeout: int | None = None,
    wait_seconds: int | None = None,
    benchmark_runner: Callable[..., Any] | None = None,
    persist: Callable[[CloudConnectionRecord, str, Any], str] | None = None,
    store: Any = None,
) -> dict[str, Any]:
    """Drain a bounded batch of AWS change events from SQS and dispatch each.

    Long-polls the operator-owned SQS queue (EventBridge→SQS) with the control
    plane's OWN ambient credentials, parses each CloudTrail message, and
    dispatches a per-resource posture re-evaluation for events that belong to
    *record*'s account. This is a BOUNDED pass: at most ``max_batches`` receives
    of ``max_messages`` each, then it returns — there is no forever loop; an
    operator or scheduler tick invokes it repeatedly.

    Message lifecycle: a successfully dispatched message is deleted; a malformed
    or foreign-account message is logged and deleted (redelivery cannot help); a
    transient dispatch failure is logged and LEFT on the queue for the visibility
    timeout to redeliver. Never raises — one bad message cannot sink the batch.

    Returns a non-secret summary of what happened (counts + status). With no
    queue configured it is a no-op (``status="disabled"``).
    """
    tenant_id = tenant_id or record.tenant_id
    queue_url = queue_url or os.environ.get(EVENT_QUEUE_URL_ENV, "").strip()

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

    max_messages = max(1, min(int(max_messages if max_messages is not None else config.AWS_EVENT_MAX_MESSAGES), 10))
    max_batches = max(1, int(max_batches if max_batches is not None else config.AWS_EVENT_MAX_BATCHES))
    visibility_timeout = max(
        0, int(visibility_timeout if visibility_timeout is not None else config.AWS_EVENT_VISIBILITY_TIMEOUT)
    )
    wait_seconds = max(0, min(int(wait_seconds if wait_seconds is not None else config.AWS_EVENT_WAIT_SECONDS), 20))

    if sqs_client is None:
        try:
            import boto3
        except ImportError:
            summary["status"] = "boto3_missing"
            return summary
        try:
            sqs_client = boto3.client("sqs")
        except Exception as exc:  # noqa: BLE001 — control-plane credential/config error must not crash
            logger.warning("Could not create SQS client for event ingestion: %s", type(exc).__name__)
            summary["status"] = "no_credentials"
            return summary

    # Broker one read-only customer session for the whole batch (AssumeRole is not
    # cheap); every dispatch reuses it. Absent a session, dispatch would broker
    # per-message — brokering once here is the bounded, efficient path.
    if session is None:
        try:
            from agent_bom.cloud.connection_broker import broker_session

            session = broker_session(record, session_name=f"agent-bom-event-{record.id[:8]}")
        except Exception as exc:  # noqa: BLE001 — a broker failure is not fatal to the queue drain contract
            logger.warning("Could not broker read-only session for event ingestion: %s", type(exc).__name__)
            summary["status"] = "broker_failed"
            return summary

    for _ in range(max_batches):  # bounded: always terminates
        summary["batches"] += 1
        try:
            resp = sqs_client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=max_messages,
                WaitTimeSeconds=wait_seconds,
                VisibilityTimeout=visibility_timeout,
            )
        except Exception as exc:  # noqa: BLE001 — throttle / transient receive error: stop this pass cleanly
            logger.warning("SQS receive failed during event ingestion: %s", type(exc).__name__)
            summary["errors"] += 1
            break

        messages = resp.get("Messages", []) or []
        if not messages:
            break  # empty queue: nothing more to drain this pass

        for message in messages:
            summary["received"] += 1
            receipt = message.get("ReceiptHandle")
            body = message.get("Body", "")

            event = parse_cloudtrail_event(body)
            if event is None:
                summary["skipped_malformed"] += 1
                _delete_message(sqs_client, queue_url, receipt, summary)  # poison: drop it
                continue

            if event.account != _account_from_role_ref(record.role_ref):
                # Not this connection's account — never scan a foreign account.
                summary["skipped_foreign"] += 1
                _delete_message(sqs_client, queue_url, receipt, summary)
                continue

            try:
                dispatch_change_event(
                    event,
                    record,
                    tenant_id=tenant_id,
                    session=session,
                    benchmark_runner=benchmark_runner,
                    persist=persist,
                    store=store,
                )
            except Exception as exc:  # noqa: BLE001 — leave on queue for redelivery; never crash the drain
                logger.warning(
                    "Event dispatch failed for %s/%s: %s",
                    event.resource_type,
                    event.resource_id,
                    type(exc).__name__,
                )
                summary["errors"] += 1
                continue  # do NOT delete — visibility timeout redelivers

            summary["processed"] += 1
            _delete_message(sqs_client, queue_url, receipt, summary)

    return summary


def _delete_message(sqs_client: Any, queue_url: str, receipt: str | None, summary: dict[str, Any]) -> None:
    """Best-effort SQS delete; a delete failure is logged, never raised."""
    if not receipt:
        return
    try:
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt)
        summary["deleted"] += 1
    except Exception as exc:  # noqa: BLE001 — delete failure only means one redelivery
        logger.warning("SQS delete failed during event ingestion: %s", type(exc).__name__)
