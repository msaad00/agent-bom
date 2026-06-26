"""Read-only cloud audit-trail ingestion — behavioral security-signal extraction.

This is **not** a log/observability platform. agent-bom reads the
security-relevant slice of each cloud's native audit trail (AWS CloudTrail,
Azure Activity Log, GCP Cloud Audit Logs), derives **behavioral graph edges**
("who *did* reach what"), emits a few behavioral findings, and drops the raw
events. Logs stay in the customer's account; agent-bom never stores, indexes,
or re-emits raw log lines.

Design contract
---------------
* **Read-only** — only the providers' read/lookup APIs are ever called
  (``cloudtrail:LookupEvents``, ``Microsoft.Insights/eventtypes/values/read``,
  ``logging.logEntries.list``). No write/mutate API is referenced anywhere.
* **Opt-in** — disabled unless ``AGENT_BOM_AUDIT_TRAIL`` is truthy. A scan that
  does not set it is a clean no-op; nothing is read.
* **Nothing-silent** — a missing read permission yields a clear, actionable
  warning naming the exact grant required, never a silent skip or a crash.
* **Bounded** — lookback window and event count are capped (env-configurable);
  hitting a cap appends a ``truncated`` warning, never silent truncation.
* **No raw-log retention** — the reader returns normalized
  ``(principal, action, resource, time, outcome)`` tuples only. The builder
  aggregates them into ``(principal, resource, action) → count + last_seen``
  edges; the raw event list is never persisted into the report contract.

The output of :func:`collect_audit_trail` is the ``status: ok`` payload contract
that :func:`agent_bom.graph.builder._add_cloud_audit_behavioral` consumes,
mirroring the Snowflake ACCESS_HISTORY → ACCESSED layer.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Opt-in gate ───────────────────────────────────────────────────────────
_OPT_IN_ENV = "AGENT_BOM_AUDIT_TRAIL"

# ── Bounds (env-configurable; never silently exceeded) ────────────────────
_LOOKBACK_ENV = "AGENT_BOM_AUDIT_TRAIL_LOOKBACK_HOURS"
_MAX_EVENTS_ENV = "AGENT_BOM_AUDIT_TRAIL_MAX_EVENTS"
_DEFAULT_LOOKBACK_HOURS = 24
_DEFAULT_MAX_EVENTS = 2000
_MAX_LOOKBACK_HOURS = 24 * 14  # two weeks — a security slice, not an archive
_HARD_MAX_EVENTS = 20000

# ── Action classification → relationship class ────────────────────────────
# Write/management/invoke verbs map to INVOKED (an action *taken*); read verbs
# map to ACCESSED (data/resource *reached*). Kept deliberately small and
# explicit — the default is ACCESSED so an unknown verb still draws a reach
# edge rather than being dropped.
_INVOKE_VERB_PREFIXES = (
    "create",
    "delete",
    "update",
    "modify",
    "put",
    "set",
    "attach",
    "detach",
    "start",
    "stop",
    "run",
    "invoke",
    "terminate",
    "write",
    "remove",
    "add",
    "assume",
    "authorize",
    "revoke",
    "deploy",
    "reboot",
    "restore",
)

_SENSITIVE_RESOURCE_HINTS = (
    "secret",
    "key",
    "credential",
    "iam",
    "kms",
    "vault",
    "password",
    "token",
    "policy",
    "role",
)


def is_enabled() -> bool:
    """True when audit-trail ingestion is opted in via ``AGENT_BOM_AUDIT_TRAIL``."""
    return os.environ.get(_OPT_IN_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _bounded_int(env: str, default: int, hard_max: int) -> int:
    raw = os.environ.get(env, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using default %d", env, raw, default)
        return default
    if value <= 0:
        return default
    return min(value, hard_max)


def lookback_hours() -> int:
    """Configured lookback window in hours, clamped to :data:`_MAX_LOOKBACK_HOURS`."""
    return _bounded_int(_LOOKBACK_ENV, _DEFAULT_LOOKBACK_HOURS, _MAX_LOOKBACK_HOURS)


def max_events() -> int:
    """Configured per-provider event cap, clamped to :data:`_HARD_MAX_EVENTS`."""
    return _bounded_int(_MAX_EVENTS_ENV, _DEFAULT_MAX_EVENTS, _HARD_MAX_EVENTS)


def classify_action(action: str) -> str:
    """Map a raw cloud action verb to a relationship class.

    Returns ``"invoked"`` for management/write/mutate verbs and ``"accessed"``
    for everything else (reads + unknown verbs). The action string may be a
    fully-qualified event name (``ec2:RunInstances``, ``Microsoft.Storage/...``);
    the leading service prefix is stripped before matching.
    """
    verb = (action or "").strip()
    if not verb:
        return "accessed"
    # Strip a service prefix: "ec2:RunInstances" -> "RunInstances",
    # "Microsoft.Storage/storageAccounts/write" -> "write".
    for sep in (":", "/"):
        if sep in verb:
            verb = verb.rsplit(sep, 1)[-1]
    low = verb.lower()
    if any(low.startswith(p) for p in _INVOKE_VERB_PREFIXES):
        return "invoked"
    return "accessed"


def _is_sensitive_resource(resource: str) -> bool:
    low = (resource or "").lower()
    return any(hint in low for hint in _SENSITIVE_RESOURCE_HINTS)


# ── Normalized event ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuditEvent:
    """A single normalized, security-relevant audit event.

    Carries only the signal needed to draw a behavioral edge — never the raw
    log record. ``time`` is an ISO-8601 string (or empty if absent).
    """

    principal: str
    action: str
    resource: str
    time: str = ""
    outcome: str = "success"  # "success" | "failure"

    def as_tuple(self) -> tuple[str, str, str, str, str]:
        return (self.principal, self.action, self.resource, self.time, self.outcome)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _iso(value: Any) -> str:
    """Best-effort ISO-8601 normalization of a timestamp-ish value."""
    if value is None or value == "":
        return ""
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    return str(value).strip()


# ── Permission-guidance strings (nothing-silent) ──────────────────────────

_GRANT_GUIDANCE = {
    "aws": "grant cloudtrail:LookupEvents to enable audit-trail behavioral edges",
    "azure": ("grant the 'Monitoring Reader' role (Microsoft.Insights/eventtypes/values/read) to enable audit-trail behavioral edges"),
    "gcp": "grant roles/logging.viewer (logging.logEntries.list) to enable audit-trail behavioral edges",
}


def _permission_warning(provider: str, detail: str = "") -> str:
    guidance = _GRANT_GUIDANCE.get(provider, "grant read-only audit-log access")
    base = f"{provider}: audit-trail read denied — {guidance}"
    return f"{base} ({detail})" if detail else base


# ── AWS CloudTrail (read-only LookupEvents) ───────────────────────────────


def read_aws_cloudtrail(
    *,
    region: str | None = None,
    profile: str | None = None,
    now: datetime | None = None,
    session_factory: Any | None = None,
) -> tuple[list[AuditEvent], list[str]]:
    """Read recent management events from CloudTrail via read-only LookupEvents.

    ``session_factory`` (a zero-arg callable returning a boto3-like session) is
    an injection point for tests; production uses the standard boto3 chain.
    Returns ``(events, warnings)``; warnings are actionable, never silent.
    """
    warnings: list[str] = []
    start = (now or _now()) - timedelta(hours=lookback_hours())
    cap = max_events()

    if session_factory is None:
        try:
            import boto3  # noqa: F811

            def session_factory() -> Any:  # type: ignore[misc]
                kwargs: dict[str, Any] = {}
                if region:
                    kwargs["region_name"] = region
                if profile:
                    kwargs["profile_name"] = profile
                return boto3.Session(**kwargs)
        except ImportError:
            return [], ["aws: boto3 not installed; install 'agent-bom[aws]' to enable audit-trail edges"]

    try:
        from botocore.exceptions import ClientError, NoCredentialsError  # type: ignore
    except ImportError:  # pragma: no cover - boto3 implies botocore
        ClientError = Exception  # type: ignore[assignment,misc]  # noqa: N806
        NoCredentialsError = Exception  # type: ignore[assignment,misc]  # noqa: N806

    try:
        session = session_factory()
        client = session.client("cloudtrail")
    except NoCredentialsError:
        return [], ["aws: no credentials resolved for CloudTrail audit-trail read"]
    except Exception as exc:  # pragma: no cover - defensive
        return [], [f"aws: could not initialize CloudTrail client ({exc})"]

    events: list[AuditEvent] = []
    truncated = False
    try:
        paginator = client.get_paginator("lookup_events")
        pages = paginator.paginate(
            StartTime=start,
            EndTime=(now or _now()),
            PaginationConfig={"PageSize": 50},
        )
        for page in pages:
            for raw in page.get("Events", []) or []:
                evt = _normalize_aws_event(raw)
                if evt is None:
                    continue
                events.append(evt)
                if len(events) >= cap:
                    truncated = True
                    break
            if truncated:
                break
    except ClientError as exc:  # type: ignore[misc]
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            return [], [_permission_warning("aws", "cloudtrail:LookupEvents denied")]
        return [], [f"aws: CloudTrail LookupEvents failed ({code or exc})"]
    except Exception as exc:  # pragma: no cover - defensive
        return [], [f"aws: CloudTrail read error ({exc})"]

    if truncated:
        warnings.append(f"aws: audit-trail capped at {cap} events (raise {_MAX_EVENTS_ENV} to widen)")
    return events, warnings


def _normalize_aws_event(raw: Any) -> AuditEvent | None:
    if not isinstance(raw, dict):
        return None
    action = _clean(raw.get("EventName"))
    principal = _clean(raw.get("Username"))
    resources = raw.get("Resources") or []
    resource = ""
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            resource = _clean(first.get("ResourceName")) or _clean(first.get("ResourceType"))
    resource = resource or _clean(raw.get("EventSource"))
    if not principal or not action or not resource:
        return None
    return AuditEvent(
        principal=principal,
        action=action,
        resource=resource,
        time=_iso(raw.get("EventTime")),
        outcome="success",
    )


# ── Azure Activity Log (read-only) ────────────────────────────────────────


def read_azure_activity_log(
    *,
    subscription_id: str | None = None,
    now: datetime | None = None,
    client_factory: Any | None = None,
) -> tuple[list[AuditEvent], list[str]]:
    """Read recent management events from the Azure Activity Log (read-only).

    ``client_factory`` returns a ``MonitorManagementClient``-like object whose
    ``activity_logs.list(filter=...)`` yields event records; injected for tests.
    """
    warnings: list[str] = []
    start = (now or _now()) - timedelta(hours=lookback_hours())
    cap = max_events()

    resolved_sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
    if not resolved_sub:
        return [], [
            "azure: AZURE_SUBSCRIPTION_ID not set; provide a subscription to enable audit-trail edges",
        ]

    if client_factory is None:
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
            from azure.mgmt.monitor import MonitorManagementClient  # type: ignore

            def client_factory() -> Any:  # type: ignore[misc]
                return MonitorManagementClient(DefaultAzureCredential(), resolved_sub)
        except ImportError:
            return [], ["azure: azure-mgmt-monitor not installed; install 'agent-bom[azure]'"]

    try:
        client = client_factory()
    except Exception as exc:  # pragma: no cover - defensive
        return [], [f"azure: could not initialize Activity Log client ({exc})"]

    events: list[AuditEvent] = []
    truncated = False
    filt = f"eventTimestamp ge '{start.isoformat()}'"
    try:
        for raw in client.activity_logs.list(filter=filt):
            evt = _normalize_azure_event(raw)
            if evt is None:
                continue
            events.append(evt)
            if len(events) >= cap:
                truncated = True
                break
    except Exception as exc:
        name = type(exc).__name__
        msg = str(exc)
        if "Authorization" in msg or "Forbidden" in msg or name in {"HttpResponseError", "ClientAuthenticationError"}:
            return [], [_permission_warning("azure", "Activity Log read denied")]
        return [], [f"azure: Activity Log read failed ({name}: {msg})"]

    if truncated:
        warnings.append(f"azure: audit-trail capped at {cap} events (raise {_MAX_EVENTS_ENV} to widen)")
    return events, warnings


def _azure_attr(raw: Any, name: str) -> Any:
    if isinstance(raw, dict):
        return raw.get(name)
    return getattr(raw, name, None)


def _normalize_azure_event(raw: Any) -> AuditEvent | None:
    caller = _clean(_azure_attr(raw, "caller"))
    operation = _azure_attr(raw, "operation_name")
    action = _clean(_azure_attr(operation, "value") if operation is not None else "")
    resource = _clean(_azure_attr(raw, "resource_id"))
    status_obj = _azure_attr(raw, "status")
    status_val = _clean(_azure_attr(status_obj, "value") if status_obj is not None else "")
    outcome = "failure" if status_val.lower() in {"failed", "failure"} else "success"
    if not caller or not action or not resource:
        return None
    return AuditEvent(
        principal=caller,
        action=action,
        resource=resource,
        time=_iso(_azure_attr(raw, "event_timestamp")),
        outcome=outcome,
    )


# ── GCP Cloud Audit Logs (read-only logging read) ─────────────────────────


def read_gcp_audit_logs(
    *,
    project_id: str | None = None,
    now: datetime | None = None,
    client_factory: Any | None = None,
) -> tuple[list[AuditEvent], list[str]]:
    """Read recent Cloud Audit Log entries (read-only ``logging.logEntries.list``).

    ``client_factory`` returns a ``google.cloud.logging.Client``-like object
    exposing ``list_entries(filter_=..., page_size=...)``; injected for tests.
    """
    warnings: list[str] = []
    start = (now or _now()) - timedelta(hours=lookback_hours())
    cap = max_events()

    resolved_project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    if not resolved_project:
        return [], [
            "gcp: GOOGLE_CLOUD_PROJECT not set; provide a project to enable audit-trail edges",
        ]

    if client_factory is None:
        try:
            from google.cloud import logging as gcp_logging  # type: ignore

            def client_factory() -> Any:  # type: ignore[misc]
                return gcp_logging.Client(project=resolved_project)
        except ImportError:
            return [], ["gcp: google-cloud-logging not installed; install 'agent-bom[gcp]'"]

    try:
        client = client_factory()
    except Exception as exc:  # pragma: no cover - defensive
        return [], [f"gcp: could not initialize Cloud Logging client ({exc})"]

    events: list[AuditEvent] = []
    truncated = False
    filt = f'logName:"cloudaudit.googleapis.com" AND timestamp >= "{start.replace(microsecond=0).isoformat()}"'
    try:
        for entry in client.list_entries(filter_=filt, page_size=min(cap, 1000)):
            evt = _normalize_gcp_entry(entry)
            if evt is None:
                continue
            events.append(evt)
            if len(events) >= cap:
                truncated = True
                break
    except Exception as exc:
        name = type(exc).__name__
        msg = str(exc)
        if "permission" in msg.lower() or "denied" in msg.lower() or name in {"Forbidden", "PermissionDenied"}:
            return [], [_permission_warning("gcp", "logging.logEntries.list denied")]
        return [], [f"gcp: Cloud Audit Logs read failed ({name}: {msg})"]

    if truncated:
        warnings.append(f"gcp: audit-trail capped at {cap} events (raise {_MAX_EVENTS_ENV} to widen)")
    return events, warnings


def _normalize_gcp_entry(entry: Any) -> AuditEvent | None:
    payload = getattr(entry, "payload", None)
    if not isinstance(payload, dict):
        payload = {}
    auth = payload.get("authenticationInfo") or {}
    principal = _clean(auth.get("principalEmail")) if isinstance(auth, dict) else ""
    action = _clean(payload.get("methodName"))
    resource = _clean(payload.get("resourceName"))
    status = payload.get("status") or {}
    code = status.get("code") if isinstance(status, dict) else None
    outcome = "failure" if code not in (None, 0) else "success"
    ts = getattr(entry, "timestamp", None)
    if not principal or not action or not resource:
        return None
    return AuditEvent(
        principal=principal,
        action=action,
        resource=resource,
        time=_iso(ts),
        outcome=outcome,
    )


# ── Aggregation + payload assembly ─────────────────────────────────────────


@dataclass
class _Aggregate:
    principal: str
    action: str
    resource: str
    relationship: str
    count: int = 0
    last_seen: str = ""
    failures: int = 0
    sensitive: bool = False


def aggregate_events(events: Iterable[AuditEvent]) -> list[dict[str, Any]]:
    """Collapse raw events into ``(principal, resource, action)`` edge records.

    Deterministic: records are keyed by ``(principal, resource, action)``,
    counted, and stamped with the latest ``time`` seen. The raw events are
    *not* retained — only the aggregate edge descriptor is returned. Output is
    sorted for byte-stable downstream graph construction.
    """
    buckets: dict[tuple[str, str, str], _Aggregate] = {}
    for evt in events:
        principal = _clean(evt.principal)
        action = _clean(evt.action)
        resource = _clean(evt.resource)
        if not principal or not action or not resource:
            continue
        rel = classify_action(action)
        key = (principal, resource, action)
        agg = buckets.get(key)
        if agg is None:
            agg = _Aggregate(
                principal=principal,
                action=action,
                resource=resource,
                relationship=rel,
                sensitive=_is_sensitive_resource(resource),
            )
            buckets[key] = agg
        agg.count += 1
        if _clean(evt.outcome).lower() == "failure":
            agg.failures += 1
        ts = _iso(evt.time)
        if ts and ts > agg.last_seen:
            agg.last_seen = ts

    records = [
        {
            "principal": agg.principal,
            "action": agg.action,
            "resource": agg.resource,
            "relationship": agg.relationship,
            "count": agg.count,
            "last_seen": agg.last_seen,
            "failure_count": agg.failures,
            "is_sensitive_resource": agg.sensitive,
        }
        for agg in buckets.values()
    ]
    records.sort(key=lambda r: (r["principal"], r["resource"], r["action"]))
    return records


def derive_behavioral_findings(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Derive a few behavioral findings from aggregated edges (security signal).

    No raw logs are referenced — only the aggregate descriptors. Findings:

    * **sensitive-resource access** — a principal reached a secret/IAM/KMS-class
      resource.
    * **repeated authorization failure** — a principal accumulated denied
      attempts against a resource (probing signal).
    """
    findings: list[dict[str, Any]] = []
    for rec in records:
        if rec.get("is_sensitive_resource"):
            findings.append(
                {
                    "kind": "sensitive_resource_access",
                    "severity": "medium",
                    "principal": rec["principal"],
                    "resource": rec["resource"],
                    "action": rec["action"],
                    "observed_count": rec["count"],
                    "last_seen": rec["last_seen"],
                    "message": (f"{rec['principal']} {rec['action']} sensitive resource {rec['resource']} ({rec['count']}x)"),
                }
            )
        if rec.get("failure_count", 0) >= 3:
            findings.append(
                {
                    "kind": "repeated_access_failure",
                    "severity": "low",
                    "principal": rec["principal"],
                    "resource": rec["resource"],
                    "action": rec["action"],
                    "failure_count": rec["failure_count"],
                    "last_seen": rec["last_seen"],
                    "message": (f"{rec['principal']} had {rec['failure_count']} denied {rec['action']} attempts on {rec['resource']}"),
                }
            )
    findings.sort(key=lambda f: (f["kind"], f["principal"], f["resource"], f["action"]))
    return findings


def collect_audit_trail(
    *,
    provider: str,
    account: str = "",
    now: datetime | None = None,
    **reader_kwargs: Any,
) -> dict[str, Any]:
    """Collect, aggregate, and package the audit-trail behavioral payload.

    Returns the ``status: ok`` contract consumed by the graph builder's
    ``_add_cloud_audit_behavioral`` layer, or a ``status: skipped`` /
    ``status: error`` envelope carrying actionable warnings. Raw events never
    appear in the returned payload — only aggregated edge records + findings.

    ``provider`` is one of ``"aws" | "azure" | "gcp"``. ``now`` is injected for
    determinism in tests.
    """
    if not is_enabled():
        return {
            "status": "skipped",
            "provider": provider,
            "reason": f"audit-trail ingestion is opt-in; set {_OPT_IN_ENV}=1 to enable",
            "warnings": [],
        }

    readers: dict[str, Callable[..., tuple[list[AuditEvent], list[str]]]] = {
        "aws": read_aws_cloudtrail,
        "azure": read_azure_activity_log,
        "gcp": read_gcp_audit_logs,
    }
    reader = readers.get(provider)
    if reader is None:
        return {
            "status": "error",
            "provider": provider,
            "warnings": [f"unknown audit-trail provider {provider!r}"],
        }

    events, warnings = reader(now=now, **reader_kwargs)
    records = aggregate_events(events)
    findings = derive_behavioral_findings(records)
    return {
        "status": "ok",
        "provider": provider,
        "account": _clean(account),
        "behavioral_edges": records,
        "behavioral_findings": findings,
        "event_count": len(events),  # count only — raw events are dropped here
        "warnings": warnings,
    }


__all__ = [
    "AuditEvent",
    "aggregate_events",
    "classify_action",
    "collect_audit_trail",
    "derive_behavioral_findings",
    "is_enabled",
    "lookback_hours",
    "max_events",
    "read_aws_cloudtrail",
    "read_azure_activity_log",
    "read_gcp_audit_logs",
]
