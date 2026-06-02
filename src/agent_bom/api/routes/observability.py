"""Observability and data ingestion API routes.

Endpoints:
    POST /v1/traces        ingest OpenTelemetry traces
    POST /v1/results/push  receive pushed scan results from CLI
    POST /v1/ocsf/ingest   receive OCSF interoperability events
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.models import JobStatus, PushPayload, ScanJob, ScanRequest
from agent_bom.api.pipeline import _persist_graph_snapshot
from agent_bom.api.runtime_event_store import (
    RuntimeObservationRecord,
    get_runtime_event_store,
    sanitize_runtime_metadata,
)
from agent_bom.api.stores import _get_analytics_store, _get_fleet_store, _get_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.api.tenant_quota import enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.graph.severity import ocsf_to_severity
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import (
    sanitize_command_args,
    sanitize_env_vars,
    sanitize_error,
    sanitize_security_warnings,
    sanitize_sensitive_payload,
    sanitize_text,
    sanitize_url,
)

router = APIRouter()
_logger = logging.getLogger(__name__)


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _triggered_by(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "push"


def _normalize_pushed_report(body: PushPayload, *, fallback_scan_id: str) -> dict:
    """Coerce pushed payloads onto the canonical scan report contract.

    The main scan pipeline emits `blast_radius` and agent `type`, while some
    push clients still send `blast_radii` and `agent_type`. Normalizing here
    keeps graph persistence, UI pages, and downstream exporters aligned.
    """
    report = body.model_dump()
    blast_radius = deepcopy(report.get("blast_radius") or report.get("blast_radii") or [])
    report["blast_radius"] = blast_radius
    if "blast_radii" not in report:
        report["blast_radii"] = deepcopy(blast_radius)
    report["scan_id"] = str(report.get("scan_id") or fallback_scan_id)

    normalized_agents: list[dict] = []
    for raw_agent in report.get("agents", []):
        agent = dict(raw_agent)
        agent_type = str(agent.get("type") or agent.get("agent_type") or "").strip()
        if agent_type:
            agent["type"] = agent_type
            agent["agent_type"] = agent_type
        sanitized_servers: list[dict] = []
        for raw_server in agent.get("mcp_servers", []) or agent.get("servers", []) or []:
            if not isinstance(raw_server, dict):
                continue
            server = dict(raw_server)
            server["command"] = sanitize_text(server.get("command", ""), max_len=200)
            server["args"] = sanitize_command_args(list(server.get("args", []) or []))
            server["url"] = sanitize_url(str(server.get("url") or "")) if server.get("url") else None
            server["env"] = sanitize_env_vars(dict(server.get("env", {}) or {}))
            server["security_warnings"] = sanitize_security_warnings(list(server.get("security_warnings", []) or []))
            server["security_intelligence"] = [
                sanitize_security_intelligence_entry(item)
                for item in (server.get("security_intelligence", []) or [])
                if isinstance(item, dict)
            ]
            sanitized_servers.append(server)
        if "mcp_servers" in agent:
            agent["mcp_servers"] = sanitized_servers
        elif sanitized_servers:
            agent["servers"] = sanitized_servers
        normalized_agents.append(agent)
    report["agents"] = normalized_agents
    return report


def _extract_ocsf_events(body: dict | list[dict]) -> list[dict]:
    if isinstance(body, list):
        events = body
    elif isinstance(body, dict):
        if isinstance(body.get("events"), list):
            events = body["events"]
        elif "class_uid" in body or "class_name" in body:
            events = [body]
        else:
            raise ValueError("OCSF ingest expects a single event, a list of events, or an object with an 'events' array")
    else:
        raise ValueError("OCSF ingest payload must be an object or array")

    normalized_events = [event for event in events if isinstance(event, dict)]
    if len(normalized_events) != len(events):
        raise ValueError("OCSF ingest events must be JSON objects")
    return normalized_events


def _slug(value: str) -> str:
    return "_".join(part for part in value.lower().replace("/", " ").replace("-", " ").split() if part)


def _ocsf_timestamp(value: object) -> str:
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1_000_000_000_000:
            seconds /= 1000.0
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    if isinstance(value, str) and value.strip().isdigit():
        return _ocsf_timestamp(int(value.strip()))
    if isinstance(value, str) and value.strip():
        return value.strip()
    return _now()


def _resource_name(event: dict) -> str:
    resources = event.get("resources")
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, dict) and str(resource.get("name", "")).strip():
                return str(resource["name"]).strip()
    for key in ("resource", "tool_name", "tool"):
        candidate = str(event.get(key, "")).strip()
        if candidate:
            return candidate
    return ""


def _ocsf_finding_message(event: dict) -> str:
    if message := str(event.get("message", "")).strip():
        return message
    finding_info = event.get("finding_info")
    if isinstance(finding_info, dict):
        for key in ("title", "desc", "uid"):
            candidate = str(finding_info.get(key, "")).strip()
            if candidate:
                return candidate
    return str(event.get("class_name", "OCSF event")).strip() or "OCSF event"


def _ocsf_finding_detector(event: dict) -> str:
    finding_info = event.get("finding_info")
    if isinstance(finding_info, dict):
        analytic = finding_info.get("analytic")
        if isinstance(analytic, dict):
            for key in ("uid", "name", "type"):
                candidate = str(analytic.get(key, "")).strip()
                if candidate:
                    return candidate
        types = finding_info.get("types")
        if isinstance(types, list):
            for item in types:
                candidate = str(item).strip()
                if candidate:
                    return candidate
        if uid := str(finding_info.get("uid", "")).strip():
            return uid
    return _slug(str(event.get("class_name", "ocsf_event")).strip() or "ocsf_event")


def _normalize_ocsf_event(event: dict, *, tenant_id: str) -> dict:
    class_name = str(event.get("class_name", "")).strip() or "OCSF Event"
    class_uid = event.get("class_uid")
    class_slug = _slug(class_name) or "ocsf_event"
    source_meta = event.get("metadata")
    metadata_uid = ""
    source_id = ""
    if isinstance(source_meta, dict):
        product = source_meta.get("product")
        if isinstance(product, dict):
            source_id = str(product.get("name", "")).strip()
        if not source_id:
            source_id = str(source_meta.get("log_name", "")).strip()
        metadata_uid = str(source_meta.get("uid", "")).strip()
    event_id = ""
    finding_info = event.get("finding_info")
    if isinstance(finding_info, dict):
        event_id = str(finding_info.get("uid", "")).strip()
    if not event_id:
        event_id = metadata_uid or str(uuid.uuid4())
    severity = str(event.get("severity", "")).strip().lower()
    if not severity:
        try:
            severity = ocsf_to_severity(int(event.get("severity_id", 0)))
        except Exception:
            severity = "unknown"
    normalized = {
        "event_id": event_id,
        "event_timestamp": _ocsf_timestamp(event.get("time") or event.get("start_time") or event.get("event_time")),
        "tenant_id": tenant_id,
        "event_type": f"ocsf_{class_slug}",
        "detector": _ocsf_finding_detector(event),
        "severity": severity or "unknown",
        "tool_name": _resource_name(event),
        "message": _ocsf_finding_message(event),
        "agent_name": "",
        "session_id": "",
        "trace_id": "",
        "request_id": "",
        "source_id": source_id,
        "ocsf_class_uid": class_uid,
        "ocsf_class_name": class_name,
    }
    observables = event.get("observables")
    if isinstance(observables, list):
        for observable in observables:
            if isinstance(observable, dict):
                trace_id = str(observable.get("trace_id", "")).strip()
                if trace_id:
                    normalized["trace_id"] = trace_id
                    break
    return normalized


def _bounded(value: object, *, max_len: int = 200) -> str:
    return sanitize_text(value, max_len=max_len)


def _event_session_id(payload: dict[str, Any]) -> str:
    for key in ("session_id", "trace_id", "request_id"):
        value = str(payload.get(key) or "").strip()
        if value:
            return _bounded(value)
    return f"runtime-{uuid.uuid4()}"


def _runtime_observation_from_event(event: dict[str, Any], *, tenant_id: str, source: str = "api") -> RuntimeObservationRecord:
    observed_at = str(event.get("event_timestamp") or event.get("observed_at") or event.get("timestamp") or _now())
    event_id = str(event.get("event_id") or event.get("observation_id") or "").strip() or str(uuid.uuid4())
    summary: dict[str, Any] = {}
    for key in ("message", "reason", "decision", "risk", "policy", "blocked"):
        if key in event:
            summary[key] = sanitize_sensitive_payload(event[key], key=key, max_str_len=500)
    metadata_source = event.get("metadata") if isinstance(event.get("metadata"), dict) else event
    return RuntimeObservationRecord(
        tenant_id=tenant_id,
        observation_id=_bounded(event_id),
        session_id=_event_session_id(event),
        observed_at=_bounded(observed_at, max_len=80),
        source=_bounded(event.get("source_id") or event.get("source") or source, max_len=120),
        surface=_bounded(event.get("surface") or "runtime", max_len=80),
        event_type=_bounded(event.get("event_type") or event.get("type") or "runtime_event", max_len=120),
        severity=_bounded(str(event.get("severity") or "unknown").lower(), max_len=40),
        verdict=_bounded(event.get("verdict") or event.get("action_taken") or event.get("decision") or "observed", max_len=80),
        tool_name=_bounded(event.get("tool_name") or event.get("tool") or "", max_len=200),
        agent_name=_bounded(event.get("agent_name") or event.get("agent_id") or "", max_len=200),
        trace_id=_bounded(event.get("trace_id") or "", max_len=200),
        span_id=_bounded(event.get("span_id") or "", max_len=200),
        request_id=_bounded(event.get("request_id") or "", max_len=200),
        summary=sanitize_runtime_metadata(summary),
        metadata=sanitize_runtime_metadata(metadata_source),
    )


def _persist_runtime_observations(events: list[dict[str, Any]], *, tenant_id: str, source: str = "api") -> int:
    store = get_runtime_event_store()
    count = 0
    for event in events:
        store.put_observation(_runtime_observation_from_event(event, tenant_id=tenant_id, source=source))
        count += 1
    return count


def _persist_llm_costs(body: dict, *, tenant_id: str) -> dict[str, Any]:
    """Price GenAI spans in an OTLP payload and persist per-call cost records.

    Token counts come from OTel GenAI semantic conventions; cost is the open
    price model in agent_bom.cost_model. Failures never block trace ingest.
    """
    try:
        from agent_bom.api.cost_store import LLMCostRecord, get_cost_store
        from agent_bom.cost_model import compute_cost_usd, is_priced
        from agent_bom.otel_ingest import parse_ml_api_spans

        calls = parse_ml_api_spans(body)
    except Exception:  # noqa: BLE001
        _logger.warning("LLM cost ingest skipped", exc_info=True)
        return {"calls": 0, "cost_usd": 0.0}

    store = get_cost_store()
    total = 0.0
    observed = _now()
    for call in calls:
        cost = compute_cost_usd(call.provider, call.model_name, call.input_tokens, call.output_tokens)
        total += cost
        agent = _bounded(getattr(call, "agent", "") or "", max_len=120)
        store.record_cost(
            LLMCostRecord(
                tenant_id=tenant_id,
                call_id=f"{call.trace_id}:{call.span_id}",
                agent=agent,
                session_id=call.trace_id,
                provider=_bounded(call.provider, max_len=60),
                model=_bounded(call.model_name, max_len=120),
                input_tokens=max(0, int(call.input_tokens)),
                output_tokens=max(0, int(call.output_tokens)),
                cost_usd=cost,
                priced=is_priced(call.provider, call.model_name),
                observed_at=observed,
            )
        )
    return {"calls": len(calls), "cost_usd": round(total, 6)}


@router.post("/v1/traces", tags=["observability"])
async def ingest_traces(request: Request, body: dict) -> dict:
    """Ingest OpenTelemetry trace data and flag vulnerable tool calls.

    Accepts OTLP JSON format traces containing `adk.tool.*` spans.
    Cross-references tool calls against completed scan results to flag
    any calls that touch packages with known CVEs.
    """
    try:
        from agent_bom.otel_ingest import flag_vulnerable_tool_calls, parse_otel_traces

        # GenAI cost spans are independent of tool-call traces — price them first
        # so spend is captured even for payloads with no adk.tool.* spans.
        llm_cost = _persist_llm_costs(body, tenant_id=_tenant_id(request))

        traces = parse_otel_traces(body)
        if not traces:
            return {
                "traces": 0,
                "flagged": [],
                "llm_calls": llm_cost["calls"],
                "llm_cost_usd": llm_cost["cost_usd"],
                "message": "No tool call traces found",
            }

        # Gather vulnerable packages and servers from scan history
        vuln_packages: dict[str, set[str]] = defaultdict(set)
        vuln_servers: dict[str, set[str]] = defaultdict(set)
        for job in _get_store().list_all(tenant_id=_tenant_id(request)):
            if job.status == JobStatus.DONE and job.result:
                for br in job.result.get("blast_radius", []):
                    cve_id = br.get("vulnerability_id", "")
                    pkg = br.get("package", "")
                    if pkg:
                        if cve_id:
                            vuln_packages[pkg].add(cve_id)
                        else:
                            vuln_packages[pkg]
                    for srv in br.get("affected_servers", []):
                        name = srv if isinstance(srv, str) else srv.get("name", "")
                        if name:
                            if cve_id:
                                vuln_servers[name].add(cve_id)
                            else:
                                vuln_servers[name]

        flagged = flag_vulnerable_tool_calls(
            traces,
            {pkg: sorted(cves) for pkg, cves in vuln_packages.items()},
            {server: sorted(cves) for server, cves in vuln_servers.items()},
        )

        if flagged:
            analytics_events = [
                {
                    "event_id": f"{flag.trace.trace_id}:{flag.trace.span_id}",
                    "event_timestamp": _now(),
                    "event_type": "vulnerable_tool_call",
                    "detector": "otel_vulnerable_tool_call",
                    "severity": flag.severity,
                    "tool_name": flag.trace.tool_name,
                    "message": flag.reason,
                    "agent_name": "",
                    "session_id": flag.trace.trace_id,
                    "trace_id": flag.trace.trace_id,
                    "span_id": flag.trace.span_id,
                    "source_id": "otel",
                }
                for flag in flagged
            ]
            try:
                _get_analytics_store().record_events(analytics_events, tenant_id=_tenant_id(request))
            except Exception:  # noqa: BLE001
                _logger.warning("Trace analytics sync skipped", exc_info=True)
            _persist_runtime_observations(analytics_events, tenant_id=_tenant_id(request), source="otel")

        return {
            "traces": len(traces),
            "persisted_events": len(flagged),
            "llm_calls": llm_cost["calls"],
            "llm_cost_usd": llm_cost["cost_usd"],
            "flagged": [
                {
                    "tool_name": f.trace.tool_name,
                    "server": f.server or f.trace.server_name,
                    "package_name": f.package_name or f.trace.package_name,
                    "cve_ids": f.matched_cves,
                    "reason": f.reason,
                    "severity": f.severity,
                    "span_id": f.trace.span_id,
                }
                for f in flagged
            ],
        }
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


@router.post("/v1/results/push", tags=["push"], status_code=201)
async def receive_push(request: Request, body: PushPayload) -> dict:
    """Receive pushed scan results from a CLI instance.

    Stores as a completed ScanJob with source metadata.
    """
    tenant_id = _tenant_id(request)
    job = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        source_id=body.source_id or None,
        triggered_by=f"{_triggered_by(request)}:{body.source_id}" if body.source_id else _triggered_by(request),
        created_at=_now(),
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = _now()
    job_result = _normalize_pushed_report(body, fallback_scan_id=job.job_id)
    job_result["pushed"] = True
    job.result = job_result
    job.progress.append(f"Received via push from source={body.source_id}")
    try:
        _persist_graph_snapshot(job, job_result)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Pushed-result graph persistence failed: %s", exc)
        job.progress.append(f"Graph persistence skipped: {sanitize_error(exc)}")
    # Per-tenant quota lock keeps (check + insert) atomic (audit-4 P1).
    with tenant_quota_guard(tenant_id, lambda: enforce_retained_jobs_quota(tenant_id)):
        _get_store().put(job)
    return {"job_id": job.job_id, "source_id": body.source_id, "status": "stored"}


@router.post("/v1/ocsf/ingest", tags=["observability"], status_code=202)
async def ingest_ocsf(request: Request, body: dict | list[dict]) -> dict:
    """Ingest OCSF events and normalize them onto the canonical runtime-event path."""
    from agent_bom.api.audit_log import log_action

    tenant_id = _tenant_id(request)
    try:
        ocsf_events = _extract_ocsf_events(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    normalized_events = [_normalize_ocsf_event(event, tenant_id=tenant_id) for event in ocsf_events]
    class_counts: dict[str, int] = defaultdict(int)
    for event in normalized_events:
        class_counts[str(event.get("ocsf_class_uid", "unknown"))] += 1

    try:
        if normalized_events:
            _get_analytics_store().record_events(normalized_events, tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("OCSF analytics ingest skipped: %s", exc)
    _persist_runtime_observations(normalized_events, tenant_id=tenant_id, source="ocsf")

    source_ids = sorted({str(event.get("source_id", "")).strip() for event in normalized_events if str(event.get("source_id", "")).strip()})
    log_action(
        "ocsf.ingest",
        actor=_triggered_by(request),
        resource="ocsf/ingest",
        tenant_id=tenant_id,
        batch_size=len(normalized_events),
        class_counts=dict(class_counts),
        source_ids=source_ids,
    )
    return {
        "ingested": len(normalized_events),
        "tenant_id": tenant_id,
        "class_counts": dict(class_counts),
        "sources": source_ids,
    }


@router.post("/v1/runtime/events", tags=["runtime", "observability"], status_code=202, dependencies=[_dep("runtime_ingest")])
async def ingest_runtime_events(request: Request, body: dict | list[dict]) -> dict[str, object]:
    """Persist metadata-only runtime observations for tenant-scoped querying."""
    tenant_id = _tenant_id(request)
    if isinstance(body, list):
        events = body
    elif isinstance(body, dict) and isinstance(body.get("events"), list):
        events = body["events"]
    else:
        events = [body]
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise HTTPException(status_code=400, detail="Runtime event ingest expects an event object or events array")
    persisted = _persist_runtime_observations(cast(list[dict[str, Any]], events), tenant_id=tenant_id, source="runtime")
    return {
        "schema_version": "runtime.observability.v1",
        "persisted": persisted,
        "tenant_id": tenant_id,
        "redaction_status": "metadata_only",
        "raw_payload_stored": False,
    }


@router.get("/v1/runtime/sessions", tags=["runtime", "observability"], dependencies=[_dep("read")])
async def list_runtime_sessions(
    request: Request,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, object]:
    """List tenant-scoped runtime sessions derived from persisted observations."""
    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 500))
    bounded_offset = max(0, offset)
    sessions = get_runtime_event_store().list_sessions(tenant_id, limit=bounded_limit, offset=bounded_offset)
    return {
        "schema_version": "runtime.observability.v1",
        "tenant_id": tenant_id,
        "count": len(sessions),
        "limit": bounded_limit,
        "offset": bounded_offset,
        "sessions": [session.to_dict() for session in sessions],
    }


@router.get("/v1/runtime/observations", tags=["runtime", "observability"], dependencies=[_dep("read")])
async def list_runtime_observations(
    request: Request,
    session_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, object]:
    """List metadata-only runtime observations for the active tenant."""
    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 500))
    bounded_offset = max(0, offset)
    observations = get_runtime_event_store().list_observations(
        tenant_id,
        session_id=session_id,
        limit=bounded_limit,
        offset=bounded_offset,
    )
    return {
        "schema_version": "runtime.observability.v1",
        "tenant_id": tenant_id,
        "count": len(observations),
        "limit": bounded_limit,
        "offset": bounded_offset,
        "observations": [observation.to_dict() for observation in observations],
    }


@router.get("/v1/runtime/sessions/{session_id}/observations", tags=["runtime", "observability"], dependencies=[_dep("read")])
async def list_runtime_session_observations(
    request: Request,
    session_id: str,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, object]:
    """List observations for one runtime session in the active tenant."""
    tenant_id = _tenant_id(request)
    session = get_runtime_event_store().get_session(tenant_id, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Runtime session not found")
    observations = get_runtime_event_store().list_observations(
        tenant_id,
        session_id=session_id,
        limit=max(1, min(limit, 500)),
        offset=max(0, offset),
    )
    return {
        "schema_version": "runtime.observability.v1",
        "tenant_id": tenant_id,
        "session": session.to_dict(),
        "count": len(observations),
        "observations": [observation.to_dict() for observation in observations],
    }


@router.post("/v1/ui/errors", tags=["observability"], dependencies=[_dep("read")])
async def ingest_ui_error(request: Request, body: dict) -> dict:
    """Ingest a sanitized client-side dashboard error report."""
    from agent_bom.api.audit_log import log_action

    def _sanitize_log_value(value: object, max_len: int) -> str:
        text = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
        text = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
        return text[:max_len]

    tenant_id = _tenant_id(request)
    message = _sanitize_log_value(body.get("message", ""), 500)
    digest = _sanitize_log_value(body.get("digest", ""), 128)
    path = _sanitize_log_value(body.get("path", ""), 256)
    component = _sanitize_log_value(body.get("component", "dashboard"), 128) or "dashboard"
    log_action(
        "ui.client_error",
        actor=_triggered_by(request),
        resource="ui/error",
        tenant_id=tenant_id,
        message=message,
        digest=digest,
        path=path,
        component=component,
    )
    log_component = _sanitize_log_value(component, 128) or "dashboard"
    log_digest = _sanitize_log_value(digest, 128)
    log_path = _sanitize_log_value(path, 256)
    _logger.warning(
        "ui client error tenant=%s component=%s digest=%s path=%s",
        tenant_id,
        log_component,
        log_digest,
        log_path,
    )
    return {"ok": True}


async def _render_prometheus_metrics(request: Request | None = None):
    """Prometheus scrape endpoint — exposes control-plane and pilot metrics.

    Catalog lives in docs/OBSERVABILITY_METRICS.md — keep that doc in sync
    when adding or renaming series here.
    """
    from starlette.responses import Response

    try:
        from agent_bom.api.metrics import render_prometheus_lines
        from agent_bom.api.oidc import oidc_decode_failure_count

        store = _get_fleet_store()
        tenant_id = getattr(getattr(request, "state", None), "tenant_id", "").strip() if request is not None else ""
        # /metrics may be scraped without a tenant-bound auth context. Avoid
        # aggregating fleet gauges across every tenant in that case.
        agents = store.list_by_tenant(tenant_id) if tenant_id else []
        lines = [
            "# HELP agent_bom_fleet_total Total agents in fleet",
            "# TYPE agent_bom_fleet_total gauge",
            f"agent_bom_fleet_total {len(agents)}",
            "# HELP agent_bom_fleet_quarantined Quarantined agents",
            "# TYPE agent_bom_fleet_quarantined gauge",
            f"agent_bom_fleet_quarantined {sum(1 for a in agents if getattr(a, 'lifecycle_state', '') == 'quarantined')}",
            "# HELP agent_bom_oidc_decode_failures_total Failed OIDC decode or verification attempts",
            "# TYPE agent_bom_oidc_decode_failures_total counter",
            f"agent_bom_oidc_decode_failures_total {oidc_decode_failure_count()}",
        ]
        lines.extend(render_prometheus_lines())
        return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8")
    except Exception:  # noqa: BLE001
        return Response("# No metrics available\n", media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/metrics", tags=["observability"], dependencies=[_dep("read")])
async def prometheus_metrics(request: Request):
    return await _render_prometheus_metrics(request)


@router.get("/v1/observability/costs", tags=["observability", "finops"], dependencies=[_dep("read")])
async def get_llm_costs(request: Request, agent: str | None = None, limit: int = 1000) -> dict[str, object]:
    """Per-agent / per-model / per-provider LLM spend for the active tenant.

    Spend is derived from token counts on ingested OTel GenAI spans priced via
    the open cost model (agent_bom.cost_model). Includes budget posture.
    """
    from agent_bom.api.cost_store import budget_status, get_cost_store, summarize

    tenant_id = _tenant_id(request)
    store = get_cost_store()
    bounded_limit = max(1, min(limit, 10000))
    records = store.list_records(tenant_id, limit=bounded_limit)
    if agent:
        records = [r for r in records if r.agent == agent]
    report = summarize(records)
    spend = store.total_spend(tenant_id, agent=agent)
    budget = store.get_budget(tenant_id, agent or "")
    if budget is None and agent:
        budget = store.get_budget(tenant_id, "")
    report["budget"] = budget_status(spend, budget)
    report["schema_version"] = "observability.costs.v1"
    report["tenant_id"] = tenant_id
    report["price_model_captured"] = __import__("agent_bom.cost_model", fromlist=["PRICE_TABLE_CAPTURED"]).PRICE_TABLE_CAPTURED
    return report


@router.get("/v1/observability/costs/budget", tags=["observability", "finops"], dependencies=[_dep("read")])
async def get_llm_cost_budget(request: Request, agent: str = "") -> dict[str, object]:
    """Return the configured spend budget and current utilization."""
    from agent_bom.api.cost_store import budget_status, get_cost_store

    tenant_id = _tenant_id(request)
    store = get_cost_store()
    budget = store.get_budget(tenant_id, agent)
    spend = store.total_spend(tenant_id, agent=agent or None)
    return {"schema_version": "observability.costs.v1", "tenant_id": tenant_id, **budget_status(spend, budget)}


@router.put("/v1/observability/costs/budget", tags=["observability", "finops"], dependencies=[_dep("config")])
async def set_llm_cost_budget(request: Request, body: dict) -> dict[str, object]:
    """Set a tenant (or per-agent) USD spend cap. Body: {limit_usd, agent?}."""
    from agent_bom.api.cost_store import CostBudget, budget_status, get_cost_store

    tenant_id = _tenant_id(request)
    raw_limit = body.get("limit_usd")
    if raw_limit is None:
        raise HTTPException(status_code=400, detail="'limit_usd' is required and must be a number")
    try:
        limit_usd = float(raw_limit)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'limit_usd' is required and must be a number") from exc
    if limit_usd < 0:
        raise HTTPException(status_code=400, detail="'limit_usd' must be non-negative")
    agent = _bounded(str(body.get("agent", "") or ""), max_len=120)
    mode = str(body.get("mode", "report") or "report").strip().lower()
    if mode not in ("report", "enforce"):
        raise HTTPException(status_code=400, detail="'mode' must be 'report' or 'enforce'")
    store = get_cost_store()
    store.set_budget(CostBudget(tenant_id=tenant_id, agent=agent, limit_usd=limit_usd, updated_at=_now(), mode=mode))
    spend = store.total_spend(tenant_id, agent=agent or None)
    return {
        "schema_version": "observability.costs.v1",
        "tenant_id": tenant_id,
        "updated": True,
        **budget_status(spend, store.get_budget(tenant_id, agent)),
    }
