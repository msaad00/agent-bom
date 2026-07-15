"""Observability and data ingestion API routes.

Endpoints:
    POST /v1/traces                          ingest OpenTelemetry traces
    POST /v1/traces/attack-paths             per-span trace -> attack-path join
    GET  /v1/traces/connectors               list native trace-pull connectors
    POST /v1/traces/connectors/{provider}/pull  pull + correlate Langfuse/LangSmith traces
    POST /v1/results/push                    receive pushed scan results from CLI
    POST /v1/ocsf/ingest                     receive OCSF interoperability events
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

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
from agent_bom.canonical_ids import canonical_id
from agent_bom.config import API_MAX_OCSF_INGEST_EVENTS
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
infra_router = APIRouter()
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
                source_id = str(product.get("vendor_name", "")).strip()
        if not source_id:
            source_id = str(source_meta.get("log_name", "")).strip()
        metadata_uid = str(source_meta.get("uid", "")).strip()
    event_id = ""
    finding_info = event.get("finding_info")
    if isinstance(finding_info, dict):
        event_id = str(finding_info.get("uid", "")).strip()
    if not event_id:
        event_id = metadata_uid
    severity = str(event.get("severity", "")).strip().lower()
    if not severity:
        try:
            severity = ocsf_to_severity(int(event.get("severity_id", 0)))
        except Exception:
            severity = "unknown"
    event_timestamp = _ocsf_timestamp(event.get("time") or event.get("start_time") or event.get("event_time"))
    detector = _ocsf_finding_detector(event)
    tool_name = _resource_name(event)
    message = _ocsf_finding_message(event)
    if not event_id:
        # Deterministic content-derived ID so retries of an id-less OCSF event
        # collapse on the runtime observation PK (tenant_id, observation_id)
        # instead of leaking a fresh uuid4 per ingest (audit item J).
        event_id = canonical_id(
            "ocsf_event",
            tenant_id,
            source_id,
            event_timestamp,
            class_uid,
            class_name,
            detector,
            tool_name,
            message,
        )
    normalized = {
        "event_id": event_id,
        "event_timestamp": event_timestamp,
        "tenant_id": tenant_id,
        "event_type": f"ocsf_{class_slug}",
        "detector": detector,
        "severity": severity or "unknown",
        "tool_name": tool_name,
        "message": message,
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
    event_id = str(event.get("event_id") or event.get("observation_id") or "").strip()
    if not event_id:
        # Deterministic content-derived ID so a retried id-less runtime event
        # dedups on the observation PK instead of leaking uuid4 (audit item J).
        event_id = canonical_id(
            "runtime_event",
            tenant_id,
            event.get("source_id") or event.get("source") or source,
            event.get("session_id") or event.get("trace_id") or event.get("request_id") or "",
            observed_at,
            event.get("event_type") or event.get("type") or "runtime_event",
            event.get("tool_name") or event.get("tool") or "",
            event.get("message") or event.get("reason") or event.get("decision") or "",
        )
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
    if not events:
        return 0
    store = get_runtime_event_store()
    records = [_runtime_observation_from_event(event, tenant_id=tenant_id, source=source) for event in events]
    persisted = store.put_observations_batch(records)
    # Opt-in runtime emitter plugins receive a redacted routing envelope per
    # persisted observation (off by default; see plugin_activation). Never lets
    # a third-party emitter failure affect the persisted ingest result.
    from agent_bom.plugin_activation import fan_out_runtime_event, runtime_emitter_activation_enabled

    if runtime_emitter_activation_enabled():
        for record in records:
            fan_out_runtime_event(record)
    return persisted


def _finish_ocsf_ingest(normalized_events: list[dict[str, Any]], *, tenant_id: str) -> None:
    try:
        if normalized_events:
            _get_analytics_store().record_events(normalized_events, tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("OCSF analytics ingest skipped: %s", sanitize_text(exc))
    _persist_runtime_observations(normalized_events, tenant_id=tenant_id, source="ocsf")


# OTel attribute keys carrying the chargeback/showback allocation (#2925).
# ``agent.cost_center`` / ``gen_ai.cost_center`` name the budget unit; any
# ``allocation.tag.<name>`` attribute becomes a freeform showback tag.
_COST_CENTER_KEYS = ("agent.cost_center", "gen_ai.cost_center", "cost_center")
_ALLOCATION_TAG_PREFIX = "allocation.tag."
_MAX_ALLOCATION_TAGS = 16


def _attr_str(attr_value: Any) -> str:
    if not isinstance(attr_value, dict):
        return ""
    return str(attr_value.get("stringValue") or attr_value.get("intValue") or attr_value.get("doubleValue") or "").strip()


def _allocation_for_spans(body: dict) -> dict[str, tuple[str, dict[str, str]]]:
    """Map ``trace_id:span_id`` -> (cost_center, allocation_tags) from OTLP attrs.

    Span-level attributes win over resource-level ones, so a per-call override
    beats a service-wide default. Tolerant of any non-OTLP shape (returns {}).
    """
    out: dict[str, tuple[str, dict[str, str]]] = {}
    try:
        resource_spans = body.get("resourceSpans") if isinstance(body, dict) else None
        if not isinstance(resource_spans, list):
            return out
        for rs in resource_spans:
            res_cc, res_tags = _read_allocation_attrs(rs.get("resource", {}).get("attributes", []) if isinstance(rs, dict) else [])
            for ss in rs.get("scopeSpans", []) if isinstance(rs, dict) else []:
                for span in ss.get("spans", []) if isinstance(ss, dict) else []:
                    if not isinstance(span, dict):
                        continue
                    span_cc, span_tags = _read_allocation_attrs(span.get("attributes", []))
                    merged_tags = {**res_tags, **span_tags}
                    cost_center = span_cc or res_cc
                    call_id = f"{span.get('traceId', '')}:{span.get('spanId', '')}"
                    out[call_id] = (cost_center, merged_tags)
    except Exception:  # noqa: BLE001
        return {}
    return out


def _read_allocation_attrs(attributes: Any) -> tuple[str, dict[str, str]]:
    cost_center = ""
    tags: dict[str, str] = {}
    if not isinstance(attributes, list):
        return cost_center, tags
    for attr in attributes:
        if not isinstance(attr, dict):
            continue
        key = str(attr.get("key", "")).strip()
        value = _attr_str(attr.get("value", {}))
        if not key or not value:
            continue
        if key in _COST_CENTER_KEYS and not cost_center:
            cost_center = _bounded(value, max_len=120)
        elif key.startswith(_ALLOCATION_TAG_PREFIX) and len(tags) < _MAX_ALLOCATION_TAGS:
            tag_name = _bounded(key[len(_ALLOCATION_TAG_PREFIX) :], max_len=60)
            if tag_name:
                tags[tag_name] = _bounded(value, max_len=120)
    return cost_center, tags


def _persist_llm_costs(body: dict, *, tenant_id: str) -> dict[str, Any]:
    """Price GenAI spans in an OTLP payload and persist per-call cost records.

    Token counts come from OTel GenAI semantic conventions; cost is the open
    price model in agent_bom.cost_model. Chargeback allocation (cost_center +
    allocation tags) is read from span/resource attributes. Failures never
    block trace ingest.
    """
    try:
        from agent_bom.api.cost_store import LLMCostRecord, get_cost_store
        from agent_bom.cost_model import compute_cost_usd, is_priced
        from agent_bom.otel_ingest import parse_ml_api_spans

        calls = parse_ml_api_spans(body)
    except Exception:  # noqa: BLE001
        _logger.warning("LLM cost ingest skipped", exc_info=True)
        return {"calls": 0, "cost_usd": 0.0}

    allocation = _allocation_for_spans(body)
    store = get_cost_store()
    total = 0.0
    observed = _now()
    for call in calls:
        cost = compute_cost_usd(call.provider, call.model_name, call.input_tokens, call.output_tokens)
        total += cost
        agent = _bounded(getattr(call, "agent", "") or "", max_len=120)
        call_id = f"{call.trace_id}:{call.span_id}"
        cost_center, allocation_tags = allocation.get(call_id, ("", {}))
        store.record_cost(
            LLMCostRecord(
                tenant_id=tenant_id,
                call_id=call_id,
                agent=agent,
                session_id=call.trace_id,
                provider=_bounded(call.provider, max_len=60),
                model=_bounded(call.model_name, max_len=120),
                input_tokens=max(0, int(call.input_tokens)),
                output_tokens=max(0, int(call.output_tokens)),
                cost_usd=cost,
                priced=is_priced(call.provider, call.model_name),
                observed_at=observed,
                cost_center=cost_center,
                allocation_tags=allocation_tags,
            )
        )
    return {"calls": len(calls), "cost_usd": round(total, 6)}


def _screen_content_enabled(explicit: bool | None) -> bool:
    """Resolve whether opt-in trace-content screening runs for this request.

    Off by default and preserves the metadata-only privacy posture: content is
    only screened when the request explicitly opts in, or the deployment set the
    ``AGENT_BOM_TRACE_CONTENT_SCREENING`` default.
    """
    if explicit is not None:
        return bool(explicit)
    from agent_bom.config import trace_content_screening_enabled

    return trace_content_screening_enabled()


def _screen_trace_content_events(body: dict, *, tenant_id: str) -> list[dict[str, Any]]:
    """Run Shield over trace content (opt-in) and return redacted finding events.

    Raw content is screened in-memory and never stored — only the redacted
    detector/severity/summary per span is returned/persisted.
    """
    from agent_bom.trace_content import screen_trace_content

    try:
        findings = screen_trace_content(body)
    except Exception:  # noqa: BLE001 — screening never blocks metadata ingest
        _logger.warning("Trace content screening skipped", exc_info=True)
        return []
    events: list[dict[str, Any]] = []
    for finding in findings:
        events.append(
            {
                "event_id": f"{finding.trace_id}:{finding.span_id}:{finding.detector}",
                "event_timestamp": _now(),
                "event_type": "trace_content_finding",
                "detector": f"shield_{finding.detector}",
                "severity": finding.severity,
                "tool_name": finding.tool_name,
                "message": finding.message,
                "session_id": finding.trace_id,
                "trace_id": finding.trace_id,
                "span_id": finding.span_id,
                "source_id": "otel_content",
            }
        )
    if events:
        try:
            _get_analytics_store().record_events(events, tenant_id=tenant_id)
        except Exception:  # noqa: BLE001
            _logger.warning("Trace content analytics sync skipped", exc_info=True)
        _persist_runtime_observations(events, tenant_id=tenant_id, source="otel_content")
    return events


@router.post("/traces", tags=["observability"])
async def ingest_traces(request: Request, body: dict, screen_content: bool | None = None) -> dict:
    """Ingest OpenTelemetry trace data and flag vulnerable tool calls.

    Accepts OTLP JSON format traces containing `adk.tool.*` spans.
    Cross-references tool calls against completed scan results to flag
    any calls that touch packages with known CVEs.

    Span *metadata* is parsed by default; content is never read or stored.
    Pass ``screen_content=true`` (opt-in; default follows
    ``AGENT_BOM_TRACE_CONTENT_SCREENING``) to additionally run Shield over trace
    content and surface injection / PII / credential-leak findings. Raw content
    is screened in-memory and never persisted.
    """
    try:
        from agent_bom.otel_ingest import flag_vulnerable_tool_calls, parse_otel_traces

        tenant_id = _tenant_id(request)
        # GenAI cost spans are independent of tool-call traces — price them first
        # so spend is captured even for payloads with no adk.tool.* spans.
        llm_cost = _persist_llm_costs(body, tenant_id=tenant_id)

        # Opt-in, privacy-safe content screening (off by default).
        content_findings: list[dict[str, Any]] = []
        if _screen_content_enabled(screen_content):
            content_findings = _screen_trace_content_events(body, tenant_id=tenant_id)

        traces = parse_otel_traces(body)
        if not traces:
            return {
                "traces": 0,
                "flagged": [],
                "llm_calls": llm_cost["calls"],
                "llm_cost_usd": llm_cost["cost_usd"],
                "content_findings": content_findings,
                "content_screened": _screen_content_enabled(screen_content),
                "message": "No tool call traces found",
            }

        # Gather vulnerable packages and servers from scan history
        vuln_packages: dict[str, set[str]] = defaultdict(set)
        vuln_servers: dict[str, set[str]] = defaultdict(set)
        for job in _get_store().list_all(tenant_id=tenant_id):
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
                _get_analytics_store().record_events(analytics_events, tenant_id=tenant_id)
            except Exception:  # noqa: BLE001
                _logger.warning("Trace analytics sync skipped", exc_info=True)
            _persist_runtime_observations(analytics_events, tenant_id=tenant_id, source="otel")

        return {
            "traces": len(traces),
            "persisted_events": len(flagged),
            "llm_calls": llm_cost["calls"],
            "llm_cost_usd": llm_cost["cost_usd"],
            "content_findings": content_findings,
            "content_screened": _screen_content_enabled(screen_content),
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


# ─── Per-span attack-path correlation (#3898) ─────────────────────────────
#
# Resolve each traced tool-call span to the exact BlastRadius it hit (the precise
# reachable CVE + exposed credential + NHI + blast radius), rather than an
# aggregate "run_shell called 12x". The submitted trace is correlated in-memory
# against the tenant's scan blast radii; no raw span content is stored.


def _blast_radius_views_for_tenant(tenant_id: str) -> list[Any]:
    """Adapt persisted scan blast-radius dicts into objects the correlation reads."""
    from types import SimpleNamespace

    views: list[Any] = []
    for job in _get_store().list_all(tenant_id=tenant_id):
        if job.status != JobStatus.DONE or not job.result:
            continue
        for br in job.result.get("blast_radius", []) or []:
            if not isinstance(br, dict):
                continue
            pkg_spec = str(br.get("package", "") or "")
            pkg_name = pkg_spec.split("@", 1)[0] if pkg_spec else ""
            servers = [s if isinstance(s, str) else str(s.get("name", "")) for s in br.get("affected_servers", []) or []]
            agents = [a if isinstance(a, str) else str(a.get("name", "")) for a in br.get("affected_agents", []) or []]
            tools = [t if isinstance(t, str) else str(t.get("name", "")) for t in br.get("exposed_tools", []) or []]
            vuln = SimpleNamespace(
                id=str(br.get("vulnerability_id", "") or ""),
                severity=str(br.get("severity", "unknown") or "unknown"),
                cvss_score=br.get("cvss_score"),
                epss_score=br.get("epss_score"),
                is_kev=bool(br.get("is_kev", False)),
            )
            views.append(
                SimpleNamespace(
                    vulnerability=vuln,
                    package=SimpleNamespace(name=pkg_name),
                    affected_servers=servers,
                    affected_agents=agents,
                    exposed_tools=tools,
                    exposed_credentials=[str(c) for c in br.get("exposed_credentials", []) or []],
                    risk_score=float(br.get("risk_score", 0.0) or 0.0),
                )
            )
    return views


def _nhi_by_credential_for_tenant(tenant_id: str) -> dict[str, list[dict[str, Any]]]:
    """Best-effort map of exposed credential name -> the NHIs that hold it.

    Reads the tenant's unified graph: for each managed-identity node, the
    credential nodes it reaches (1-2 hops) index that identity. Never raises —
    returns an empty map when no graph/identity data is available.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    try:
        from agent_bom.api.stores import _get_graph_store
        from agent_bom.graph.nhi_governance import evaluate_identity_governance
        from agent_bom.graph.types import EntityType

        graph = _get_graph_store().load_graph(tenant_id=tenant_id)
        identities = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
        if not identities:
            return out
        verdicts = {v.node_id: v.to_dict() for v in evaluate_identity_governance(graph)}
        for node in identities[:5000]:
            verdict = verdicts.get(node.id, {"node_id": node.id, "name": str(node.attributes.get("name") or node.id)})
            # Walk up to 2 hops for reachable credential nodes.
            frontier = [node.id]
            seen: set[str] = set()
            for _hop in range(2):
                next_frontier: list[str] = []
                for nid in frontier:
                    for edge in graph.edges_from(nid):
                        target = graph.nodes.get(edge.target)
                        if target is None or edge.target in seen:
                            continue
                        seen.add(edge.target)
                        if target.entity_type == EntityType.CREDENTIAL:
                            cred_name = str(target.attributes.get("name") or target.attributes.get("env_var") or target.id)
                            out.setdefault(cred_name.lower(), []).append(verdict)
                        else:
                            next_frontier.append(edge.target)
                frontier = next_frontier
    except Exception:  # noqa: BLE001
        _logger.warning("NHI credential resolution skipped", exc_info=True)
        return out
    return out


@router.post("/traces/attack-paths", tags=["observability"], dependencies=[_dep("read")])
async def correlate_trace_attack_paths(request: Request, body: dict, span_id: str | None = None) -> dict[str, object]:
    """Resolve each traced tool-call span to its exact attack path (#3898).

    Accepts an OTLP JSON trace and correlates every vulnerable tool-call span
    against the tenant's scan blast radii, returning per-span the exact reachable
    CVE, exposed credentials, resolved non-human identities, and blast radius.
    Correlation is in-memory; raw span content is never stored. Pass ``span_id``
    to scope the answer to a single span.
    """
    from agent_bom.otel_ingest import parse_otel_traces
    from agent_bom.runtime_correlation import correlate_spans_to_attack_paths

    tenant_id = _tenant_id(request)
    try:
        traces = parse_otel_traces(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    if span_id:
        traces = [t for t in traces if t.span_id == span_id]

    blast_radii = _blast_radius_views_for_tenant(tenant_id)
    nhi_by_credential = _nhi_by_credential_for_tenant(tenant_id)
    attack_paths = correlate_spans_to_attack_paths(traces, blast_radii, nhi_by_credential=nhi_by_credential)
    return {
        "schema_version": "observability.trace_attack_paths.v1",
        "tenant_id": tenant_id,
        "spans": len(traces),
        "count": len(attack_paths),
        "attack_paths": [path.to_dict() for path in attack_paths],
    }


@router.get("/traces/connectors", tags=["observability", "connectors"], dependencies=[_dep("read")])
async def list_trace_connectors_route() -> dict[str, object]:
    """List native trace-pull connectors (Langfuse, LangSmith)."""
    from agent_bom.trace_connectors import list_trace_connectors

    return {"schema_version": "observability.trace_connectors.v1", "connectors": list_trace_connectors()}


@router.post(
    "/traces/connectors/{provider}/pull",
    tags=["observability", "connectors"],
    dependencies=[_dep("runtime_ingest")],
)
async def pull_trace_connector(request: Request, provider: str, body: dict) -> dict[str, object]:
    """Pull traces from an LLM-observability platform and correlate them (#3899).

    Body: ``{"credentials": {...}, "limit": int, "screen_content": bool}``. The
    provider's credentials (Langfuse public/secret key or LangSmith API key) are
    used for auth only and never logged. Pulled traces feed the same parser +
    per-span correlation pipeline as pushed OTLP. ``screen_content`` opts in to
    Shield content screening (off by default; raw content is never stored).
    """
    from agent_bom.otel_ingest import parse_otel_traces
    from agent_bom.runtime_correlation import correlate_spans_to_attack_paths
    from agent_bom.trace_connectors import (
        TraceConnectorError,
        TraceConnectorValidationError,
        fetch_traces,
    )

    tenant_id = _tenant_id(request)
    credentials = body.get("credentials") if isinstance(body.get("credentials"), dict) else {}
    if not credentials:
        raise HTTPException(status_code=400, detail="connector credentials are required")
    try:
        limit = max(1, min(int(body.get("limit", 50) or 50), 1000))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'limit' must be an integer") from exc
    raw_screen = body.get("screen_content")
    screen_content = _screen_content_enabled(None if raw_screen is None else bool(raw_screen))

    try:
        otlp = fetch_traces(provider, credentials, limit=limit, include_content=screen_content)
    except TraceConnectorValidationError as exc:
        # Invalid/unsafe caller input (e.g. SSRF-blocked host) — a client error.
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    except TraceConnectorError as exc:
        # sanitize_error keeps credentials out of the response/logs.
        raise HTTPException(status_code=502, detail=sanitize_error(exc)) from exc

    traces = parse_otel_traces(otlp)
    blast_radii = _blast_radius_views_for_tenant(tenant_id)
    nhi_by_credential = _nhi_by_credential_for_tenant(tenant_id)
    attack_paths = correlate_spans_to_attack_paths(traces, blast_radii, nhi_by_credential=nhi_by_credential)
    content_findings = _screen_trace_content_events(otlp, tenant_id=tenant_id) if screen_content else []
    return {
        "schema_version": "observability.trace_connectors.v1",
        "tenant_id": tenant_id,
        "provider": provider.strip().lower(),
        "pulled_spans": len(traces),
        "content_screened": screen_content,
        "attack_paths": [path.to_dict() for path in attack_paths],
        "content_findings": content_findings,
    }


# Extra (non-declared) keys that still mark a payload as a real pushed report.
# ``PushPayload`` is ``extra="allow"`` so the full scan report rides through, but
# that also let arbitrary junk validate into an empty ScanJob. A genuine push
# always sets at least one declared field (source_id/agents/blast_radii/…) or
# carries one of these canonical report keys.
_RECOGNIZED_PUSH_EXTRA_KEYS = frozenset(
    {
        "blast_radius",
        "scan_id",
        "summary",
        "posture_scorecard",
        "findings",
        "packages",
        "vulnerabilities",
        "agent_projects",
        "report",
        "observed_at",
    }
)


@router.post("/results/push", tags=["push"], status_code=201)
async def receive_push(request: Request, body: PushPayload) -> dict:
    """Receive pushed scan results from a CLI instance.

    Stores as a completed ScanJob with source metadata.
    """
    # ``model_fields_set`` includes ``extra="allow"`` keys, so intersect with the
    # declared fields to see whether the client set a real push field.
    provided_declared = body.model_fields_set & set(type(body).model_fields)
    extra_keys = set(body.model_extra or {})
    if not provided_declared and not (extra_keys & _RECOGNIZED_PUSH_EXTRA_KEYS):
        raise HTTPException(
            status_code=422,
            detail=(
                "results push payload missing recognized fields; expected at least one of source_id, agents, blast_radii, warnings, summary"
            ),
        )
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
        _logger.warning("Pushed-result graph persistence failed: %s", sanitize_text(exc))
        job.progress.append(f"Graph persistence skipped: {sanitize_error(exc)}")
    # Per-tenant quota lock keeps (check + insert) atomic (audit-4 P1).
    with tenant_quota_guard(tenant_id, lambda: enforce_retained_jobs_quota(tenant_id)):
        _get_store().put(job)
    return {"job_id": job.job_id, "source_id": body.source_id, "status": "stored"}


@router.post("/ocsf/ingest", tags=["observability"], status_code=202)
async def ingest_ocsf(request: Request, body: dict | list[dict]) -> dict:
    """Ingest OCSF events and normalize them onto the canonical runtime-event path."""
    from agent_bom.api.audit_log import log_action

    tenant_id = _tenant_id(request)
    try:
        ocsf_events = _extract_ocsf_events(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    if len(ocsf_events) > API_MAX_OCSF_INGEST_EVENTS:
        raise HTTPException(
            status_code=422,
            detail=f"OCSF ingest accepts at most {API_MAX_OCSF_INGEST_EVENTS} events per request",
        )

    normalized_events = [_normalize_ocsf_event(event, tenant_id=tenant_id) for event in ocsf_events]
    class_counts: dict[str, int] = defaultdict(int)
    for event in normalized_events:
        class_counts[str(event.get("ocsf_class_uid", "unknown"))] += 1

    await asyncio.to_thread(_finish_ocsf_ingest, normalized_events, tenant_id=tenant_id)

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


@router.post("/runtime/events", tags=["runtime", "observability"], status_code=202, dependencies=[_dep("runtime_ingest")])
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


@router.get("/runtime/sessions", tags=["runtime", "observability"], dependencies=[_dep("read")])
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


@router.get("/runtime/observations", tags=["runtime", "observability"], dependencies=[_dep("read")])
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


@router.get("/runtime/trace-explorer", tags=["runtime", "observability"], dependencies=[_dep("read")])
async def trace_explorer(
    request: Request,
    limit: int = 100,
) -> dict[str, object]:
    """Langfuse-style trace explorer joined to findings and policy decisions (#3608).

    Fuses gateway/proxy feed events and persisted runtime observations into
    session-grouped spans. Each span carries correlated findings (CVE, reach
    band, compliance controls) and blocked/observed verdict metadata.

    The whole assembly — unbounded findings iteration, synchronous psycopg
    session/observation reads, and CPU-bound serialization — is offloaded via
    ``asyncio.to_thread`` so it never blocks the event loop under scale.
    """
    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 200))
    return await asyncio.to_thread(_build_trace_explorer_payload_sync, tenant_id, limit=bounded_limit)


def _build_trace_explorer_payload_sync(tenant_id: str, *, limit: int = 100) -> dict[str, object]:
    """Heavy trace-explorer assembly; always run off the event loop.

    Findings iteration is bounded by ``limit`` so a large estate can never fold
    an unbounded number of scan findings into one request.
    """
    from agent_bom.api.cost_store import get_cost_store
    from agent_bom.api.routes.gateway_feed import _load_tenant_alerts, build_gateway_feed
    from agent_bom.api.routes.scan import _completed_jobs_for_tenant, _iter_scan_findings
    from agent_bom.api.trace_explorer import build_trace_explorer_payload

    bounded_limit = max(1, min(limit, 200))
    alerts = _load_tenant_alerts(tenant_id)
    llm_records = list(get_cost_store().list_records(tenant_id, limit=bounded_limit))
    feed = build_gateway_feed(
        tenant_id=tenant_id,
        alerts=alerts,
        llm_records=llm_records,
        limit=bounded_limit,
    )
    findings: list[dict[str, Any]] = []
    for job in _completed_jobs_for_tenant(tenant_id):
        for finding in _iter_scan_findings(job):
            findings.append(finding)
            if len(findings) >= bounded_limit:
                break
        if len(findings) >= bounded_limit:
            break
    store = get_runtime_event_store()
    sessions = [session.to_dict() for session in store.list_sessions(tenant_id, limit=bounded_limit, offset=0)]
    observations = [observation.to_dict() for observation in store.list_observations(tenant_id, limit=bounded_limit, offset=0)]
    return build_trace_explorer_payload(
        tenant_id=tenant_id,
        feed_events=cast(list[dict[str, Any]], feed.get("events", [])),
        findings=findings,
        sessions=sessions,
        observations=observations,
        limit=bounded_limit,
    )


async def _trace_explorer_payload_for_tenant(tenant_id: str, *, limit: int = 100) -> dict[str, object]:
    """Shared trace explorer builder for runtime surfaces (offloaded off-loop)."""
    bounded_limit = max(1, min(limit, 200))
    return await asyncio.to_thread(_build_trace_explorer_payload_sync, tenant_id, limit=bounded_limit)


@router.get("/runtime/approval-queue", tags=["runtime", "observability"], dependencies=[_dep("read")])
async def runtime_approval_queue(
    request: Request,
    status: str | None = None,
    limit: int = 100,
) -> dict[str, object]:
    """List blocked runtime spans awaiting or after human approval (#3617)."""
    from agent_bom.api.hitl_approval_queue import build_hitl_queue_items
    from agent_bom.api.hitl_approval_store import get_hitl_approval_store

    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 200))
    trace_payload = await _trace_explorer_payload_for_tenant(tenant_id, limit=bounded_limit)
    status_filter = status.strip().lower() if status else None
    if status_filter not in {None, "", "pending", "approved", "denied"}:
        raise HTTPException(status_code=400, detail="status must be pending, approved, or denied")
    items = build_hitl_queue_items(
        tenant_id=tenant_id,
        trace_payload=trace_payload,
        store=get_hitl_approval_store(),
        status_filter=status_filter or None,
    )
    pending = sum(1 for item in items if item.get("status") == "pending")
    return {
        "schema_version": "runtime.approval_queue.v1",
        "tenant_id": tenant_id,
        "count": len(items),
        "pending_count": pending,
        "items": items[:bounded_limit],
    }


class _HitlDecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str
    note: str = ""


@router.post(
    "/runtime/approval-queue/{item_id}/decision",
    tags=["runtime", "observability"],
    dependencies=[_dep("policy.manage")],
)
async def runtime_approval_decision(request: Request, item_id: str, body: _HitlDecisionBody) -> dict[str, object]:
    """Approve or deny a blocked runtime span; emits a signed audit event."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.hitl_approval_queue import apply_hitl_decision, build_hitl_queue_items
    from agent_bom.api.hitl_approval_store import get_hitl_approval_store

    tenant_id = _tenant_id(request)
    actor = _triggered_by(request)
    store = get_hitl_approval_store()
    trace_payload = await _trace_explorer_payload_for_tenant(tenant_id, limit=200)
    queue_items = build_hitl_queue_items(
        tenant_id=tenant_id,
        trace_payload=trace_payload,
        store=store,
    )
    queue_item = next((item for item in queue_items if item.get("item_id") == item_id), None)
    if queue_item is None:
        raise HTTPException(status_code=404, detail="Approval queue item not found")
    try:
        record = apply_hitl_decision(
            tenant_id=tenant_id,
            item_id=item_id,
            decision=body.decision,
            actor=actor,
            note=body.note,
            queue_item=queue_item,
            store=store,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    log_action(
        "runtime.hitl_decision",
        actor=actor,
        resource=f"runtime/approval-queue/{item_id}",
        tenant_id=tenant_id,
        decision=record.status.value,
        span_id=record.span_id,
        agent=record.agent,
        tool=record.tool,
        linked_finding_ids=record.linked_finding_ids,
        compliance_controls=record.compliance_controls,
        note=record.note,
    )
    return {
        "schema_version": "runtime.approval_queue.v1",
        "item": record.to_dict(),
    }


@router.get("/runtime/sessions/{session_id}/observations", tags=["runtime", "observability"], dependencies=[_dep("read")])
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


@router.post("/ui/errors", tags=["observability"], dependencies=[_dep("read")])
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


@infra_router.get("/metrics", tags=["observability"], dependencies=[_dep("read")])
async def prometheus_metrics(request: Request):
    return await _render_prometheus_metrics(request)


@router.get("/observability/costs", tags=["observability", "finops"], dependencies=[_dep("read")])
async def get_llm_costs(
    request: Request,
    agent: str | None = None,
    cost_center: str | None = None,
    tag: str | None = None,
    limit: int = 1000,
) -> dict[str, object]:
    """Per-agent / per-model / per-provider / per-cost-center LLM spend.

    Spend is derived from token counts on ingested OTel GenAI spans priced via
    the open cost model (agent_bom.cost_model). Includes budget posture and the
    chargeback/showback rollup ``by_cost_center`` (#2925). Pass ``cost_center``
    to scope the report (and budget) to one allocation unit, or ``tag`` to add a
    ``by_tag`` showback slice for a freeform allocation tag.
    """
    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 10000))
    # The fetch (up to 10k records) plus the summarize / owner-report / budget /
    # forecast CPU work is all synchronous; offload it in one hop so a large cost
    # ledger can never block the event loop.
    return await asyncio.to_thread(
        _build_llm_costs_report_sync,
        tenant_id,
        agent=agent,
        cost_center=cost_center,
        tag=tag,
        limit=bounded_limit,
    )


def _build_llm_costs_report_sync(
    tenant_id: str,
    *,
    agent: str | None,
    cost_center: str | None,
    tag: str | None,
    limit: int,
) -> dict[str, object]:
    """Fetch + compute the LLM cost report off the event loop."""
    from agent_bom.api.cost_forecast import forecast_spend
    from agent_bom.api.cost_owner import owner_cost_report
    from agent_bom.api.cost_store import budget_status, get_cost_store, summarize, summarize_by_tag

    store = get_cost_store()
    records = store.list_records(tenant_id, limit=limit)
    if agent:
        records = [r for r in records if r.agent == agent]
    if cost_center:
        records = [r for r in records if (r.cost_center or "") == cost_center]
    report = summarize(records)
    # Owner-attributed rollup (#3909): spend grouped by the accountable owner
    # recorded on the blueprint governing each agent. Spend from an ungoverned
    # agent rolls up under "unattributed" so nothing is silently dropped.
    report["by_owner"] = owner_cost_report(store, tenant_id, records)["by_owner"]
    if tag:
        report["tag_rollup"] = summarize_by_tag(records, _bounded(tag, max_len=60))
    if cost_center:
        spend = store.total_spend_by_cost_center(tenant_id, cost_center)
        budget = store.get_budget(tenant_id, "", cost_center=cost_center)
    else:
        spend = store.total_spend(tenant_id, agent=agent)
        budget = store.get_budget(tenant_id, agent or "")
        if budget is None and agent:
            budget = store.get_budget(tenant_id, "")
    report["budget"] = budget_status(spend, budget)
    # Forward-looking companion to the point-in-time budget posture: burn rate +
    # projected runway derived from the same records. Reference only.
    report["forecast"] = forecast_spend(records, budget=budget)
    report["schema_version"] = "observability.costs.v1"
    report["tenant_id"] = tenant_id
    report["price_model_captured"] = __import__("agent_bom.cost_model", fromlist=["PRICE_TABLE_CAPTURED"]).PRICE_TABLE_CAPTURED
    return report


@router.get("/observability/costs/budget", tags=["observability", "finops"], dependencies=[_dep("read")])
async def get_llm_cost_budget(
    request: Request, agent: str = "", cost_center: str = "", owner: str = "", workflow: str = ""
) -> dict[str, object]:
    """Return the configured spend budget and current utilization.

    Pass ``cost_center`` to read a chargeback budget scoped to one allocation
    unit (#2925), or ``owner`` (optionally with ``workflow``) to read an
    accountable-owner budget (#3909), instead of the per-agent / tenant-wide cap.
    """
    from agent_bom.api.cost_store import budget_status, get_cost_store

    tenant_id = _tenant_id(request)
    store = get_cost_store()
    if owner:
        from agent_bom.api.cost_owner import agent_owner_index, owner_spend

        budget = store.get_budget(tenant_id, "", owner=owner, workflow=workflow)
        spend = owner_spend(store, agent_owner_index(tenant_id), tenant_id, owner, workflow)
    elif cost_center:
        budget = store.get_budget(tenant_id, "", cost_center=cost_center)
        spend = store.total_spend_by_cost_center(tenant_id, cost_center)
    else:
        budget = store.get_budget(tenant_id, agent)
        spend = store.total_spend(tenant_id, agent=agent or None)
    return {"schema_version": "observability.costs.v1", "tenant_id": tenant_id, **budget_status(spend, budget)}


@router.put("/observability/costs/budget", tags=["observability", "finops"], dependencies=[_dep("config")])
async def set_llm_cost_budget(request: Request, body: dict) -> dict[str, object]:
    """Set a USD spend cap. Body: {limit_usd, agent?, cost_center?, owner?, workflow?, mode?}.

    A ``cost_center`` scopes the cap to one chargeback unit (#2925); ``agent``
    scopes it to one agent; ``owner`` scopes it to an accountable human/team as
    recorded on the governing blueprint (#3909), optionally narrowed to one
    governing blueprint via ``workflow``; none set means tenant-wide. ``agent`` /
    ``cost_center`` / ``owner`` are mutually exclusive, and ``workflow`` requires
    ``owner``.
    """
    from agent_bom.api.cost_owner import owner_spend as _owner_spend
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
    cost_center = _bounded(str(body.get("cost_center", "") or ""), max_len=120)
    owner = _bounded(str(body.get("owner", "") or ""), max_len=200)
    workflow = _bounded(str(body.get("workflow", "") or ""), max_len=120)
    if sum(1 for scope in (agent, cost_center, owner) if scope) > 1:
        raise HTTPException(status_code=400, detail="'agent', 'cost_center' and 'owner' budgets are mutually exclusive")
    if workflow and not owner:
        raise HTTPException(status_code=400, detail="'workflow' requires an 'owner' scope")
    mode = str(body.get("mode", "report") or "report").strip().lower()
    if mode not in ("report", "enforce"):
        raise HTTPException(status_code=400, detail="'mode' must be 'report' or 'enforce'")
    store = get_cost_store()
    store.set_budget(
        CostBudget(
            tenant_id=tenant_id,
            agent=agent,
            limit_usd=limit_usd,
            updated_at=_now(),
            mode=mode,
            cost_center=cost_center,
            owner=owner,
            workflow=workflow,
        )
    )
    if owner:
        from agent_bom.api.cost_owner import agent_owner_index

        spend = _owner_spend(store, agent_owner_index(tenant_id), tenant_id, owner, workflow)
        stored = store.get_budget(tenant_id, "", owner=owner, workflow=workflow)
    elif cost_center:
        spend = store.total_spend_by_cost_center(tenant_id, cost_center)
        stored = store.get_budget(tenant_id, "", cost_center=cost_center)
    else:
        spend = store.total_spend(tenant_id, agent=agent or None)
        stored = store.get_budget(tenant_id, agent)
    return {
        "schema_version": "observability.costs.v1",
        "tenant_id": tenant_id,
        "updated": True,
        **budget_status(spend, stored),
    }


@router.get("/observability/costs/forecast", tags=["observability", "finops"], dependencies=[_dep("read")])
async def get_llm_cost_forecast(request: Request, agent: str | None = None, limit: int = 10000) -> dict[str, object]:
    """Project LLM spend burn rate and budget runway for the active tenant.

    Derives a recent burn rate (trailing 24h / 7d) from ``observed_at`` on
    persisted cost records and extrapolates to the configured budget — returning
    projected period spend, days of runway, and an exhaustion date. Reference
    only: a forecast never blocks a call (enforcement stays in the relay) and
    returns a clear ``status`` with null projections on sparse/empty history.
    """
    from agent_bom.api.cost_forecast import forecast_for_tenant

    bounded_limit = max(1, min(limit, 10000))
    scoped_agent = _bounded(agent, max_len=120) if agent else None
    return forecast_for_tenant(_tenant_id(request), agent=scoped_agent, limit=bounded_limit)


@router.get("/observability/anomalies", tags=["observability", "finops"], dependencies=[_dep("read")])
async def get_anomalies(request: Request, z_threshold: float = 3.0) -> dict[str, object]:
    """Detect cost and behavior anomalies (per-agent spend + per-session call-rate
    z-scores) for the active tenant. Proactive surfacing of runaway agents."""
    from agent_bom.api.anomaly import scan_anomalies

    bounded = max(1.0, min(z_threshold, 10.0))
    return scan_anomalies(_tenant_id(request), z_threshold=bounded)
