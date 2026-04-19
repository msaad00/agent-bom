"""Observability and data ingestion API routes.

Endpoints:
    POST /v1/traces        ingest OpenTelemetry traces
    POST /v1/results/push  receive pushed scan results from CLI
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from copy import deepcopy

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.models import JobStatus, PushPayload, ScanJob, ScanRequest
from agent_bom.api.pipeline import _persist_graph_snapshot
from agent_bom.api.stores import _get_analytics_store, _get_fleet_store, _get_store
from agent_bom.api.tenant_quota import enforce_retained_jobs_quota
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _tenant_id(request: Request) -> str:
    return getattr(request.state, "tenant_id", "default")


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
        normalized_agents.append(agent)
    report["agents"] = normalized_agents
    return report


@router.post("/v1/traces", tags=["observability"])
async def ingest_traces(request: Request, body: dict) -> dict:
    """Ingest OpenTelemetry trace data and flag vulnerable tool calls.

    Accepts OTLP JSON format traces containing `adk.tool.*` spans.
    Cross-references tool calls against completed scan results to flag
    any calls that touch packages with known CVEs.
    """
    try:
        from agent_bom.otel_ingest import flag_vulnerable_tool_calls, parse_otel_traces

        traces = parse_otel_traces(body)
        if not traces:
            return {"traces": 0, "flagged": [], "message": "No tool call traces found"}

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
                    "event_type": "vulnerable_tool_call",
                    "detector": "otel_vulnerable_tool_call",
                    "severity": flag.severity,
                    "tool_name": flag.trace.tool_name,
                    "message": flag.reason,
                    "agent_name": "",
                }
                for flag in flagged
            ]
            try:
                _get_analytics_store().record_events(analytics_events, tenant_id=_tenant_id(request))
            except Exception:  # noqa: BLE001
                _logger.warning("Trace analytics sync skipped", exc_info=True)

        return {
            "traces": len(traces),
            "persisted_events": len(flagged),
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
    enforce_retained_jobs_quota(tenant_id)
    job = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
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
    _get_store().put(job)
    return {"job_id": job.job_id, "source_id": body.source_id, "status": "stored"}


@router.get("/metrics", tags=["observability"])
async def prometheus_metrics():
    """Prometheus scrape endpoint — returns latest scan metrics."""
    from starlette.responses import Response

    try:
        from agent_bom.api.oidc import oidc_decode_failure_count

        store = _get_fleet_store()
        agents = store.list_all()
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
        return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8")
    except Exception:  # noqa: BLE001
        return Response("# No metrics available\n", media_type="text/plain; version=0.0.4; charset=utf-8")
