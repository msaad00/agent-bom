"""Cross-domain overview aggregation route.

Composes existing per-domain summary logic into a single read-only payload that
powers the unified overview / command-center landing page. No new scan or
ingestion logic lives here — every metric is read from a store or summary
function that another route already exposes:

    * Cloud / CNAPP + Ops + Findings  -> scan-job store (blast radius, sources)
    * Runtime                          -> deployment-context signals
    * LLM cost                         -> cost store summary
    * NHI / identity                   -> agent-identity store + fleet store
    * Posture                          -> latest scan posture scorecard

Endpoints:
    GET /v1/overview   cross-domain posture snapshot for the landing page
"""

from __future__ import annotations

import logging
from typing import Any, cast

from fastapi import APIRouter, Request

from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_fleet_store, _get_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])
_logger = logging.getLogger(__name__)

_SEVERITY_KEYS = ("critical", "high", "medium", "low")


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _empty_severity() -> dict[str, int]:
    return {key: 0 for key in _SEVERITY_KEYS}


def _severity_from_summary(
    summary: dict[str, Any],
    finding_summary: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Rebuild severity histogram from compact scan ``summary`` metadata."""
    severity = _empty_severity()
    by_sev = (finding_summary or {}).get("by_severity") or {}
    if isinstance(by_sev, dict) and by_sev:
        for key in _SEVERITY_KEYS:
            severity[key] = int(by_sev.get(key) or 0)
        return severity
    severity["critical"] = int(
        summary.get("critical_unified_findings") or summary.get("critical_findings") or 0
    )
    severity["high"] = int(summary.get("high_unified_findings") or 0)
    total = int(summary.get("total_vulnerabilities") or summary.get("total_findings") or 0)
    remainder = max(0, total - severity["critical"] - severity["high"])
    if remainder:
        severity["medium"] = remainder
    return severity


def _rollup_from_blast_radius(blast_radius: list[dict[str, Any]]) -> dict[str, Any]:
    severity = _empty_severity()
    kev = 0
    credential_exposed = 0
    seen_ids: set[str] = set()
    top_risks: list[dict[str, Any]] = []

    for b in blast_radius:
        vid = b.get("vulnerability_id", "")
        if vid and vid in seen_ids:
            continue
        if vid:
            seen_ids.add(vid)
        sev = (b.get("severity") or "").lower()
        if sev in severity:
            severity[sev] += 1
        is_kev = bool(b.get("cisa_kev") or b.get("is_kev"))
        if is_kev:
            kev += 1
        creds = b.get("exposed_credentials") or []
        if creds:
            credential_exposed += 1
        risk = b.get("risk_score")
        if risk is None:
            risk = (b.get("blast_score") or 0) / 10
        top_risks.append(
            {
                "vulnerability_id": vid,
                "package": b.get("package"),
                "severity": sev or "low",
                "risk_score": round(float(risk or 0), 1),
                "is_kev": is_kev,
                "cvss_score": b.get("cvss_score"),
                "epss_score": b.get("epss_score"),
                "affected_agents": list(b.get("affected_agents") or []),
            }
        )

    top_risks.sort(key=lambda r: r["risk_score"], reverse=True)
    return {
        "severity": severity,
        "kev": kev,
        "credential_exposed": credential_exposed,
        "unique_cves": len(seen_ids),
        "top_risks": top_risks[:10],
    }


def _rollup_from_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = cast(dict[str, Any], result.get("summary") or {})
    finding_summary = cast(dict[str, Any], result.get("finding_summary") or {})
    severity = _severity_from_summary(summary, finding_summary)
    total_vulns = int(summary.get("total_vulnerabilities") or summary.get("total_findings") or 0)
    unique_cves = total_vulns if total_vulns else sum(severity.values())
    return {
        "severity": severity,
        "kev": 0,
        "credential_exposed": 0,
        "unique_cves": unique_cves,
        "unique_packages": int(summary.get("unique_packages") or summary.get("total_packages") or 0),
        "top_risks": [],
    }


def _scan_rollup(jobs: list[Any]) -> dict[str, Any]:
    """Aggregate severity counts, sources, scans, and top-risk findings."""
    severity = _empty_severity()
    sources: set[str] = set()
    scan_count = 0
    done_count = 0
    failed_count = 0
    running_count = 0
    kev = 0
    credential_exposed = 0
    unique_cves = 0
    unique_packages = 0
    top_risks: list[dict[str, Any]] = []
    latest_scan_at: str | None = None

    for job in jobs:
        status = getattr(job, "status", None)
        if status == JobStatus.FAILED:
            failed_count += 1
        elif status == JobStatus.RUNNING:
            running_count += 1
        if status != JobStatus.DONE or not job.result:
            continue
        scan_count += 1
        done_count += 1
        result = cast(dict[str, Any], job.result)

        created = getattr(job, "created_at", None)
        created_str = str(created) if created is not None else None
        if created_str and (latest_scan_at is None or created_str > latest_scan_at):
            latest_scan_at = created_str

        for src in result.get("scan_sources", []) or []:
            if src:
                sources.add(str(src))

        blast_radius = result.get("blast_radius") or []
        if blast_radius:
            partial = _rollup_from_blast_radius(cast(list[dict[str, Any]], blast_radius))
            for key in _SEVERITY_KEYS:
                severity[key] += partial["severity"][key]
            kev += partial["kev"]
            credential_exposed += partial["credential_exposed"]
            unique_cves += partial["unique_cves"]
            top_risks.extend(partial["top_risks"])
            for agent in result.get("agents", []) or []:
                for server in agent.get("mcp_servers", []) or []:
                    for pkg in server.get("packages", []) or []:
                        name = pkg.get("name")
                        if name:
                            unique_packages += 1
        else:
            partial = _rollup_from_summary(result)
            for key in _SEVERITY_KEYS:
                severity[key] += partial["severity"][key]
            kev += partial["kev"]
            credential_exposed += partial["credential_exposed"]
            unique_cves += partial["unique_cves"]
            unique_packages = max(unique_packages, partial["unique_packages"])
            top_risks.extend(partial["top_risks"])

    top_risks.sort(key=lambda r: r["risk_score"], reverse=True)

    return {
        "severity": severity,
        "sources": sorted(sources),
        "scan_count": scan_count,
        "done_count": done_count,
        "failed_count": failed_count,
        "running_count": running_count,
        "kev": kev,
        "credential_exposed": credential_exposed,
        "unique_cves": unique_cves,
        "unique_packages": unique_packages,
        "top_risks": top_risks[:10],
        "latest_scan_at": latest_scan_at,
    }


def _posture_snapshot(jobs: list[Any]) -> dict[str, Any]:
    """Letter grade + score from the latest completed scan (same as /v1/posture)."""
    for job in jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        result = cast(dict[str, Any], job.result)
        scorecard = result.get("posture_scorecard")
        if isinstance(scorecard, dict) and scorecard:
            return {
                "grade": scorecard.get("grade", "N/A"),
                "score": scorecard.get("score", 0),
                "summary": scorecard.get("summary", ""),
            }
        summary = result.get("summary")
        if isinstance(summary, dict) and (
            summary.get("total_vulnerabilities") or summary.get("total_findings")
        ):
            from agent_bom.posture import _score_to_grade

            critical = int(
                summary.get("critical_unified_findings") or summary.get("critical_findings") or 0
            )
            high = int(summary.get("high_unified_findings") or 0)
            total = int(summary.get("total_vulnerabilities") or summary.get("total_findings") or 0)
            penalty = min(100.0, critical * 12.0 + high * 6.0 + max(0, total - critical - high) * 1.5)
            score = max(0.0, round(100.0 - penalty, 1))
            return {
                "grade": _score_to_grade(score),
                "score": score,
                "summary": f"{total} finding(s) from latest completed scan",
            }
        break
    return {"grade": "N/A", "score": 0, "summary": "No completed scans available"}


def _runtime_snapshot(request: Request, jobs: list[Any]) -> dict[str, Any]:
    """Runtime signals (gateway / proxy / traces / mesh) for the Runtime domain.

    Reuses the same deployment-context derivation that powers nav badges so the
    overview and the rest of the UI agree on what runtime surfaces are live.
    """
    try:
        from agent_bom.api.routes.compliance import _derive_deployment_context

        ctx = _derive_deployment_context(request, jobs)
    except Exception:  # pragma: no cover - defensive; degrade to empty signals
        _logger.debug("deployment-context derivation failed", exc_info=True)
        ctx = {}
    active = sum(1 for key in ("has_gateway", "has_proxy", "has_traces", "has_mesh") if ctx.get(key))
    return {
        "has_gateway": bool(ctx.get("has_gateway")),
        "has_proxy": bool(ctx.get("has_proxy")),
        "has_traces": bool(ctx.get("has_traces")),
        "has_mesh": bool(ctx.get("has_mesh")),
        "deployment_mode": ctx.get("deployment_mode", "local"),
        "active_surfaces": active,
    }


def _cost_snapshot(request: Request) -> dict[str, Any]:
    """LLM spend rollup from the cost store (same source as /v1/observability/costs)."""
    try:
        from agent_bom.api.cost_store import get_cost_store, summarize

        store = get_cost_store()
        records = store.list_records(_tenant_id(request), limit=10000)
        report = summarize(records)
        budget = store.get_budget(_tenant_id(request), "")
        return {
            "total_cost_usd": report.get("total_cost_usd", 0.0),
            "total_calls": report.get("total_calls", 0),
            "agents": len(report.get("by_agent", {}) or {}),
            "budget_configured": budget is not None,
        }
    except Exception:  # pragma: no cover - cost store optional
        _logger.debug("cost snapshot failed", exc_info=True)
        return {"total_cost_usd": 0.0, "total_calls": 0, "agents": 0, "budget_configured": False}


def _identity_snapshot(request: Request) -> dict[str, Any]:
    """NHI / fleet counts from the identity + fleet stores."""
    tenant_id = _tenant_id(request)
    identities = 0
    try:
        from agent_bom.api.agent_identity_store import get_agent_identity_store

        identities = len(get_agent_identity_store().list(tenant_id, limit=1000))
    except Exception:  # pragma: no cover - identity store optional
        _logger.debug("identity snapshot failed", exc_info=True)

    fleet_total = 0
    low_trust = 0
    try:
        agents = _get_fleet_store().list_by_tenant(tenant_id)
        fleet_total = len(agents)
        low_trust = sum(1 for a in agents if float(getattr(a, "trust_score", 0.0) or 0.0) < 50)
    except Exception:  # pragma: no cover - fleet store optional
        _logger.debug("fleet snapshot failed", exc_info=True)

    return {
        "managed_identities": identities,
        "fleet_agents": fleet_total,
        "low_trust_agents": low_trust,
    }


@router.get("/v1/overview", tags=["overview"])
async def get_overview(request: Request) -> dict[str, Any]:
    """Cross-domain posture snapshot for the unified landing page.

    Read-only. Composes existing stores and summary helpers into one payload
    keyed by domain so the overview page can render a tile per domain plus a
    shared top-risks strip without fanning out to a dozen endpoints.
    """
    jobs = _get_store().list_all(tenant_id=_tenant_id(request))

    scan = _scan_rollup(jobs)
    posture = _posture_snapshot(jobs)
    runtime = _runtime_snapshot(request, jobs)
    cost = _cost_snapshot(request)
    identity = _identity_snapshot(request)

    critical_high = scan["severity"]["critical"] + scan["severity"]["high"]

    domains = {
        "cloud": {
            "label": "Cloud / CNAPP",
            "href": "/findings",
            "metric": scan["unique_cves"],
            "metric_label": "open CVEs",
            "status": _status_for(scan["severity"]["critical"], scan["severity"]["high"]),
            "detail": {
                "critical": scan["severity"]["critical"],
                "high": scan["severity"]["high"],
                "kev": scan["kev"],
                "sources": scan["sources"],
            },
        },
        "runtime": {
            "label": "Runtime",
            "href": "/gateway",
            "metric": runtime["active_surfaces"],
            "metric_label": "active surfaces",
            "status": "ok" if runtime["active_surfaces"] > 0 else "idle",
            "detail": runtime,
        },
        "cost": {
            "label": "LLM Cost",
            "href": "/cost",
            "metric": round(float(cost["total_cost_usd"]), 2),
            "metric_label": "USD tracked",
            "status": "ok" if cost["total_calls"] > 0 else "idle",
            "detail": cost,
        },
        "identity": {
            "label": "NHI / Identity",
            "href": "/identity",
            "metric": identity["managed_identities"] + identity["fleet_agents"],
            "metric_label": "identities + agents",
            "status": _identity_status(identity),
            "detail": identity,
        },
        "ops": {
            "label": "Ops",
            "href": "/jobs",
            "metric": scan["scan_count"],
            "metric_label": "completed scans",
            "status": "warn" if scan["failed_count"] > 0 else ("ok" if scan["scan_count"] > 0 else "idle"),
            "detail": {
                "done": scan["done_count"],
                "failed": scan["failed_count"],
                "running": scan["running_count"],
                "packages": scan["unique_packages"],
            },
        },
    }

    return {
        "schema_version": "overview.v1",
        "tenant_id": _tenant_id(request),
        "posture": posture,
        "headline": {
            "critical": scan["severity"]["critical"],
            "high": scan["severity"]["high"],
            "critical_high": critical_high,
            "kev": scan["kev"],
            "credential_exposed": scan["credential_exposed"],
            "scans": scan["scan_count"],
            "latest_scan_at": scan["latest_scan_at"],
        },
        "domains": domains,
        "top_risks": scan["top_risks"],
    }


def _status_for(critical: int, high: int) -> str:
    if critical > 0:
        return "critical"
    if high > 0:
        return "warn"
    return "ok"


def _identity_status(identity: dict[str, Any]) -> str:
    if identity["low_trust_agents"] > 0:
        return "warn"
    if identity["fleet_agents"] or identity["managed_identities"]:
        return "ok"
    return "idle"
