"""Cross-domain overview aggregation route.

Composes existing per-domain summary logic into a single read-only payload that
powers the unified overview / command-center landing page. No new scan or
ingestion logic lives here — every metric is read from a store or summary
function that another route already exposes:

    * Cloud / CNAPP + Ops + Findings  -> scan-job store (blast radius, sources)
    * Runtime                          -> deployment-context signals
    * LLM cost                         -> cost store summary
    * NHI / identity                   -> agent-identity store + fleet store
    * Posture + headline               -> latest scan posture scorecard, folded
      with compliance-hub current-state severity counts so findings ingested via
      ``POST /v1/findings/bulk`` move the grade/headline (not scan jobs alone)

Domain tiles (cloud / vuln / code / runtime / ...) remain scan-scoped by
design; only the top-level posture + headline aggregate scan + ingested
evidence.

Endpoints:
    GET /v1/overview   cross-domain posture snapshot for the landing page
"""

from __future__ import annotations

import logging
from typing import Any, cast
from urllib.parse import urlencode

from fastapi import APIRouter, Request

from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_fleet_store, _get_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])
_logger = logging.getLogger(__name__)

_SEVERITY_KEYS = ("critical", "high", "medium", "low")
# ``unrated`` is the honest home for findings whose severity the histogram does
# not recognize (empty / "unknown" / vendor-specific). Without it those findings
# incremented the CVE count but were dropped from the severity strip, producing
# the "39 CVEs / 0 severities" mismatch. Every severity histogram in this module
# now carries it so ``sum(severity.values())`` reconciles with the counted total.
_UNRATED_KEY = "unrated"
_ALL_SEVERITY_KEYS = (*_SEVERITY_KEYS, _UNRATED_KEY)
_HUB_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info", "unknown")

# Coverage lanes — the five security domains, in display order (issue #3946).
_COVERAGE_DOMAINS = ("cspm", "vuln", "appsec_sca", "dspm", "aispm")
_COVERAGE_LABELS = {
    "cspm": "CSPM",
    "vuln": "Vuln mgmt",
    "appsec_sca": "AppSec / SCA",
    "dspm": "DSPM",
    "aispm": "AISPM",
}


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _empty_severity() -> dict[str, int]:
    return {key: 0 for key in _ALL_SEVERITY_KEYS}


def _bucket(sev: str | None, severity: dict[str, int]) -> str:
    """Return the histogram bucket for ``sev`` — an exact match or ``unrated``.

    The single choke point shared by every rollup so a finding is counted in one
    and only one bucket and no unknown severity is silently dropped.
    """
    key = (sev or "").strip().lower()
    return key if key in _SEVERITY_KEYS else _UNRATED_KEY


def _graph_drill_href(
    *,
    rollup: bool = True,
    severity: str | None = None,
    relationships: str | None = None,
    layers: str | None = None,
) -> str:
    """Build a /graph deep-link for overview domain tiles."""
    params: dict[str, str] = {}
    if rollup:
        params["rollup"] = "1"
    if severity:
        params["severity"] = severity
    if relationships:
        params["relationships"] = relationships
    if layers:
        params["layers"] = layers
    query = urlencode(params)
    return f"/graph?{query}" if query else "/graph"


def _cloud_graph_href(severity: dict[str, int]) -> str:
    if severity["critical"] > 0:
        return _graph_drill_href(severity="critical")
    if severity["high"] > 0:
        return _graph_drill_href(severity="high")
    return _graph_drill_href()


def _severity_from_summary(
    summary: dict[str, Any],
    finding_summary: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Rebuild severity histogram from compact scan ``summary`` metadata."""
    severity = _empty_severity()
    total = int(summary.get("total_vulnerabilities") or summary.get("total_findings") or 0)
    by_sev = (finding_summary or {}).get("by_severity") or {}
    if isinstance(by_sev, dict) and by_sev:
        for raw_key, raw_val in by_sev.items():
            severity[_bucket(str(raw_key), severity)] += int(raw_val or 0)
        counted = sum(severity.values())
        # Reconcile with the scalar total so no finding is lost to a severity
        # band the per-severity map omitted (info/unknown/vendor-specific).
        if total > counted:
            severity[_UNRATED_KEY] += total - counted
        return severity
    severity["critical"] = int(summary.get("critical_unified_findings") or summary.get("critical_findings") or 0)
    severity["high"] = int(summary.get("high_unified_findings") or 0)
    # The remainder are of unknown band (only critical/high are itemized in the
    # compact summary) — record them as ``unrated`` rather than fabricating a
    # ``medium`` count. This keeps ``sum(severity) == total``.
    remainder = max(0, total - severity["critical"] - severity["high"])
    if remainder:
        severity[_UNRATED_KEY] = remainder
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
        # Always count into exactly one bucket — unknown severities land in
        # ``unrated`` instead of being dropped (the 39-CVEs / 0-severities bug).
        severity[_bucket(sev, severity)] += 1
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
    # One source of truth: the CVE count is the histogram total, so the severity
    # strip and the headline number can never disagree.
    return {
        "severity": severity,
        "kev": kev,
        "credential_exposed": credential_exposed,
        "unique_cves": sum(severity.values()),
        "top_risks": top_risks[:10],
    }


def _rollup_from_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = cast(dict[str, Any], result.get("summary") or {})
    finding_summary = cast(dict[str, Any], result.get("finding_summary") or {})
    severity = _severity_from_summary(summary, finding_summary)
    # ``_severity_from_summary`` reconciles the histogram with the scalar total,
    # so the histogram sum is the single source of truth for the CVE count.
    unique_cves = sum(severity.values())
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
            for key in _ALL_SEVERITY_KEYS:
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
            for key in _ALL_SEVERITY_KEYS:
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


def _row_domain(row: dict[str, Any]) -> str:
    """Return the security domain for a serialized finding row.

    Prefers the first-class ``security_domain`` field (set by
    ``Finding.to_dict``); falls back to the source/type mapping for legacy rows.
    ``vuln`` is the safe default for legacy CVE rows that predate the taxonomy.
    """
    from agent_bom.finding_scope import domain_for_row

    return domain_for_row(row) or "vuln"


def _domain_rollup(jobs: list[Any]) -> list[dict[str, Any]]:
    """Group unified findings by security domain into the five coverage lanes.

    Reads each completed scan's unified ``findings`` stream (deduped by finding
    id across re-scans) and buckets it by ``security_domain``. Each lane carries
    a severity strip whose values sum to the lane count, so the UI can never
    render a count that contradicts its severity strip. Empty lanes are still
    returned at zero so the coverage row is always the same five domains.
    """
    lanes: dict[str, dict[str, int]] = {dom: _empty_severity() for dom in _COVERAGE_DOMAINS}
    counts: dict[str, int] = {dom: 0 for dom in _COVERAGE_DOMAINS}
    seen: set[str] = set()

    for job in jobs:
        if getattr(job, "status", None) != JobStatus.DONE or not job.result:
            continue
        result = cast(dict[str, Any], job.result)
        for row in result.get("findings", []) or []:
            if not isinstance(row, dict):
                continue
            identity = str(row.get("id") or row.get("canonical_id") or row.get("cve_id") or id(row))
            if identity in seen:
                continue
            seen.add(identity)
            dom = _row_domain(row)
            lanes[dom][_bucket(str(row.get("severity") or ""), lanes[dom])] += 1
            counts[dom] += 1

    return [
        {
            "domain": dom,
            "label": _COVERAGE_LABELS[dom],
            "href": f"/findings?domain={dom}",
            "count": counts[dom],
            "severity": lanes[dom],
        }
        for dom in _COVERAGE_DOMAINS
    ]


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
        if isinstance(summary, dict) and (summary.get("total_vulnerabilities") or summary.get("total_findings")):
            from agent_bom.posture import _score_to_grade

            critical = int(summary.get("critical_unified_findings") or summary.get("critical_findings") or 0)
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


def _hub_severity_snapshot(request: Request) -> dict[str, int]:
    """Per-severity counts of hub-ingested findings (POST /v1/findings/bulk).

    Reads the same compliance-hub ledger that powers /v1/compliance/hub/posture
    via the store's indexed ``severity_breakdown`` (a GROUP BY / dict count, no
    payload hydration) so bulk-ingested evidence contributes to the overview
    posture + headline instead of being invisible until a scan runs. Tenant
    scope is owned by the request; the store method is tenant-keyed. Degrades to
    zeros if the hub store is unavailable so the overview never fails closed on
    an optional dependency.
    """
    empty = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    try:
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        store = get_compliance_hub_store()
        breakdown = getattr(store, "severity_breakdown", None)
        if not callable(breakdown):
            return empty
        counts = breakdown(_tenant_id(request)) or {}
    except Exception:  # pragma: no cover - hub store optional
        _logger.debug("hub severity snapshot failed", exc_info=True)
        return empty
    for key, value in counts.items():
        empty[str(key).lower()] = empty.get(str(key).lower(), 0) + int(value or 0)
    return empty


def _blend_posture_with_hub(
    posture: dict[str, Any],
    scan_severity: dict[str, int],
    hub_severity: dict[str, int],
) -> dict[str, Any]:
    """Fold hub-ingested findings into the scan posture grade.

    With no hub findings the scan posture is returned unchanged (the demo estate
    and every scan-only tenant keep their existing grade). When findings have
    been bulk-ingested, a combined penalty score is derived from scan + hub
    severity and the grade can only move *down* (``min`` of the two scores), so
    ingested evidence never launders a failing posture into a passing one.
    """
    hub_total = sum(int(hub_severity.get(k, 0) or 0) for k in _HUB_SEVERITY_KEYS)
    scan_total = sum(int(v) for v in scan_severity.values())
    posture_is_na = posture.get("grade") in (None, "N/A")

    # An existing scorecard/summary posture stays authoritative unless ingested
    # evidence adds to it — never recompute a graded scan from severity counts
    # (that would double-penalize and drift the published grade). Only synthesize
    # a grade from counts when the posture is N/A but findings exist, so the
    # blurb can never claim "no vulnerabilities" while the counted total > 0.
    if hub_total <= 0 and not posture_is_na:
        return posture
    if hub_total <= 0 and scan_total <= 0:
        return posture

    from agent_bom.posture import _score_to_grade

    combined_critical = int(scan_severity["critical"]) + int(hub_severity.get("critical", 0) or 0)
    combined_high = int(scan_severity["high"]) + int(hub_severity.get("high", 0) or 0)
    combined_total = scan_total + hub_total
    penalty = min(
        100.0,
        combined_critical * 12.0 + combined_high * 6.0 + max(0, combined_total - combined_critical - combined_high) * 1.5,
    )
    combined_score = max(0.0, round(100.0 - penalty, 1))

    if posture_is_na:
        final_score = combined_score
    else:
        final_score = min(float(posture.get("score") or 0.0), combined_score)

    if hub_total > 0:
        summary = f"{combined_total} finding(s) across scans + ingested evidence"
    else:
        summary = f"{combined_total} finding(s) from completed scans"

    return {
        "grade": _score_to_grade(final_score),
        "score": final_score,
        "summary": summary,
    }


def _cloud_account_count(request: Request) -> int:
    """Connected cloud accounts for the Cloud posture domain tile."""
    try:
        from agent_bom.api.connection_store import get_connection_store

        return len(get_connection_store().list_for_tenant(_tenant_id(request)))
    except Exception:  # pragma: no cover - connection store optional
        _logger.debug("cloud account snapshot failed", exc_info=True)
        return 0


def _repo_scan_count(jobs: list[Any]) -> int:
    """Count completed jobs that targeted a remote repo URL or repo scan source."""
    count = 0
    for job in jobs:
        if job.status != JobStatus.DONE:
            continue
        request = getattr(job, "request", None)
        repo_url = getattr(request, "repo_url", None) if request is not None else None
        if isinstance(repo_url, str) and repo_url.strip():
            count += 1
            continue
        result = cast(dict[str, Any], getattr(job, "result", None) or {})
        sources = result.get("scan_sources") or []
        if isinstance(sources, list) and any(
            isinstance(src, str) and ("repo" in src.lower() or "project" in src.lower()) for src in sources
        ):
            count += 1
    return count


@router.get("/overview", tags=["overview"])
async def get_overview(request: Request) -> dict[str, Any]:
    """Cross-domain posture snapshot for the unified landing page.

    Read-only. Composes existing stores and summary helpers into one payload
    keyed by domain so the overview page can render a tile per domain plus a
    shared top-risks strip without fanning out to a dozen endpoints.
    """
    jobs = _get_store().list_all(tenant_id=_tenant_id(request))

    scan = _scan_rollup(jobs)
    coverage = _domain_rollup(jobs)
    hub_severity = _hub_severity_snapshot(request)
    posture = _blend_posture_with_hub(_posture_snapshot(jobs), scan["severity"], hub_severity)
    runtime = _runtime_snapshot(request, jobs)
    cost = _cost_snapshot(request)
    identity = _identity_snapshot(request)

    hub_findings = sum(int(hub_severity.get(k, 0) or 0) for k in _HUB_SEVERITY_KEYS)
    headline_critical = scan["severity"]["critical"] + int(hub_severity.get("critical", 0) or 0)
    headline_high = scan["severity"]["high"] + int(hub_severity.get("high", 0) or 0)
    critical_high = headline_critical + headline_high

    cloud_accounts = _cloud_account_count(request)
    repo_scans = _repo_scan_count(jobs)

    domains = {
        "cloud": {
            "label": "Cloud posture",
            "href": "/connections",
            "graph_href": _cloud_graph_href(scan["severity"]),
            "metric": cloud_accounts,
            "metric_label": "accounts connected",
            "status": "ok" if cloud_accounts > 0 else "idle",
            "detail": {
                "accounts": cloud_accounts,
                "sources": scan["sources"],
            },
        },
        "vuln": {
            "label": "Vuln / SCA",
            "href": "/findings?issue=vulnerability",
            "graph_href": _cloud_graph_href(scan["severity"]),
            "metric": scan["unique_cves"],
            "metric_label": "open CVEs",
            "status": _status_for(scan["severity"]["critical"], scan["severity"]["high"]),
            "detail": {
                "critical": scan["severity"]["critical"],
                "high": scan["severity"]["high"],
                "kev": scan["kev"],
                "packages": scan["unique_packages"],
                # Full histogram (incl. ``unrated``) so the UI never renders a
                # metric that contradicts its severity strip.
                "severity": scan["severity"],
            },
        },
        "code": {
            "label": "Code / repo",
            "href": "/scan",
            "graph_href": _graph_drill_href(layers="directory,source_file,config_file,package,framework,vulnerability"),
            "metric": repo_scans,
            "metric_label": "repo scans",
            "status": "ok" if repo_scans > 0 else "idle",
            "detail": {"repo_scans": repo_scans, "packages": scan["unique_packages"]},
        },
        "runtime": {
            "label": "Runtime",
            "href": "/gateway",
            "graph_href": _graph_drill_href(relationships="runtime"),
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
            "graph_href": _graph_drill_href(layers="agent,user,role,policy", relationships="governance"),
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
            "critical": headline_critical,
            "high": headline_high,
            "critical_high": critical_high,
            "kev": scan["kev"],
            "credential_exposed": scan["credential_exposed"],
            "scans": scan["scan_count"],
            "latest_scan_at": scan["latest_scan_at"],
            "hub_findings": hub_findings,
        },
        "domains": domains,
        "coverage": coverage,
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
