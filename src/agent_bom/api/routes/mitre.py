"""MITRE technique-coverage API routes (#3892).

Endpoint:
    GET /v1/mitre/coverage   per-framework technique coverage for the tenant

Coverage is the honest read of *which adversary techniques the estate's
findings actually provide evidence for* versus the full technique catalogue,
unified across MITRE ATT&CK, MITRE ATLAS, and MAESTRO. "Covered" means a
finding maps to the technique; "uncovered" means no evidence yet — never an
assertion that the technique is mitigated. See :mod:`agent_bom.mitre_coverage`.
"""

from __future__ import annotations

import logging
from typing import Any, cast

import anyio.to_thread
from fastapi import APIRouter, Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


router = APIRouter(dependencies=[_dep("read")])
_logger = logging.getLogger(__name__)

# Finding-payload fields the coverage aggregation reads. Kept small so native
# scan rows can be projected cheaply without the full finding-view pipeline.
_TAG_FIELDS: tuple[str, ...] = (
    "attack_tags",
    "attack_techniques",
    "mitre_attack_tags",
    "atlas_tags",
    "mitre_atlas_tags",
)


def _native_coverage_findings(jobs: list[Any]) -> list[dict[str, Any]]:
    """Project completed native scans into slim coverage findings.

    Only technique tags, a stable id, and the finding source are needed, so we
    read ``blast_radius`` directly instead of the heavier finding-view path.
    """
    from agent_bom.api.models import JobStatus

    rows: list[dict[str, Any]] = []
    for job in jobs:
        if getattr(job, "status", None) != JobStatus.DONE or not getattr(job, "result", None):
            continue
        result = job.result or {}
        job_id = str(getattr(job, "job_id", "") or "")
        for idx, item in enumerate(result.get("blast_radius", []) or []):
            if not isinstance(item, dict):
                continue
            vuln = str(item.get("vulnerability_id") or item.get("id") or "")
            pkg = str(item.get("package") or item.get("package_name") or "")
            row: dict[str, Any] = {
                "id": item.get("finding_id") or item.get("id") or f"{job_id}:{vuln}:{pkg}:{idx}",
                "source": item.get("source") or "blast_radius",
            }
            for field in _TAG_FIELDS:
                value = item.get(field)
                if value:
                    row[field] = value
            rows.append(row)
    return rows


def _build_coverage(tenant_id: str, jobs: list[Any]) -> dict[str, Any]:
    """Collect the tenant's findings and compute coverage (runs off-loop)."""
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.mitre_coverage import build_mitre_coverage

    findings: list[dict[str, Any]] = []
    store = get_compliance_hub_store()
    try:
        hub_findings = store.list(tenant_id)
    except Exception:  # pragma: no cover - defensive: never fail coverage on a store hiccup
        _logger.warning("hub store list failed for tenant coverage", exc_info=True)
        hub_findings = []
    findings.extend(f for f in hub_findings if isinstance(f, dict))
    findings.extend(_native_coverage_findings(jobs))

    coverage = build_mitre_coverage(findings)
    coverage["sources"] = {
        "hub_findings": len(hub_findings),
        "native_findings": len(findings) - len(hub_findings),
    }
    return coverage


@router.get("/mitre/coverage", tags=["mitre"])
async def mitre_coverage(request: Request) -> dict[str, Any]:
    """Per-framework MITRE technique coverage for the current tenant.

    Aggregates hub-ingested plus native scan findings and reports, for each of
    MITRE ATT&CK, MITRE ATLAS, and MAESTRO: the covered technique count and
    list (techniques with >=1 finding of evidence), the total catalogue count,
    the coverage percentage, and the covered techniques' finding references.

    Honest by construction: uncovered techniques mean "no evidence", not
    "safe". The store read runs off the event loop.
    """
    tenant_id = require_request_tenant_id(request)
    from agent_bom.api.stores import _get_store

    jobs = _get_store().list_all(tenant_id=tenant_id)
    return await anyio.to_thread.run_sync(_build_coverage, tenant_id, jobs)
