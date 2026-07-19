"""KSPM cluster-posture REST route (issue #4134 stage 3).

Exposes live Kubernetes security posture as a first-class resource, DISTINCT
from k8s image discovery (which feeds the vulnerability scan path). This route
never lists container images; it returns the posture evidence envelope — the
pinned CIS Kubernetes Benchmark provenance, every collector's explicit
executed/skipped/unevaluable/failed state, and the canonical :class:`ScanRun`
outcome — and persists each run so partial/unevaluable state stays visible and
can never be laundered into a clean pass.

Endpoints:
    POST /v1/kspm/clusters/posture   run + persist a live cluster-posture scan
    GET  /v1/kspm/clusters/posture   return the tenant's latest persisted run

The blocking, read-only collection (SA-token transport / kubelet reads) runs off
the event loop in a worker thread under backpressure, so a live scan can never
stall the event loop.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.k8s import K8sPostureResult, scan_live_cluster_posture_with_evidence
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(tags=["kspm"])
_logger = logging.getLogger(__name__)

_SCAN_DEP = require_authenticated_permission("scan")
_READ_DEP = require_authenticated_permission("read")

_SCHEMA_VERSION = "kspm.cluster.posture.v1"


class ClusterPostureRequest(BaseModel):
    """Scope for a live cluster-posture run (all fields optional)."""

    model_config = ConfigDict(extra="forbid")

    namespace: str = Field(default="default", max_length=253)
    all_namespaces: bool = False
    context: str | None = Field(default=None, max_length=253)
    enable_nodes_configz: bool = False


def _collect_posture(
    *,
    namespace: str,
    all_namespaces: bool,
    context: str | None,
    enable_nodes_configz: bool,
) -> K8sPostureResult:
    """Run the live posture collection (isolated seam for offload + testing)."""
    return scan_live_cluster_posture_with_evidence(
        namespace=namespace,
        all_namespaces=all_namespaces,
        context=context,
        enable_nodes_configz=enable_nodes_configz,
    )


def _posture_payload(result: K8sPostureResult, *, run_id: str, created_at: str, cluster_ref: str) -> dict[str, Any]:
    """Project a posture result into the persisted + returned evidence envelope."""
    evidence = result.to_evidence_dict()
    return {
        "schema_version": _SCHEMA_VERSION,
        "resource": "cluster_posture",
        "run_id": run_id,
        "created_at": created_at,
        "cluster_ref": cluster_ref,
        "status": evidence["status"],
        "transport": evidence["transport"],
        "benchmark": evidence["benchmark"],
        "collectors": evidence["collectors"],
        "finding_count": evidence["finding_count"],
        "severity_summary": result.severity_summary(),
        "scan_run": result.to_scan_run().to_dict(),
        "note": (
            "Live, read-only Kubernetes posture. Per-collector execution state is explicit: "
            "a denied/absent read is 'unevaluable' and a failed read is 'failed' — never a clean pass. "
            "This resource carries security posture, not container-image inventory."
        ),
    }


def _empty_payload() -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "resource": "cluster_posture",
        "run_id": None,
        "created_at": None,
        "cluster_ref": None,
        "status": "no_data",
        "transport": "",
        "benchmark": None,
        "collectors": [],
        "finding_count": 0,
        "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "scan_run": {"outcome": "complete", "issues": [], "warning_count": 0},
        "note": "No cluster-posture run has been recorded for this tenant yet.",
    }


@router.post("/kspm/clusters/posture")
async def run_cluster_posture(
    request: Request,
    body: ClusterPostureRequest | None = None,
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Run a live Kubernetes cluster-posture scan, persist it, and return the envelope.

    The heavy read-only collection is offloaded to a worker thread under
    backpressure. The returned (and persisted) body carries the benchmark
    provenance, honest per-collector states, and the canonical ScanRun outcome,
    so a partial/denied run reads ``partial`` — never a clean pass.
    """
    from agent_bom.api.kspm_posture_store import KspmPostureRun, get_kspm_posture_store

    tenant_id = require_request_tenant_id(request)
    scope = body or ClusterPostureRequest()
    run_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()

    try:
        async with adaptive_backpressure("kspm_posture"):
            result = await anyio.to_thread.run_sync(
                lambda: _collect_posture(
                    namespace=scope.namespace,
                    all_namespaces=scope.all_namespaces,
                    context=scope.context,
                    enable_nodes_configz=scope.enable_nodes_configz,
                )
            )
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.exception("KSPM cluster posture failed")
        raise HTTPException(status_code=500, detail="KSPM cluster posture failed; see server logs.") from exc

    cluster_ref = f"{result.transport or 'unknown'}:{'all' if scope.all_namespaces else scope.namespace}"
    payload = _posture_payload(result, run_id=run_id, created_at=created_at, cluster_ref=cluster_ref)

    store = get_kspm_posture_store()
    await anyio.to_thread.run_sync(
        lambda: store.put(
            KspmPostureRun(
                tenant_id=tenant_id,
                run_id=run_id,
                cluster_ref=cluster_ref,
                created_at=created_at,
                payload=payload,
            )
        )
    )
    return payload


@router.get("/kspm/clusters/posture")
async def latest_cluster_posture(
    request: Request,
    _role: Any = _READ_DEP,
) -> dict[str, Any]:
    """Return this tenant's most recent persisted cluster-posture run.

    Honest empty (``status: no_data``) when no run exists — never an implied
    pass. The stored envelope preserves every collector's execution state and the
    ScanRun outcome exactly as recorded.
    """
    from agent_bom.api.kspm_posture_store import get_kspm_posture_store

    tenant_id = require_request_tenant_id(request)
    store = get_kspm_posture_store()
    latest = await anyio.to_thread.run_sync(lambda: store.latest_for_tenant(tenant_id))
    if latest is None:
        return _empty_payload()
    return latest.payload
