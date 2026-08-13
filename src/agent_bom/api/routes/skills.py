"""First-class skills-scan REST route (#4790 REST parity).

The CLI (``agent-bom skills scan``) and MCP (``skill_scan``) already expose the
skills/instruction scanner; this route adds the missing REST + UI surface over
the SAME shared implementation — :func:`agent_bom.skills_service.scan_skill_targets`
— so detection never forks. It is a member of the synchronous AI supply-chain
scan family (``/v1/scan/prompt-scan``, ``/v1/scan/dataset-cards``) and adopts
that family's security posture verbatim by reusing its helpers:

* Local-path scans are **disabled by default** and, when enabled, confined to a
  configured scan root (``AGENT_BOM_API_SCAN_ROOT``) via
  :func:`agent_bom.api.routes.scan._api_scan_path_or_400` — no absolute paths,
  no ``..`` traversal, no symlink escape, owner-checked.
* The blocking scan runs **off the event loop** under shared backpressure via
  :func:`agent_bom.api.routes.scan._ai_scan_call`.

Endpoints:
    POST /v1/skills/scan   scan skill/instruction targets, persist, return verdicts
    GET  /v1/skills/scan   return this tenant's latest persisted scan (honest empty)

The returned envelope is the shared scanner's ``SkillsScanReport.to_dict()`` —
the same per-file trust verdict, provenance status, and audit findings the SARIF
export models — so an unsigned skill reads ``review`` / ``pending`` and is never
laundered into a clean pass. The latest run is persisted per-tenant so the UI
lands on the last result instead of an empty page.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(tags=["skills"])
_logger = logging.getLogger(__name__)

_SCAN_DEP = require_authenticated_permission("scan")
_READ_DEP = require_authenticated_permission("read")

# Bound the request surface so a caller cannot enqueue an unbounded fan-out.
_MAX_TARGETS = 200


class SkillsScanRequest(BaseModel):
    """Targets for a skills scan (paths relative to the configured scan root)."""

    model_config = ConfigDict(extra="forbid")

    directories: list[str] = Field(default_factory=list, max_length=_MAX_TARGETS)
    files: list[str] = Field(default_factory=list, max_length=_MAX_TARGETS)


def _empty_payload() -> dict[str, Any]:
    """Honest empty envelope — no run recorded for this tenant yet."""
    return {
        "scan_type": "skills",
        "report_type": "skills_scan",
        "status": "no_data",
        "run_id": None,
        "created_at": None,
        "summary": {
            "files_scanned": 0,
            "bundles": 0,
            "bundled_files": 0,
            "packages_found": 0,
            "servers_found": 0,
            "credential_env_vars": 0,
            "findings": 0,
            "verified_files": 0,
            "suspicious_files": 0,
            "malicious_files": 0,
            "blocked_files": 0,
            "high_risk_files": 0,
            "clean_files": 0,
            "suspicious_status_files": 0,
            "malicious_status_files": 0,
            "pending_status_files": 0,
            "unavailable_status_files": 0,
        },
        "files": [],
        "note": "No skills scan has been recorded for this tenant yet.",
    }


@router.post("/skills/scan")
async def run_skills_scan(
    request: Request,
    body: SkillsScanRequest | None = None,
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Scan skill/instruction targets, persist the run, and return per-file verdicts.

    Reuses the shared ``scan_skill_targets`` impl and the sibling scan family's
    path-confinement + off-loop offload. Returns the aggregated report with the
    per-file trust verdict and provenance; an unsigned skill reads ``review`` /
    ``pending`` — never an implied clean pass.
    """
    # Reuse the sibling scan family's confinement + offload helpers verbatim so
    # the skills scan inherits the exact same security posture and backpressure.
    from agent_bom.api.routes.scan import _ai_scan_call, _api_scan_path_or_400
    from agent_bom.api.skills_scan_store import SkillsScanRun, get_skills_scan_store
    from agent_bom.skills_service import scan_skill_targets

    tenant_id = require_request_tenant_id(request)
    scope = body or SkillsScanRequest()

    targets: list[Path] = []
    for raw in [*scope.directories, *scope.files]:
        targets.append(Path(_api_scan_path_or_400(raw)))
    if not targets:
        raise HTTPException(status_code=422, detail="At least one directory or file target is required.")

    run_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()

    # `catalog_path` is intentionally omitted: on a shared API host we must not
    # write a cross-tenant catalog file to disk. Persistence is per-tenant below.
    report = await _ai_scan_call(scan_skill_targets, targets)
    payload: dict[str, Any] = {
        "scan_type": "skills",
        "run_id": run_id,
        "created_at": created_at,
        "status": "completed",
        **report.to_dict(),
    }

    store = get_skills_scan_store()
    await anyio.to_thread.run_sync(
        lambda: store.put(SkillsScanRun(tenant_id=tenant_id, run_id=run_id, created_at=created_at, payload=payload))
    )
    return payload


@router.get("/skills/scan")
async def latest_skills_scan(
    request: Request,
    _role: Any = _READ_DEP,
) -> dict[str, Any]:
    """Return this tenant's most recent persisted skills scan (honest empty when none)."""
    from agent_bom.api.skills_scan_store import get_skills_scan_store

    tenant_id = require_request_tenant_id(request)
    store = get_skills_scan_store()
    latest = await anyio.to_thread.run_sync(lambda: store.latest_for_tenant(tenant_id))
    if latest is None:
        return _empty_payload()
    return latest.payload
