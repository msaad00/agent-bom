"""Scan API routes.

Endpoints:
    POST /v1/scan                      start a scan (async, returns job_id)
    POST /v1/scan/check                check one package before installation
    GET  /v1/scan/{job_id}             fetch scan status + full results
    GET  /v1/scan/{job_id}/status      poll lightweight scan status
    GET  /v1/scan/{job_id}/attack-flow attack flow graph (React Flow)
    GET  /v1/scan/{job_id}/context-graph context graph with lateral movement
    GET  /v1/scan/{job_id}/graph-export graph export (json/dot/mermaid/graphml/cypher)
    GET  /v1/scan/{job_id}/licenses    license compliance report
    GET  /v1/scan/{job_id}/vex         VEX document
    GET  /v1/scan/{job_id}/skill-audit skill security audit
    POST /v1/scan/{job_id}/cancel      cooperative cancel for pending/running jobs
    DELETE /v1/scan/{job_id}           discard a job record
    GET  /v1/scan/{job_id}/stream      SSE — real-time scan progress
    GET  /v1/jobs                      list all scan jobs
    GET  /v1/findings                  list findings from completed scans
    GET  /v1/inventory                 list inventory from completed scans
    POST /v1/scan/dataset-cards        scan dataset cards & DVC files
    POST /v1/scan/training-pipelines   scan ML training pipeline artifacts
    POST /v1/scan/browser-extensions   scan browser extensions
    POST /v1/scan/model-provenance     check HF/Ollama model provenance
    POST /v1/scan/prompt-scan          scan prompts for injection/secrets
    POST /v1/scan/model-files          scan model files for unsafe formats
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import os
import time
import uuid
from collections.abc import AsyncIterator, Callable, Mapping
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Annotated, Any, Literal, NamedTuple, cast

import anyio.to_thread
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from werkzeug.security import safe_join

from agent_bom.api import job_status_count_cache
from agent_bom.api.finding_list_envelope import HUB_LIST_OFFSET_CEILING as _HUB_LIST_OFFSET_CEILING
from agent_bom.api.finding_list_envelope import finding_list_envelope
from agent_bom.api.finding_reachability import project_persisted_graph_reachability
from agent_bom.api.hub_ingest import hub_ingest_store_writes, hub_store_call
from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    deterministic_batch_id,
    idempotency_request_fingerprint,
)
from agent_bom.api.models import (
    BrowserExtensionsRequest,
    DatasetCardsRequest,
    JobStatus,
    ModelFilesRequest,
    ModelProvenanceRequest,
    PromptScanRequest,
    ScanJob,
    ScanRequest,
    TrainingPipelinesRequest,
)
from agent_bom.api.pipeline import _now, request_scan_cancellation, submit_scan_job
from agent_bom.api.scan_batches import child_request_for_target, refresh_batch_parent, scan_request_targets
from agent_bom.api.scan_job_reconciliation import reconcile_scan_jobs_active
from agent_bom.api.stores import (
    _get_graph_store,
    _get_idempotency_store,
    _get_store,
    _job_lock,
    _jobs_get,
    _jobs_is_compacted,
    _jobs_pop,
    _jobs_put,
)
from agent_bom.api.tenancy import require_body_tenant_match, require_request_tenant_id
from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.canonical_ids import canonical_finding_id, canonical_id
from agent_bom.finding_scope import (
    FINDING_SEVERITY_FILTERS,
    FindingClass,
    canonical_finding_severity_filter,
)
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)
_LOCAL_SCAN_DISABLE_VALUES = {"0", "false", "no", "off", "disabled"}
_BULK_FINDINGS_MAX_ITEMS = 1000
_BULK_FINDINGS_SOURCE_MAX_LENGTH = 128


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _require_json_content_type(request: Request) -> None:
    """Reject ambiguous bulk-ingest bodies before accepting caller data."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json" and not media_type.endswith("+json"):
        raise HTTPException(status_code=422, detail="Content-Type must be application/json")


def _api_local_scans_enabled() -> bool:
    configured = os.getenv("AGENT_BOM_API_LOCAL_PATH_SCANS", os.getenv("AGENT_BOM_ENABLE_LOCAL_PATH_SCANS", "disabled"))
    return configured.strip().lower() not in _LOCAL_SCAN_DISABLE_VALUES


async def _scan_graph_compute_call(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    """Run graph rendering/derivation for scan subresources off the event loop."""
    return await asyncio.to_thread(fn, *args, **kwargs)


async def _ai_scan_call(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    """Run blocking dedicated AI-scan work off-loop under shared backpressure."""
    try:
        async with adaptive_backpressure("ai_scan"):
            return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


# Shared off-loop hub ingest write path (also used by /v1/compliance/ingest).
# Aliased here so existing references / monkeypatch targets keep working.
_hub_store_call = hub_store_call
_bulk_ingest_store_writes = hub_ingest_store_writes


def _api_scan_root() -> Path:
    """Return the configured API filesystem scan root.

    API-local path scans are disabled unless explicitly enabled. Workstation
    pilots can set ``AGENT_BOM_API_LOCAL_PATH_SCANS=enabled`` and optionally
    scope ``AGENT_BOM_API_SCAN_ROOT`` to a tenant workspace mount.
    """
    configured = os.getenv("AGENT_BOM_API_SCAN_ROOT", "").strip()
    root = Path(configured).expanduser() if configured else Path.home()
    try:
        resolved = root.resolve()
    except (OSError, RuntimeError) as exc:
        from agent_bom.security import SecurityError

        raise SecurityError("Configured scan root is not available") from exc
    if not resolved.exists() or not resolved.is_dir():
        from agent_bom.security import SecurityError

        raise SecurityError("Configured scan root is not available")
    return resolved


def _enforce_api_scan_path_owner(resolved: Path, root: Path) -> None:
    """Reject paths not owned by the API process unless explicitly allowed."""
    if os.getenv("AGENT_BOM_API_SCAN_ALLOW_FOREIGN_OWNER", "").strip().lower() in {"1", "true", "yes", "on"}:
        return
    if os.name == "nt":
        return
    from agent_bom.security import SecurityError

    try:
        uid = os.getuid()
        root_stat = root.stat()
        path_stat = resolved.stat()
    except OSError as exc:
        raise SecurityError("Path is not available") from exc
    if root_stat.st_uid != uid or path_stat.st_uid != uid:
        raise SecurityError("Path owner is outside the API scan boundary")


def _sanitize_api_path(user_path: str) -> str:
    """Validate and sanitize a user-supplied path from an API request.

    Interprets ``user_path`` as relative to the configured API scan root
    (absolute paths are rejected). The resolved path is normalised, has any
    symlinks resolved, and is verified to remain within the scan root
    using ``os.path.commonpath`` before being returned.
    """
    from agent_bom.security import SecurityError

    if not _api_local_scans_enabled():
        raise SecurityError("Local filesystem scan endpoints are disabled")

    # Normalise basic whitespace
    user_path = (user_path or "").strip()
    if not user_path:
        raise SecurityError("Empty paths are not allowed")

    # 1. Reject absolute paths — API callers must use paths relative to the scan root.
    if os.path.isabs(user_path):
        raise SecurityError(f"Absolute paths are not allowed: {user_path}")

    # 2. Reject path traversal in raw input (../ segments)
    if ".." in user_path.split(os.sep):
        raise SecurityError(f"Path traversal not allowed: {user_path}")

    # 3. Compute fixed root and join user path under it
    scan_root = _api_scan_root()
    root = os.path.realpath(str(scan_root))
    candidate = safe_join(root, user_path)
    if candidate is None:
        raise SecurityError("Path resolves outside configured scan root")

    # 4. Resolve to real absolute path (follows symlinks)
    try:
        resolved_path = Path(candidate).resolve(strict=True)
    except OSError as exc:
        raise SecurityError("Path does not exist inside configured scan root") from exc

    # 5. Containment check — ensure resolved path stays within the configured root.
    if os.path.commonpath([root, os.path.realpath(str(resolved_path))]) != root:
        raise SecurityError("Path resolves outside configured scan root")

    current = Path(root)
    for part in Path(user_path).parts:
        current = current / part
        try:
            if current.is_symlink():
                raise SecurityError("Symlink path components are not allowed for API local scans")
        except OSError as exc:
            raise SecurityError("Path does not exist inside configured scan root") from exc

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = -1
    try:
        fd = os.open(candidate, flags)
        opened = os.fstat(fd)
        resolved_stat = resolved_path.stat()
        if (opened.st_dev, opened.st_ino) != (resolved_stat.st_dev, resolved_stat.st_ino):
            raise SecurityError("Path changed during validation")
    except OSError as exc:
        raise SecurityError("Path cannot be opened safely inside configured scan root") from exc
    finally:
        if fd >= 0:
            os.close(fd)

    _enforce_api_scan_path_owner(resolved_path, scan_root)

    return str(resolved_path)


def _api_scan_path_or_400(user_path: str) -> str:
    from agent_bom.security import SecurityError, sanitize_text

    try:
        return _sanitize_api_path(user_path)
    except SecurityError as exc:
        _logger.warning("blocked local API scan path: %s", sanitize_text(exc))
        raise HTTPException(status_code=400, detail="Invalid scan path") from exc


# Local-path fields on a ScanRequest that must be confined to the API scan jail
# before the job is queued. Non-path targets (images, connectors, repo_url, k8s)
# are intentionally excluded.
_SCAN_LOCAL_PATH_SINGLE_FIELDS = ("inventory", "gha_path", "sbom", "external_scan", "vex")
_SCAN_LOCAL_PATH_LIST_FIELDS = ("tf_dirs", "agent_projects", "jupyter_dirs", "filesystem_paths")


def _sanitize_scan_request_paths(body: ScanRequest) -> ScanRequest:
    """Confine every local-path field on a scan request to the API scan jail.

    The primary ``POST /v1/scan`` flow historically ran only
    :func:`agent_bom.security.validate_path` on these fields, which rejects
    ``..`` traversal but accepts absolute paths and does not confine them to a
    configured root — letting an authenticated caller read arbitrary host files
    (e.g. ``{"inventory": "/etc/hosts"}``). Route each populated field through the
    same :func:`_api_scan_path_or_400` helper and ``_api_local_scans_enabled``
    gate the dedicated scan endpoints use, so the default posture rejects
    local-path scans consistently on the primary endpoint too. ``external_scan``
    and ``vex`` are included here even though they were opened unvalidated.
    """
    updates: dict[str, Any] = {}
    for field in _SCAN_LOCAL_PATH_SINGLE_FIELDS:
        value = getattr(body, field)
        if value:
            updates[field] = _api_scan_path_or_400(value)
    for field in _SCAN_LOCAL_PATH_LIST_FIELDS:
        values = getattr(body, field)
        if values:
            updates[field] = [_api_scan_path_or_400(entry) for entry in values]
    if not updates:
        return body
    return body.model_copy(update=updates)


def _dataclass_to_dict(obj: object) -> object:
    """Convert a dataclass to dict, handling nested dataclasses."""
    import dataclasses

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dataclass_to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(i) for i in obj]
    return obj


def _request_header(request: Request, key: str) -> str:
    headers = getattr(request, "headers", None)
    if headers is None:
        return ""
    return str(headers.get(key, "") or "")


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _triggered_by(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "api"


def _visible_to_tenant(job: ScanJob, tenant_id: str) -> bool:
    return getattr(job, "tenant_id", "default") == tenant_id


def _completed_jobs_for_tenant(tenant_id: str) -> list[ScanJob]:
    return [job for job in _get_store().list_all(tenant_id=tenant_id) if job.status == JobStatus.DONE and job.result]


def iter_tenant_scan_spine_findings(
    tenant_id: str,
    *,
    since: str | None = None,
    severity: str | None = None,
    scan_id: str | None = None,
    scope: Mapping[str, str] | None = None,
    status: str = "all",
) -> list[dict[str, Any]]:
    """Current scan-spine findings for a tenant — the same source ``/v1/findings`` shows.

    The scan pipeline never writes the compliance hub, so these live only in the
    in-memory job store. The scheduled findings export unions this with the hub
    stream so a scan-based estate is not silently exported as empty. Bounded by
    the scan-job results already resident in memory (no per-tenant DB scan).
    """
    from agent_bom.api.compliance_hub_store import status_matches
    from agent_bom.api.findings_current import current_scan_findings
    from agent_bom.finding_scope import safe_finding_response_payload

    rows = current_scan_findings(
        _completed_jobs_for_tenant(tenant_id),
        since=since,
        scan_id=scan_id,
        iter_findings=_iter_scan_findings,
    )
    if severity:
        normalized = severity.lower()
        rows = [item for item in rows if str(item.get("severity", "")).lower() == normalized]
    rows = [item for item in rows if status_matches(item, status)]
    if scope:
        rows = [item for item in rows if _row_matches_scope(item, dict(scope))]
    return [safe_finding_response_payload(row) for row in rows]


def persisted_finding_evidence(
    *,
    tenant_id: str,
    cve_id: str,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Return one vulnerability from the same persisted finding sources as REST.

    MCP tools call this in-process instead of running a second laptop scan. The
    response distinguishes an empty persisted estate from a process that has no
    persisted scan evidence at all, allowing standalone MCP mode to retain its
    local-scan fallback without mixing the two scopes.
    """
    scan_jobs = _completed_jobs_for_tenant(tenant_id)
    if scan_id:
        scan_jobs = [job for job in scan_jobs if str((job.result or {}).get("scan_id") or job.job_id) == scan_id]
    rows = iter_tenant_scan_spine_findings(tenant_id, scan_id=scan_id, status="all")
    bulk_rows = _bulk_ingested_findings_for_tenant(tenant_id)
    if scan_id:
        bulk_rows = [row for row in bulk_rows if str(row.get("scan_id") or "") == scan_id]
    from agent_bom.finding_scope import safe_finding_response_payload

    rows.extend(safe_finding_response_payload(row) for row in bulk_rows)
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("canonical_id") or row.get("id") or ""),
            str(row.get("cve_id") or row.get("vulnerability_id") or ""),
            str(row.get("package") or row.get("package_name") or ""),
        )
        deduped[key] = row
    wanted = cve_id.strip().upper()
    matched = [
        row
        for row in deduped.values()
        if str(row.get("cve_id") or row.get("vulnerability_id") or row.get("id") or "").strip().upper() == wanted
    ]
    # An explicit scan scope must never fall through to an unrelated local MCP
    # scan merely because the requested persisted scan is absent.
    source_available = bool(scan_jobs or bulk_rows or scan_id)
    return {
        "available": source_available,
        "source": "persisted_scan_findings",
        "scope": {"tenant_id": tenant_id, "scan_id": scan_id},
        "completeness": {
            "status": "complete",
            "reason": "",
        },
        "findings": matched,
    }


class BulkFindingsRequest(BaseModel):
    """Normalized finding ingest for headless clients and agent runtimes."""

    model_config = ConfigDict(extra="forbid")

    findings: list[dict[str, Any]] = Field(min_length=1, max_length=_BULK_FINDINGS_MAX_ITEMS)
    source: str = Field(default="api", min_length=1, max_length=_BULK_FINDINGS_SOURCE_MAX_LENGTH)
    schema_version: str = Field(default="v1", min_length=1, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str | None = Field(default=None, description="Deprecated compatibility field; request tenant scope is authoritative.")
    observed_at: str | None = Field(
        default=None,
        description="Observation timestamp from scan completion; defaults to ingest time when omitted.",
    )
    reconcile_absent: bool = Field(
        default=False,
        description=("When true, mark open findings in the same source scope that are absent from this batch as resolved at observed_at."),
    )

    @field_validator("findings")
    @classmethod
    def _findings_must_be_objects(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in value:
            if not item:
                raise ValueError("findings must contain non-empty objects")
        return value

    @field_validator("source")
    @classmethod
    def _source_must_be_stable_label(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("source is required")
        return normalized


class PackageCheckRequest(BaseModel):
    """Pinned package check shared with the CLI and MCP surfaces."""

    model_config = ConfigDict(extra="forbid")

    package: str = Field(min_length=1, max_length=512)
    ecosystem: str = Field(default="npm", min_length=1, max_length=32)
    version: str | None = Field(default=None, max_length=256)

    @field_validator("package")
    @classmethod
    def _package_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("package is required")
        return normalized

    @field_validator("ecosystem")
    @classmethod
    def _ecosystem_must_be_supported(cls, value: str) -> str:
        from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
        from agent_bom.mcp_server_runtime import validate_ecosystem

        return validate_ecosystem(value, SUPPORTED_PACKAGE_ECOSYSTEM_SET)


def _bulk_ingested_findings_for_tenant(tenant_id: str) -> list[dict[str, Any]]:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    return [item for item in get_compliance_hub_store().list(tenant_id) if isinstance(item, dict) and item.get("origin") == "bulk_ingest"]


def _derive_bulk_finding_id(row: dict[str, Any], *, source: str) -> str:
    """Return a deterministic identity key for a bulk finding lacking an ``id``.

    Idempotency requires the identity key to be a pure function of finding
    content — never the per-attempt ``batch_id`` or wall clock. We fold in the
    stable discriminators (source, rule/vuln, location, package) via the shared
    ``uuid5`` canonicaliser so a resent identical batch collapses onto the same
    rows instead of appending duplicates.
    """
    raw_asset = row.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    rule = row.get("vulnerability_id") or row.get("cve_id") or row.get("rule_id") or row.get("title") or ""
    location = row.get("location") or row.get("file_path") or asset.get("location") or ""
    package = row.get("package") or row.get("package_name") or asset.get("name") or asset.get("identifier") or ""
    return canonical_finding_id(source, str(rule), str(location), str(package))


def _coerce_bulk_severity(value: Any, *, ordinal: int) -> str:
    """Validate/normalise a bulk finding's severity, failing closed on bad types.

    A non-string severity (nested object, number, list) cannot be honestly
    mapped to a severity bucket — accepting it materialised a row that leaked the
    value verbatim and never matched the severity filter. Reject it with a 422.
    A string severity is normalised to the canonical enum; an unrecognised label
    maps to ``unknown`` explicitly (never leaked as-is).
    """
    if value is None:
        return "unknown"
    if not isinstance(value, str):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: severity must be a string severity label, not {type(value).__name__}",
        )
    from agent_bom.graph.severity import normalize_severity

    return normalize_severity(value)


def _coerce_bulk_cvss(value: Any, *, ordinal: int) -> float | None:
    """Validate/coerce a bulk finding's cvss_score to a 0.0-10.0 float or null.

    A non-numeric string (``"NaNstring"``), a nested object, NaN/inf, or an
    out-of-range number cannot be an honest CVSS base score — accepting it left a
    value that never matched a cvss filter. Reject it with a 422. ``None`` /
    absent is allowed (no score); a numeric string that parses cleanly in range
    is coerced to float.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a number in 0.0-10.0 or null, not bool",
        )
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"finding {ordinal}: cvss_score {value!r} is not a number in 0.0-10.0",
            ) from None
    else:
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a number in 0.0-10.0 or null, not {type(value).__name__}",
        )
    if not math.isfinite(score) or not (0.0 <= score <= 10.0):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a finite number within 0.0-10.0",
        )
    return score


def _normalized_bulk_finding(row: dict[str, Any], *, source: str, batch_id: str, ordinal: int) -> dict[str, Any]:
    payload = dict(row)
    client_id = row.get("id")
    # Client-stable ids win; otherwise derive a content-deterministic id so
    # resends collapse (idempotent) rather than mint a fresh batch_id:ordinal.
    payload["id"] = str(client_id) if client_id else _derive_bulk_finding_id(row, source=source)
    payload.setdefault("source", source)
    # Fail closed on garbage severity/cvss types instead of materialising a row
    # that leaks the value verbatim and never matches the severity/cvss filter.
    payload["severity"] = _coerce_bulk_severity(row.get("severity"), ordinal=ordinal)
    cvss = _coerce_bulk_cvss(row.get("cvss_score"), ordinal=ordinal)
    if cvss is None:
        payload.pop("cvss_score", None)
    else:
        payload["cvss_score"] = cvss
    payload["origin"] = "bulk_ingest"
    payload["batch_id"] = batch_id
    payload["bulk_ordinal"] = ordinal
    return payload


def _redact_finding_page(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from agent_bom.finding_scope import safe_finding_response_payload

    return [safe_finding_response_payload(row) for row in rows]


def _scan_source_labels(job: ScanJob) -> list[str]:
    labels: list[str] = []
    req = job.request
    labels.extend(req.images)
    if req.inventory:
        labels.append("inventory")
    if req.k8s:
        labels.append("kubernetes")
    if req.sbom:
        labels.append("sbom-import")
    if req.external_scan:
        labels.append("external_scan")
    if req.repo_url and str(req.repo_url).strip():
        labels.append(str(req.repo_url).strip())
    labels.extend(req.connectors)
    labels.extend(req.filesystem_paths)
    labels.extend(req.agent_projects)
    return labels or ["local-agents"]


def _finding_identity(finding: dict[str, Any]) -> str:
    """Stable identity used to collapse the default findings view.

    Prefers the finding ``id`` (what Postgres' ``hub_findings_current`` keys on)
    and falls back to the vuln:package content key when a scan row omits ``id``.
    """
    from agent_bom.api.findings_current import finding_identity

    return finding_identity(finding)


def _finding_key(finding: dict[str, Any]) -> str:
    vuln_id = finding.get("vulnerability_id") or finding.get("cve_id") or finding.get("id") or finding.get("title") or ""
    raw_asset = finding.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    package = finding.get("package") or finding.get("package_name") or asset.get("name", "")
    return f"{vuln_id}:{package}"


def _row_vuln_id(finding: dict[str, Any]) -> str:
    """Return the CVE/advisory identifier for a finding, source-agnostic.

    The unified stream carries it under ``cve_id`` while the blast-radius and
    package-vulnerability representations carry the same value under
    ``vulnerability_id`` — normalizing here lets the three collapse together.
    """
    return str(finding.get("cve_id") or finding.get("vulnerability_id") or "").strip()


def _package_base_name(finding: dict[str, Any]) -> str:
    """Return the bare package name (no version) shared across representations.

    Blast-radius rows carry ``pkg@version`` while package-vulnerability rows
    carry a bare ``package`` + separate ``package_version``; the unified stream
    encodes it only in the ``"CVE-…: pkg@version"`` title. Strip all three to a
    common lowercase base so the same vuln+package folds to one canonical group.
    """
    package = str(finding.get("package") or finding.get("package_name") or "").strip()
    if not package:
        title = str(finding.get("title") or "")
        if ": " in title:
            package = title.split(": ", 1)[1].strip()
    if "@" in package:
        package = package.split("@", 1)[0]
    return package.strip().lower()


def _canonical_group_key(finding: dict[str, Any]) -> str:
    """Collapse the three per-CVE representations onto one grouping key.

    Findings that carry a CVE/advisory id group by
    ``(vuln_id, package_base, asset)`` so the ``MCP_SCAN`` (unified),
    ``blast_radius`` and ``package_vulnerability`` rows for the *same
    vulnerability on the same asset* merge into a single list row. Non-CVE
    findings (posture, malicious-package, etc.) fall back to their stable
    identity so distinct findings stay distinct.

    ``asset`` is in the key, and its absence was a real under-count. The three
    representations this function exists to merge all describe one vulnerability
    on **one** asset, so the asset was never needed to merge them — but leaving
    it out also merged the same package version across *different* assets. A
    scan of one repository never noticed, because a package appears once. An
    estate does: the demo ships fifteen advisories across 768 inventoried
    package rows in 129 container images, and ``/v1/findings`` reported 1,833 of
    2,616 rows — the entire vulnerability lane folded to fifteen — while every
    surface described the result as the total. A dedup key that omits the scope
    of the thing it dedupes is the same defect class that once dropped a second
    tenant's rows here.
    """
    vuln = _row_vuln_id(finding)
    if vuln:
        return f"vuln:{vuln.lower()}:{_package_base_name(finding)}:{_row_asset_key(finding)}"
    return f"id:{_finding_identity(finding)}"


def _row_asset_key(finding: dict[str, Any]) -> str:
    """The asset a row is about, in whichever spelling its representation uses.

    Empty when a representation names no asset — which keeps the merge working:
    a blast-radius row that identifies no asset still folds onto the unified row
    for the same vulnerability and package rather than splitting off on its own.
    """
    raw_asset = finding.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    for value in (
        asset.get("identifier"),
        asset.get("canonical_id"),
        asset.get("stable_id"),
        finding.get("resource_id"),
    ):
        text = str(value or "").strip()
        if text:
            return text.lower()
    return ""


_EMPTY_FIELD_VALUES: tuple[Any, ...] = (None, "", [], {})

# Descriptive/structural fields safe to backfill from the supplementary
# (blast-radius / package-vulnerability) representations onto the authoritative
# unified finding. Reachability and VEX verdicts are deliberately excluded: the
# unified stream is the source of truth for those and must not be overridden by
# a coarser blast-radius projection (see the unified-stream-wins contract).
_SUPPLEMENTARY_BACKFILL_FIELDS: tuple[str, ...] = (
    "package",
    "package_name",
    "package_version",
    "ecosystem",
    "summary",
    "description",
    "cvss_score",
    "cvss_vector",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "network_exploitable",
    "references",
    "fixed_version",
    "epss_score",
    "affected_agents",
    "affected_servers",
    "exposed_credentials",
    "exposed_tools",
    "phantom_tools",
)


def _backfill_supplementary_fields(base: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Fill only empty descriptive fields on ``base`` from ``incoming``.

    Never overrides a value the authoritative row already carries, so the
    unified finding's identifiers and reachability stay intact while
    package/CVE metadata from the supplementary representations is preserved.
    """
    for field in _SUPPLEMENTARY_BACKFILL_FIELDS:
        value = incoming.get(field)
        if value in _EMPTY_FIELD_VALUES:
            continue
        if base.get(field) in _EMPTY_FIELD_VALUES:
            base[field] = value


def _normalize_finding_identifiers(finding: dict[str, Any]) -> dict[str, Any]:
    """Guarantee every list row carries ``cve_id``/``title``/``finding_type``.

    Blast-radius and package-vulnerability rows carry the identifier only under
    ``vulnerability_id`` and omit ``title``/``finding_type``; normalize those so
    no row surfaces null identifiers regardless of which representation seeded it.
    """
    vuln = finding.get("cve_id") or finding.get("vulnerability_id")
    if vuln:
        if not finding.get("cve_id"):
            finding["cve_id"] = vuln
        if not finding.get("vulnerability_id"):
            finding["vulnerability_id"] = vuln
    if not finding.get("title"):
        package = finding.get("package") or finding.get("package_name") or ""
        # Never fall back to summary/description here: those are replay-only,
        # redacted-on-read fields, and the title is not redacted — deriving it
        # from them would leak sensitive free-text past _redact_finding_page.
        if vuln and package:
            finding["title"] = f"{vuln}: {package}"
        elif vuln:
            finding["title"] = str(vuln)
        elif package:
            finding["title"] = f"Vulnerability in {package}"
        else:
            finding["title"] = str(finding.get("finding_type") or "Finding")
    if not finding.get("finding_type"):
        finding["finding_type"] = "CVE" if vuln else "VULNERABILITY"
    return finding


def _finding_from_blast_radius(item: dict[str, Any], job: ScanJob) -> dict[str, Any]:
    vulnerability_id = item.get("vulnerability_id") or item.get("id") or ""
    package = item.get("package") or item.get("package_name") or ""
    vex_status = item.get("vex_status")
    risk_score = item.get("risk_score", item.get("blast_score", 0))
    if "vex_suppressed" in item:
        vex_suppressed = bool(item.get("vex_suppressed"))
    else:
        vex_suppressed = risk_score == 0.0 and vex_status in {"not_affected", "fixed"}
    canonical_id = item.get("canonical_id") or item.get("finding_id")
    row = {
        "id": canonical_id or f"{vulnerability_id}:{package}",
        "canonical_id": canonical_id,
        "asset": item.get("asset"),
        "vulnerability_id": vulnerability_id,
        "package": package,
        "severity": (item.get("severity") or "unknown").lower(),
        "source": "blast_radius",
        "scan_id": job.job_id,
        "scan_sources": _scan_source_labels(job),
        "affected_agents": item.get("affected_agents", []),
        "affected_servers": item.get("affected_servers", []),
        "exposed_credentials": item.get("exposed_credentials", []),
        "exposed_tools": item.get("exposed_tools", []),
        "phantom_tools": item.get("phantom_tools", []),
        "risk_score": risk_score,
        "cvss_score": item.get("cvss_score"),
        "epss_score": item.get("epss_score"),
        "attack_vector_summary": item.get("attack_vector_summary"),
        "impact_category": item.get("impact_category"),
        "ai_risk_context": item.get("ai_risk_context"),
        "fixed_version": item.get("fixed_version"),
        "is_kev": bool(item.get("is_kev") or item.get("cisa_kev")),
        "graph_reachable": item.get("graph_reachable"),
        "symbol_reachability": item.get("symbol_reachability"),
        "reachable_affected_symbols": item.get("reachable_affected_symbols", []),
        "match_confidence_tier": item.get("match_confidence_tier"),
        "vex_status": vex_status,
        "vex_justification": item.get("vex_justification"),
        "vex_suppressed": vex_suppressed,
        "compliance_tags": item.get("compliance_tags"),
    }
    for tag_field in (
        "owasp_tags",
        "atlas_tags",
        "attack_tags",
        "nist_ai_rmf_tags",
        "owasp_mcp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
        "cmmc_tags",
        "nist_800_53_tags",
        "fedramp_tags",
        "pci_dss_tags",
    ):
        if tag_field in item:
            row[tag_field] = item.get(tag_field) or []
    from agent_bom.finding_runtime_evidence import compliance_tags_from_finding_row

    row["framework_tags"] = compliance_tags_from_finding_row(row)
    return row


def _iter_package_findings(job: ScanJob) -> list[dict[str, Any]]:
    result = job.result or {}
    findings: list[dict[str, Any]] = []
    scan_sources = _scan_source_labels(job)
    for agent in result.get("agents", []) or []:
        if not isinstance(agent, dict):
            continue
        agent_name = str(agent.get("name") or "")
        for server in agent.get("mcp_servers", []) or []:
            if not isinstance(server, dict):
                continue
            server_name = str(server.get("name") or "")
            for package in server.get("packages", []) or []:
                if not isinstance(package, dict):
                    continue
                package_name = str(package.get("name") or "")
                for vuln in package.get("vulnerabilities", []) or []:
                    if not isinstance(vuln, dict):
                        continue
                    vuln_id = str(vuln.get("id") or vuln.get("vulnerability_id") or "")
                    findings.append(
                        {
                            "id": vuln_id,
                            "vulnerability_id": vuln_id,
                            "package": package_name,
                            "package_version": package.get("version"),
                            "ecosystem": package.get("ecosystem"),
                            "severity": str(vuln.get("severity") or "unknown").lower(),
                            "summary": vuln.get("summary") or vuln.get("description"),
                            "source": "package_vulnerability",
                            "scan_id": job.job_id,
                            "scan_sources": scan_sources,
                            "affected_agents": [agent_name] if agent_name else [],
                            "affected_servers": [server_name] if server_name else [],
                            "cvss_score": vuln.get("cvss_score"),
                            "cvss_vector": vuln.get("cvss_vector"),
                            "attack_vector": vuln.get("attack_vector"),
                            "attack_complexity": vuln.get("attack_complexity"),
                            "privileges_required": vuln.get("privileges_required"),
                            "user_interaction": vuln.get("user_interaction"),
                            "network_exploitable": bool(vuln.get("network_exploitable")),
                            "epss_score": vuln.get("epss_score"),
                            "fixed_version": vuln.get("fixed_version"),
                            "is_kev": bool(vuln.get("is_kev")),
                            "references": vuln.get("references", []),
                        }
                    )
    return findings


def _effective_reach_lookup(job: ScanJob) -> dict[str, dict[str, Any]]:
    """Build a per-vuln lookup of the effective-reach breakdown.

    Builds a one-shot context graph from the job's ``agents`` +
    ``blast_radius`` and runs :func:`agent_bom.effective_reach.annotate_graph`.
    Returned dict is keyed by *vulnerability_id* (e.g. ``CVE-2024-1234``)
    so the various finding shapes (top-level, blast-radius, package
    inner-vuln) can all hydrate from the same map.
    """
    result = job.result or {}
    try:
        from agent_bom.context_graph import NodeKind, build_context_graph

        graph = build_context_graph(
            result.get("agents", []) or [],
            result.get("blast_radius", []) or result.get("blast_radii", []) or [],
        )
    except Exception:  # pragma: no cover - never break the findings list
        return {}
    out: dict[str, dict[str, Any]] = {}
    for node in graph.nodes.values():
        if node.kind != NodeKind.VULNERABILITY:
            continue
        breakdown = node.metadata.get("effective_reach")
        if isinstance(breakdown, dict):
            out[node.label] = breakdown
    return out


def _attach_unified_graph_view(payload: dict[str, Any], result: dict[str, Any], *, scan_id: str, tenant_id: str) -> dict[str, Any]:
    """Attach the canonical graph view without changing legacy context fields."""
    try:
        from agent_bom.graph.builder import build_unified_graph_from_report

        unified = build_unified_graph_from_report(result, scan_id=scan_id, tenant_id=tenant_id)
    except Exception:  # pragma: no cover - graph bridge must not break legacy response
        payload.setdefault("warnings", []).append("Unified graph view unavailable for this scan result")
        return payload

    payload["unified_graph"] = {
        "schema_version": "agent-bom.graph/v1",
        **unified.to_dict(),
    }
    return payload


def _context_graph_payload(result: dict[str, Any], *, agent: str | None, scan_id: str, tenant_id: str) -> dict[str, Any]:
    from agent_bom.context_graph import (
        NodeKind,
        build_context_graph,
        collect_lateral_paths,
        compute_interaction_risks,
        to_serializable,
    )

    graph = build_context_graph(
        result.get("agents", []),
        result.get("blast_radius", []),
    )
    paths: list = []
    paths_truncated = False
    if agent:
        node_id = f"agent:{agent}"
        if node_id in graph.nodes:
            paths, paths_truncated = collect_lateral_paths(graph, [node_id])
    else:
        source_ids = (nid for nid, node in sorted(graph.nodes.items()) if node.kind == NodeKind.AGENT)
        paths, paths_truncated = collect_lateral_paths(graph, source_ids)
    risks = compute_interaction_risks(graph)

    payload = to_serializable(graph, paths, risks)
    payload["stats"]["lateral_paths_truncated"] = paths_truncated
    return _attach_unified_graph_view(payload, result, scan_id=scan_id, tenant_id=tenant_id)


def _graph_export_response(result: dict[str, Any], *, format: str, mermaid_limit: int) -> dict | str | PlainTextResponse:
    from agent_bom.output.graph_export import (
        build_graph_from_scan_data,
        to_cypher,
        to_dot,
        to_graphml,
        to_mermaid,
    )
    from agent_bom.output.graph_export import (
        to_json as graph_to_json,
    )

    graph = build_graph_from_scan_data(result)

    def _render_mermaid(g: Any) -> PlainTextResponse:
        if mermaid_limit == 0:
            return PlainTextResponse(
                to_mermaid(g, max_nodes=None, max_edges=None),
                media_type="text/plain",
            )
        return PlainTextResponse(
            to_mermaid(g, max_nodes=mermaid_limit),
            media_type="text/plain",
        )

    formats = {
        "dot": lambda g: PlainTextResponse(to_dot(g), media_type="text/vnd.graphviz"),
        "mermaid": _render_mermaid,
        "graphml": lambda g: PlainTextResponse(to_graphml(g), media_type="application/xml"),
        "cypher": lambda g: PlainTextResponse(to_cypher(g), media_type="text/plain"),
    }
    if format in formats:
        return formats[format](graph)
    return graph_to_json(graph)


def _iter_scan_findings(job: ScanJob) -> list[dict[str, Any]]:
    result = job.result or {}
    reach = _effective_reach_lookup(job)
    from agent_bom.finding_runtime_evidence import (
        attach_runtime_evidence_to_finding,
        build_tenant_runtime_evidence_index,
        compliance_tags_from_finding_row,
    )

    tenant_id = str(getattr(job, "tenant_id", None) or "default")
    runtime_index = build_tenant_runtime_evidence_index(tenant_id)
    incidents = result.get("runtime_incident_feedback") if isinstance(result.get("runtime_incident_feedback"), list) else []

    # CWPP runtime/EDR workload evidence (#4158 stage 3): additive, read-only.
    # Only workload-scoped rows are annotated, and only when this tenant actually
    # has runtime signals — an empty index leaves every row untouched, so absence
    # of runtime data is never rendered as a clean workload. Reachability is never
    # invented here.
    from agent_bom.cloud.runtime_workload_evidence import (
        RuntimeWorkloadEvidenceIndex,
        attach_workload_runtime_evidence_to_finding,
    )
    from agent_bom.cloud.runtime_workload_evidence_store import get_runtime_workload_evidence_store

    workload_runtime_index: RuntimeWorkloadEvidenceIndex | None = None
    try:
        _wl_index = RuntimeWorkloadEvidenceIndex.from_store(get_runtime_workload_evidence_store(), tenant_id)
        if not _wl_index.is_empty():
            workload_runtime_index = _wl_index
    except Exception:  # noqa: BLE001 - runtime evidence is additive; never break the read path
        workload_runtime_index = None

    def _attach_reach(row: dict[str, Any]) -> dict[str, Any]:
        from agent_bom.symbol_reach_triage import adjust_effective_reach_breakdown, symbol_reachability_from_payload

        vuln_id = row.get("vulnerability_id") or row.get("cve_id") or row.get("id") or ""
        breakdown = reach.get(str(vuln_id))
        sym = symbol_reachability_from_payload(row)
        if breakdown:
            adjusted = adjust_effective_reach_breakdown(breakdown, sym)
            row["effective_reach"] = adjusted
            row.setdefault("effective_reach_score", adjusted.get("composite"))
            row.setdefault("effective_reach_band", adjusted.get("band"))
        elif sym:
            from agent_bom.symbol_reach_triage import apply_composite_delta, band_from_composite

            composite = apply_composite_delta(0.0, sym)
            row["effective_reach"] = {
                "composite": composite,
                "band": band_from_composite(composite),
                "symbol_reachability": sym,
            }
            row.setdefault("effective_reach_score", composite)
            row.setdefault("effective_reach_band", band_from_composite(composite))
        row.setdefault("framework_tags", compliance_tags_from_finding_row(row))
        # Scan completion is authoritative observation time for scan-spine rows.
        # Do not infer first-seen history from the currently retained job set.
        observed_at = getattr(job, "completed_at", None) or getattr(job, "created_at", None)
        if observed_at is not None:
            row.setdefault("last_observed", observed_at)
        attach_runtime_evidence_to_finding(row, runtime_index, incidents=incidents)
        if workload_runtime_index is not None:
            attach_workload_runtime_evidence_to_finding(row, workload_runtime_index)
        return row

    # Collapse the three per-vulnerability representations (unified ``findings``
    # stream, ``blast_radius`` projection, nested ``package_vulnerability``) onto
    # one row per canonical id. The unified stream is processed first and stays
    # authoritative; later representations only backfill descriptive fields the
    # unified row is missing (package/CVE metadata) — never reachability or VEX,
    # so the unified-stream-wins contract holds. This keeps ``/v1/findings`` in
    # step with the overview count instead of emitting one row per representation.
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    def _absorb(row: dict[str, Any]) -> None:
        key = _canonical_group_key(row)
        # Older persisted blast/package projections did not carry ``asset``.
        # If exactly one authoritative row already exists for this
        # vulnerability+package, fold the anonymous compatibility row into it.
        # Never guess when multiple assets match: preserving a separate row is
        # safer than silently combining distinct estate assets.
        if _row_vuln_id(row) and not _row_asset_key(row):
            prefix = f"vuln:{_row_vuln_id(row).lower()}:{_package_base_name(row)}:"
            candidates = [candidate for candidate in order if candidate.startswith(prefix)]
            if len(candidates) == 1:
                key = candidates[0]
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = row
            order.append(key)
            return
        _backfill_supplementary_fields(existing, row)

    for item in result.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row.setdefault("scan_id", job.job_id)
        row.setdefault("scan_sources", _scan_source_labels(job))
        _absorb(_attach_reach(row))

    for item in result.get("blast_radius", []) or result.get("blast_radii", []) or []:
        if not isinstance(item, dict):
            continue
        _absorb(_attach_reach(_finding_from_blast_radius(item, job)))

    for row in _iter_package_findings(job):
        _absorb(_attach_reach(row))

    findings = [grouped[key] for key in order]
    # Surface the triage assignee as the finding owner (the simple ownership cut).
    # Built once per tenant and matched per row; rows with no triage assignee keep
    # whatever owner the scan spine already set (an explicit None when unassigned,
    # rendered "Unassigned" only in the CLI/UI).
    from agent_bom.api.routes.enterprise import build_tenant_triage_owner_index, triage_owner_for

    owner_index = build_tenant_triage_owner_index(tenant_id)
    for row in findings:
        _normalize_finding_identifiers(row)
        if owner_index:
            raw_asset = row.get("asset")
            asset = raw_asset if isinstance(raw_asset, dict) else {}
            raw_evidence = row.get("evidence")
            evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
            package = str(row.get("package") or row.get("package_name") or evidence.get("package_name") or asset.get("name") or "")
            assignee = triage_owner_for(
                owner_index,
                vuln_id=str(row.get("vulnerability_id") or row.get("cve_id") or ""),
                package=package,
                server_name=str(row.get("server_name") or ""),
            )
            if assignee:
                row["owner"] = assignee
    return findings


def _inventory_packages_from_agents(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for agent in agents:
        agent_name = str(agent.get("name") or "")
        for server in agent.get("mcp_servers", []) or []:
            if not isinstance(server, dict):
                continue
            server_name = str(server.get("name") or "")
            for package in server.get("packages", []) or []:
                if not isinstance(package, dict):
                    continue
                row = {
                    "name": package.get("name", ""),
                    "version": package.get("version", ""),
                    "ecosystem": package.get("ecosystem", ""),
                    "agent": agent_name,
                    "server": server_name,
                }
                key = (
                    str(row["name"]),
                    str(row["version"]),
                    str(row["ecosystem"]),
                    str(row["agent"]),
                    str(row["server"]),
                )
                if key in seen:
                    continue
                seen.add(key)
                packages.append(row)
    return packages


def _job_summary_payload(job: ScanJob) -> dict[str, Any]:
    """Build a lightweight summary payload for list surfaces."""
    from agent_bom.security import sanitize_sensitive_payload

    result = job.result if isinstance(job.result, dict) else {}
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else None
    aggregation = result.get("aggregation") if isinstance(result.get("aggregation"), dict) else None
    scan_run = result.get("scan_run") if isinstance(result.get("scan_run"), dict) else None
    warnings_value = result.get("warnings")
    warnings: list[Any] = warnings_value if isinstance(warnings_value, list) else []
    raw_warning_count = (scan_run or {}).get("warning_count")
    warning_count = max(0, min(100, raw_warning_count)) if isinstance(raw_warning_count, int) else len(warnings)
    generated_at = result.get("generated_at") or (scan_run or {}).get("generated_at")
    scan_timestamp = result.get("scan_timestamp") or generated_at
    request_payload = sanitize_sensitive_payload(job.request.model_dump(exclude_defaults=True, exclude_none=True))
    return {
        "job_id": job.job_id,
        "tenant_id": job.tenant_id,
        "batch_id": job.batch_id,
        "parent_job_id": job.parent_job_id,
        "child_job_ids": list(job.child_job_ids),
        "target": job.target,
        "target_index": job.target_index,
        "target_count": job.target_count,
        "source_id": job.source_id,
        "schedule_id": job.schedule_id,
        "status": job.status,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "request": request_payload if isinstance(request_payload, dict) else {},
        "summary": summary,
        "aggregation": aggregation,
        "scan_timestamp": scan_timestamp,
        "generated_at": generated_at,
        "scan_run": scan_run,
        "scan_outcome": (scan_run or {}).get("outcome"),
        "warning_count": warning_count,
        "warnings_preview": [str(item) for item in warnings[:3]],
        "pushed": bool(result.get("pushed")),
        "error": job.error,
    }


def _job_for_request(request: Request, job_id: str) -> ScanJob:
    tenant_id = _tenant_id(request)
    in_mem = _jobs_get(job_id)
    if in_mem is not None and _visible_to_tenant(in_mem, tenant_id):
        if _jobs_is_compacted(in_mem):
            persisted = _get_store().get(job_id, tenant_id=tenant_id)
            if persisted is not None:
                if persisted.child_job_ids:
                    refreshed = refresh_batch_parent(persisted.job_id, tenant_id=tenant_id)
                    return refreshed or persisted
                return cast(ScanJob, persisted)
        if in_mem.child_job_ids:
            refreshed = refresh_batch_parent(in_mem.job_id, tenant_id=tenant_id)
            return refreshed or in_mem
        return in_mem
    job = _get_store().get(job_id, tenant_id=tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.child_job_ids:
        refreshed = refresh_batch_parent(job.job_id, tenant_id=tenant_id)
        return refreshed or job
    return cast(ScanJob, job)


def _redact_scan_result_for_response(result: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop replay-only fields from top-level scan findings before API return."""
    if not isinstance(result, dict):
        return result
    from agent_bom.cloud.cis_remediation import fail_closed_cis_result

    redacted = cast(dict[str, Any], fail_closed_cis_result(result))
    findings = result.get("findings")
    if not isinstance(findings, list):
        return redacted
    from agent_bom.finding_scope import safe_finding_response_payload

    redacted["findings"] = [safe_finding_response_payload(item) for item in findings if isinstance(item, Mapping)]
    return redacted


def _job_response_payload(job: ScanJob) -> ScanJob:
    redacted_result = _redact_scan_result_for_response(job.result)
    if redacted_result is job.result:
        return job
    return job.model_copy(update={"result": redacted_result})


def enqueue_scan_job(
    *,
    tenant_id: str,
    triggered_by: str,
    request_body: ScanRequest,
    source_id: str | None = None,
    quota_guarded: bool = False,
    dispatch: bool = True,
) -> ScanJob:
    """Persist and optionally dispatch a scan job for async execution.

    ``quota_guarded`` is reserved for a caller already holding the tenant quota
    guard while it atomically admits an adjacent resource such as a trial scan
    credit and idempotency record.  It prevents a non-reentrant nested lock.
    """
    store = _get_store()
    targets = scan_request_targets(request_body)

    if len(targets) > 1:
        if quota_guarded:
            raise ValueError("quota_guarded admission only supports one scan job")
        batch_id = str(uuid.uuid4())
        now = _now()
        parent_job_id = str(uuid.uuid4())
        child_jobs: list[ScanJob] = []
        for index, target in enumerate(targets, start=1):
            child_jobs.append(
                ScanJob(
                    job_id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    batch_id=batch_id,
                    parent_job_id=parent_job_id,
                    target=target,
                    target_index=index,
                    target_count=len(targets),
                    source_id=source_id,
                    triggered_by=triggered_by,
                    created_at=now,
                    request=child_request_for_target(request_body, target),
                )
            )

        parent = ScanJob(
            job_id=parent_job_id,
            tenant_id=tenant_id,
            batch_id=batch_id,
            child_job_ids=[job.job_id for job in child_jobs],
            source_id=source_id,
            triggered_by=triggered_by,
            status=JobStatus.RUNNING,
            created_at=now,
            started_at=now,
            request=request_body,
            progress=[f"Batch scan created with {len(child_jobs)} target job(s)"],
            target_count=len(targets),
        )

        attempted_jobs = len(child_jobs) + 1
        with tenant_quota_guard(
            tenant_id,
            lambda: enforce_active_scan_quota(tenant_id, attempted=attempted_jobs),
            lambda: enforce_retained_jobs_quota(tenant_id, attempted=attempted_jobs),
        ):
            store.put(parent)
            _jobs_put(parent.job_id, parent)
            for child in child_jobs:
                store.put(child)
                _jobs_put(child.job_id, child)
            try:
                refresh_batch_parent(parent.job_id, tenant_id=tenant_id)
            except Exception:  # noqa: BLE001
                pass
            try:
                reconcile_scan_jobs_active(store)
            except Exception:  # noqa: BLE001
                pass

        for child in child_jobs:
            dispatch_scan_job(child)
        return parent

    job = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        source_id=source_id,
        triggered_by=triggered_by,
        created_at=_now(),
        request=request_body,
    )

    # Hold the per-tenant quota lock across the (check + insert) pair so two
    # concurrent requests serialise here and the second caller's check sees
    # the first caller's row. Without this, a tenant exceeds quota by N
    # under load (audit-4 P1).
    admission = (
        contextlib.nullcontext()
        if quota_guarded
        else tenant_quota_guard(
            tenant_id,
            lambda: enforce_active_scan_quota(tenant_id),
            lambda: enforce_retained_jobs_quota(tenant_id),
        )
    )
    with admission:
        store.put(job)
        _jobs_put(job.job_id, job)
        # Recompute after durable enqueue so the gauge survives missed
        # increments and reflects queued + running work from the store.
        try:
            reconcile_scan_jobs_active(store)
        except Exception:  # noqa: BLE001
            pass

    if not dispatch:
        return job
    try:
        dispatch_scan_job(job)
    except Exception as exc:  # noqa: BLE001 - local/shared dispatch boundary
        # The job row already exists. Never leave it looking claimable when the
        # handoff failed, because an HTTP retry could otherwise create a second
        # job while this orphan remains permanently pending.
        job.status = JobStatus.FAILED
        job.completed_at = _now()
        job.error = "Scan dispatch failed before execution."
        job.progress.append("Dispatch failed before execution")
        try:
            store.put(job)
        except Exception as persist_exc:  # noqa: BLE001
            _logger.error(
                "Failed to persist scan dispatch failure job=%s: %s",
                job.job_id,
                sanitize_error(persist_exc, generic=True),
            )
        _jobs_put(job.job_id, job, compact_terminal=True)
        try:
            reconcile_scan_jobs_active(store)
        except Exception:  # noqa: BLE001
            pass
        _logger.error(
            "Scan dispatch failed job=%s: %s",
            job.job_id,
            sanitize_error(exc, generic=True),
        )
        raise RuntimeError("Scan dispatch failed before execution.") from None
    return job


def dispatch_scan_job(job: ScanJob) -> None:
    """Dispatch an already-persisted scan through the configured durable queue."""

    store = _get_store()
    from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch

    if distributed_scans_enabled() and store_supports_dispatch(store):
        store.enqueue_for_dispatch(job)
    else:
        submit_scan_job(job)


# ─── Core Scan Endpoints ─────────────────────────────────────────────────────


@router.post("/scan", response_model=ScanJob, status_code=202, tags=["scan"])
async def create_scan(request: Request, body: ScanRequest) -> ScanJob:
    """Start a scan. Returns immediately with a job_id.
    Poll GET /v1/scan/{job_id} for results, or stream via /v1/scan/{job_id}/stream.

    ``format`` selects the shape of the completed result. ``json`` (the default)
    leaves the AI-BOM JSON in ``result``; ``cyclonedx``, ``sarif``, ``spdx``,
    ``html``, and ``text`` render that report into ``result_document``, which is
    what the CLI and MCP surfaces emit for the same value.

    Retry-safe: repeating the request with the same ``Idempotency-Key`` header
    returns the first job instead of minting a new job_id per attempt; reusing
    the key with a different body is a 409 conflict.
    """
    tenant_id = _tenant_id(request)
    # Confine local-path targets to the API scan jail before any queueing or
    # idempotency work — the same gate/helper the dedicated scan endpoints use.
    body = _sanitize_scan_request_paths(body)
    idem_key = _request_header(request, "Idempotency-Key")
    idem_source = _request_header(request, "X-Agent-Bom-Source-Id") or "scan"
    request_hash = idempotency_request_fingerprint(body)
    if idem_key:
        try:
            cached = _get_idempotency_store().get(
                "/v1/scan",
                tenant_id,
                idem_source,
                idem_key,
                request_hash=request_hash,
            )
        except IdempotencyConflictError as exc:
            raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
        if cached is not None:
            cached_job_id = str(cached.get("job_id") or "")
            existing = _jobs_get(cached_job_id) if cached_job_id else None
            if existing is None and cached_job_id:
                existing = _get_store().get(cached_job_id, tenant_id=tenant_id)
            if existing is not None:
                return _job_response_payload(existing)

    job = enqueue_scan_job(
        tenant_id=tenant_id,
        triggered_by=_triggered_by(request),
        request_body=body,
    )
    if idem_key:
        _get_idempotency_store().put(
            "/v1/scan",
            tenant_id,
            idem_source,
            idem_key,
            {"job_id": job.job_id},
            request_hash=request_hash,
        )
    return job


@router.post("/scan/check", tags=["scan"])
async def check_package(body: PackageCheckRequest) -> dict[str, Any]:
    """Check one package with the same vulnerability intelligence as MCP."""

    from mcp.server.fastmcp.exceptions import ToolError

    from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
    from agent_bom.mcp_server_runtime import validate_ecosystem
    from agent_bom.mcp_tools.scanning import check_impl

    try:
        result = await check_impl(
            package=body.package,
            ecosystem=body.ecosystem,
            version=body.version,
            _validate_ecosystem=lambda value: validate_ecosystem(value, SUPPORTED_PACKAGE_ECOSYSTEM_SET),
            _truncate_response=lambda value: value,
        )
    except ToolError as exc:
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc

    payload = json.loads(result)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="Package check returned an invalid response")
    return payload


@router.get("/scan/drivers", tags=["scan"])
async def list_scan_drivers(include_planned: bool = True) -> dict:
    """List scanner driver contracts and orchestration semantics."""

    from agent_bom.scanners.registry import (
        list_registered_scanners,
        scanner_registry_summary,
        scanner_registry_warnings,
    )

    return {
        "drivers": [registration.to_dict() for registration in list_registered_scanners(include_planned=include_planned)],
        "summary": scanner_registry_summary(),
        "warnings": scanner_registry_warnings(),
    }


@router.get("/scan/{job_id}", response_model=ScanJob, tags=["scan"])
async def get_scan(request: Request, job_id: str) -> ScanJob:
    """Fetch scan status and full results.

    ``result`` is always the canonical AI-BOM JSON. When the request asked for a
    non-json ``format``, ``result_document`` carries that rendering and
    ``result_format`` names it.
    """
    return _job_response_payload(_job_for_request(request, job_id))


@router.get("/scan/{job_id}/status", tags=["scan"])
async def get_scan_status(request: Request, job_id: str) -> dict[str, Any]:
    """Poll lightweight scan status without serializing large result payloads."""
    return _job_summary_payload(_job_for_request(request, job_id))


@router.get("/scan/{job_id}/attack-flow", tags=["scan"])
async def get_attack_flow(
    request: Request,
    job_id: str,
    cve: str | None = None,
    severity: str | None = None,
    framework: str | None = None,
    agent: str | None = None,
) -> dict:
    """Get the attack flow graph for a completed scan.

    Returns React Flow-compatible nodes/edges showing the CVE -> package ->
    server -> agent attack chain with credential and tool branches.

    Query params for filtering:
      ?cve=CVE-2025-xxx     - show only this CVE's blast radius
      ?severity=critical     - filter by severity level
      ?framework=LLM05       - filter by OWASP/ATLAS/NIST tag
      ?agent=claude-desktop  - filter to a specific agent
    """
    job = _job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    from agent_bom.output.attack_flow import build_attack_flow

    blast_radius = job.result.get("blast_radius", [])
    agents_data = job.result.get("agents", [])

    return build_attack_flow(
        blast_radius,
        agents_data,
        cve=cve,
        severity=severity,
        framework=framework,
        agent_name=agent,
    )


@router.get("/scan/{job_id}/context-graph", tags=["scan"])
async def get_context_graph(request: Request, job_id: str, agent: str | None = None) -> dict:
    """Get the agent context graph with lateral movement analysis.

    Returns nodes, edges, lateral paths, interaction risks, and stats for
    a completed scan.  Optionally filter lateral paths to a single agent.

    Query params:
      ?agent=claude-desktop  - only compute lateral paths from this agent
    """
    job = _job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    tenant_id = str(getattr(request.state, "tenant_id", "") or "")
    return cast(
        dict,
        await _scan_graph_compute_call(_context_graph_payload, job.result, agent=agent, scan_id=job.job_id, tenant_id=tenant_id),
    )


@router.get("/scan/{job_id}/graph-export", tags=["scan"], response_model=None)
async def get_graph_export(
    request: Request,
    job_id: str,
    format: str = "json",
    mermaid_limit: Annotated[
        int,
        Query(
            ge=0,
            le=5000,
            description="Maximum nodes rendered for Mermaid output; 0 renders the full graph.",
        ),
    ] = 80,
) -> dict | str | PlainTextResponse:
    """Export the dependency graph in graph-native formats.

    Query params:
      ?format=json      JSON nodes/edges (default)
      ?format=dot       Graphviz DOT
      ?format=mermaid   Mermaid flowchart
      ?format=graphml   GraphML with AIBOM attributes (yEd/Gephi/NetworkX)
      ?format=cypher    Neo4j Cypher import script
      ?mermaid_limit=80 Maximum nodes rendered for Mermaid; 0 renders all
    """
    job = _job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    result = job.result if isinstance(job.result, dict) else {}
    return cast(
        "dict | str | PlainTextResponse",
        await _scan_graph_compute_call(_graph_export_response, result, format=format, mermaid_limit=mermaid_limit),
    )


@router.get("/scan/{job_id}/remediation", tags=["scan"])
async def get_remediation_plan(request: Request, job_id: str) -> dict:
    """Get the remediation plan for a completed scan, and nothing else.

    ``GET /v1/scan/{job_id}`` returns the canonical AI-BOM document — every
    finding, blast radius, asset and exposure path. The remediation surface read
    one field off it, so the transfer tracked the size of the estate rather than
    the size of the plan. Measured on the demo estate (2,068 assets / 2,716
    findings): an 8.7 MB job payload for a 41 KB plan, 99.5% of it discarded by
    the caller and all of it parsed by the browser first.

    The plan is inherently bounded — one entry per upgradable package, not per
    asset — so it is returned whole, with ``total`` stated rather than left for
    the client to infer.
    """
    job = _job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")
    plan = job.result.get("remediation_plan") or [] if isinstance(job.result, dict) else []
    return {"job_id": job_id, "remediation_plan": plan, "total": len(plan)}


@router.get("/scan/{job_id}/licenses", tags=["scan"])
async def get_licenses(request: Request, job_id: str) -> dict:
    """Get the license compliance report for a completed scan.

    Returns license findings, summary, compliance status, and per-package
    license categorization (permissive, copyleft, commercial risk, unknown).
    """
    job = _job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    # If the scan already computed license_report, return it
    if isinstance(job.result, dict) and job.result.get("license_report"):
        return cast(dict, job.result["license_report"])

    # Otherwise compute on-the-fly from scan result agents
    from agent_bom.license_policy import evaluate_license_policy as _eval_lic
    from agent_bom.license_policy import to_serializable as _lic_ser
    from agent_bom.models import Agent as _AgentModel
    from agent_bom.models import AgentType as _AgentType
    from agent_bom.models import MCPServer as _ServerModel
    from agent_bom.models import Package as _PkgModel

    agents_data = job.result.get("agents", []) if isinstance(job.result, dict) else []
    model_agents = []
    for ad in agents_data:
        servers = []
        for sd in ad.get("mcp_servers", []):
            pkgs = [
                _PkgModel(
                    name=p.get("name", ""),
                    version=p.get("version", ""),
                    ecosystem=p.get("ecosystem", ""),
                    license=p.get("license"),
                    license_expression=p.get("license_expression"),
                )
                for p in sd.get("packages", [])
            ]
            servers.append(_ServerModel(name=sd.get("name", ""), command=sd.get("command", ""), packages=pkgs))
        model_agents.append(
            _AgentModel(name=ad.get("name", ""), agent_type=_AgentType(ad.get("type", "custom")), config_path="", mcp_servers=servers)
        )

    lic_report = _eval_lic(model_agents)
    return _lic_ser(lic_report)


@router.get("/scan/{job_id}/vex", tags=["scan"])
async def get_vex(request: Request, job_id: str) -> dict:
    """Get the VEX (Vulnerability Exploitability eXchange) document for a completed scan.

    Returns VEX statements with vulnerability status (affected, not_affected,
    fixed, under_investigation), justifications, and statistics.
    """
    job = _job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    # Return pre-computed VEX data if available
    if isinstance(job.result, dict) and job.result.get("vex"):
        return cast(dict, job.result["vex"])

    # Otherwise generate on-the-fly from blast_radii
    return {"statements": [], "stats": {"total_statements": 0, "affected": 0, "not_affected": 0, "fixed": 0, "under_investigation": 0}}


@router.get("/scan/{job_id}/skill-audit", tags=["scan"])
async def get_skill_audit(request: Request, job_id: str) -> dict:
    """Get the skill security audit results for a completed scan.

    Returns findings from the skill file security audit including
    typosquat detection, unverified servers, shell access, and more.
    Empty results if no skill files were scanned.
    """
    job = _job_for_request(request, job_id)

    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    return cast(
        dict,
        job.result.get(
            "skill_audit",
            {
                "findings": [],
                "packages_checked": 0,
                "servers_checked": 0,
                "credentials_checked": 0,
                "passed": True,
            },
        ),
    )


@router.post("/scan/{job_id}/cancel", response_model=ScanJob, tags=["scan"])
async def cancel_scan(request: Request, job_id: str) -> ScanJob:
    """Request cooperative cancellation of a pending or running scan job.

    Sets ``JobStatus.CANCELLED``; the worker exits at the next pipeline
    checkpoint. Terminal jobs are returned unchanged. Use ``DELETE`` to discard
    the job record after cancellation (or for already-finished jobs).
    """
    job = _job_for_request(request, job_id)
    request_scan_cancellation(job)
    return _job_response_payload(_job_for_request(request, job_id))


@router.delete("/scan/{job_id}", status_code=204, tags=["scan"])
async def delete_scan(request: Request, job_id: str) -> None:
    """Discard a job record.

    For pending/running jobs, requests cooperative cancellation first so the
    worker does not finish into a resurrected DONE state after discard.
    """
    job = _job_for_request(request, job_id)
    if job.status in {JobStatus.PENDING, JobStatus.RUNNING}:
        request_scan_cancellation(job)
    in_memory = _jobs_pop(job_id) if _visible_to_tenant(job, _tenant_id(request)) else None
    in_store = _get_store().delete(job_id, tenant_id=_tenant_id(request))
    if not in_memory and not in_store:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@router.get("/scan/{job_id}/stream", tags=["scan"])
async def stream_scan(request: Request, job_id: str) -> Response:
    """Server-Sent Events stream for real-time scan progress.

    Connect with EventSource:
        const es = new EventSource('/v1/scan/{job_id}/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    try:
        from sse_starlette.sse import EventSourceResponse
    except ImportError as exc:
        raise HTTPException(
            status_code=501,
            detail="SSE requires sse-starlette. Install: pip install 'agent-bom[api]'",
        ) from exc

    _job_for_request(request, job_id)
    tenant_id = _tenant_id(request)

    import json as _json

    async def event_generator() -> AsyncIterator[dict[str, Any]]:
        sent = 0
        lock = _job_lock(job_id)
        start = time.monotonic()
        while time.monotonic() - start < 2100:  # 35 min max (exceeds stuck-job timeout)
            current = _jobs_get(job_id)
            if current is None:
                break
            if not _visible_to_tenant(current, tenant_id):
                break
            # Thread-safe snapshot of new progress lines and status
            with lock:
                new_lines = list(current.progress[sent:])
                status = current.status
            from agent_bom.security import sanitize_sensitive_payload

            for line in new_lines:
                try:
                    parsed = _json.loads(line)
                    if isinstance(parsed, dict) and parsed.get("type") == "step":
                        parsed = sanitize_sensitive_payload(parsed)
                        yield {"data": _json.dumps(parsed)}
                    else:
                        yield {"data": _json.dumps({"type": "progress", "message": sanitize_sensitive_payload(line)})}
                except (_json.JSONDecodeError, ValueError):
                    yield {"data": _json.dumps({"type": "progress", "message": sanitize_sensitive_payload(line)})}
                sent += 1
            if status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
                yield {"data": _json.dumps({"type": "done", "status": status, "job_id": job_id})}
                break
            await asyncio.sleep(0.25)

    return cast(Response, EventSourceResponse(event_generator()))


@router.get("/jobs", tags=["scan"])
async def list_jobs(
    request: Request,
    # enforce limit/offset caps via Pydantic so callers
    # cannot pass `?limit=10000` to fan out the in-memory scan-job list.
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    include_details: bool = False,
    q: Annotated[str | None, Query(max_length=200)] = None,
    status: JobStatus | None = None,
) -> dict:
    """List all scan jobs (for the UI job history panel).

    Search and status predicates are applied by the persistence backend before
    pagination, so totals and exports describe the full filtered collection.

    The store reads run in a worker thread. ``count_summary`` and
    ``count_summary_by_status`` are unbounded aggregates, and the dashboard
    activity feed polls this route continuously, so running them inline would
    stall every unrelated route for the duration of each poll. Backpressure
    sheds excess concurrent reads with ``429 + Retry-After`` rather than piling
    up worker threads — the same guard ``/findings`` uses.
    """
    try:
        async with adaptive_backpressure("jobs"):
            return await anyio.to_thread.run_sync(
                _list_jobs_impl,
                request,
                limit,
                offset,
                include_details,
                q,
                status,
            )
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _list_jobs_impl(
    request: Request,
    limit: int,
    offset: int,
    include_details: bool,
    q: str | None,
    status: JobStatus | None,
) -> dict:
    """Synchronous body of :func:`list_jobs`, run in a worker thread."""
    tenant_id = _tenant_id(request)
    store = _get_store()
    query = q.strip() if q else None
    filter_kwargs: dict[str, Any] = {}
    if query:
        filter_kwargs["query"] = query
    if status is not None:
        filter_kwargs["status"] = status
    count_summary = getattr(store, "count_summary", None)
    if callable(count_summary):
        total = count_summary(tenant_id=tenant_id, **filter_kwargs)
        summary = store.list_summary(tenant_id=tenant_id, limit=limit, offset=offset, **filter_kwargs)
    else:
        summary = store.list_summary(tenant_id=tenant_id)
        if query:
            summary = [
                item
                for item in summary
                if query.casefold()
                in " ".join(str(item.get(key) or "") for key in ("job_id", "source_id", "triggered_by", "schedule_id", "target")).casefold()
            ]
        if status is not None:
            summary = [item for item in summary if item.get("status") == status]
        total = len(summary)
        summary = summary[offset : offset + limit]
    count_summary_by_status = getattr(store, "count_summary_by_status", None)
    if callable(count_summary_by_status):
        # The activity feed polls this route continuously and the aggregate is
        # unbounded, so repeated polls are served from a short-lived cache. A
        # job write drops the tenant's entries. Across workers the guarantee is
        # bounded staleness rather than immediate consistency; seconds is fine
        # for a progress display and nothing gates on this number.
        status_counts = job_status_count_cache.get_counts(tenant_id, query)
        if status_counts is None:
            status_counts = count_summary_by_status(tenant_id=tenant_id, query=query)
            job_status_count_cache.set_counts(tenant_id, query, status_counts)
    else:
        status_counts = {}
    enriched: list[dict[str, Any]] = []
    for item in summary:
        in_mem = _jobs_get(item["job_id"])
        if isinstance(in_mem, ScanJob) and _visible_to_tenant(in_mem, tenant_id):
            enriched.append(_job_summary_payload(in_mem))
            continue

        if include_details:
            # Keep list surfaces compatible with lightweight stores and tests
            # that only implement paged summaries. Hydrate only when the caller
            # asks for details and the job is not already in memory.
            try:
                get_job = getattr(store, "get", None)
                full_job = get_job(item["job_id"], tenant_id=tenant_id) if callable(get_job) else None
            except Exception:
                full_job = None
            enriched.append(_job_summary_payload(full_job) if isinstance(full_job, ScanJob) else item)
            continue

        enriched.append(item)
    return {
        # emit schema_version on terminal list responses
        # so downstream consumers can pin a contract independent of API path.
        "schema_version": "v1",
        "jobs": enriched,
        "count": len(enriched),
        "total": total,
        "limit": limit,
        "offset": offset,
        "status_counts": status_counts,
    }


_ALLOWED_FINDING_SORTS = ("effective_reach", "cvss", "severity")
# Lifecycle-status filter (default ``open`` = live posture). ``open`` maps to
# status IN (open, reopened) in the store; ``resolved`` to status = resolved;
# ``all`` applies no lifecycle predicate.
_ALLOWED_FINDING_STATUSES = ("open", "resolved", "all")
_DEFAULT_FINDING_STATUS = "open"
_ALLOWED_FINDING_SEVERITIES = FINDING_SEVERITY_FILTERS


def _normalize_finding_sort(sort: str) -> str:
    sort_key = sort.lower().strip() if isinstance(sort, str) else "effective_reach"
    if sort_key not in _ALLOWED_FINDING_SORTS:
        raise HTTPException(
            status_code=422,
            detail=f"invalid sort '{sort}'; accepted values: {', '.join(_ALLOWED_FINDING_SORTS)}",
        )
    return sort_key


_FRESHNESS_BUCKETS = ("last_24_hours", "last_7_days", "last_30_days", "older", "unavailable")
_FACET_SCAN_BUDGET = 50_000
_FACET_DEADLINE_SECONDS = 1.5


def _freshness_bucket(row: Mapping[str, Any], *, now: datetime | None = None) -> str:
    """Classify only an observed timestamp; missing/invalid evidence is unavailable."""
    raw = row.get("last_observed") or row.get("last_seen")
    if not isinstance(raw, str) or not raw.strip():
        return "unavailable"
    try:
        observed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return "unavailable"
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    age_seconds = max(0.0, (current.astimezone(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds())
    if age_seconds <= 24 * 60 * 60:
        return "last_24_hours"
    if age_seconds <= 7 * 24 * 60 * 60:
        return "last_7_days"
    if age_seconds <= 30 * 24 * 60 * 60:
        return "last_30_days"
    return "older"


def _normalize_facet_severity(raw: Any) -> str:
    """Fold a stored severity string into the facet histogram's bands."""
    value = str(raw or "unknown").strip().lower()
    if value == "informational":
        value = "info"
    if value not in ("critical", "high", "medium", "low", "info", "unknown"):
        value = "unknown"
    return value


# Scope keys that live in the finding payload (or are computed from it) and so
# cannot be expressed as a predicate on the current-state table's materialised
# columns. Their presence disables the severity aggregate below.
_FACET_PAYLOAD_SCOPE_KEYS = ("provider", "account_ref", "environment", "domain", "finding_class", "q")

# Bands whose filter value equals the persisted string exactly, so the store's
# ``LOWER(severity) = %s`` predicate selects the same rows the Python walk keeps.
# ``info`` is excluded because it also folds the persisted ``informational``
# alias, and ``unknown`` because it also absorbs blank/unrecognised severities —
# for those two the store predicate is narrower than the walk, so pushing them
# down would silently drop rows.
_FACET_LITERAL_SEVERITY_BANDS = frozenset({"critical", "high", "medium", "low"})


def _facet_severity_histogram(
    tenant_id: str,
    *,
    severity: str | None,
    scan_id: str | None,
    since: str | None,
    scope: Mapping[str, str],
    status: str,
) -> dict[str, int] | None:
    """Serve the self-excluding severity histogram from the store's aggregate.

    Every other facet dimension is gated on ``severity_matches``, so a
    ``?severity=`` request only needs severity-matching rows resident — except
    this histogram, which by contract excludes its own filter and therefore
    needs every band. Answering it with the store's indexed ``GROUP BY`` (the
    same one the overview headline reconciles against) lets the caller push
    ``severity`` into the store query and stop walking the non-matching
    remainder in Python.

    Returns ``None`` when the request is not expressible as that aggregate — no
    active severity filter (the walk is already minimal), a payload-side scope
    filter, a ``scan_id`` the aggregate does not carry, or a store without the
    capability — in which case the caller keeps the unfiltered walk unchanged.
    """
    if severity is None or scan_id is not None:
        return None
    if severity.strip().lower() not in _FACET_LITERAL_SEVERITY_BANDS:
        return None
    if any(key in scope for key in _FACET_PAYLOAD_SCOPE_KEYS):
        return None

    from agent_bom.api.compliance_hub_store import get_compliance_hub_store, status_matches
    from agent_bom.export.runner import iter_scan_spine_findings

    breakdown = getattr(get_compliance_hub_store(), "current_severity_breakdown", None)
    if not callable(breakdown):
        return None
    try:
        raw = breakdown(tenant_id, since=since, status=status)
    except TypeError:
        # A store whose aggregate cannot honour the active predicates would
        # silently answer a different question; keep the exact walk instead.
        return None

    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
    for band, value in dict(raw).items():
        counts[_normalize_facet_severity(band)] += int(value)

    # The aggregate covers the hub's current state only. The read path also
    # unions the resident scan spine, so fold its (bounded, in-memory) rows in
    # under the same predicates or the histogram would undercount a scan estate.
    for row in iter_scan_spine_findings(
        tenant_id,
        severity=None,
        since=since,
        scan_id=scan_id,
        scope=scope,
        status="all",
    ):
        if status_matches(row, status):
            counts[_normalize_facet_severity(row.get("severity"))] += 1
    return counts


def _finding_facets(
    tenant_id: str,
    *,
    severity: str | None,
    scan_id: str | None,
    since: str | None,
    scope: Mapping[str, str],
    status: str,
) -> tuple[dict[str, dict[str, int]], int]:
    facets, total, _metadata = _finding_facets_bounded(
        tenant_id,
        severity=severity,
        scan_id=scan_id,
        since=since,
        scope=scope,
        status=status,
    )
    return facets, total


def _finding_facets_bounded(
    tenant_id: str,
    *,
    severity: str | None,
    scan_id: str | None,
    since: str | None,
    scope: Mapping[str, str],
    status: str,
    scan_budget: int | None = None,
    deadline_seconds: float | None = None,
) -> tuple[dict[str, dict[str, int]], int, dict[str, Any]]:
    """Compute self-excluding facets in one bounded canonical-stream pass.

    A row is tested against every dimension's self-excluding predicate while it
    is resident, avoiding four full tenant walks. When the row/deadline budget
    is reached the counts remain useful lower-bound evidence and are explicitly
    marked approximate by the caller.

    The budgets resolve from the module constants at call time so a test can
    reproduce truncation by lowering them instead of seeding 50k rows.
    """
    scan_budget = _FACET_SCAN_BUDGET if scan_budget is None else scan_budget
    deadline_seconds = _FACET_DEADLINE_SECONDS if deadline_seconds is None else deadline_seconds

    from agent_bom.api.compliance_hub_store import status_matches
    from agent_bom.export.runner import iter_current_findings
    from agent_bom.finding_scope import FINDING_CLASSES, SECURITY_DOMAINS, finding_class_for_row, lenses_for_row

    class_counts: dict[str, int] = {key: 0 for key in FINDING_CLASSES}
    severity_counts: dict[str, int] = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
    status_counts: dict[str, int] = {key: 0 for key in ("open", "resolved")}
    domain_counts: dict[str, int] = {key: 0 for key in SECURITY_DOMAINS}
    freshness_counts: dict[str, int] = {key: 0 for key in _FRESHNESS_BUCKETS}

    class_scope = dict(scope)
    class_scope.pop("finding_class", None)
    domain_scope = dict(scope)
    domain_scope.pop("domain", None)
    full_scope = dict(scope)
    base_scope = dict(full_scope)
    base_scope.pop("finding_class", None)
    base_scope.pop("domain", None)
    total = 0
    scanned_rows = 0
    truncated = False
    reason = ""
    deadline: float | None = None

    # The severity histogram is the only dimension that excludes its own filter;
    # when the store can answer it directly, ``severity`` becomes a store-side
    # predicate and the walk stops paying for non-matching rows (#4588 follow-up).
    pushed_severity_counts = _facet_severity_histogram(
        tenant_id,
        severity=severity,
        scan_id=scan_id,
        since=since,
        scope=full_scope,
        status=status,
    )
    walk_severity = severity if pushed_severity_counts is not None else None

    for row in iter_current_findings(
        tenant_id,
        severity=walk_severity,
        since=since,
        scan_id=scan_id,
        scope=base_scope,
        status="all",
    ):
        if scanned_rows >= scan_budget:
            truncated = True
            reason = "scan_budget"
            break
        if deadline is None:
            # Bound facet processing, not the backing iterator's time-to-first
            # row. A slow cursor setup must not turn a non-empty tenant into a
            # zero-count Findings response.
            deadline = time.monotonic() + max(0.001, deadline_seconds)
        elif time.monotonic() >= deadline:
            truncated = True
            reason = "deadline"
            break
        scanned_rows += 1
        finding_class = finding_class_for_row(row)
        row_severity = _normalize_facet_severity(row.get("severity"))
        # Re-checked in Python even when the predicate was pushed down, so a
        # store that ignores the kwarg degrades to slow, never to wrong.
        severity_matches = severity is None or row_severity == severity.lower()
        status_matches_active = status_matches(row, status)
        full_scope_matches = _row_matches_scope(row, full_scope)

        if severity_matches and status_matches_active and _row_matches_scope(row, class_scope):
            class_counts[finding_class] += 1
        if pushed_severity_counts is None and status_matches_active and full_scope_matches:
            # Only meaningful on the unfiltered walk: once ``severity`` is a
            # store-side predicate this stream no longer carries the other bands.
            severity_counts[row_severity] += 1
        if severity_matches and full_scope_matches:
            row_status = "resolved" if str(row.get("status") or "").strip().lower() == "resolved" else "open"
            status_counts[row_status] += 1
        if severity_matches and status_matches_active and _row_matches_scope(row, domain_scope):
            for value in lenses_for_row(row):
                if value in domain_counts:
                    domain_counts[value] += 1
        if severity_matches and status_matches_active and full_scope_matches:
            total += 1
            freshness_counts[_freshness_bucket(row)] += 1

    # ``total`` and the severity histogram have to answer the same question on
    # the same basis. Under pushdown the histogram is the store's unbounded
    # aggregate while the walk is row-budgeted, so a truncated walk would put an
    # exact facet next to a lower-bound total and the two would contradict.
    # The aggregate applies the identical predicates here (pushdown is refused
    # whenever a scan_id or a payload-side scope key is present, so the walk's
    # scope test is vacuous), which makes its count for the filtered band the
    # exact total — take it, and both numbers come from one derivation again.
    total_exact = not truncated
    if truncated and pushed_severity_counts is not None and severity is not None:
        total = pushed_severity_counts.get(_normalize_facet_severity(severity), total)
        total_exact = True
    # The walk-derived dimensions stay lower bounds after that substitution, so
    # say per dimension which is which — "approximate" alone cannot tell a
    # consumer that severity is exact while finding_class is not.
    walk_state = "bounded" if truncated else "exact"
    dimensions = {
        "finding_class": walk_state,
        "severity": "exact" if (pushed_severity_counts is not None or not truncated) else "bounded",
        "status": walk_state,
        "domain": walk_state,
        "freshness": walk_state,
    }
    return (
        {
            "finding_class": class_counts,
            "severity": pushed_severity_counts if pushed_severity_counts is not None else severity_counts,
            "status": status_counts,
            "domain": domain_counts,
            "freshness": freshness_counts,
        },
        total,
        {
            "status": "partial" if truncated else "complete",
            "reason": reason,
            "scanned_rows": scanned_rows,
            "scan_budget": scan_budget,
            "deadline_ms": int(deadline_seconds * 1000),
            "total_exact": total_exact,
            "dimensions": dimensions,
        },
    )


def _canonical_scope_filters(
    provider: str | None,
    account: str | None,
    environment: str | None,
    domain: str | None,
    finding_class: str | None = None,
    q: str | None = None,
    kev: bool | None = None,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
) -> dict[str, str]:
    """Normalize the optional scope/domain filters into an active-filter map.

    Server-side canonicalization (issue #3946): values are lowercased/trimmed
    and empty inputs dropped. Unknown values are kept (not rejected) so the
    endpoint never raises on ad-hoc input — an unmatched value simply returns no
    findings. ``account`` maps to the finding's ``account_ref``.

    ``framework`` / ``control`` power the compliance drill-through (epic #4790):
    the framework identifier (a UI section id such as ``nist-csf`` / ``iso27001``)
    is resolved once here to the finding's ``*_tags`` field and canonical slug so
    the per-row predicate stays a cheap containment check. An unresolved
    framework is stored raw so the predicate returns an honest empty match.
    ``control`` is only meaningful alongside a framework and is dropped otherwise.
    """
    filters: dict[str, str] = {}
    if framework and framework.strip():
        from agent_bom.compliance_coverage import resolve_framework_filter

        meta = resolve_framework_filter(framework)
        if meta is not None:
            filters["framework_tag_field"] = meta.tag_field
            filters["framework_slug"] = meta.slug
        else:
            filters["framework"] = framework.strip().lower()
        if control and control.strip():
            filters["control"] = control.strip()
    if provider and provider.strip():
        filters["provider"] = provider.strip().lower()
    if account and account.strip():
        filters["account_ref"] = account.strip().lower()
    if environment and environment.strip():
        filters["environment"] = environment.strip().lower()
    if domain and domain.strip():
        # Map the pre-rename ``appsec_sca`` alias to ``aspm`` so historical
        # deep-links keep resolving; unknown values pass through untouched.
        from agent_bom.finding_scope import _LEGACY_DOMAIN_ALIASES

        key = domain.strip().lower()
        filters["domain"] = _LEGACY_DOMAIN_ALIASES.get(key, key)
    if finding_class:
        filters["finding_class"] = finding_class
    if kev is not None:
        filters["kev"] = "true" if kev else "false"
    if q and q.strip():
        filters["q"] = q.strip()
    if owner and owner.strip():
        filters["owner"] = owner.strip().lower()
    if sla and sla.strip():
        filters["sla"] = sla.strip().lower()
    return filters


def _row_matches_scope(row: dict[str, Any], filters: dict[str, str]) -> bool:
    """Scope/domain predicate for a finding row.

    Thin wrapper over :func:`agent_bom.finding_scope.row_matches_scope` — the one
    source of truth shared with the hub store's scope-filtered keyset path so the
    in-memory scan-finding filter and the bulk-ingest store filter can never
    diverge on the overlapping-lens semantics. Retained under this name because
    ``routes/cloud.py`` imports it.
    """
    from agent_bom.finding_scope import row_matches_scope

    return row_matches_scope(row, filters)


def _resolve_bulk_findings_total(
    *,
    tenant_id: str,
    severity: str | None,
    scan_id: str | None,
    approximate_total: bool,
    offset: int,
    bulk_total: int | None,
    page_len: int,
    limit: int,
    window_days: int = 0,
    status: str | None = None,
) -> tuple[int | None, bool]:
    """Return ``(total, total_approximate)`` for the bulk-ingest slice."""
    from agent_bom.api.findings_count_cache import cache_key, get_cached_total, set_cached_total

    key = cache_key(tenant_id=tenant_id, severity=severity, scan_id=scan_id, origin="bulk_ingest", window_days=window_days, status=status)
    if not approximate_total:
        if bulk_total is not None:
            set_cached_total(key, bulk_total)
            return bulk_total, False
        cached = get_cached_total(key)
        if cached is not None:
            # Cache entries are populated only from an exact store COUNT.  A
            # normal request reusing that value remains complete; labelling it
            # approximate made the campaign workflow reject a second request
            # as provisional even though the underlying membership was exact.
            return cached, False
        return bulk_total, False

    if offset == 0 and bulk_total is not None:
        set_cached_total(key, bulk_total)
        return bulk_total, False

    cached = get_cached_total(key)
    if cached is not None:
        return cached, True

    # Cold cache on a deep page: expose a conservative lower bound so paging
    # controls stay usable until the client revisits offset=0.
    if page_len < limit:
        return offset + page_len, True
    return offset + limit, True


def _finding_sort_key(row: dict[str, Any], sort: str) -> tuple[float, float, float]:
    """Stable sort key — descending order on the requested signal,
    with CVSS + severity-rank tiebreakers so the order is fully
    deterministic for a given input.
    """
    from agent_bom.api.compliance_hub_store import compute_effective_reach_score
    from agent_bom.graph.severity import severity_policy_rank

    sev_rank = severity_policy_rank(str(row.get("severity", "")))
    cvss = float(row.get("cvss_score") or 0.0)
    reach_val = compute_effective_reach_score(row)

    if sort == "cvss":
        primary = cvss
    elif sort == "severity":
        primary = float(sev_rank)
    else:  # default — effective_reach
        primary = reach_val
    # Descending: negate, with cvss + severity as deterministic tiebreakers.
    return (-primary, -cvss, -float(sev_rank))


_BULK_MERGE_CHUNK = 256


class MergedScanBulkPage(NamedTuple):
    """A merged page plus the frontier needed to resume the keyset walk.

    ``next_scan_index`` is how many pre-sorted scan findings have been consumed
    (skipped + emitted); ``next_bulk_cursor`` is the hub keyset cursor of the
    last consumed bulk row (``""`` when no bulk row was consumed). Together they
    let ``/v1/findings`` emit ONE compound cursor so a keyset caller walks the
    full merged set with 0 dups / 0 drops instead of losing the scan half after
    page 1.
    """

    rows: list[dict[str, Any]]
    next_scan_index: int
    next_bulk_cursor: str
    has_more: bool


def _merged_scan_bulk_page(
    scan_findings: list[dict[str, Any]],
    *,
    bulk_list: Any,
    tenant_id: str,
    sort_key: str,
    severity: str | None,
    scan_id: str | None,
    offset: int,
    limit: int,
    scan_start: int = 0,
    bulk_cursor: str | None = None,
    since: str | None = None,
    scope: Mapping[str, str] | None = None,
    status: str | None = None,
    scope_metadata: dict[str, Any] | None = None,
) -> MergedScanBulkPage:
    """Merge pre-sorted scan findings with bulk hub pages without O(table) work.

    Streams two sorted sources with a two-pointer walk so deep ``offset`` does
    not require loading ``offset + limit`` bulk rows up front or re-sorting the
    full combined window in memory. The bulk source is refilled by keyset cursor
    (``list_current_page``) so the merge stays sargable and — critically — the
    frontier it stops at is expressible as one resumable cursor. ``scan_start``
    (index into ``scan_findings``) and ``bulk_cursor`` (hub keyset position)
    resume a prior page; ``status`` filters the bulk source's lifecycle status
    to match the merged scan findings' basis (default open) so both halves
    reconcile.

    Each source is consumed strictly in order (scan by ascending index, bulk in
    the store's keyset order), so a page consumes a contiguous prefix of each
    source after its resume point — that is what makes the walk drop-free and
    dup-free regardless of the merge comparator's tiebreakers.
    """
    from agent_bom.api.finding_cursor import cursor_from_current_row

    scan_i = scan_start
    bulk_buf: list[dict[str, Any]] = []
    bulk_i = 0
    fetch_cursor: str | None = bulk_cursor or None
    bulk_exhausted = False
    last_bulk_consumed: dict[str, Any] | None = None

    extra_kwargs: dict[str, Any] = {}
    if since:
        extra_kwargs["since"] = since
    if status is not None:
        extra_kwargs["status"] = status
    if scope:
        extra_kwargs["scope"] = dict(scope)
        if scope_metadata is not None:
            # One dict across every refill: ``collect_scope_filtered_page``
            # accumulates, so the merged page reports the combined walk.
            extra_kwargs["scope_metadata"] = scope_metadata

    def _refill_bulk() -> bool:
        nonlocal bulk_buf, bulk_i, fetch_cursor, bulk_exhausted
        if bulk_exhausted:
            bulk_buf = []
            bulk_i = 0
            return False
        bulk_result = bulk_list(
            tenant_id,
            limit=_BULK_MERGE_CHUNK,
            sort=sort_key,
            severity=severity,
            scan_id=scan_id,
            origin="bulk_ingest",
            include_total=False,
            cursor=fetch_cursor,
            **extra_kwargs,
        )
        bulk_buf = bulk_result[0]
        fetch_cursor = bulk_result[2] if len(bulk_result) > 2 else None
        if not fetch_cursor:
            bulk_exhausted = True
        bulk_i = 0
        return bool(bulk_buf)

    def bulk_head() -> dict[str, Any] | None:
        if bulk_i >= len(bulk_buf) and not _refill_bulk():
            return None
        return bulk_buf[bulk_i]

    def scan_head() -> dict[str, Any] | None:
        if scan_i >= len(scan_findings):
            return None
        return scan_findings[scan_i]

    def take_scan() -> dict[str, Any]:
        nonlocal scan_i
        row = scan_findings[scan_i]
        scan_i += 1
        return row

    def take_bulk() -> dict[str, Any]:
        nonlocal bulk_i, last_bulk_consumed
        row = bulk_buf[bulk_i]
        bulk_i += 1
        last_bulk_consumed = row
        return row

    def pick_next() -> dict[str, Any] | None:
        scan_row = scan_head()
        bulk_row = bulk_head()
        if scan_row is None and bulk_row is None:
            return None
        if bulk_row is None:
            return take_scan()
        if scan_row is None:
            return take_bulk()
        if _finding_sort_key(scan_row, sort_key) <= _finding_sort_key(bulk_row, sort_key):
            return take_scan()
        return take_bulk()

    skipped = 0
    while skipped < offset:
        if pick_next() is None:
            break
        skipped += 1

    page: list[dict[str, Any]] = []
    for _ in range(limit):
        row = pick_next()
        if row is None:
            break
        page.append(row)

    has_more = scan_head() is not None or bulk_head() is not None
    if last_bulk_consumed is not None:
        next_bulk_cursor = cursor_from_current_row(last_bulk_consumed, sort=sort_key)
    else:
        next_bulk_cursor = bulk_cursor or ""
    return MergedScanBulkPage(page, scan_i, next_bulk_cursor, has_more)


@router.get("/findings", tags=["scan"])
async def list_findings(
    request: Request,
    q: Annotated[str | None, Query(max_length=256)] = None,
    severity: str | None = None,
    scan_id: Annotated[str | None, Query(max_length=128)] = None,
    sort: str = "effective_reach",
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    approximate_total: bool = False,
    provider: Annotated[str | None, Query(max_length=64)] = None,
    account: Annotated[str | None, Query(max_length=256)] = None,
    environment: Annotated[str | None, Query(max_length=64)] = None,
    domain: Annotated[str | None, Query(max_length=32)] = None,
    window_days: Annotated[int | None, Query(ge=0, le=3650)] = None,
    status: Annotated[str, Query(max_length=16)] = _DEFAULT_FINDING_STATUS,
    finding_class: FindingClass | None = None,
    kev: Annotated[bool | None, Query(description="Only known-exploited (KEV) findings, or only non-KEV when false")] = None,
    group_occurrences: Annotated[
        bool,
        Query(description="Group vulnerability occurrences by advisory and package while preserving asset-scoped rows"),
    ] = False,
    framework: Annotated[
        str | None,
        Query(max_length=64, description="Compliance framework drill-through, e.g. soc2 / nist-csf (compliance section id)"),
    ] = None,
    control: Annotated[
        str | None,
        Query(max_length=64, description="Framework control code, narrows within framework (e.g. CC6.1)"),
    ] = None,
    owner: Annotated[str | None, Query(max_length=256)] = None,
    sla: Literal["overdue", "due", "unassigned"] | None = None,
    include_facets: bool = False,
) -> dict:
    """List unified findings aggregated from completed scan results.

    The heavy work — dedup/sort of in-memory scan findings plus synchronous
    store reads — runs in a worker thread so a single deep read cannot block
    the event loop and freeze unrelated requests (e.g. ``/health``) under load.
    ``anyio.to_thread.run_sync`` propagates the current context, and the tenant
    scope is read from ``request.state`` and passed explicitly to the store, so
    behavior is identical to running inline.

    The read is additionally guarded by adaptive backpressure (the same shared
    primitive the graph route uses): the in-memory default hub copies and
    re-sorts the whole current-state table per request, so a burst of deep
    ``?sort=cvss`` reads at scale can pile up worker threads and starve
    ``/health`` and unrelated endpoints. Under genuine saturation the guard
    sheds excess reads with ``429 + Retry-After`` instead of degrading every
    route. Normal single-reader load never trips it.

    ``offset`` is a compatibility path capped at 10,000 (a deep ``OFFSET`` scans
    linearly): past the ceiling the endpoint returns ``400`` and steers callers
    to ``cursor``/``next_cursor``, the unbounded-depth pagination contract shared
    with ``/v1/compliance/hub/findings``.
    """
    try:
        async with adaptive_backpressure("findings"):
            implementation = _list_finding_groups_impl if group_occurrences else _list_findings_impl
            return await anyio.to_thread.run_sync(
                implementation,
                request,
                q,
                severity,
                scan_id,
                sort,
                limit,
                offset,
                cursor,
                approximate_total,
                provider,
                account,
                environment,
                domain,
                window_days,
                status,
                finding_class,
                kev,
                include_facets,
                framework,
                control,
                owner,
                sla,
            )
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _list_findings_impl(
    request: Request,
    q: str | None,
    severity: str | None,
    scan_id: str | None,
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    include_facets: bool = False,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
) -> dict:
    """Synchronous body of :func:`list_findings` (runs in a worker thread).

    Default sort is ``effective_reach`` — the composite triage signal that
    combines CVSS / EPSS / KEV with reachable-tool capability, credential
    visibility and agent breadth.  Pass ``?sort=cvss`` for the legacy
    CVSS-only ordering, or ``?sort=severity`` for severity-band ordering.

    Pass ``?approximate_total=true`` to skip ``COUNT(*)`` on deep pages.
    Tenants above ``AGENT_BOM_FINDINGS_APPROXIMATE_TOTAL_THRESHOLD`` (default
    50000) automatically reuse cached totals and skip ``COUNT(*)`` once a warm
    cache entry exists. The first page (``offset=0``) still computes an exact
    total and caches it when the cache is cold and the tenant is below the
    threshold. Later pages reuse the cached count; when the cache is cold the
    response carries a conservative lower bound and ``total_approximate: true``.

    Pass ``?cursor=`` with the ``next_cursor`` from a prior response for
    keyset pagination through bulk-ingested hub findings (avoids deep
    ``OFFSET`` cost). ``cursor`` and non-zero ``offset`` cannot be combined.
    """
    from agent_bom.api import time_window
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store, status_matches
    from agent_bom.api.finding_cursor import decode_finding_cursor, decode_merged_scan_cursor

    tenant_id = _tenant_id(request)
    # Default read-window (≈90d): bound counts to a recent, honestly-labelled
    # window at scale. ``window_days=0`` widens to all history (#4009).
    resolved_window = time_window.normalize_window_days(window_days)
    window_since = time_window.window_since_iso(resolved_window)
    # Silently falling back masked typos as "wrong order"; reject clearly.
    sort_key = _normalize_finding_sort(sort)
    try:
        severity = canonical_finding_severity_filter(severity)
    except ValueError:
        # A bogus severity previously returned an empty 200 that reads as
        # "no findings" — reject using the same contract as report exports.
        raise HTTPException(
            status_code=422,
            detail=f"invalid severity; accepted values: {', '.join(_ALLOWED_FINDING_SEVERITIES)}",
        ) from None
    status_key = status.strip().lower() if isinstance(status, str) else _DEFAULT_FINDING_STATUS
    if status_key not in _ALLOWED_FINDING_STATUSES:
        # A bogus status previously returned an empty 200 that reads as "no
        # findings" — a trap, and worse hid the live posture. Reject clearly,
        # mirroring the severity contract.
        raise HTTPException(
            status_code=422,
            detail=f"invalid status '{status}'; accepted values: {', '.join(_ALLOWED_FINDING_STATUSES)}",
        )
    if cursor and offset:
        raise HTTPException(status_code=400, detail="cursor and offset are mutually exclusive")
    if offset > _HUB_LIST_OFFSET_CEILING:
        # Deep OFFSET scans linearly; mirror the sibling hub list route and cap
        # the compatibility offset path. Cursor pagination is the unbounded-depth
        # contract, so steer deep walks there instead of degrading the read path.
        raise HTTPException(
            status_code=400,
            detail=f"offset exceeds ceiling {_HUB_LIST_OFFSET_CEILING}; use cursor pagination for deeper walks",
        )
    # A ``/v1/findings`` cursor is either a compound merged token (scan + hub
    # frontier) or a plain hub keyset cursor. Decode the compound form first so a
    # keyset caller resuming the scan half is routed to the merged walk rather
    # than 400-ing against the plain decoder.
    merged_cursor: tuple[int, str] | None = None
    if cursor:
        try:
            merged_cursor = decode_merged_scan_cursor(cursor, expected_sort=sort_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
        if merged_cursor is None:
            try:
                decode_finding_cursor(cursor, expected_sort=sort_key)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    from agent_bom.api.findings_count_cache import (
        cache_key,
        get_cached_total,
        resolve_effective_approximate_total,
    )

    effective_approximate_total = resolve_effective_approximate_total(
        requested=approximate_total,
        tenant_id=tenant_id,
        severity=severity,
        scan_id=scan_id,
        window_days=resolved_window,
        status=status_key,
    )
    cached_bulk_total = get_cached_total(
        cache_key(
            tenant_id=tenant_id,
            severity=severity,
            scan_id=scan_id,
            origin="bulk_ingest",
            window_days=resolved_window,
            status=status_key,
        )
    )
    if approximate_total or effective_approximate_total:
        # Explicit ``approximate_total=true`` (and the auto-threshold path) must
        # NOT force the O(table) exact COUNT — reuse the cached/approximate total
        # and surface ``total_approximate: true`` instead. The prior
        # ``offset == 0`` override paid the full count on every first page even
        # when a warm cache was present (~10x slower than the default path) and
        # returned an exact total with no flag (#3641). Warm the cache with one
        # exact count only when it is cold on the first page.
        include_bulk_total = not cursor and cached_bulk_total is None and offset == 0
    else:
        include_bulk_total = not cursor and cached_bulk_total is None

    # Default (no ``scan_id``) view collapses to the current state per finding:
    # re-scanning a project emits the same finding ``id`` under a fresh
    # ``scan_id``, and the in-memory store retains every completed job. Without
    # deduping, ``total`` inflated by one full copy per re-scan (Postgres reads
    # ``hub_findings_current`` which already dedupes). Iterate jobs oldest-first
    # so the latest occurrence of each finding id wins; ``?scan_id=`` still
    # returns that scan's rows verbatim.
    from agent_bom.api.findings_current import current_scan_findings

    scope_filters = _canonical_scope_filters(
        provider,
        account,
        environment,
        domain,
        finding_class,
        q,
        kev=kev,
        framework=framework,
        control=control,
        owner=owner,
        sla=sla,
    )

    store = get_compliance_hub_store()
    bulk_list = getattr(store, "list_current_page", None) or getattr(store, "list_page", None)
    has_current_page = callable(getattr(store, "list_current_page", None))
    total_approximate = False
    next_cursor: str | None = None
    warnings: list[str] = []

    # Resume frontiers. A compound merged cursor carries both a scan-findings
    # index and the hub keyset position; a plain cursor carries only the hub
    # position (scan half was already fully delivered on earlier pages). The
    # merged walk (with ``list_current_page``) is what keeps the scan half from
    # being dropped after page 1.
    scan_start = merged_cursor[0] if merged_cursor is not None else 0
    bulk_cursor_in: str | None = (merged_cursor[1] or None) if merged_cursor is not None else cursor

    if cursor and merged_cursor is None:
        # Plain hub keyset cursor: the in-memory scan findings were delivered on
        # earlier (merged) pages, so their full current-state fold is discarded
        # here. Skip that O(all-completed-jobs) fold entirely.
        scan_findings: list[dict[str, Any]] = []
        if _completed_jobs_for_tenant(tenant_id):
            warnings.append("cursor pagination applies to bulk-ingested findings only; in-memory scan findings appear on the first page")
    else:
        scan_findings = current_scan_findings(
            _completed_jobs_for_tenant(tenant_id),
            since=window_since,
            scan_id=scan_id,
            iter_findings=_iter_scan_findings,
        )
        if severity:
            normalized = severity.lower()
            scan_findings = [item for item in scan_findings if str(item.get("severity", "")).lower() == normalized]
        # In-memory scan findings carry no lifecycle status, so they are treated
        # as ``open`` (live by construction): the default + ``all`` include them,
        # ``status=resolved`` excludes them. Reconciles with the hub store's
        # sargable status predicate for a single open-only basis by default.
        scan_findings = [item for item in scan_findings if status_matches(item, status_key)]
        if scope_filters:
            scan_findings = [item for item in scan_findings if _row_matches_scope(item, scope_filters)]
        scan_findings.sort(key=lambda row: _finding_sort_key(row, sort_key))

    from agent_bom.api.finding_cursor import encode_merged_scan_cursor

    # Take the merged (scan + hub) keyset walk whenever the scan half is in play:
    # a page-1 request that has scan findings, or any resume of a compound merged
    # cursor. Pure-bulk reads (no scan findings, plain cursor) keep the simpler
    # hub-only keyset path and its plain cursors — unchanged. ``_merged_scan_bulk_page``
    # requires the cursor-capable ``list_current_page``, hence ``has_current_page``.
    use_merged = has_current_page and (merged_cursor is not None or (not cursor and bool(scan_findings)))

    def _encode_merged_next(page: MergedScanBulkPage) -> str | None:
        if not page.has_more:
            return None
        return encode_merged_scan_cursor(sort=sort_key, scan_index=page.next_scan_index, bulk_cursor=page.next_bulk_cursor)

    # Scope/domain filters run INSIDE the store on pre-enrichment current rows,
    # batched + keyset-paged (provider/account/environment live in the JSON
    # payload and ``domain`` is a computed overlapping-lens SET, so neither can be
    # a single SQL predicate). This keeps the fast keyset path — a scoped page
    # never materializes the whole tenant and ``next_cursor`` is emitted — while
    # ``total`` is honestly approximate (no O(table) COUNT under a scope filter).
    # Completeness of the store-internal scope walk. The walk is bounded by a
    # row budget + wall-clock deadline, so a sparse filter can return an empty
    # page with a resume cursor; that must be labelled partial, never presented
    # as an honest "no results".
    scope_metadata: dict[str, Any] = {}
    if scope_filters and has_current_page and callable(bulk_list):
        scope_arg = dict(scope_filters)
        if use_merged:
            # scan findings (already scope-filtered) merge with the scope-filtered
            # bulk source under one keyset frontier so later pages keep both halves.
            merged = _merged_scan_bulk_page(
                scan_findings,
                bulk_list=bulk_list,
                tenant_id=tenant_id,
                sort_key=sort_key,
                severity=severity,
                scan_id=scan_id,
                offset=offset,
                limit=limit,
                scan_start=scan_start,
                bulk_cursor=bulk_cursor_in,
                since=window_since,
                scope=scope_arg,
                status=status_key,
                scope_metadata=scope_metadata,
            )
            page_rows = merged.rows
            next_cursor = _encode_merged_next(merged)
        else:
            bulk_result = bulk_list(
                tenant_id,
                limit=limit,
                offset=0 if cursor else offset,
                sort=sort_key,
                severity=severity,
                scan_id=scan_id,
                origin="bulk_ingest",
                include_total=False,
                cursor=bulk_cursor_in,
                since=window_since,
                scope=scope_arg,
                status=status_key,
                scope_metadata=scope_metadata,
            )
            page_rows = bulk_result[0]
            next_cursor = bulk_result[2] if len(bulk_result) > 2 else None
        total = None
        total_approximate = True
    elif callable(bulk_list) and not scope_filters:
        if use_merged:
            # A COUNT probe is only worth paying on page 1 (no incoming cursor);
            # resume pages stay approximate to avoid an O(table) count per page.
            if merged_cursor is None:
                bulk_result = bulk_list(
                    tenant_id,
                    limit=1,
                    offset=0,
                    sort=sort_key,
                    severity=severity,
                    scan_id=scan_id,
                    origin="bulk_ingest",
                    include_total=include_bulk_total,
                    since=window_since,
                    status=status_key,
                )
                bulk_total = bulk_result[1]
            else:
                bulk_total = None
            merged = _merged_scan_bulk_page(
                scan_findings,
                bulk_list=bulk_list,
                tenant_id=tenant_id,
                sort_key=sort_key,
                severity=severity,
                scan_id=scan_id,
                offset=offset,
                limit=limit,
                scan_start=scan_start,
                bulk_cursor=bulk_cursor_in,
                since=window_since,
                status=status_key,
            )
            page_rows = merged.rows
            next_cursor = _encode_merged_next(merged)
            if merged_cursor is None:
                resolved_bulk, total_approximate = _resolve_bulk_findings_total(
                    tenant_id=tenant_id,
                    severity=severity,
                    scan_id=scan_id,
                    approximate_total=approximate_total or effective_approximate_total,
                    offset=offset,
                    bulk_total=bulk_total,
                    page_len=len(page_rows),
                    limit=limit,
                    window_days=resolved_window,
                    status=status_key,
                )
                total = None if resolved_bulk is None else len(scan_findings) + resolved_bulk
            else:
                total = None
                total_approximate = True
        else:
            bulk_result = bulk_list(
                tenant_id,
                limit=limit,
                offset=0 if cursor else offset,
                sort=sort_key,
                severity=severity,
                scan_id=scan_id,
                origin="bulk_ingest",
                include_total=include_bulk_total,
                cursor=bulk_cursor_in,
                since=window_since,
                status=status_key,
            )
            page_rows = bulk_result[0]
            bulk_total = bulk_result[1]
            next_cursor = bulk_result[2] if len(bulk_result) > 2 else None
            total, total_approximate = _resolve_bulk_findings_total(
                tenant_id=tenant_id,
                severity=severity,
                scan_id=scan_id,
                approximate_total=approximate_total or effective_approximate_total,
                offset=0 if cursor else offset,
                bulk_total=bulk_total,
                page_len=len(page_rows),
                limit=limit,
                window_days=resolved_window,
                status=status_key,
            )
    else:
        bulk_findings = _bulk_ingested_findings_for_tenant(tenant_id)
        if scan_id:
            bulk_findings = [item for item in bulk_findings if str(item.get("scan_id") or "") == scan_id]
        if severity:
            normalized = severity.lower()
            bulk_findings = [item for item in bulk_findings if str(item.get("severity", "")).lower() == normalized]
        bulk_findings = [item for item in bulk_findings if status_matches(item, status_key)]
        if scope_filters:
            bulk_findings = [item for item in bulk_findings if _row_matches_scope(item, scope_filters)]
        combined = scan_findings + bulk_findings
        combined.sort(key=lambda row: _finding_sort_key(row, sort_key))
        total = len(combined)
        # No keyset store here (store exposes neither list_page nor
        # list_current_page): ``combined`` is fully materialized in memory, so walk
        # it by index. The merged cursor's ``scan_index`` slot doubles as that
        # index so ``has_more`` stays honest and the rest is retrievable (0 drops).
        start = scan_start if merged_cursor is not None else offset
        page_rows = combined[start : start + limit]
        end = start + len(page_rows)
        if end < len(combined):
            next_cursor = encode_merged_scan_cursor(sort=sort_key, scan_index=end, bulk_cursor="")

    facets: dict[str, dict[str, int]] | None = None
    facet_completeness: dict[str, Any] | None = None
    if include_facets:
        facets, facet_total, facet_completeness = _finding_facets_bounded(
            tenant_id,
            severity=severity,
            scan_id=scan_id,
            since=window_since,
            scope=scope_filters,
            status=status_key,
        )
        # A partial walk that could not process even one row is not evidence
        # that the result set is empty. Preserve the list path's total instead
        # of replacing it with a misleading zero.
        if (
            facet_completeness["status"] == "complete"
            or facet_completeness["scanned_rows"] > 0
            # An aggregate-derived total is authoritative even if the walk that
            # ran alongside it processed no rows at all.
            or facet_completeness["total_exact"]
        ):
            total = facet_total
        # A truncated walk does not always mean an approximate total: when the
        # store aggregate answered the filtered band, that count *is* the total
        # and matches the severity facet exactly. Labelling it approximate would
        # understate a number that is exact.
        total_approximate = not facet_completeness["total_exact"]
        if facet_completeness["status"] != "complete":
            bounded = sorted(name for name, state in facet_completeness["dimensions"].items() if state == "bounded")
            warnings.append(
                "Facet counting stopped after "
                f"{facet_completeness['scanned_rows']} scanned rows ({facet_completeness['reason']}); "
                f"these facet counts are lower bounds, not totals: {', '.join(bounded)}."
            )

    try:
        reachability = project_persisted_graph_reachability(
            page_rows,
            graph_store=_get_graph_store(),
            tenant_id=tenant_id,
            scan_id=scan_id,
        )
        page_rows = reachability.rows
        if reachability.truncated:
            warnings.append(
                "Graph reachability projection is bounded to the highest-risk 1000 persisted paths; unmatched findings remain unassessed."
            )
    except Exception as exc:  # noqa: BLE001 — optional evidence must not fail the findings list
        _logger.warning("Finding graph reachability projection skipped: %s", sanitize_error(exc))
        warnings.append("Graph reachability evidence is unavailable for this page; unmatched findings remain unassessed.")

    scope_completeness: dict[str, Any] | None = None
    if scope_filters and scope_metadata:
        scope_truncated = bool(scope_metadata.get("truncated"))
        scope_completeness = {
            "status": "partial" if scope_truncated else "complete",
            "reason": str(scope_metadata.get("reason") or ""),
            "scanned_rows": int(scope_metadata.get("scanned_rows") or 0),
            "scan_budget": int(scope_metadata.get("scan_budget") or 0),
        }
        if scope_truncated:
            warnings.append(
                "Scope filter matching stopped after "
                f"{scope_completeness['scanned_rows']} scanned rows ({scope_completeness['reason']}); "
                "this page is partial — continue with next_cursor for the rest."
            )

    page = _redact_finding_page(page_rows)
    envelope = finding_list_envelope(
        findings=page,
        total=total,
        limit=limit,
        offset=0 if cursor else offset,
        sort=sort_key,
        scan_id=scan_id,
        cursor=cursor or "",
        next_cursor=next_cursor or "",
        filters={
            key: value
            for key, value in {
                "finding_class": finding_class,
                "q": q.strip() if q and q.strip() else None,
                "framework": framework.strip() if framework and framework.strip() else None,
                "control": control.strip() if control and control.strip() else None,
                "owner": owner.strip().lower() if owner and owner.strip() else None,
                "sla": sla,
            }.items()
            if value is not None
        },
        warnings=warnings,
        total_approximate=total_approximate,
        source="scan_and_current_ingest_findings",
        scope="tenant current-state findings",
    )
    # Echo the applied read-window so clients label counts honestly as
    # "last Nd" rather than "all" (#4009).
    envelope["window"] = time_window.window_metadata(resolved_window)
    envelope["count_metadata"]["window"] = envelope["window"]
    if scope_completeness is not None:
        envelope["scope_completeness"] = scope_completeness
    if facets is not None:
        envelope["facets"] = facets
        envelope["facets_approximate"] = bool(facet_completeness and facet_completeness["status"] != "complete")
        envelope["facet_metadata"] = {
            "freshness": {
                "basis": ["last_observed", "last_seen"],
                "thresholds_hours": [24, 168, 720],
                "missing_or_invalid": "unavailable",
            },
            "completeness": facet_completeness,
        }
    return envelope


_FINDING_GROUP_MAX_OCCURRENCES = 50_000
_FINDING_GROUP_OCCURRENCE_SAMPLE = 25


def _finding_group_identity(row: dict[str, Any]) -> tuple[str, str]:
    """Return the canonical aggregate identity without changing occurrence IDs."""
    supplied_id = str(row.get("finding_group_id") or "").strip()
    supplied_key = str(row.get("finding_group_key") or "").strip()
    if supplied_id and supplied_key:
        return supplied_id, supplied_key

    vulnerability_id = _row_vuln_id(row).lower()
    if vulnerability_id:
        group_key = f"vulnerability:{vulnerability_id}:{_package_base_name(row).lower()}"
    else:
        group_key = f"occurrence:{_finding_identity(row)}"
    return supplied_id or canonical_id("finding-group", group_key), supplied_key or group_key


def _finding_occurrence_summary(row: dict[str, Any]) -> dict[str, Any]:
    """Project the bounded fields needed to expand a grouped issue row."""
    return {
        key: row.get(key)
        for key in (
            "finding_id",
            "occurrence_id",
            "canonical_id",
            "asset",
            "severity",
            "package_version",
            "scan_id",
            "status",
            "owner",
            "sla_due_at",
            "last_seen",
            "last_observed",
            "graph_reachable",
            "graph_min_hop_distance",
        )
        if row.get(key) is not None
    }


def _list_finding_groups_impl(
    request: Request,
    q: str | None,
    severity: str | None,
    scan_id: str | None,
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    include_facets: bool = False,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
) -> dict[str, Any]:
    """Build a bounded server-side issue queue over canonical occurrence rows.

    Raw ``GET /v1/findings`` remains the authoritative per-asset workflow
    surface. This view walks that exact filtered queue, groups only rows sharing
    the canonical asset-independent issue identity, and returns bounded
    occurrence summaries for expansion. A row-budget hit is explicit partial
    evidence; it is never described as a complete group count.
    """
    from agent_bom.api.finding_cursor import decode_finding_group_cursor, encode_finding_group_cursor

    sort_key = _normalize_finding_sort(sort)
    if cursor:
        try:
            group_offset = decode_finding_group_cursor(cursor, expected_sort=sort_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid grouped findings cursor") from exc
        if group_offset is None:
            raise HTTPException(status_code=400, detail="Cursor is not valid for grouped findings")
    else:
        group_offset = offset

    rows: list[dict[str, Any]] = []
    source_cursor: str | None = None
    first_page: dict[str, Any] | None = None
    warnings: list[str] = []
    while len(rows) < _FINDING_GROUP_MAX_OCCURRENCES:
        page = _list_findings_impl(
            request,
            q,
            # Severity is applied after grouping so the issue histogram remains
            # self-excluding. Otherwise two asset occurrences of one advisory
            # would be presented as two separate severity-filter counts.
            None,
            scan_id,
            sort_key,
            min(1000, _FINDING_GROUP_MAX_OCCURRENCES - len(rows)),
            0,
            source_cursor,
            True,
            provider,
            account,
            environment,
            domain,
            window_days,
            status,
            finding_class,
            kev,
            include_facets and first_page is None,
            framework,
            control,
            owner,
            sla,
        )
        if first_page is None:
            first_page = page
        page_rows = page.get("findings")
        if isinstance(page_rows, list):
            rows.extend(row for row in page_rows if isinstance(row, dict))
        warnings.extend(str(item) for item in page.get("warnings", []) if str(item))
        source_cursor = str(page.get("next_cursor") or "") or None
        if not source_cursor:
            break

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        group_id, group_key = _finding_group_identity(row)
        group = grouped.get(group_id)
        if group is None:
            representative = dict(row)
            representative["finding_group_id"] = group_id
            representative["finding_group_key"] = group_key
            representative["occurrence_count"] = 0
            representative["occurrences"] = []
            representative["occurrences_truncated"] = False
            grouped[group_id] = representative
            group = representative
        group["occurrence_count"] = int(group["occurrence_count"]) + 1
        occurrences = group["occurrences"]
        if isinstance(occurrences, list) and len(occurrences) < _FINDING_GROUP_OCCURRENCE_SAMPLE:
            occurrences.append(_finding_occurrence_summary(row))
        else:
            group["occurrences_truncated"] = True

    all_groups = list(grouped.values())
    grouped_severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
    for group in all_groups:
        grouped_severity_counts[_normalize_facet_severity(group.get("severity"))] += 1
    normalized_severity = severity.strip().lower() if severity and severity.strip() else None
    groups = [
        group
        for group in all_groups
        if normalized_severity is None or _normalize_facet_severity(group.get("severity")) == normalized_severity
    ]
    truncated = source_cursor is not None
    if truncated:
        warnings.append("Issue grouping stopped after 50,000 occurrence rows; group and occurrence counts are lower bounds.")
    page_groups = groups[group_offset : group_offset + limit]
    next_offset = group_offset + len(page_groups)
    next_cursor = ""
    if next_offset < len(groups):
        next_cursor = encode_finding_group_cursor(sort=sort_key, offset=next_offset)

    filters = dict(first_page.get("filters") or {}) if first_page else {}
    filters["group_occurrences"] = True
    if normalized_severity is not None:
        filters["severity"] = normalized_severity
    envelope = finding_list_envelope(
        findings=page_groups,
        total=len(groups),
        limit=limit,
        offset=0 if cursor else offset,
        sort=sort_key,
        scan_id=scan_id,
        cursor=cursor or "",
        next_cursor=next_cursor,
        filters=filters,
        warnings=list(dict.fromkeys(warnings)),
        total_approximate=truncated,
        source="scan_and_current_ingest_finding_groups",
        scope="tenant current-state issue groups over asset-scoped occurrences",
    )
    envelope["grouping"] = {
        "status": "partial" if truncated else "complete",
        "scanned_occurrences": len(rows),
        "scan_budget": _FINDING_GROUP_MAX_OCCURRENCES,
        "occurrence_total": sum(int(group.get("occurrence_count") or 0) for group in groups),
        "occurrence_sample_limit": _FINDING_GROUP_OCCURRENCE_SAMPLE,
    }
    if first_page:
        if "window" in first_page:
            envelope["window"] = first_page["window"]
            envelope["count_metadata"]["window"] = first_page["window"]
        for key in ("facets", "facets_approximate", "facet_metadata", "scope_completeness"):
            if key in first_page:
                envelope[key] = first_page[key]
        if include_facets:
            envelope.setdefault("facets", {})["severity"] = grouped_severity_counts
            envelope["facet_metadata"]["severity_basis"] = "canonical issue groups"
    return envelope


def current_findings_snapshot(request: Request, *, max_findings: int = 50_000) -> dict[str, Any]:
    """Collect the canonical current finding queue for an internal consumer.

    Compliance narratives and other in-process surfaces need the same merged
    scan-job + current-ingest evidence as ``GET /v1/findings``. The walk uses
    that endpoint's keyset contract and is explicitly bounded; a bound hit is
    returned as partial evidence rather than silently called complete.
    """
    rows: list[dict[str, Any]] = []
    cursor: str | None = None
    first_total: int | None = None
    first_metadata: dict[str, Any] | None = None
    warnings: list[str] = []
    while len(rows) < max_findings:
        page = _list_findings_impl(
            request,
            q=None,
            severity=None,
            scan_id=None,
            sort="effective_reach",
            limit=min(1000, max_findings - len(rows)),
            offset=0,
            cursor=cursor,
            approximate_total=cursor is not None,
            window_days=None,
            status=_DEFAULT_FINDING_STATUS,
        )
        if first_metadata is None:
            first_metadata = page.get("count_metadata") if isinstance(page.get("count_metadata"), dict) else {}
            first_total = page.get("total") if isinstance(page.get("total"), int) else None
        page_rows = page.get("findings")
        if isinstance(page_rows, list):
            rows.extend(row for row in page_rows if isinstance(row, dict))
        warnings.extend(str(item) for item in page.get("warnings", []) if str(item))
        cursor = str(page.get("next_cursor") or "") or None
        if not cursor:
            break

    tenant_id = _tenant_id(request)
    jobs = _completed_jobs_for_tenant(tenant_id)
    agent_names: set[str] = set()
    package_keys: set[tuple[str, str, str]] = set()
    summary_agent_counts: list[int] = []
    summary_package_counts: list[int] = []
    generated_values: list[str] = []
    completed_scan_ids: set[str] = set()
    for job in jobs:
        result = job.result if isinstance(job.result, dict) else {}
        completed_scan_ids.add(str(result.get("scan_id") or job.job_id))
        for agent in result.get("agents", []) if isinstance(result.get("agents"), list) else []:
            if isinstance(agent, dict) and str(agent.get("name") or "").strip():
                agent_names.add(str(agent["name"]).strip())
        for package in result.get("packages", []) if isinstance(result.get("packages"), list) else []:
            if isinstance(package, dict):
                package_keys.add(
                    (
                        str(package.get("name") or ""),
                        str(package.get("version") or ""),
                        str(package.get("ecosystem") or ""),
                    )
                )
        raw_summary = result.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        if isinstance(summary.get("total_agents"), int):
            summary_agent_counts.append(summary["total_agents"])
        if isinstance(summary.get("total_packages"), int):
            summary_package_counts.append(summary["total_packages"])
        generated = result.get("generated_at") or job.completed_at
        if isinstance(generated, str) and generated:
            generated_values.append(generated)

    # Bulk-ingested/current findings can carry useful inventory identity even
    # when no full report envelope exists. Count the observed identities; never
    # manufacture placeholder agents or packages to match a summary scalar.
    for row in rows:
        raw_agents = row.get("affected_agents")
        if isinstance(raw_agents, list):
            agent_names.update(str(name).strip() for name in raw_agents if str(name).strip())
        raw_asset = row.get("asset")
        asset = raw_asset if isinstance(raw_asset, dict) else {}
        package_value = str(row.get("package") or row.get("package_name") or "").strip()
        if package_value:
            package_keys.add((package_value, str(row.get("package_version") or ""), str(row.get("ecosystem") or "")))
        elif str(asset.get("asset_type") or "").lower() == "package" and str(asset.get("name") or "").strip():
            package_keys.add((str(asset["name"]).strip(), "", ""))

    truncated = cursor is not None
    if truncated:
        warnings.append(f"Narrative evidence is bounded to {max_findings} current findings; additional rows remain.")
    return {
        "schema_version": "finding-snapshot.v1",
        "tenant_id": tenant_id,
        "findings": rows,
        "count": len(rows),
        "total": first_total,
        "total_agents": len(agent_names) if agent_names else max(summary_agent_counts, default=0),
        "total_packages": len(package_keys) if package_keys else max(summary_package_counts, default=0),
        "generated_at": max(generated_values, default=""),
        "scan_ids": sorted(completed_scan_ids | {str(row.get("scan_id")) for row in rows if row.get("scan_id")}),
        "completed_scan_count": len(jobs),
        "warnings": list(dict.fromkeys(warnings)),
        "count_metadata": first_metadata or {},
        "completeness": {
            "status": "partial" if truncated else "complete",
            "reason": "snapshot row bound reached" if truncated else "",
        },
    }


@router.post(
    "/findings/bulk",
    tags=["scan"],
    status_code=201,
    dependencies=[Depends(_require_json_content_type)],
)
async def ingest_bulk_findings(request: Request, body: BulkFindingsRequest) -> dict:
    """Append normalized findings for the request tenant.

    This is the agent-native counterpart to `/v1/compliance/ingest`: callers
    that already have normalized finding objects can post them directly instead
    of wrapping them as SARIF/CycloneDX/CSV content. Request authentication owns
    the tenant scope; `tenant_id` in the JSON body is accepted only for legacy
    clients and is never trusted for routing.
    """
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    tenant_id = _tenant_id(request)
    require_body_tenant_match(body.tenant_id, tenant_id)

    # Batch-level replay safety: an identical retry under the same
    # Idempotency-Key returns the first cached response (same batch_id and
    # counts); a reused key with a different body is a 409 conflict. This is
    # additive to the row-level (tenant_id, finding_id) collapse below.
    idem_key = _request_header(request, "Idempotency-Key")
    idem_source = _request_header(request, "X-Agent-Bom-Source-Id") or "bulk-ingest"
    request_hash = idempotency_request_fingerprint(body)
    if idem_key:
        try:
            cached = _get_idempotency_store().get(
                "/v1/findings/bulk",
                tenant_id,
                idem_source,
                idem_key,
                request_hash=request_hash,
            )
        except IdempotencyConflictError as exc:
            raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
        if cached is not None:
            cached["idempotent_replay"] = True
            return cast(dict, cached)

    # Deterministic batch id so a resend of the same body (even without an
    # Idempotency-Key header) collapses onto one logical batch. Random per-request
    # ids made ``upsert_current_batch``'s (canonical, batch_id) observation key
    # miss on every replay, inflating ``scan_count`` (P1-5).
    batch_id = deterministic_batch_id(idem_key or request_hash)
    payloads = [
        _normalized_bulk_finding(row, source=body.source, batch_id=batch_id, ordinal=idx) for idx, row in enumerate(body.findings, start=1)
    ]
    from agent_bom.api.finding_lifecycle import normalize_observed_at

    observed_at = normalize_observed_at(body.observed_at or body.metadata.get("observed_at"))
    hub_store = get_compliance_hub_store()

    # Offload the blocking psycopg write sequence (ledger append + current-state
    # upsert + reconcile + delta emission) to a worker thread so concurrent bulk
    # ingest cannot freeze the event loop and unrelated requests (mirrors the
    # read path). See ``_bulk_ingest_store_writes`` / ``_hub_store_call``.
    from agent_bom.api.hub_observations_partition import ObservationPartitionRangeError

    try:
        store_result = await _hub_store_call(
            _bulk_ingest_store_writes,
            hub_store,
            tenant_id,
            payloads,
            observed_at=observed_at,
            batch_id=batch_id,
            source=body.source,
            reconcile_absent=body.reconcile_absent,
        )
    except ObservationPartitionRangeError as exc:
        # observed_at is so far past/future it is almost certainly bad data — a
        # clean 4xx instead of a raw partition CheckViolation 500.
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
    new_total = store_result["new_total"]
    reconciled = store_result["reconciled"]
    delta_results = store_result["delta_results"]
    distinct_findings = store_result["distinct_findings"]
    duplicate_payloads = store_result["duplicate_payloads"]
    warnings: list[str] = []
    if duplicate_payloads:
        warnings.append(
            f"{duplicate_payloads} duplicate payload(s) collapsed onto an existing canonical id; "
            f"{distinct_findings} distinct finding(s) were stored"
        )
    response = {
        "schema_version": "v1",
        "batch_id": batch_id,
        "ingested": len(payloads),
        "distinct_findings": distinct_findings,
        "duplicate_payloads": duplicate_payloads,
        "tenant_total": new_total,
        "tenant_id": tenant_id,
        "source": body.source,
        "observed_at": observed_at,
        "warnings": warnings,
    }
    if body.reconcile_absent:
        response["reconciled"] = reconciled
    if delta_results:
        delivered = sum(
            1
            for result in delta_results
            if (result.get("status") == "delivered" if isinstance(result, dict) else getattr(result, "delivered", False))
        )
        response["delta_stream"] = {"emitted_batches": len(delta_results), "delivered": delivered}
    if idem_key:
        _get_idempotency_store().put(
            "/v1/findings/bulk",
            tenant_id,
            idem_source,
            idem_key,
            response,
            request_hash=request_hash,
        )
    return response


@router.get("/inventory", tags=["scan"])
async def list_inventory(
    request: Request,
    # enforce limit cap server-side via Pydantic.
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List agent and package inventory aggregated from completed scan results."""
    tenant_id = _tenant_id(request)
    agents: list[dict[str, Any]] = []
    jobs: list[dict[str, str]] = []
    for job in _completed_jobs_for_tenant(tenant_id):
        # Skip batch parents: their aggregated agents duplicate the children
        # that already contribute to the inventory roll-up.
        if job.child_job_ids:
            continue
        result = job.result or {}
        job_agents = [item for item in result.get("agents", []) or [] if isinstance(item, dict)]
        if not job_agents:
            continue
        agents.extend(job_agents)
        jobs.append({"job_id": job.job_id, "created_at": job.created_at, "completed_at": job.completed_at or ""})

    packages = _inventory_packages_from_agents(agents)
    total = len(agents)
    package_total = len(packages)
    job_total = len(jobs)
    page = agents[offset : offset + limit]
    packages_page = packages[offset : offset + limit]
    jobs_page = jobs[offset : offset + limit]
    return {
        # Scope marker so callers never conflate this population with live
        # local-disk discovery at /v1/agents. This endpoint is the scanned
        # estate: agents/packages aggregated from completed scan jobs.
        "scope": "scanned_estate",
        "source": (
            "Agents and packages aggregated from completed scan jobs (the scanned "
            "estate). For live local-disk discovery of AI-client configs on this "
            "host, see /v1/agents."
        ),
        "agents": page,
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
        # Honest truncation across the three roll-up arrays that share this
        # offset/limit window (fleet-style list contract).
        "has_more": offset + len(page) < total or offset + len(packages_page) < package_total or offset + len(jobs_page) < job_total,
        "packages": packages_page,
        "package_count": len(packages_page),
        "package_total": package_total,
        "jobs": jobs_page,
        "job_count": len(jobs_page),
        "job_total": job_total,
        "warnings": [],
    }


# ─── Dedicated Scan Endpoints ─────────────────────────────────────────────────
# Lightweight, synchronous scans for specific asset types.
# Each returns results directly (no job queue — these are fast local scans).


@router.post("/scan/dataset-cards", tags=["scan"], status_code=200)
async def scan_dataset_cards(request: DatasetCardsRequest) -> dict:
    """Scan directories for HuggingFace dataset cards, DVC files, and data lineage.

    Returns dataset metadata, license info, and security flags
    (unlicensed data, missing cards, unversioned data, remote sources).
    """
    from agent_bom.parsers.dataset_cards import scan_dataset_directory

    results = []
    safe_dirs = []
    for d in request.directories:
        resolved = _api_scan_path_or_400(d)
        safe_dirs.append(resolved)
        result = await _ai_scan_call(scan_dataset_directory, resolved)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))

    return {"scan_type": "dataset-cards", "directories": safe_dirs, "results": results}


@router.post("/scan/training-pipelines", tags=["scan"], status_code=200)
async def scan_training_pipelines(request: TrainingPipelinesRequest) -> dict:
    """Scan directories for ML training pipeline artifacts.

    Detects MLflow runs, W&B metadata, Kubeflow pipeline definitions.
    Flags unsafe serialization (pickle), missing provenance, exposed credentials.
    """
    from agent_bom.parsers.training_pipeline import scan_training_directory

    results = []
    safe_dirs = []
    for d in request.directories:
        resolved = _api_scan_path_or_400(d)
        safe_dirs.append(resolved)
        result = await _ai_scan_call(scan_training_directory, resolved)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))

    return {"scan_type": "training-pipelines", "directories": safe_dirs, "results": results}


@router.post("/scan/browser-extensions", tags=["scan"], status_code=200)
async def scan_browser_extensions_endpoint(request: BrowserExtensionsRequest) -> dict:
    """Scan installed browser extensions (Chrome, Chromium, Brave, Edge, Firefox).

    Detects dangerous permissions (debugger, nativeMessaging, cookies),
    AI assistant domain access, and broad host permissions.
    """
    from agent_bom.parsers.browser_extensions import discover_browser_extensions

    extensions = await _ai_scan_call(
        discover_browser_extensions,
        include_low_risk=request.include_low_risk,
    )
    ext_dicts: list[Any] = [e.to_dict() if hasattr(e, "to_dict") else _dataclass_to_dict(e) for e in extensions]

    return {
        "scan_type": "browser-extensions",
        "total": len(ext_dicts),
        "critical": sum(1 for e in ext_dicts if e.get("risk_level") == "critical"),
        "high": sum(1 for e in ext_dicts if e.get("risk_level") == "high"),
        "extensions": ext_dicts,
    }


@router.post("/scan/model-provenance", tags=["scan"], status_code=200)
async def scan_model_provenance(request: ModelProvenanceRequest) -> dict:
    """Check model provenance for HuggingFace and Ollama models.

    Verifies serialization safety (safetensors vs pickle), digest integrity,
    model card presence, gating status, and public exposure risk.
    """
    from agent_bom.cloud.model_provenance import check_hf_models, check_ollama_models

    results: list[Any] = []
    if request.hf_models:
        hf_results = await _ai_scan_call(check_hf_models, request.hf_models)
        results.extend(r.to_dict() if hasattr(r, "to_dict") else _dataclass_to_dict(r) for r in hf_results)
    if request.ollama_models:
        ollama_results = await _ai_scan_call(check_ollama_models, request.ollama_models)
        results.extend(r.to_dict() if hasattr(r, "to_dict") else _dataclass_to_dict(r) for r in ollama_results)

    return {
        "scan_type": "model-provenance",
        "total": len(results),
        "unsafe_format": sum(1 for r in results if not r.get("is_safe_format", True)),
        "results": results,
    }


@router.post("/scan/prompt-scan", tags=["scan"], status_code=200)
async def scan_prompts(request: PromptScanRequest) -> dict:
    """Scan prompt files for injection patterns, hardcoded secrets, and unsafe instructions.

    Detects prompt injection, jailbreak patterns, hardcoded API keys,
    shell execution instructions, and data exfiltration patterns.
    """
    from agent_bom.parsers.prompt_scanner import scan_prompt_files

    safe_dirs: list[Path] = []
    all_paths: list[Path] = []
    for d in request.directories:
        resolved = _api_scan_path_or_400(d)
        safe_dirs.append(Path(resolved))
    for f in request.files:
        resolved = _api_scan_path_or_400(f)
        all_paths.append(Path(resolved))

    results = []
    for safe in safe_dirs:
        result = await _ai_scan_call(scan_prompt_files, root=safe)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))
    if all_paths:
        result = await _ai_scan_call(scan_prompt_files, paths=all_paths)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))

    return {"scan_type": "prompt-scan", "results": results}


@router.post("/scan/model-files", tags=["scan"], status_code=200)
async def scan_model_files_endpoint(request: ModelFilesRequest) -> dict:
    """Scan directories for ML model files and assess serialization safety.

    Detects pickle deserialization risks (.pkl, .pt), verifies file integrity,
    and flags unsafe model formats.
    """
    from agent_bom.model_files import scan_model_files, scan_model_manifests, verify_model_hash

    all_files = []
    all_manifests = []
    all_warnings = []
    for d in request.directories:
        resolved = _api_scan_path_or_400(d)
        files, warnings = await _ai_scan_call(scan_model_files, resolved)
        manifests, manifest_warnings = await _ai_scan_call(scan_model_manifests, resolved)
        all_files.extend(files)
        all_manifests.extend(manifests)
        all_warnings.extend(warnings)
        all_warnings.extend(manifest_warnings)

    if request.verify_hashes:
        for f in all_files:
            hash_result = await _ai_scan_call(verify_model_hash, f["path"])
            f["sha256"] = hash_result.get("sha256")

    return {
        "scan_type": "model-files",
        "total": len(all_files),
        "manifest_total": len(all_manifests),
        "unsafe": sum(1 for f in all_files if f.get("security_flags")),
        "files": all_files,
        "manifests": all_manifests,
        "warnings": all_warnings,
    }
