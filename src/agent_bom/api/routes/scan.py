"""Scan API routes.

Endpoints:
    POST /v1/scan                      start a scan (async, returns job_id)
    GET  /v1/scan/{job_id}             fetch scan status + full results
    GET  /v1/scan/{job_id}/status      poll lightweight scan status
    GET  /v1/scan/{job_id}/attack-flow attack flow graph (React Flow)
    GET  /v1/scan/{job_id}/context-graph context graph with lateral movement
    GET  /v1/scan/{job_id}/graph-export graph export (json/dot/mermaid/graphml/cypher)
    GET  /v1/scan/{job_id}/licenses    license compliance report
    GET  /v1/scan/{job_id}/vex         VEX document
    GET  /v1/scan/{job_id}/skill-audit skill security audit
    DELETE /v1/scan/{job_id}           cancel / discard a job
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
import logging
import os
import time
import uuid
from functools import partial
from pathlib import Path
from typing import Annotated, Any

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from werkzeug.security import safe_join

from agent_bom.api.finding_list_envelope import finding_list_envelope
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
from agent_bom.api.pipeline import _now, submit_scan_job
from agent_bom.api.scan_batches import child_request_for_target, refresh_batch_parent, scan_request_targets
from agent_bom.api.scan_job_reconciliation import reconcile_scan_jobs_active
from agent_bom.api.stores import (
    _get_idempotency_store,
    _get_store,
    _job_lock,
    _jobs_get,
    _jobs_is_compacted,
    _jobs_pop,
    _jobs_put,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.canonical_ids import canonical_finding_id
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)
_LOCAL_SCAN_DISABLE_VALUES = {"0", "false", "no", "off", "disabled"}
_BULK_FINDINGS_MAX_ITEMS = 1000
_BULK_FINDINGS_SOURCE_MAX_LENGTH = 128


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _api_local_scans_enabled() -> bool:
    configured = os.getenv("AGENT_BOM_API_LOCAL_PATH_SCANS", os.getenv("AGENT_BOM_ENABLE_LOCAL_PATH_SCANS", "disabled"))
    return configured.strip().lower() not in _LOCAL_SCAN_DISABLE_VALUES


async def _scan_graph_compute_call(fn, /, *args, **kwargs):
    """Run graph rendering/derivation for scan subresources off the event loop."""
    return await asyncio.to_thread(fn, *args, **kwargs)


async def _ai_scan_call(fn, /, *args, **kwargs):
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


def _normalized_bulk_finding(row: dict[str, Any], *, source: str, batch_id: str, ordinal: int) -> dict[str, Any]:
    payload = dict(row)
    client_id = row.get("id")
    # Client-stable ids win; otherwise derive a content-deterministic id so
    # resends collapse (idempotent) rather than mint a fresh batch_id:ordinal.
    payload["id"] = str(client_id) if client_id else _derive_bulk_finding_id(row, source=source)
    payload.setdefault("source", source)
    payload.setdefault("severity", "unknown")
    payload["origin"] = "bulk_ingest"
    payload["batch_id"] = batch_id
    payload["bulk_ordinal"] = ordinal
    return payload


_LIFECYCLE_RESPONSE_KEYS = (
    "origin",
    "batch_id",
    "bulk_ordinal",
    "status",
    "first_seen",
    "last_seen",
    "resolved_at",
    "reopened_at",
    "scan_count",
    "canonical_id",
)


def _redact_finding_page(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    redacted = redact_for_persistence(rows, EvidenceTier.SAFE_TO_STORE)
    if not isinstance(redacted, list):
        return []
    page: list[dict[str, Any]] = []
    for clean, raw in zip(redacted, rows):
        if not isinstance(clean, dict):
            continue
        for key in _LIFECYCLE_RESPONSE_KEYS:
            if key not in clean and key in raw:
                clean[key] = raw[key]
        page.append(clean)
    return page


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
    raw_id = finding.get("id")
    if raw_id:
        return str(raw_id)
    return _finding_key(finding)


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

    Findings that carry a CVE/advisory id group by ``(vuln_id, package_base)``
    so the ``MCP_SCAN`` (unified), ``blast_radius`` and ``package_vulnerability``
    rows for the same vulnerability merge into a single list row. Non-CVE
    findings (posture, malicious-package, etc.) fall back to their stable
    identity so distinct findings stay distinct.
    """
    vuln = _row_vuln_id(finding)
    if vuln:
        return f"vuln:{vuln.lower()}:{_package_base_name(finding)}"
    return f"id:{_finding_identity(finding)}"


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
    row = {
        "id": item.get("finding_id") or f"{vulnerability_id}:{package}",
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
        compute_interaction_risks,
        find_lateral_paths,
        to_serializable,
    )

    graph = build_context_graph(
        result.get("agents", []),
        result.get("blast_radius", []),
    )
    paths: list = []
    if agent:
        node_id = f"agent:{agent}"
        if node_id in graph.nodes:
            paths = find_lateral_paths(graph, node_id)
    else:
        for nid, node in graph.nodes.items():
            if node.kind == NodeKind.AGENT:
                paths.extend(find_lateral_paths(graph, nid))
    risks = compute_interaction_risks(graph)

    payload = to_serializable(graph, paths, risks)
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

    def _render_mermaid(g):
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

    runtime_index = build_tenant_runtime_evidence_index(str(getattr(job, "tenant_id", None) or "default"))
    incidents = result.get("runtime_incident_feedback") if isinstance(result.get("runtime_incident_feedback"), list) else []

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
        return attach_runtime_evidence_to_finding(row, runtime_index, incidents=incidents)

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
    for row in findings:
        _normalize_finding_identifiers(row)
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
                return persisted
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
    return job


def _redact_scan_result_for_response(result: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop replay-only fields from top-level scan findings before API return."""
    if not isinstance(result, dict):
        return result
    findings = result.get("findings")
    if not isinstance(findings, list):
        return result
    redacted = dict(result)
    redacted["findings"] = redact_for_persistence(findings, EvidenceTier.SAFE_TO_STORE)
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
) -> ScanJob:
    """Persist and queue a scan job for async execution."""
    store = _get_store()
    targets = scan_request_targets(request_body)

    def _dispatch(job: ScanJob) -> None:
        # In a clustered control plane, hand the job to the shared dispatch queue
        # so any replica can claim and run it (work-stealing). Single-node
        # deployments keep running the job on this process directly.
        from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch

        if distributed_scans_enabled() and store_supports_dispatch(store):
            store.enqueue_for_dispatch(job)
        else:
            submit_scan_job(job)

    if len(targets) > 1:
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
            _dispatch(child)
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
    with tenant_quota_guard(
        tenant_id,
        lambda: enforce_active_scan_quota(tenant_id),
        lambda: enforce_retained_jobs_quota(tenant_id),
    ):
        store.put(job)
        _jobs_put(job.job_id, job)
        # Recompute after durable enqueue so the gauge survives missed
        # increments and reflects queued + running work from the store.
        try:
            reconcile_scan_jobs_active(store)
        except Exception:  # noqa: BLE001
            pass

    _dispatch(job)
    return job


# ─── Core Scan Endpoints ─────────────────────────────────────────────────────


@router.post("/scan", response_model=ScanJob, status_code=202, tags=["scan"])
async def create_scan(request: Request, body: ScanRequest) -> ScanJob:
    """Start a scan. Returns immediately with a job_id.
    Poll GET /v1/scan/{job_id} for results, or stream via /v1/scan/{job_id}/stream.

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
    """Fetch scan status and full results."""
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
    return await _scan_graph_compute_call(_context_graph_payload, job.result, agent=agent, scan_id=job.job_id, tenant_id=tenant_id)


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
    return await _scan_graph_compute_call(_graph_export_response, result, format=format, mermaid_limit=mermaid_limit)


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
        return job.result["license_report"]

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
        return job.result["vex"]

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

    return job.result.get(
        "skill_audit",
        {
            "findings": [],
            "packages_checked": 0,
            "servers_checked": 0,
            "credentials_checked": 0,
            "passed": True,
        },
    )


@router.delete("/scan/{job_id}", status_code=204, tags=["scan"])
async def delete_scan(request: Request, job_id: str) -> None:
    """Discard a job record."""
    job = _job_for_request(request, job_id)
    in_memory = _jobs_pop(job_id) if _visible_to_tenant(job, _tenant_id(request)) else None
    in_store = _get_store().delete(job_id, tenant_id=_tenant_id(request))
    if not in_memory and not in_store:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@router.get("/scan/{job_id}/stream", tags=["scan"])
async def stream_scan(request: Request, job_id: str):
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

    async def event_generator():
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

    return EventSourceResponse(event_generator())


@router.get("/jobs", tags=["scan"])
async def list_jobs(
    request: Request,
    # enforce limit/offset caps via Pydantic so callers
    # cannot pass `?limit=10000` to fan out the in-memory scan-job list.
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    include_details: bool = False,
) -> dict:
    """List all scan jobs (for the UI job history panel).

    Supports pagination via ``limit`` (default 50, max 1000) and ``offset``.
    """
    tenant_id = _tenant_id(request)
    store = _get_store()
    count_summary = getattr(store, "count_summary", None)
    if callable(count_summary):
        total = count_summary(tenant_id=tenant_id)
        summary = store.list_summary(tenant_id=tenant_id, limit=limit, offset=offset)
    else:
        summary = store.list_summary(tenant_id=tenant_id)
        total = len(summary)
        summary = summary[offset : offset + limit]
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
    }


_ALLOWED_FINDING_SORTS = ("effective_reach", "cvss", "severity")
_ALLOWED_FINDING_SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "informational",
    "none",
    "unknown",
)


def _canonical_scope_filters(
    provider: str | None,
    account: str | None,
    environment: str | None,
    domain: str | None,
) -> dict[str, str]:
    """Normalize the optional scope/domain filters into an active-filter map.

    Server-side canonicalization (issue #3946): values are lowercased/trimmed
    and empty inputs dropped. Unknown values are kept (not rejected) so the
    endpoint never raises on ad-hoc input — an unmatched value simply returns no
    findings. ``account`` maps to the finding's ``account_ref``.
    """
    filters: dict[str, str] = {}
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
    return filters


def _row_matches_scope(row: dict[str, Any], filters: dict[str, str]) -> bool:
    """Return True when a finding row matches every active scope filter.

    The ``domain`` facet matches against the finding's overlapping coverage-lens
    set, not just its primary domain, so ``domain=aspm`` returns SAST + secrets +
    repo dependencies + IaC, and ``domain=vuln`` returns every CVE (mirroring the
    overlapping coverage lanes on the overview).
    """
    from agent_bom.finding_scope import domain_for_row, lenses_for_row

    for key in ("provider", "account_ref", "environment"):
        wanted = filters.get(key)
        if wanted is not None and str(row.get(key) or "").strip().lower() != wanted:
            return False
    wanted_domain = filters.get("domain")
    if wanted_domain is not None:
        lenses = lenses_for_row(row) or ({domain_for_row(row) or ""} if domain_for_row(row) else set())
        if wanted_domain not in lenses:
            return False
    return True


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
) -> tuple[int | None, bool]:
    """Return ``(total, total_approximate)`` for the bulk-ingest slice."""
    from agent_bom.api.findings_count_cache import cache_key, get_cached_total, set_cached_total

    key = cache_key(tenant_id=tenant_id, severity=severity, scan_id=scan_id, origin="bulk_ingest")
    if not approximate_total:
        if bulk_total is not None:
            set_cached_total(key, bulk_total)
            return bulk_total, False
        cached = get_cached_total(key)
        if cached is not None:
            return cached, True
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
) -> list[dict[str, Any]]:
    """Merge pre-sorted scan findings with bulk hub pages without O(table) work.

    Streams two sorted sources with a two-pointer walk so deep ``offset`` does
    not require loading ``offset + limit`` bulk rows up front or re-sorting the
    full combined window in memory.
    """
    scan_i = 0
    bulk_remote_offset = 0
    bulk_buf: list[dict[str, Any]] = []
    bulk_i = 0

    def _refill_bulk() -> bool:
        nonlocal bulk_buf, bulk_i, bulk_remote_offset
        bulk_result = bulk_list(
            tenant_id,
            limit=_BULK_MERGE_CHUNK,
            offset=bulk_remote_offset,
            sort=sort_key,
            severity=severity,
            scan_id=scan_id,
            origin="bulk_ingest",
            include_total=False,
        )
        bulk_buf = bulk_result[0]
        bulk_remote_offset += len(bulk_buf)
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
        nonlocal bulk_i
        row = bulk_buf[bulk_i]
        bulk_i += 1
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
            return []
        skipped += 1

    page: list[dict[str, Any]] = []
    for _ in range(limit):
        row = pick_next()
        if row is None:
            break
        page.append(row)
    return page


@router.get("/findings", tags=["scan"])
async def list_findings(
    request: Request,
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
) -> dict:
    """List vulnerability findings aggregated from completed scan results.

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
    """
    try:
        async with adaptive_backpressure("findings"):
            return await anyio.to_thread.run_sync(
                _list_findings_impl,
                request,
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
            )
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _list_findings_impl(
    request: Request,
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
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.finding_cursor import decode_finding_cursor

    tenant_id = _tenant_id(request)
    sort_key = sort.lower().strip() if isinstance(sort, str) else "effective_reach"
    if sort_key not in _ALLOWED_FINDING_SORTS:
        # Silently falling back masked typos as "wrong order"; reject clearly.
        raise HTTPException(
            status_code=422,
            detail=f"invalid sort '{sort}'; accepted values: {', '.join(_ALLOWED_FINDING_SORTS)}",
        )
    if severity is not None and severity.strip().lower() not in _ALLOWED_FINDING_SEVERITIES:
        # A bogus severity previously returned an empty 200 that reads as
        # "no findings" — a trap. Reject with the accepted set instead.
        raise HTTPException(
            status_code=422,
            detail=f"invalid severity '{severity}'; accepted values: {', '.join(_ALLOWED_FINDING_SEVERITIES)}",
        )
    if cursor and offset:
        raise HTTPException(status_code=400, detail="cursor and offset are mutually exclusive")
    if cursor:
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
    )
    cached_bulk_total = get_cached_total(cache_key(tenant_id=tenant_id, severity=severity, scan_id=scan_id, origin="bulk_ingest"))
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
    deduped: dict[str, dict[str, Any]] = {}
    for job in sorted(
        _completed_jobs_for_tenant(tenant_id),
        key=lambda job: (job.completed_at or "", job.created_at or "", job.job_id),
    ):
        if scan_id and job.job_id != scan_id:
            continue
        if job.child_job_ids and job.job_id != scan_id:
            continue
        for row in _iter_scan_findings(job):
            deduped[_finding_identity(row)] = row
    scan_findings: list[dict[str, Any]] = list(deduped.values())
    if severity:
        normalized = severity.lower()
        scan_findings = [item for item in scan_findings if str(item.get("severity", "")).lower() == normalized]
    scope_filters = _canonical_scope_filters(provider, account, environment, domain)
    if scope_filters:
        scan_findings = [item for item in scan_findings if _row_matches_scope(item, scope_filters)]
    scan_findings.sort(key=lambda row: _finding_sort_key(row, sort_key))

    store = get_compliance_hub_store()
    bulk_list = getattr(store, "list_current_page", None) or getattr(store, "list_page", None)
    total_approximate = False
    next_cursor: str | None = None
    warnings: list[str] = []
    if cursor and scan_findings:
        warnings.append("cursor pagination applies to bulk-ingested findings only; in-memory scan findings appear on the first page")
    # When scope/domain filters are active, page over the fully-materialized
    # combined list so ``total``/``count`` stay honest (the keyset store path
    # does not carry the scope predicates). No scope filter -> unchanged fast
    # path, so existing pagination behavior is byte-for-byte backward compatible.
    if callable(bulk_list) and not scope_filters:
        if scan_findings and not cursor:
            bulk_result = bulk_list(
                tenant_id,
                limit=1,
                offset=0,
                sort=sort_key,
                severity=severity,
                scan_id=scan_id,
                origin="bulk_ingest",
                include_total=include_bulk_total,
            )
            bulk_total = bulk_result[1]
            page_rows = _merged_scan_bulk_page(
                scan_findings,
                bulk_list=bulk_list,
                tenant_id=tenant_id,
                sort_key=sort_key,
                severity=severity,
                scan_id=scan_id,
                offset=offset,
                limit=limit,
            )
            resolved_bulk, total_approximate = _resolve_bulk_findings_total(
                tenant_id=tenant_id,
                severity=severity,
                scan_id=scan_id,
                approximate_total=approximate_total or effective_approximate_total,
                offset=offset,
                bulk_total=bulk_total,
                page_len=len(page_rows),
                limit=limit,
            )
            total = None if resolved_bulk is None else len(scan_findings) + resolved_bulk
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
                cursor=cursor,
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
            )
    else:
        bulk_findings = _bulk_ingested_findings_for_tenant(tenant_id)
        if scan_id:
            bulk_findings = [item for item in bulk_findings if str(item.get("scan_id") or "") == scan_id]
        if severity:
            normalized = severity.lower()
            bulk_findings = [item for item in bulk_findings if str(item.get("severity", "")).lower() == normalized]
        if scope_filters:
            bulk_findings = [item for item in bulk_findings if _row_matches_scope(item, scope_filters)]
        combined = scan_findings + bulk_findings
        combined.sort(key=lambda row: _finding_sort_key(row, sort_key))
        total = len(combined)
        page_rows = combined[offset : offset + limit]

    page = _redact_finding_page(page_rows)
    return finding_list_envelope(
        findings=page,
        total=total,
        limit=limit,
        offset=0 if cursor else offset,
        sort=sort_key,
        scan_id=scan_id,
        cursor=cursor or "",
        next_cursor=next_cursor or "",
        warnings=warnings,
        total_approximate=total_approximate,
    )


@router.post("/findings/bulk", tags=["scan"], status_code=201)
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
    ignored_body_tenant = bool(body.tenant_id and body.tenant_id != tenant_id)

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
            return cached

    # Deterministic batch id so a resend of the same body (even without an
    # Idempotency-Key header) collapses onto one logical batch. Random per-request
    # ids made ``upsert_current_batch``'s (canonical, batch_id) observation key
    # miss on every replay, inflating ``scan_count`` (P1-5).
    batch_id = deterministic_batch_id(idem_key or request_hash)
    payloads = [
        _normalized_bulk_finding(row, source=body.source, batch_id=batch_id, ordinal=idx) for idx, row in enumerate(body.findings, start=1)
    ]
    from agent_bom.api.finding_lifecycle import collect_present_canonical_ids, normalize_observed_at

    observed_at = normalize_observed_at(body.observed_at or body.metadata.get("observed_at"))
    hub_store = get_compliance_hub_store()
    from agent_bom.delta_stream import (
        capture_hub_snapshots,
        emit_hub_finding_deltas_if_enabled,
        needs_hub_prior_snapshots,
        resolved_canonical_ids,
    )

    prior_snapshots: dict[str, Any] = {}
    if needs_hub_prior_snapshots(reconcile_absent=body.reconcile_absent):
        prior_snapshots = capture_hub_snapshots(hub_store, tenant_id, source=body.source)
    new_total = hub_store.add(tenant_id, payloads)
    hub_store.upsert_current_batch(
        tenant_id,
        payloads,
        observed_at=observed_at,
        batch_id=batch_id,
        source=body.source,
    )
    reconciled = 0
    resolved_ids: set[str] = set()
    if body.reconcile_absent:
        present = collect_present_canonical_ids(payloads, source=body.source)
        resolved_ids = resolved_canonical_ids(prior_snapshots, present)
        reconciled = hub_store.reconcile_current_absent(
            tenant_id,
            present_canonical_ids=present,
            observed_at=observed_at,
            scope_source=body.source,
        )
    delta_results = emit_hub_finding_deltas_if_enabled(
        tenant_id=tenant_id,
        hub_store=hub_store,
        prior=prior_snapshots,
        batch_findings=payloads,
        resolved_canonical_ids=resolved_ids,
        observed_at=observed_at,
        batch_id=batch_id,
        source=body.source,
    )
    warnings = ["tenant_id in body ignored; request tenant scope is authoritative"] if ignored_body_tenant else []
    response = {
        "schema_version": "v1",
        "batch_id": batch_id,
        "ingested": len(payloads),
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
    page = agents[offset : offset + limit]
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
        "packages": packages,
        "package_count": len(packages),
        "jobs": jobs,
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
