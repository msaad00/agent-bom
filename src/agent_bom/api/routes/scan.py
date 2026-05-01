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
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from werkzeug.security import safe_join

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
from agent_bom.api.pipeline import _now, _run_scan_sync, get_executor
from agent_bom.api.scan_job_reconciliation import reconcile_scan_jobs_active
from agent_bom.api.stores import (
    _get_store,
    _job_lock,
    _jobs_get,
    _jobs_pop,
    _jobs_put,
)
from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota, tenant_quota_guard

router = APIRouter()
_logger = logging.getLogger(__name__)
_LOCAL_SCAN_DISABLE_VALUES = {"0", "false", "no", "off", "disabled"}


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _api_local_scans_enabled() -> bool:
    configured = os.getenv("AGENT_BOM_API_LOCAL_PATH_SCANS", os.getenv("AGENT_BOM_ENABLE_LOCAL_PATH_SCANS", "enabled"))
    return configured.strip().lower() not in _LOCAL_SCAN_DISABLE_VALUES


def _api_scan_root() -> Path:
    """Return the configured API filesystem scan root.

    Workstation pilots keep the historical default of ``$HOME``. Shared
    control-plane deployments should set ``AGENT_BOM_API_SCAN_ROOT`` to a
    tenant workspace mount, or disable these endpoints and scan via endpoint
    agents instead.
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
    from agent_bom.security import SecurityError

    try:
        return _sanitize_api_path(user_path)
    except SecurityError as exc:
        _logger.warning("blocked local API scan path: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid scan path") from exc


def _dataclass_to_dict(obj: object) -> object:
    """Convert a dataclass to dict, handling nested dataclasses."""
    import dataclasses

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dataclass_to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(i) for i in obj]
    return obj


def _tenant_id(request: Request) -> str:
    return getattr(request.state, "tenant_id", "default")


def _triggered_by(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "api"


def _visible_to_tenant(job: ScanJob, tenant_id: str) -> bool:
    return getattr(job, "tenant_id", "default") == tenant_id


def _completed_jobs_for_tenant(tenant_id: str) -> list[ScanJob]:
    return [job for job in _get_store().list_all(tenant_id=tenant_id) if job.status == JobStatus.DONE and job.result]


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
    labels.extend(req.connectors)
    labels.extend(req.filesystem_paths)
    labels.extend(req.agent_projects)
    return labels or ["local-agents"]


def _finding_key(finding: dict[str, Any]) -> str:
    vuln_id = finding.get("vulnerability_id") or finding.get("cve_id") or finding.get("id") or finding.get("title") or ""
    raw_asset = finding.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    package = finding.get("package") or finding.get("package_name") or asset.get("name", "")
    return f"{vuln_id}:{package}"


def _finding_from_blast_radius(item: dict[str, Any], job: ScanJob) -> dict[str, Any]:
    vulnerability_id = item.get("vulnerability_id") or item.get("id") or ""
    package = item.get("package") or item.get("package_name") or ""
    return {
        "id": item.get("finding_id") or f"{vulnerability_id}:{package}",
        "vulnerability_id": vulnerability_id,
        "package": package,
        "severity": (item.get("severity") or "unknown").lower(),
        "source": "blast_radius",
        "scan_id": job.job_id,
        "scan_sources": _scan_source_labels(job),
        "affected_agents": item.get("affected_agents", []),
        "affected_servers": item.get("affected_servers", []),
        "risk_score": item.get("risk_score", item.get("blast_score", 0)),
        "fixed_version": item.get("fixed_version"),
        "is_kev": bool(item.get("is_kev") or item.get("cisa_kev")),
    }


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
                            "epss_score": vuln.get("epss_score"),
                            "fixed_version": vuln.get("fixed_version"),
                            "is_kev": bool(vuln.get("is_kev")),
                            "references": vuln.get("references", []),
                        }
                    )
    return findings


def _iter_scan_findings(job: ScanJob) -> list[dict[str, Any]]:
    result = job.result or {}
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in result.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row.setdefault("scan_id", job.job_id)
        row.setdefault("scan_sources", _scan_source_labels(job))
        key = _finding_key(row)
        if key in seen:
            continue
        seen.add(key)
        findings.append(row)

    for item in result.get("blast_radius", []) or result.get("blast_radii", []) or []:
        if not isinstance(item, dict):
            continue
        row = _finding_from_blast_radius(item, job)
        key = _finding_key(row)
        if key in seen:
            continue
        seen.add(key)
        findings.append(row)

    for row in _iter_package_findings(job):
        key = _finding_key(row)
        if key in seen:
            continue
        seen.add(key)
        findings.append(row)

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
    request_payload = sanitize_sensitive_payload(job.request.model_dump(exclude_defaults=True, exclude_none=True))
    return {
        "job_id": job.job_id,
        "tenant_id": job.tenant_id,
        "status": job.status,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "request": request_payload if isinstance(request_payload, dict) else {},
        "summary": summary,
        "scan_timestamp": result.get("scan_timestamp"),
        "pushed": bool(result.get("pushed")),
        "error": job.error,
    }


def _job_for_request(request: Request, job_id: str) -> ScanJob:
    tenant_id = _tenant_id(request)
    in_mem = _jobs_get(job_id)
    if in_mem is not None and _visible_to_tenant(in_mem, tenant_id):
        return in_mem
    job = _get_store().get(job_id, tenant_id=tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


def enqueue_scan_job(
    *,
    tenant_id: str,
    triggered_by: str,
    request_body: ScanRequest,
    source_id: str | None = None,
) -> ScanJob:
    """Persist and queue a scan job for async execution."""
    store = _get_store()

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

    loop = asyncio.get_running_loop()
    loop.run_in_executor(get_executor(), _run_scan_sync, job)
    return job


# ─── Core Scan Endpoints ─────────────────────────────────────────────────────


@router.post("/v1/scan", response_model=ScanJob, status_code=202, tags=["scan"])
async def create_scan(request: Request, body: ScanRequest) -> ScanJob:
    """Start a scan. Returns immediately with a job_id.
    Poll GET /v1/scan/{job_id} for results, or stream via /v1/scan/{job_id}/stream.
    """
    return enqueue_scan_job(
        tenant_id=_tenant_id(request),
        triggered_by=_triggered_by(request),
        request_body=body,
    )


@router.get("/v1/scan/{job_id}", response_model=ScanJob, tags=["scan"])
async def get_scan(request: Request, job_id: str) -> ScanJob:
    """Fetch scan status and full results."""
    return _job_for_request(request, job_id)


@router.get("/v1/scan/{job_id}/status", tags=["scan"])
async def get_scan_status(request: Request, job_id: str) -> dict[str, Any]:
    """Poll lightweight scan status without serializing large result payloads."""
    return _job_summary_payload(_job_for_request(request, job_id))


@router.get("/v1/scan/{job_id}/attack-flow", tags=["scan"])
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


@router.get("/v1/scan/{job_id}/context-graph", tags=["scan"])
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

    from agent_bom.context_graph import (
        NodeKind,
        build_context_graph,
        compute_interaction_risks,
        find_lateral_paths,
        to_serializable,
    )

    graph = build_context_graph(
        job.result.get("agents", []),
        job.result.get("blast_radius", []),
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

    return to_serializable(graph, paths, risks)


@router.get("/v1/scan/{job_id}/graph-export", tags=["scan"], response_model=None)
async def get_graph_export(request: Request, job_id: str, format: str = "json") -> dict | str | PlainTextResponse:
    """Export the dependency graph in graph-native formats.

    Query params:
      ?format=json      JSON nodes/edges (default)
      ?format=dot       Graphviz DOT
      ?format=mermaid   Mermaid flowchart
      ?format=graphml   GraphML with AIBOM attributes (yEd/Gephi/NetworkX)
      ?format=cypher    Neo4j Cypher import script
    """
    from fastapi.responses import PlainTextResponse

    job = _job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

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

    result = job.result if isinstance(job.result, dict) else {}
    graph = build_graph_from_scan_data(result)

    _formats = {
        "dot": lambda g: PlainTextResponse(to_dot(g), media_type="text/vnd.graphviz"),
        "mermaid": lambda g: PlainTextResponse(to_mermaid(g), media_type="text/plain"),
        "graphml": lambda g: PlainTextResponse(to_graphml(g), media_type="application/xml"),
        "cypher": lambda g: PlainTextResponse(to_cypher(g), media_type="text/plain"),
    }
    if format in _formats:
        return _formats[format](graph)
    return graph_to_json(graph)


@router.get("/v1/scan/{job_id}/licenses", tags=["scan"])
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


@router.get("/v1/scan/{job_id}/vex", tags=["scan"])
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


@router.get("/v1/scan/{job_id}/skill-audit", tags=["scan"])
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


@router.delete("/v1/scan/{job_id}", status_code=204, tags=["scan"])
async def delete_scan(request: Request, job_id: str) -> None:
    """Discard a job record."""
    job = _job_for_request(request, job_id)
    in_memory = _jobs_pop(job_id) if _visible_to_tenant(job, _tenant_id(request)) else None
    in_store = _get_store().delete(job_id, tenant_id=_tenant_id(request))
    if not in_memory and not in_store:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@router.get("/v1/scan/{job_id}/stream", tags=["scan"])
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


@router.get("/v1/jobs", tags=["scan"])
async def list_jobs(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    include_details: bool = False,
) -> dict:
    """List all scan jobs (for the UI job history panel).

    Supports pagination via ``limit`` (default 50, max 200) and ``offset``.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    tenant_id = _tenant_id(request)
    store = _get_store()
    summary = store.list_summary(tenant_id=tenant_id)
    total = len(summary)
    page = summary[offset : offset + limit]
    enriched: list[dict[str, Any]] = []
    for item in page:
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
                full_job = get_job(item["job_id"]) if callable(get_job) else None
            except Exception:
                full_job = None
            enriched.append(_job_summary_payload(full_job) if isinstance(full_job, ScanJob) else item)
            continue

        enriched.append(item)
    return {
        "jobs": enriched,
        "count": len(enriched),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/v1/findings", tags=["scan"])
async def list_findings(
    request: Request,
    severity: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> dict:
    """List vulnerability findings aggregated from completed scan results."""
    tenant_id = _tenant_id(request)
    findings: list[dict[str, Any]] = []
    for job in _completed_jobs_for_tenant(tenant_id):
        findings.extend(_iter_scan_findings(job))

    if severity:
        normalized = severity.lower()
        findings = [item for item in findings if str(item.get("severity", "")).lower() == normalized]

    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    total = len(findings)
    page = findings[offset : offset + limit]
    return {
        "findings": page,
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
        "warnings": [],
    }


@router.get("/v1/inventory", tags=["scan"])
async def list_inventory(
    request: Request,
    limit: int = 500,
    offset: int = 0,
) -> dict:
    """List agent and package inventory aggregated from completed scan results."""
    tenant_id = _tenant_id(request)
    agents: list[dict[str, Any]] = []
    jobs: list[dict[str, str]] = []
    for job in _completed_jobs_for_tenant(tenant_id):
        result = job.result or {}
        job_agents = [item for item in result.get("agents", []) or [] if isinstance(item, dict)]
        if not job_agents:
            continue
        agents.extend(job_agents)
        jobs.append({"job_id": job.job_id, "created_at": job.created_at, "completed_at": job.completed_at or ""})

    packages = _inventory_packages_from_agents(agents)
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    total = len(agents)
    page = agents[offset : offset + limit]
    return {
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


@router.post("/v1/scan/dataset-cards", tags=["scan"], status_code=200)
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
        result = scan_dataset_directory(resolved)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))

    return {"scan_type": "dataset-cards", "directories": safe_dirs, "results": results}


@router.post("/v1/scan/training-pipelines", tags=["scan"], status_code=200)
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
        result = scan_training_directory(resolved)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))

    return {"scan_type": "training-pipelines", "directories": safe_dirs, "results": results}


@router.post("/v1/scan/browser-extensions", tags=["scan"], status_code=200)
async def scan_browser_extensions_endpoint(request: BrowserExtensionsRequest) -> dict:
    """Scan installed browser extensions (Chrome, Chromium, Brave, Edge, Firefox).

    Detects dangerous permissions (debugger, nativeMessaging, cookies),
    AI assistant domain access, and broad host permissions.
    """
    from agent_bom.parsers.browser_extensions import discover_browser_extensions

    extensions = discover_browser_extensions(include_low_risk=request.include_low_risk)
    ext_dicts: list[Any] = [e.to_dict() if hasattr(e, "to_dict") else _dataclass_to_dict(e) for e in extensions]

    return {
        "scan_type": "browser-extensions",
        "total": len(ext_dicts),
        "critical": sum(1 for e in ext_dicts if e.get("risk_level") == "critical"),
        "high": sum(1 for e in ext_dicts if e.get("risk_level") == "high"),
        "extensions": ext_dicts,
    }


@router.post("/v1/scan/model-provenance", tags=["scan"], status_code=200)
async def scan_model_provenance(request: ModelProvenanceRequest) -> dict:
    """Check model provenance for HuggingFace and Ollama models.

    Verifies serialization safety (safetensors vs pickle), digest integrity,
    model card presence, gating status, and public exposure risk.
    """
    from agent_bom.cloud.model_provenance import check_hf_models, check_ollama_models

    results: list[Any] = []
    if request.hf_models:
        hf_results = check_hf_models(request.hf_models)
        results.extend(r.to_dict() if hasattr(r, "to_dict") else _dataclass_to_dict(r) for r in hf_results)
    if request.ollama_models:
        ollama_results = check_ollama_models(request.ollama_models)
        results.extend(r.to_dict() if hasattr(r, "to_dict") else _dataclass_to_dict(r) for r in ollama_results)

    return {
        "scan_type": "model-provenance",
        "total": len(results),
        "unsafe_format": sum(1 for r in results if not r.get("is_safe_format", True)),
        "results": results,
    }


@router.post("/v1/scan/prompt-scan", tags=["scan"], status_code=200)
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
        result = scan_prompt_files(root=safe)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))
    if all_paths:
        result = scan_prompt_files(paths=all_paths)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))

    return {"scan_type": "prompt-scan", "results": results}


@router.post("/v1/scan/model-files", tags=["scan"], status_code=200)
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
        files, warnings = scan_model_files(resolved)
        manifests, manifest_warnings = scan_model_manifests(resolved)
        all_files.extend(files)
        all_manifests.extend(manifests)
        all_warnings.extend(warnings)
        all_warnings.extend(manifest_warnings)

    if request.verify_hashes:
        for f in all_files:
            hash_result = verify_model_hash(f["path"])
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
