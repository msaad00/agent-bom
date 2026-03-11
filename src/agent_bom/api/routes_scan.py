"""Scan CRUD, SSE streaming, and specialized scan endpoints."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException

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
from agent_bom.api.pipeline import _now, _run_scan_sync
from agent_bom.api.stores import (
    _get_store,
    _job_lock,
    _jobs_get,
    _jobs_pop,
    _jobs_put,
    get_executor,
)
from agent_bom.config import API_MAX_CONCURRENT_JOBS as _MAX_CONCURRENT_JOBS

router = APIRouter()
_logger = logging.getLogger(__name__)


# ─── Scan CRUD ───────────────────────────────────────────────────────────────


@router.post("/v1/scan", response_model=ScanJob, status_code=202, tags=["scan"])
async def create_scan(request: ScanRequest) -> ScanJob:
    """Start a scan. Returns immediately with a job_id.
    Poll GET /v1/scan/{job_id} for results, or stream via /v1/scan/{job_id}/stream.
    """
    store = _get_store()
    active = sum(1 for j in store.list_all() if j.status in (JobStatus.PENDING, JobStatus.RUNNING))
    if active >= _MAX_CONCURRENT_JOBS:
        raise HTTPException(
            status_code=429,
            detail=f"Max {_MAX_CONCURRENT_JOBS} concurrent scan jobs. Try again later.",
        )

    job = ScanJob(
        job_id=str(uuid.uuid4()),
        created_at=_now(),
        request=request,
    )
    store.put(job)
    _jobs_put(job.job_id, job)

    loop = asyncio.get_running_loop()
    loop.run_in_executor(get_executor(), _run_scan_sync, job)

    return job


@router.get("/v1/scan/{job_id}", response_model=ScanJob, tags=["scan"])
async def get_scan(job_id: str) -> ScanJob:
    """Poll scan status and results."""
    in_mem = _jobs_get(job_id)
    if in_mem is not None:
        return in_mem
    job = _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@router.get("/v1/scan/{job_id}/attack-flow", tags=["scan"])
async def get_attack_flow(
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
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
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
async def get_context_graph(job_id: str, agent: str | None = None) -> dict:
    """Get the agent context graph with lateral movement analysis.

    Returns nodes, edges, lateral paths, interaction risks, and stats for
    a completed scan.  Optionally filter lateral paths to a single agent.

    Query params:
      ?agent=claude-desktop  - only compute lateral paths from this agent
    """
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
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


@router.get("/v1/scan/{job_id}/licenses", tags=["scan"])
async def get_licenses(job_id: str) -> dict:
    """Get the license compliance report for a completed scan."""
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    if isinstance(job.result, dict) and job.result.get("license_report"):
        return job.result["license_report"]

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
async def get_vex(job_id: str) -> dict:
    """Get the VEX (Vulnerability Exploitability eXchange) document for a completed scan."""
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    if isinstance(job.result, dict) and job.result.get("vex"):
        return job.result["vex"]

    return {"statements": [], "stats": {"total_statements": 0, "affected": 0, "not_affected": 0, "fixed": 0, "under_investigation": 0}}


@router.get("/v1/scan/{job_id}/skill-audit", tags=["scan"])
async def get_skill_audit(job_id: str) -> dict:
    """Get the skill security audit results for a completed scan."""
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

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
async def delete_scan(job_id: str) -> None:
    """Discard a job record."""
    in_memory = _jobs_pop(job_id)
    in_store = _get_store().delete(job_id)
    if not in_memory and not in_store:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@router.get("/v1/scan/{job_id}/stream", tags=["scan"])
async def stream_scan(job_id: str):
    """Server-Sent Events stream for real-time scan progress."""
    try:
        from sse_starlette.sse import EventSourceResponse
    except ImportError as exc:
        raise HTTPException(
            status_code=501,
            detail="SSE requires sse-starlette. Install: pip install 'agent-bom[api]'",
        ) from exc

    if _jobs_get(job_id) is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    import json as _json

    async def event_generator():
        sent = 0
        lock = _job_lock(job_id)
        start = time.monotonic()
        while time.monotonic() - start < 2100:  # 35 min max
            current = _jobs_get(job_id)
            if current is None:
                break
            with lock:
                new_lines = list(current.progress[sent:])
                status = current.status
            for line in new_lines:
                try:
                    parsed = _json.loads(line)
                    if isinstance(parsed, dict) and parsed.get("type") == "step":
                        yield {"data": _json.dumps(parsed)}
                    else:
                        yield {"data": _json.dumps({"type": "progress", "message": line})}
                except (_json.JSONDecodeError, ValueError):
                    yield {"data": _json.dumps({"type": "progress", "message": line})}
                sent += 1
            if status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
                yield {"data": _json.dumps({"type": "done", "status": status, "job_id": job_id})}
                break
            await asyncio.sleep(0.25)

    return EventSourceResponse(event_generator())


@router.get("/v1/jobs", tags=["scan"])
async def list_jobs(limit: int = 50, offset: int = 0) -> dict:
    """List all scan jobs (for the UI job history panel)."""
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    summary = _get_store().list_summary()
    total = len(summary)
    page = summary[offset : offset + limit]
    return {
        "jobs": page,
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ─── Dedicated Scan Endpoints ─────────────────────────────────────────────────
# Lightweight, synchronous scans for specific asset types.


def _sanitize_api_path(user_path: str) -> str:
    """Validate and sanitize a user-supplied path from an API request.

    Interprets ``user_path`` as relative to the current user's home directory
    (absolute paths are rejected). The resolved path is normalised, has any
    symlinks resolved, and is verified to remain within the home directory
    using ``os.path.commonpath`` before being returned.
    """
    import os
    from pathlib import Path

    from agent_bom.security import SecurityError

    user_path = (user_path or "").strip()
    if not user_path:
        raise SecurityError("Empty paths are not allowed")

    if os.path.isabs(user_path):
        raise SecurityError(f"Absolute paths are not allowed: {user_path}")

    if ".." in user_path.split(os.sep):
        raise SecurityError(f"Path traversal not allowed: {user_path}")

    home = os.path.realpath(str(Path.home()))
    relative = os.path.normpath(user_path)
    candidate = os.path.join(home, relative)
    resolved = os.path.realpath(candidate)

    if os.path.commonpath([home, resolved]) != home:
        raise SecurityError(f"Path resolves outside home directory: {user_path}")

    return resolved


def _dataclass_to_dict(obj: object) -> object:
    """Convert a dataclass to dict, handling nested dataclasses."""
    import dataclasses

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dataclass_to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(i) for i in obj]
    return obj


@router.post("/v1/scan/dataset-cards", tags=["scan"], status_code=200)
async def scan_dataset_cards(request: DatasetCardsRequest) -> dict:
    """Scan directories for HuggingFace dataset cards, DVC files, and data lineage."""
    import os
    from pathlib import Path

    from agent_bom.parsers.dataset_cards import scan_dataset_directory
    from agent_bom.security import SecurityError

    home = os.path.realpath(str(Path.home()))
    results = []
    safe_dirs = []
    for d in request.directories:
        resolved = _sanitize_api_path(d)
        if os.path.commonpath([home, resolved]) == home:
            safe_dirs.append(resolved)
            result = scan_dataset_directory(resolved)
            results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))
        else:
            raise SecurityError(f"Path escapes safe root: {d}")

    return {"scan_type": "dataset-cards", "directories": safe_dirs, "results": results}


@router.post("/v1/scan/training-pipelines", tags=["scan"], status_code=200)
async def scan_training_pipelines(request: TrainingPipelinesRequest) -> dict:
    """Scan directories for ML training pipeline artifacts."""
    import os
    from pathlib import Path

    from agent_bom.parsers.training_pipeline import scan_training_directory
    from agent_bom.security import SecurityError

    home = os.path.realpath(str(Path.home()))
    results = []
    safe_dirs = []
    for d in request.directories:
        resolved = _sanitize_api_path(d)
        if os.path.commonpath([home, resolved]) == home:
            safe_dirs.append(resolved)
            result = scan_training_directory(resolved)
            results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))
        else:
            raise SecurityError(f"Path escapes safe root: {d}")

    return {"scan_type": "training-pipelines", "directories": safe_dirs, "results": results}


@router.post("/v1/scan/browser-extensions", tags=["scan"], status_code=200)
async def scan_browser_extensions_endpoint(request: BrowserExtensionsRequest) -> dict:
    """Scan installed browser extensions (Chrome, Chromium, Brave, Edge, Firefox)."""
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
    """Check model provenance for HuggingFace and Ollama models."""
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
    """Scan prompt files for injection patterns, hardcoded secrets, and unsafe instructions."""
    import os
    from pathlib import Path

    from agent_bom.parsers.prompt_scanner import scan_prompt_files
    from agent_bom.security import SecurityError

    home = os.path.realpath(str(Path.home()))
    safe_dirs: list[Path] = []
    all_paths: list[Path] = []
    for d in request.directories:
        resolved = _sanitize_api_path(d)
        if os.path.commonpath([home, resolved]) == home:
            safe_dirs.append(Path(resolved))
        else:
            raise SecurityError(f"Path escapes safe root: {d}")
    for f in request.files:
        resolved = _sanitize_api_path(f)
        if os.path.commonpath([home, resolved]) == home:
            all_paths.append(Path(resolved))
        else:
            raise SecurityError(f"Path escapes safe root: {f}")

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
    """Scan directories for ML model files and assess serialization safety."""
    import os
    from pathlib import Path

    from agent_bom.model_files import scan_model_files, verify_model_hash
    from agent_bom.security import SecurityError

    home = os.path.realpath(str(Path.home()))
    all_files = []
    all_warnings = []
    for d in request.directories:
        resolved = _sanitize_api_path(d)
        if os.path.commonpath([home, resolved]) == home:
            files, warnings = scan_model_files(resolved)
            all_files.extend(files)
            all_warnings.extend(warnings)
        else:
            raise SecurityError(f"Path escapes safe root: {d}")

    if request.verify_hashes:
        for f in all_files:
            hash_result = verify_model_hash(f["path"])
            f["sha256"] = hash_result.get("sha256")

    return {
        "scan_type": "model-files",
        "total": len(all_files),
        "unsafe": sum(1 for f in all_files if f.get("security_flags")),
        "files": all_files,
        "warnings": all_warnings,
    }
