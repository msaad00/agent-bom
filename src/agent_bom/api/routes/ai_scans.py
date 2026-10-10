"""Dedicated AI-asset scan endpoints.

Dataset cards, training pipelines, browser extensions, model provenance,
prompt files and model files. Each endpoint confines caller paths to the API
scan jail and runs the blocking scan off the event loop under shared
backpressure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter

from agent_bom.api.ai_scan_runtime import _ai_scan_call, _dataclass_to_dict
from agent_bom.api.models import (
    BrowserExtensionsRequest,
    DatasetCardsRequest,
    ModelFilesRequest,
    ModelProvenanceRequest,
    PromptScanRequest,
    TrainingPipelinesRequest,
)
from agent_bom.api.scan_path_jail import _api_scan_path_or_400

router = APIRouter()


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
