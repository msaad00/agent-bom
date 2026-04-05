"""Model binary file detection — scan for ML model artifacts.

Detects common model file formats and flags security risks
(e.g., pickle-based serialization allows arbitrary code execution).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Extension → metadata mapping
_MODEL_EXTENSIONS: dict[str, dict] = {
    ".gguf": {"format": "GGML/GGUF", "ecosystem": "llama.cpp/Ollama"},
    ".safetensors": {"format": "SafeTensors", "ecosystem": "HuggingFace"},
    ".onnx": {"format": "ONNX", "ecosystem": "ONNX Runtime"},
    ".pt": {"format": "PyTorch", "ecosystem": "PyTorch"},
    ".pth": {"format": "PyTorch Checkpoint", "ecosystem": "PyTorch"},
    ".pb": {"format": "TensorFlow ProtoBuf", "ecosystem": "TensorFlow"},
    ".tflite": {"format": "TensorFlow Lite", "ecosystem": "TFLite"},
    ".mlmodel": {"format": "Core ML", "ecosystem": "Apple Core ML"},
    ".pkl": {"format": "Pickle", "ecosystem": "scikit-learn/Python"},
    ".joblib": {"format": "Joblib", "ecosystem": "scikit-learn"},
    ".h5": {"format": "HDF5/Keras", "ecosystem": "Keras/TensorFlow"},
    ".keras": {"format": "Keras v3", "ecosystem": "Keras"},
    ".bin": {"format": "Generic Binary", "ecosystem": "Various", "min_size_mb": 10},
}

# Extensions that pose security risks
_SECURITY_FLAGS: dict[str, dict] = {
    ".pkl": {
        "severity": "HIGH",
        "type": "PICKLE_DESERIALIZATION",
        "description": (
            "Pickle files can execute arbitrary code on load via __reduce__. "
            "An attacker could embed malicious payloads. "
            "Use safetensors or ONNX format instead."
        ),
    },
    ".joblib": {
        "severity": "MEDIUM",
        "type": "JOBLIB_DESERIALIZATION",
        "description": ("Joblib uses pickle internally and may execute arbitrary code. Prefer safetensors for model weights."),
    },
}

_UNSAFE_MODEL_EXTENSIONS = frozenset({".pt", ".pth", ".pkl", ".joblib", ".bin"})
_MODEL_INDEX_FILENAMES = frozenset({"model.safetensors.index.json", "pytorch_model.bin.index.json"})
_MODEL_MANIFEST_FILENAMES = frozenset({"config.json", "tokenizer_config.json", "adapter_config.json"})


def _load_json_file(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _extract_repo_reference(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or candidate.startswith("/"):
        return None
    return candidate if "/" in candidate else None


def _safe_resolve_directory(directory: str | Path) -> Path:
    """Resolve a scan root and constrain it to known-safe local roots.

    Allowed roots:
    - current user's home directory
    - current working directory
    - system temp directory
    - optional extra roots from AGENT_BOM_SAFE_SCAN_ROOTS (os.pathsep-separated)
    """
    resolved = Path(directory).expanduser().resolve(strict=False)
    candidate = os.path.realpath(str(resolved))

    allowed_roots = {
        os.path.realpath(str(Path.home())),
        os.path.realpath(str(Path.cwd())),
        os.path.realpath(tempfile.gettempdir()),
    }

    extra_roots = os.environ.get("AGENT_BOM_SAFE_SCAN_ROOTS", "")
    for root in extra_roots.split(os.pathsep):
        root = root.strip()
        if root:
            allowed_roots.add(os.path.realpath(root))

    if not any(os.path.commonpath([root, candidate]) == root for root in allowed_roots):
        raise ValueError(f"Directory escapes safe scan roots: {candidate}")

    return Path(candidate)


def _human_size(size_bytes: int | float) -> str:
    """Convert bytes to human-readable size string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} B"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def scan_model_files(
    directory: str | Path,
) -> tuple[list[dict], list[str]]:
    """Scan a directory for ML model binary files.

    Returns (model_files, warnings) where each model_file is a dict with:
    - path, filename, extension, format, ecosystem
    - size_bytes, size_human
    - security_flags (list of dicts with severity, type, description)

    Warnings are generated for security-relevant findings (e.g., pickle files).
    """
    try:
        directory = _safe_resolve_directory(directory)
    except ValueError as exc:
        logger.warning("Model scan refused: %s", exc)
        return [], [f"Model scan: {exc}"]
    if not directory.is_dir():
        return [], [f"Model scan: {directory} is not a directory"]

    results: list[dict] = []
    warnings: list[str] = []

    for ext, info in _MODEL_EXTENSIONS.items():
        for file_path in sorted(directory.rglob(f"*{ext}")):
            # Skip hidden directories and common non-model locations
            if any(part.startswith(".") for part in file_path.parts):
                continue

            try:
                stat = file_path.stat()
            except OSError:
                continue

            size_bytes = stat.st_size

            # For .bin files, apply size heuristic to filter non-model binaries
            min_size_mb = info.get("min_size_mb", 0)
            if min_size_mb and size_bytes < min_size_mb * 1024 * 1024:
                continue

            security_flags = []
            if ext in _SECURITY_FLAGS:
                flag = _SECURITY_FLAGS[ext].copy()
                security_flags.append(flag)
                warnings.append(f"Model file {file_path.name}: {flag['severity']} — {flag['type']}. {flag['description']}")

            results.append(
                {
                    "path": str(file_path),
                    "filename": file_path.name,
                    "extension": ext,
                    "format": info["format"],
                    "ecosystem": info["ecosystem"],
                    "size_bytes": size_bytes,
                    "size_human": _human_size(size_bytes),
                    "security_flags": security_flags,
                }
            )

    return results, warnings


def scan_model_manifests(
    directory: str | Path,
) -> tuple[list[dict], list[str]]:
    """Scan a directory for model bundle manifests and lineage metadata."""
    try:
        directory = _safe_resolve_directory(directory)
    except ValueError as exc:
        logger.warning("Model manifest scan refused: %s", exc)
        return [], [f"Model manifest scan: {exc}"]
    if not directory.is_dir():
        return [], [f"Model manifest scan: {directory} is not a directory"]

    manifests: list[dict] = []
    warnings: list[str] = []

    for file_path in sorted(directory.rglob("*.json")):
        if any(part.startswith(".") for part in file_path.parts):
            continue

        name = file_path.name
        if name not in _MODEL_INDEX_FILENAMES and name not in _MODEL_MANIFEST_FILENAMES:
            continue

        payload = _load_json_file(file_path)
        if payload is None:
            continue

        manifest_type = "config"
        repo_id = _extract_repo_reference(payload.get("_name_or_path")) or _extract_repo_reference(payload.get("name_or_path"))
        base_model_id = None
        shard_count = 0
        security_flags: list[dict] = []

        if name in _MODEL_INDEX_FILENAMES:
            manifest_type = "weight_index"
            weight_map = payload.get("weight_map", {})
            if isinstance(weight_map, dict):
                shard_count = len({str(v) for v in weight_map.values() if isinstance(v, str)})
            if not shard_count:
                security_flags.append(
                    {
                        "severity": "MEDIUM",
                        "type": "EMPTY_WEIGHT_INDEX",
                        "description": "Weight index manifest has no shard mapping; bundle integrity cannot be confirmed.",
                    }
                )
        elif name == "adapter_config.json":
            manifest_type = "adapter"
            base_model_id = _extract_repo_reference(payload.get("base_model_name_or_path"))
            if not base_model_id:
                security_flags.append(
                    {
                        "severity": "MEDIUM",
                        "type": "MISSING_BASE_MODEL",
                        "description": "Adapter manifest does not declare a base model lineage reference.",
                    }
                )
        elif name == "tokenizer_config.json":
            manifest_type = "tokenizer"

        model_type = payload.get("model_type") if isinstance(payload.get("model_type"), str) else None
        architectures = payload.get("architectures") if isinstance(payload.get("architectures"), list) else []
        metadata = payload.get("metadata")
        total_size = metadata.get("total_size") if isinstance(metadata, dict) and isinstance(metadata.get("total_size"), int) else None

        manifest = {
            "path": str(file_path),
            "filename": file_path.name,
            "manifest_type": manifest_type,
            "repo_id": repo_id,
            "base_model_id": base_model_id,
            "model_type": model_type,
            "architectures": architectures,
            "shard_count": shard_count,
            "total_size_bytes": total_size,
            "security_flags": security_flags,
        }
        manifests.append(manifest)

        for flag in security_flags:
            warnings.append(f"Model manifest {file_path.name}: {flag['severity']} — {flag['type']}. {flag['description']}")

    return manifests, warnings


# ── Model weight provenance ─────────────────────────────────────


def verify_model_hash(
    file_path: str | Path,
    expected_sha256: str | None = None,
) -> dict:
    """Compute SHA-256 of a model file and optionally verify against expected hash.

    Returns dict with: sha256, match (bool|None), size_bytes, security_flags.
    """
    file_path = Path(file_path)
    result: dict = {
        "path": str(file_path),
        "sha256": None,
        "match": None,
        "size_bytes": 0,
        "security_flags": [],
    }

    if not file_path.is_file():
        result["security_flags"].append(
            {
                "severity": "HIGH",
                "type": "FILE_NOT_FOUND",
                "description": f"Model file not found: {file_path}",
            }
        )
        return result

    h = hashlib.sha256()
    size = 0
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
                size += len(chunk)
    except OSError as exc:
        result["security_flags"].append(
            {
                "severity": "MEDIUM",
                "type": "HASH_ERROR",
                "description": f"Could not read file for hashing: {exc}",
            }
        )
        return result

    result["sha256"] = h.hexdigest()
    result["size_bytes"] = size

    if expected_sha256 is not None:
        result["match"] = result["sha256"] == expected_sha256.lower()
        if not result["match"]:
            result["security_flags"].append(
                {
                    "severity": "CRITICAL",
                    "type": "HASH_MISMATCH",
                    "description": (
                        f"SHA-256 mismatch — expected {expected_sha256[:16]}..., got {result['sha256'][:16]}... File may be tampered."
                    ),
                }
            )

    return result


def check_sigstore_signature(file_path: str | Path) -> dict:
    """Check for adjacent Sigstore signature or bundle files.

    Looks for .sig, .sigstore, .bundle adjacent to the model file.
    Returns dict with: signed (bool), signature_path, security_flags.
    """
    file_path = Path(file_path)
    result: dict = {
        "path": str(file_path),
        "signed": False,
        "signature_path": None,
        "security_flags": [],
    }

    if not file_path.is_file():
        return result

    # Check for common Sigstore/cosign signature file patterns
    sig_candidates = [
        file_path.with_suffix(file_path.suffix + ".sig"),
        file_path.with_suffix(file_path.suffix + ".sigstore"),
        file_path.with_suffix(file_path.suffix + ".bundle"),
        file_path.parent / (file_path.name + ".sig"),
        file_path.parent / (file_path.name + ".sigstore"),
        file_path.parent / (file_path.name + ".bundle"),
    ]

    for candidate in sig_candidates:
        if candidate.is_file():
            result["signed"] = True
            result["signature_path"] = str(candidate)
            break

    if not result["signed"]:
        result["security_flags"].append(
            {
                "severity": "MEDIUM",
                "type": "UNSIGNED",
                "description": (
                    "No Sigstore signature found. Model provenance cannot be verified. Consider signing with cosign or sigstore."
                ),
            }
        )

    return result


def check_huggingface_provenance(
    model_name: str,
    timeout: float = 10.0,
) -> dict:
    """Query HuggingFace API for model provenance metadata.

    model_name should be in 'org/model' format (e.g., 'meta-llama/Llama-3.1-8B').
    Returns dict with: author, license, has_model_card, sha256_available, gated, security_flags.
    """
    result: dict = {
        "model": model_name,
        "author": None,
        "license": None,
        "has_model_card": False,
        "sha256_available": False,
        "gated": False,
        "downloads": None,
        "tags": [],
        "security_flags": [],
    }

    url = f"https://huggingface.co/api/models/{model_name}"
    try:
        from agent_bom.http_client import sync_get

        resp = sync_get(url, timeout=timeout, headers={"User-Agent": "agent-bom"})
        if resp is None:
            raise ConnectionError("HuggingFace API unreachable after retries")
        if resp.status_code == 404:
            result["security_flags"].append(
                {
                    "severity": "HIGH",
                    "type": "NO_PROVENANCE",
                    "description": f"Model '{model_name}' not found on HuggingFace. Cannot verify provenance.",
                }
            )
            return result
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        result["security_flags"].append(
            {
                "severity": "MEDIUM",
                "type": "PROVENANCE_CHECK_FAILED",
                "description": f"Could not reach HuggingFace API: {exc}",
            }
        )
        return result

    result["author"] = data.get("author")
    result["license"] = data.get("cardData", {}).get("license") if data.get("cardData") else data.get("license")
    result["has_model_card"] = data.get("cardData") is not None or data.get("hasModelCard", False)
    result["gated"] = data.get("gated", False)
    result["downloads"] = data.get("downloads")
    result["tags"] = data.get("tags", [])

    # Check if siblings include sha256-bearing files
    siblings = data.get("siblings", [])
    result["sha256_available"] = any(s.get("lfs", {}).get("sha256") for s in siblings if isinstance(s, dict))

    # Flag if no model card or author info
    if not result["has_model_card"]:
        result["security_flags"].append(
            {
                "severity": "LOW",
                "type": "NO_MODEL_CARD",
                "description": "Model has no model card. Documentation of training data, biases, and limitations is missing.",
            }
        )
    if not result["author"]:
        result["security_flags"].append(
            {
                "severity": "MEDIUM",
                "type": "NO_AUTHOR",
                "description": "Model has no identified author. Provenance cannot be attributed.",
            }
        )

    return result


def summarize_model_supply_chain(
    model_files: list[dict],
    model_provenance: list[dict] | None = None,
    model_hash_verification: dict | None = None,
    model_manifests: list[dict] | None = None,
) -> dict:
    """Build a stable summary of model/weight supply-chain coverage.

    This consolidates local model artifact scanning, HuggingFace provenance
    checks, and optional hash verification into one operator-facing contract
    that can be surfaced consistently in CLI, JSON, and docs.
    """
    provenance = model_provenance or []
    hash_verification = model_hash_verification or {}
    manifests = model_manifests or []

    files_with_flags = 0
    signed_files = 0
    unsigned_files = 0
    unsafe_files = 0
    total_size_bytes = 0
    ecosystems: set[str] = set()
    formats: set[str] = set()

    for model_file in model_files:
        total_size_bytes += int(model_file.get("size_bytes", 0) or 0)
        if model_file.get("security_flags"):
            files_with_flags += 1
        if model_file.get("signed") is True:
            signed_files += 1
        else:
            unsigned_files += 1
        if str(model_file.get("extension", "")).lower() in _UNSAFE_MODEL_EXTENSIONS:
            unsafe_files += 1
        ecosystem = model_file.get("ecosystem")
        if ecosystem:
            ecosystems.add(str(ecosystem))
        fmt = model_file.get("format")
        if fmt:
            formats.add(str(fmt))

    provenance_with_flags = sum(1 for item in provenance if item.get("security_flags"))
    provenance_with_digest = sum(1 for item in provenance if item.get("has_digest") is True or item.get("sha256_available") is True)
    gated_models = sum(1 for item in provenance if item.get("is_gated") is True or item.get("gated") is True)
    sources = sorted({str(item.get("source", "huggingface")) for item in provenance})
    manifest_types = sorted({str(item.get("manifest_type")) for item in manifests if item.get("manifest_type")})

    return {
        "model_files": len(model_files),
        "total_size_bytes": total_size_bytes,
        "signed_files": signed_files,
        "unsigned_files": unsigned_files,
        "unsafe_format_files": unsafe_files,
        "files_with_security_flags": files_with_flags,
        "formats": sorted(formats),
        "ecosystems": sorted(ecosystems),
        "provenance_checks": len(provenance),
        "provenance_with_digest": provenance_with_digest,
        "gated_models": gated_models,
        "provenance_with_security_flags": provenance_with_flags,
        "provenance_sources": sources,
        "manifest_files": len(manifests),
        "manifest_types": manifest_types,
        "manifests_with_repo_id": sum(1 for item in manifests if item.get("repo_id")),
        "adapter_lineage_refs": sum(1 for item in manifests if item.get("base_model_id")),
        "sharded_bundles": sum(1 for item in manifests if int(item.get("shard_count", 0) or 0) > 0),
        "manifests_with_security_flags": sum(1 for item in manifests if item.get("security_flags")),
        "hash_verification": {
            "scanned": int(hash_verification.get("scanned", 0) or 0),
            "verified": int(hash_verification.get("verified", 0) or 0),
            "tampered": int(hash_verification.get("tampered", 0) or 0),
            "unverified": int(hash_verification.get("unverified", 0) or 0),
            "offline": int(hash_verification.get("offline", 0) or 0),
            "has_tampering": bool(hash_verification.get("has_tampering", False)),
        },
    }
