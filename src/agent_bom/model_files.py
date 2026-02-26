"""Model binary file detection — scan for ML model artifacts.

Detects common model file formats and flags security risks
(e.g., pickle-based serialization allows arbitrary code execution).
"""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.error
import urllib.request
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
        "description": (
            "Joblib uses pickle internally and may execute arbitrary code. "
            "Prefer safetensors for model weights."
        ),
    },
}


def _human_size(size_bytes: int) -> str:
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
    directory = Path(directory)
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
                warnings.append(
                    f"Model file {file_path.name}: {flag['severity']} — {flag['type']}. "
                    f"{flag['description']}"
                )

            results.append({
                "path": str(file_path),
                "filename": file_path.name,
                "extension": ext,
                "format": info["format"],
                "ecosystem": info["ecosystem"],
                "size_bytes": size_bytes,
                "size_human": _human_size(size_bytes),
                "security_flags": security_flags,
            })

    return results, warnings


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
        result["security_flags"].append({
            "severity": "HIGH",
            "type": "FILE_NOT_FOUND",
            "description": f"Model file not found: {file_path}",
        })
        return result

    h = hashlib.sha256()
    size = 0
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
                size += len(chunk)
    except OSError as exc:
        result["security_flags"].append({
            "severity": "MEDIUM",
            "type": "HASH_ERROR",
            "description": f"Could not read file for hashing: {exc}",
        })
        return result

    result["sha256"] = h.hexdigest()
    result["size_bytes"] = size

    if expected_sha256 is not None:
        result["match"] = result["sha256"] == expected_sha256.lower()
        if not result["match"]:
            result["security_flags"].append({
                "severity": "CRITICAL",
                "type": "HASH_MISMATCH",
                "description": (
                    f"SHA-256 mismatch — expected {expected_sha256[:16]}..., "
                    f"got {result['sha256'][:16]}... File may be tampered."
                ),
            })

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
        result["security_flags"].append({
            "severity": "MEDIUM",
            "type": "UNSIGNED",
            "description": (
                "No Sigstore signature found. Model provenance cannot be verified. "
                "Consider signing with cosign or sigstore."
            ),
        })

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
        req = urllib.request.Request(url, headers={"User-Agent": "agent-bom"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 — URL prefix is hardcoded https://huggingface.co
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            result["security_flags"].append({
                "severity": "HIGH",
                "type": "NO_PROVENANCE",
                "description": f"Model '{model_name}' not found on HuggingFace. Cannot verify provenance.",
            })
        else:
            result["security_flags"].append({
                "severity": "MEDIUM",
                "type": "PROVENANCE_CHECK_FAILED",
                "description": f"HuggingFace API error {exc.code}: {exc.reason}",
            })
        return result
    except (urllib.error.URLError, OSError, ValueError) as exc:
        result["security_flags"].append({
            "severity": "MEDIUM",
            "type": "PROVENANCE_CHECK_FAILED",
            "description": f"Could not reach HuggingFace API: {exc}",
        })
        return result

    result["author"] = data.get("author")
    result["license"] = data.get("cardData", {}).get("license") if data.get("cardData") else data.get("license")
    result["has_model_card"] = data.get("cardData") is not None or data.get("hasModelCard", False)
    result["gated"] = data.get("gated", False)
    result["downloads"] = data.get("downloads")
    result["tags"] = data.get("tags", [])

    # Check if siblings include sha256-bearing files
    siblings = data.get("siblings", [])
    result["sha256_available"] = any(
        s.get("lfs", {}).get("sha256") for s in siblings if isinstance(s, dict)
    )

    # Flag if no model card or author info
    if not result["has_model_card"]:
        result["security_flags"].append({
            "severity": "LOW",
            "type": "NO_MODEL_CARD",
            "description": "Model has no model card. Documentation of training data, biases, and limitations is missing.",
        })
    if not result["author"]:
        result["security_flags"].append({
            "severity": "MEDIUM",
            "type": "NO_AUTHOR",
            "description": "Model has no identified author. Provenance cannot be attributed.",
        })

    return result
