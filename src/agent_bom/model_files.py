"""Model binary file detection — scan for ML model artifacts.

Detects common model file formats and flags security risks
(e.g., pickle-based serialization allows arbitrary code execution).
"""

from __future__ import annotations

import logging
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
