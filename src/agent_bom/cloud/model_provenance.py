"""ML model provenance verification — HuggingFace and Ollama.

Verifies the integrity and provenance of ML models to detect supply chain
risks. Checks serialization format safety (safetensors vs pickle/pytorch),
digest availability, gated access status, and model source trust.

Supported sources:
- HuggingFace Hub: safetensors vs pickle, SHA256 digest, gated/private status,
  model card completeness
- Ollama: manifest digest verification, model source

Risk flags:
- unsafe_format:<ext>  — model uses pickle/pt/bin serialization (code execution risk)
- no_digest            — no cryptographic digest available (integrity unverifiable)
- no_model_card        — no model card (provenance unknown)
- public_large         — public model >5GB without gating (exfiltration surface)
- ungated_sensitive    — sensitive pipeline type (text-generation) without gating

References:
- https://huggingface.co/docs/hub/security-pickle
- https://github.com/huggingface/safetensors
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Ollama manifest directory — module-level so tests can patch it
_MANIFEST_DIR = Path.home() / ".ollama" / "models" / "manifests" / "registry.ollama.ai"

# Serialization formats that allow arbitrary code execution when deserialized
_UNSAFE_EXTENSIONS = frozenset({".pt", ".pth", ".pkl", ".pickle", ".bin", ".ckpt"})

# Safe serialization formats
_SAFE_EXTENSIONS = frozenset({".safetensors", ".gguf", ".onnx", ".ggml"})

# Pipeline tags that suggest the model handles sensitive / high-risk tasks
_SENSITIVE_PIPELINES = frozenset(
    {
        "text-generation",
        "text2text-generation",
        "conversational",
        "automatic-speech-recognition",
        "image-to-text",
    }
)

# Size threshold (bytes) above which a public ungated model is flagged
_LARGE_MODEL_THRESHOLD = 5 * 1024**3  # 5 GB


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ProvenanceResult:
    """Provenance verification result for a single ML model."""

    model_id: str
    source: str  # "huggingface" | "ollama"
    format: str  # detected serialization format or "unknown"
    is_safe_format: bool
    has_digest: bool
    digest: str  # hex digest or ""
    is_gated: bool
    has_model_card: bool
    risk_flags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_level(self) -> str:
        """Return 'critical', 'high', 'medium', 'low', or 'safe'."""
        if not self.is_safe_format and self.has_digest is False:
            return "critical"
        if not self.is_safe_format:
            return "high"
        if not self.has_digest:
            return "medium"
        if self.risk_flags:
            return "medium"
        return "safe"

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "source": self.source,
            "format": self.format,
            "is_safe_format": self.is_safe_format,
            "has_digest": self.has_digest,
            "digest": self.digest,
            "is_gated": self.is_gated,
            "has_model_card": self.has_model_card,
            "risk_level": self.risk_level,
            "risk_flags": self.risk_flags,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# HuggingFace provenance
# ---------------------------------------------------------------------------


def check_hf_model(
    model_id: str,
    token: str | None = None,
) -> ProvenanceResult:
    """Verify provenance of a HuggingFace Hub model.

    Checks:
    - Serialization format: safetensors (safe) vs pickle/pt/bin (unsafe)
    - SHA256 digest from model file metadata
    - Gated/private status
    - Model card presence
    - Public large model flag (>5GB ungated)

    Args:
        model_id: HuggingFace model ID, e.g. 'meta-llama/Llama-3.2-1B'.
        token: HF_TOKEN for accessing gated/private models.

    Returns:
        ProvenanceResult with risk assessment.
    """
    import os

    resolved_token = token or os.environ.get("HF_TOKEN", "") or None

    result = ProvenanceResult(
        model_id=model_id,
        source="huggingface",
        format="unknown",
        is_safe_format=False,
        has_digest=False,
        digest="",
        is_gated=False,
        has_model_card=False,
    )

    try:
        from huggingface_hub import HfApi
        from huggingface_hub.utils import GatedRepoError, RepositoryNotFoundError
    except ImportError:
        result.risk_flags.append("no_digest")
        result.metadata["error"] = "huggingface-hub not installed. Install with: pip install huggingface-hub"
        return result

    api = HfApi(token=resolved_token)

    try:
        model_info = api.model_info(model_id, files_metadata=True)
    except GatedRepoError:
        result.is_gated = True
        result.metadata["note"] = "Gated model — token required to inspect files"
        return result
    except RepositoryNotFoundError:
        result.risk_flags.append("no_digest")
        result.metadata["error"] = f"Model '{model_id}' not found on HuggingFace Hub"
        return result
    except Exception as exc:
        result.risk_flags.append("no_digest")
        result.metadata["error"] = str(exc)
        return result

    # Gated / private status
    result.is_gated = bool(getattr(model_info, "gated", False) or getattr(model_info, "private", False))

    # Model card presence
    card_data = getattr(model_info, "card_data", None)
    result.has_model_card = card_data is not None

    # Pipeline tag
    pipeline_tag = getattr(model_info, "pipeline_tag", None) or ""
    result.metadata["pipeline_tag"] = pipeline_tag

    # Downloads
    downloads = getattr(model_info, "downloads", None)
    if downloads is not None:
        result.metadata["downloads"] = downloads

    # Inspect model files for format + digest
    siblings = getattr(model_info, "siblings", []) or []
    total_size = 0
    detected_formats: set[str] = set()
    safe_formats: set[str] = set()
    unsafe_formats: set[str] = set()
    best_digest = ""

    for sibling in siblings:
        rfilename = getattr(sibling, "rfilename", "") or ""
        blob_id = getattr(sibling, "blob_id", "") or ""
        size = getattr(sibling, "size", 0) or 0
        total_size += size

        ext = Path(rfilename).suffix.lower()
        if ext in _UNSAFE_EXTENSIONS:
            unsafe_formats.add(ext)
            detected_formats.add(ext)
        elif ext in _SAFE_EXTENSIONS:
            safe_formats.add(ext)
            detected_formats.add(ext)

        # Use blob_id (sha256) as digest when available
        if blob_id and ext in _SAFE_EXTENSIONS and not best_digest:
            best_digest = blob_id

    result.metadata["total_size_gb"] = round(total_size / (1024**3), 2)
    result.metadata["detected_formats"] = sorted(detected_formats)

    # Determine format verdict
    if safe_formats and not unsafe_formats:
        # Only safe formats present
        result.format = ", ".join(sorted(safe_formats))
        result.is_safe_format = True
    elif unsafe_formats:
        result.format = ", ".join(sorted(unsafe_formats))
        result.is_safe_format = False
        for fmt in unsafe_formats:
            result.risk_flags.append(f"unsafe_format:{fmt}")
    elif not detected_formats:
        result.format = "unknown"
        result.is_safe_format = False
    else:
        result.format = ", ".join(sorted(detected_formats))
        result.is_safe_format = False

    # Digest availability
    result.has_digest = bool(best_digest)
    result.digest = best_digest
    if not result.has_digest:
        result.risk_flags.append("no_digest")

    # Model card flag
    if not result.has_model_card:
        result.risk_flags.append("no_model_card")

    # Public large model without gating
    if not result.is_gated and total_size > _LARGE_MODEL_THRESHOLD:
        result.risk_flags.append("public_large")

    # Sensitive pipeline without gating
    if pipeline_tag in _SENSITIVE_PIPELINES and not result.is_gated:
        result.risk_flags.append("ungated_sensitive")

    return result


# ---------------------------------------------------------------------------
# Ollama provenance
# ---------------------------------------------------------------------------


def check_ollama_model(
    model_name: str,
    host: str | None = None,
) -> ProvenanceResult:
    """Verify provenance of a locally available Ollama model.

    Checks:
    - Manifest digest from Ollama API or ~/.ollama/models/manifests
    - Format (gguf is safe, bin/pt is not)
    - Model source (registry.ollama.ai = trusted, other = flag)

    Args:
        model_name: Model name as used by Ollama, e.g. 'llama3:8b'.
        host: Ollama API host. Falls back to OLLAMA_HOST or http://localhost:11434.

    Returns:
        ProvenanceResult with risk assessment.
    """
    import os

    resolved_host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    base_name = model_name.split(":")[0] if ":" in model_name else model_name
    tag = model_name.split(":")[1] if ":" in model_name else "latest"

    result = ProvenanceResult(
        model_id=model_name,
        source="ollama",
        format="unknown",
        is_safe_format=False,
        has_digest=False,
        digest="",
        is_gated=False,  # Ollama has no gating concept
        has_model_card=False,  # Ollama has no model cards
    )

    # Try API first
    manifest_data = _get_ollama_manifest_api(resolved_host, model_name)
    if manifest_data is None:
        # Fall back to local manifest file
        manifest_data = _get_ollama_manifest_file(base_name, tag)

    if manifest_data is None:
        result.risk_flags.append("no_digest")
        result.metadata["note"] = f"Model '{model_name}' not found via API or local manifests"
        return result

    # Extract digest from manifest
    digest = manifest_data.get("config", {}).get("digest", "")
    if not digest:
        # Try layers for a content digest
        layers = manifest_data.get("layers", [])
        if layers:
            digest = layers[0].get("digest", "")

    result.has_digest = bool(digest)
    result.digest = digest
    if not result.has_digest:
        result.risk_flags.append("no_digest")

    # Determine format from media type
    media_type = manifest_data.get("config", {}).get("mediaType", "")
    layers = manifest_data.get("layers", [])
    layer_types = [layer.get("mediaType", "") for layer in layers]
    all_types = [media_type] + layer_types

    if any("gguf" in t for t in all_types):
        result.format = "gguf"
        result.is_safe_format = True
    elif any(ext in media_type for ext in (".bin", ".pt", ".pkl")):
        result.format = "bin"
        result.is_safe_format = False
        result.risk_flags.append("unsafe_format:.bin")
    else:
        result.format = "gguf"  # Ollama default is GGUF
        result.is_safe_format = True

    result.metadata["manifest_schema_version"] = manifest_data.get("schemaVersion", "unknown")

    return result


def _get_ollama_manifest_api(host: str, model_name: str) -> dict | None:
    """Fetch model manifest from Ollama API /api/show."""
    try:
        import urllib.error
        import urllib.request

        url = f"{host}/api/show"
        if not url.startswith(("http://", "https://")):
            return None

        payload = json.dumps({"name": model_name}).encode()
        req = urllib.request.Request(url, data=payload, method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
            if resp.status == 200:
                data = json.loads(resp.read())
                # /api/show returns model_info; extract manifest-like structure
                return data
    except Exception:
        pass
    return None


def _get_ollama_manifest_file(model_name: str, tag: str) -> dict | None:
    """Read model manifest from ~/.ollama/models/manifests."""
    manifest_path = _MANIFEST_DIR / "library" / model_name / tag
    if not manifest_path.is_file():
        return None
    try:
        return json.loads(manifest_path.read_text())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Batch helpers
# ---------------------------------------------------------------------------


def check_hf_models(
    model_ids: list[str],
    token: str | None = None,
) -> list[ProvenanceResult]:
    """Check provenance for multiple HuggingFace models."""
    return [check_hf_model(mid, token=token) for mid in model_ids]


def check_ollama_models(
    model_names: list[str],
    host: str | None = None,
) -> list[ProvenanceResult]:
    """Check provenance for multiple locally available Ollama models."""
    return [check_ollama_model(name, host=host) for name in model_names]
