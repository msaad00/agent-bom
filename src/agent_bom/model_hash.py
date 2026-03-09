"""HuggingFace model weight hash verification for supply chain integrity.

Verifies SHA-256 hashes of local model weight files against official
HuggingFace Hub metadata.  Detects tampered or substituted model files.

Usage (CLI):
    agent-bom scan --verify-model-hashes --project-dir /path/to/project

Usage (API):
    from agent_bom.model_hash import verify_model_hashes
    results = verify_model_hashes("/path/to/models")
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# File extensions for model weight files we can verify
MODEL_WEIGHT_EXTENSIONS = {".safetensors", ".bin", ".onnx", ".gguf", ".pt", ".pth"}

# HuggingFace Hub API base
_HF_API = "https://huggingface.co/api"

# Max file size we'll hash locally (4 GB — skip larger shards)
_MAX_HASH_BYTES = 4 * 1024 * 1024 * 1024


@dataclass
class ModelHashResult:
    """Result of verifying one model weight file."""

    file_path: str
    repo_id: str
    filename: str
    expected_sha256: str | None  # None if Hub metadata unavailable
    actual_sha256: str | None  # None if file too large or unreadable
    status: str  # "ok" | "tampered" | "unverified" | "offline"
    error: str | None = None

    @property
    def is_tampered(self) -> bool:
        return self.status == "tampered"

    @property
    def is_verified(self) -> bool:
        return self.status == "ok"


@dataclass
class ModelHashReport:
    """Aggregate report for a scan of model weight files."""

    scanned: int = 0
    verified: int = 0
    tampered: int = 0
    unverified: int = 0
    offline: int = 0
    results: list[ModelHashResult] = field(default_factory=list)

    @property
    def has_tampering(self) -> bool:
        return self.tampered > 0

    def summary(self) -> dict:
        return {
            "scanned": self.scanned,
            "verified": self.verified,
            "tampered": self.tampered,
            "unverified": self.unverified,
            "offline": self.offline,
        }


# ─── Hash computation ─────────────────────────────────────────────────────────


def sha256_file(path: Path) -> str | None:
    """Compute SHA-256 of a file.  Returns hex digest or None on error."""
    try:
        if path.stat().st_size > _MAX_HASH_BYTES:
            logger.debug("Skipping hash for oversized file: %s", path)
            return None
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        logger.debug("Cannot read %s for hashing: %s", path, e)
        return None


# ─── HuggingFace Hub metadata ─────────────────────────────────────────────────


def _fetch_hub_file_hashes(repo_id: str, token: str | None = None) -> dict[str, str] | None:
    """Fetch filename → sha256 mapping from HuggingFace Hub API.

    Returns None on network failure (caller treats as offline/unverified).
    """
    try:
        import httpx
    except ImportError:
        logger.debug("httpx not available; model hash verification requires it")
        return None

    url = f"{_HF_API}/models/{repo_id}"
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = httpx.get(url, headers=headers, timeout=15.0, follow_redirects=True)
        if resp.status_code == 404:
            logger.debug("HuggingFace repo not found: %s", repo_id)
            return {}
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        logger.debug("Hub API fetch failed for %s: %s", repo_id, e)
        return None  # None signals offline/unreachable

    # siblings list: [{rfilename: "model.safetensors", ...}, ...]
    siblings = data.get("siblings", [])
    result: dict[str, str] = {}
    for entry in siblings:
        filename = entry.get("rfilename", "")
        # Hub provides lfs sha256 in entry.lfs.sha256 or entry.sha256
        sha = None
        lfs = entry.get("lfs")
        if isinstance(lfs, dict):
            sha = lfs.get("sha256")
        if not sha:
            sha = entry.get("sha256")
        if filename and sha and isinstance(sha, str):
            result[filename] = sha.lower()
    return result


def _infer_repo_id(model_dir: Path) -> str | None:
    """Try to infer the HuggingFace repo_id from a local model directory.

    Checks:
    1. config.json with ``_name_or_path`` field
    2. tokenizer_config.json with ``name_or_path``
    3. .git/config remote origin URL
    4. Falls back to directory name (may be "org/model" format)
    """
    # config.json
    for cfg_name in ("config.json", "tokenizer_config.json"):
        cfg = model_dir / cfg_name
        if cfg.exists():
            try:
                import json

                data = json.loads(cfg.read_text())
                for key in ("_name_or_path", "name_or_path"):
                    val = data.get(key, "")
                    if val and "/" in val and not val.startswith("/"):
                        return val
            except Exception:  # noqa: BLE001
                pass

    # .git/config
    git_cfg = model_dir / ".git" / "config"
    if git_cfg.exists():
        try:
            text = git_cfg.read_text()
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("url = ") and "huggingface.co" in line:
                    # url = https://huggingface.co/org/repo
                    url = line.split("url = ", 1)[1].strip()
                    parts = url.rstrip("/").split("/")
                    if len(parts) >= 2:
                        return f"{parts[-2]}/{parts[-1]}"
        except Exception:  # noqa: BLE001
            pass

    # Directory name as last resort
    name = model_dir.name
    if "/" in name:
        return name
    return None


# ─── Public API ───────────────────────────────────────────────────────────────


def verify_model_hashes(
    scan_root: str | Path,
    token: str | None = None,
    repo_id: str | None = None,
) -> ModelHashReport:
    """Verify SHA-256 hashes of model weight files under scan_root.

    Walks scan_root for weight files (.safetensors, .bin, .onnx, .gguf,
    .pt, .pth), fetches expected hashes from HuggingFace Hub, and compares.

    Args:
        scan_root: Directory to scan for model weight files.
        token: HuggingFace API token (optional, for private repos).
        repo_id: Override Hub repo ID (e.g. "mistralai/Mistral-7B-v0.1").
                 If None, inferred from config.json / directory structure.

    Returns:
        ModelHashReport with per-file results.
    """
    root = Path(scan_root)
    report = ModelHashReport()

    if not root.exists():
        logger.warning("scan_root does not exist: %s", root)
        return report

    # Collect weight files
    weight_files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in MODEL_WEIGHT_EXTENSIONS]

    if not weight_files:
        return report

    # Group files by their parent directory (each dir = one model)
    dirs: dict[Path, list[Path]] = {}
    for wf in weight_files:
        dirs.setdefault(wf.parent, []).append(wf)

    for model_dir, files in dirs.items():
        # Resolve repo_id for this model directory
        resolved_repo = repo_id or _infer_repo_id(model_dir)

        # Fetch Hub hashes (may be None on network failure, {} on 404)
        hub_hashes: dict[str, str] | None = None
        if resolved_repo:
            hub_hashes = _fetch_hub_file_hashes(resolved_repo, token=token)

        for wf in files:
            report.scanned += 1
            rel_name = wf.name
            actual_sha = sha256_file(wf)

            if actual_sha is None:
                result = ModelHashResult(
                    file_path=str(wf),
                    repo_id=resolved_repo or "unknown",
                    filename=rel_name,
                    expected_sha256=None,
                    actual_sha256=None,
                    status="unverified",
                    error="File too large or unreadable",
                )
                report.unverified += 1
                report.results.append(result)
                continue

            if hub_hashes is None:
                # Network failure — can't verify
                result = ModelHashResult(
                    file_path=str(wf),
                    repo_id=resolved_repo or "unknown",
                    filename=rel_name,
                    expected_sha256=None,
                    actual_sha256=actual_sha,
                    status="offline",
                    error="HuggingFace Hub unreachable",
                )
                report.offline += 1
                report.results.append(result)
                continue

            expected_sha = hub_hashes.get(rel_name)

            if expected_sha is None:
                # File not in Hub metadata (private shard, local fine-tune, etc.)
                result = ModelHashResult(
                    file_path=str(wf),
                    repo_id=resolved_repo or "unknown",
                    filename=rel_name,
                    expected_sha256=None,
                    actual_sha256=actual_sha,
                    status="unverified",
                    error="File not found in Hub metadata",
                )
                report.unverified += 1
            elif actual_sha.lower() == expected_sha.lower():
                result = ModelHashResult(
                    file_path=str(wf),
                    repo_id=resolved_repo or "unknown",
                    filename=rel_name,
                    expected_sha256=expected_sha,
                    actual_sha256=actual_sha,
                    status="ok",
                )
                report.verified += 1
            else:
                result = ModelHashResult(
                    file_path=str(wf),
                    repo_id=resolved_repo or "unknown",
                    filename=rel_name,
                    expected_sha256=expected_sha,
                    actual_sha256=actual_sha,
                    status="tampered",
                    error=f"Hash mismatch: expected {expected_sha[:16]}… got {actual_sha[:16]}…",
                )
                report.tampered += 1
                logger.warning(
                    "SUPPLY_CHAIN_TAMPERING: %s — expected %s, got %s",
                    wf,
                    expected_sha[:16],
                    actual_sha[:16],
                )

            report.results.append(result)

    return report
