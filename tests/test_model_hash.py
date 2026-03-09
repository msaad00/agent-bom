"""Tests for model_hash — HuggingFace model weight hash verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent_bom.model_hash import (
    MODEL_WEIGHT_EXTENSIONS,
    ModelHashReport,
    _fetch_hub_file_hashes,
    _infer_repo_id,
    sha256_file,
    verify_model_hashes,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _write_file(path: Path, content: bytes = b"fake model weights") -> str:
    """Write a file and return its SHA-256 hex digest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def _hub_response(files: dict[str, str]) -> dict:
    """Build a fake Hub API response with the given filename → sha256 mapping."""
    return {"siblings": [{"rfilename": name, "lfs": {"sha256": sha}} for name, sha in files.items()]}


# ─── sha256_file ─────────────────────────────────────────────────────────────


def test_sha256_file_correct(tmp_path):
    content = b"hello world"
    p = tmp_path / "model.safetensors"
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(p) == expected


def test_sha256_file_missing(tmp_path):
    assert sha256_file(tmp_path / "nonexistent.bin") is None


def test_sha256_file_empty(tmp_path):
    p = tmp_path / "empty.safetensors"
    p.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert sha256_file(p) == expected


# ─── _infer_repo_id ───────────────────────────────────────────────────────────


def test_infer_repo_id_from_config_json(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"_name_or_path": "mistralai/Mistral-7B-v0.1"}))
    assert _infer_repo_id(tmp_path) == "mistralai/Mistral-7B-v0.1"


def test_infer_repo_id_from_tokenizer_config(tmp_path):
    cfg = tmp_path / "tokenizer_config.json"
    cfg.write_text(json.dumps({"name_or_path": "meta-llama/Llama-2-7b-hf"}))
    assert _infer_repo_id(tmp_path) == "meta-llama/Llama-2-7b-hf"


def test_infer_repo_id_absolute_path_ignored(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"_name_or_path": "/local/path/model"}))
    # absolute path → not a repo_id → fall through
    result = _infer_repo_id(tmp_path)
    assert result is None or "/" not in (result or "").lstrip("/")


def test_infer_repo_id_no_config(tmp_path):
    # No config.json, no .git — returns None
    assert _infer_repo_id(tmp_path) is None


def test_infer_repo_id_git_config(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text('[remote "origin"]\n\turl = https://huggingface.co/bigscience/bloom\n')
    assert _infer_repo_id(tmp_path) == "bigscience/bloom"


# ─── verify_model_hashes — matching hash ─────────────────────────────────────


def test_verify_matching_hash(tmp_path):
    content = b"model weights v1"
    sha = _write_file(tmp_path / "model.safetensors", content)

    hub = _hub_response({"model.safetensors": sha})
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = hub
    mock_resp.raise_for_status = MagicMock()

    with patch("agent_bom.model_hash._fetch_hub_file_hashes", return_value={"model.safetensors": sha}):
        report = verify_model_hashes(tmp_path, repo_id="org/model")

    assert report.scanned == 1
    assert report.verified == 1
    assert report.tampered == 0
    assert not report.has_tampering
    assert report.results[0].is_verified


def test_verify_tampered_hash(tmp_path):
    content = b"tampered model weights"
    actual_sha = _write_file(tmp_path / "model.bin", content)
    wrong_sha = "a" * 64  # expected differs

    with patch("agent_bom.model_hash._fetch_hub_file_hashes", return_value={"model.bin": wrong_sha}):
        report = verify_model_hashes(tmp_path, repo_id="org/model")

    assert report.tampered == 1
    assert report.has_tampering
    assert report.results[0].is_tampered
    assert report.results[0].expected_sha256 == wrong_sha
    assert report.results[0].actual_sha256 == actual_sha


# ─── verify_model_hashes — offline graceful ──────────────────────────────────


def test_verify_offline_no_crash(tmp_path):
    _write_file(tmp_path / "model.onnx", b"weights")

    with patch("agent_bom.model_hash._fetch_hub_file_hashes", return_value=None):
        report = verify_model_hashes(tmp_path, repo_id="org/model")

    assert report.scanned == 1
    assert report.offline == 1
    assert report.verified == 0
    assert report.tampered == 0
    assert report.results[0].status == "offline"


# ─── verify_model_hashes — file not in Hub metadata ──────────────────────────


def test_verify_file_not_in_hub(tmp_path):
    _write_file(tmp_path / "adapter.safetensors", b"lora weights")

    with patch("agent_bom.model_hash._fetch_hub_file_hashes", return_value={}):
        report = verify_model_hashes(tmp_path, repo_id="org/model")

    assert report.unverified == 1
    assert report.results[0].status == "unverified"


# ─── verify_model_hashes — no weight files ───────────────────────────────────


def test_verify_no_weight_files(tmp_path):
    (tmp_path / "README.md").write_text("hello")
    (tmp_path / "config.json").write_text("{}")
    report = verify_model_hashes(tmp_path, repo_id="org/model")
    assert report.scanned == 0


def test_verify_nonexistent_root(tmp_path):
    report = verify_model_hashes(tmp_path / "doesnotexist")
    assert report.scanned == 0


# ─── verify_model_hashes — multiple files ────────────────────────────────────


def test_verify_multiple_files_mixed(tmp_path):
    sha1 = _write_file(tmp_path / "model-00001-of-00002.safetensors", b"shard1")
    _write_file(tmp_path / "model-00002-of-00002.safetensors", b"shard2 tampered")

    hub_hashes = {
        "model-00001-of-00002.safetensors": sha1,
        "model-00002-of-00002.safetensors": "b" * 64,  # wrong hash
    }
    with patch("agent_bom.model_hash._fetch_hub_file_hashes", return_value=hub_hashes):
        report = verify_model_hashes(tmp_path, repo_id="org/model")

    assert report.scanned == 2
    assert report.verified == 1
    assert report.tampered == 1


# ─── supported extensions ─────────────────────────────────────────────────────


def test_all_supported_extensions_scanned(tmp_path):
    for ext in MODEL_WEIGHT_EXTENSIONS:
        _write_file(tmp_path / f"model{ext}", b"weights")

    with patch("agent_bom.model_hash._fetch_hub_file_hashes", return_value=None):
        report = verify_model_hashes(tmp_path, repo_id="org/model")

    assert report.scanned == len(MODEL_WEIGHT_EXTENSIONS)


def test_non_weight_files_ignored(tmp_path):
    _write_file(tmp_path / "tokenizer.json", b"{}")
    _write_file(tmp_path / "vocab.txt", b"hello")
    _write_file(tmp_path / "model.safetensors", b"weights")

    with patch("agent_bom.model_hash._fetch_hub_file_hashes", return_value=None):
        report = verify_model_hashes(tmp_path, repo_id="org/model")

    assert report.scanned == 1  # only .safetensors


# ─── ModelHashReport ─────────────────────────────────────────────────────────


def test_report_summary_dict():
    report = ModelHashReport(scanned=3, verified=2, tampered=1)
    s = report.summary()
    assert s["scanned"] == 3
    assert s["verified"] == 2
    assert s["tampered"] == 1
    assert report.has_tampering


def test_report_no_tampering():
    report = ModelHashReport(scanned=1, verified=1)
    assert not report.has_tampering


# ─── _fetch_hub_file_hashes — 404 handling ────────────────────────────────────


def test_fetch_hub_404_returns_empty(tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("httpx.get", return_value=mock_resp):
        result = _fetch_hub_file_hashes("nonexistent/repo")

    assert result == {}


def test_fetch_hub_network_error_returns_none():
    import httpx

    with patch("httpx.get", side_effect=httpx.ConnectError("timeout")):
        result = _fetch_hub_file_hashes("org/model")

    assert result is None
