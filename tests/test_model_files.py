"""Tests for model binary file and manifest detection."""

import json
from pathlib import Path

from agent_bom.model_files import _human_size, scan_model_files, scan_model_manifests


def test_scan_empty_directory(tmp_path: Path):
    """Empty directory returns empty results."""
    results, warnings = scan_model_files(tmp_path)
    assert results == []
    assert warnings == []


def test_scan_safetensors(tmp_path: Path):
    """Detect .safetensors files."""
    (tmp_path / "model.safetensors").write_bytes(b"\x00" * 100)
    results, warnings = scan_model_files(tmp_path)
    assert len(results) == 1
    assert results[0]["format"] == "SafeTensors"
    assert results[0]["ecosystem"] == "HuggingFace"
    assert results[0]["security_flags"] == []
    assert warnings == []


def test_scan_gguf(tmp_path: Path):
    """Detect .gguf files."""
    (tmp_path / "llama.gguf").write_bytes(b"\x00" * 100)
    results, _ = scan_model_files(tmp_path)
    assert len(results) == 1
    assert results[0]["format"] == "GGML/GGUF"
    assert results[0]["ecosystem"] == "llama.cpp/Ollama"


def test_scan_pickle_security_flag(tmp_path: Path):
    """Pickle files should get HIGH security flag."""
    (tmp_path / "model.pkl").write_bytes(b"\x00" * 100)
    results, warnings = scan_model_files(tmp_path)
    assert len(results) == 1
    assert len(results[0]["security_flags"]) == 1
    assert results[0]["security_flags"][0]["severity"] == "HIGH"
    assert results[0]["security_flags"][0]["type"] == "PICKLE_DESERIALIZATION"
    assert any("PICKLE" in w for w in warnings)


def test_scan_joblib_security_flag(tmp_path: Path):
    """Joblib files should get MEDIUM security flag."""
    (tmp_path / "model.joblib").write_bytes(b"\x00" * 100)
    results, warnings = scan_model_files(tmp_path)
    assert len(results) == 1
    assert results[0]["security_flags"][0]["severity"] == "MEDIUM"


def test_scan_bin_size_filter(tmp_path: Path):
    """Small .bin files should be filtered out (< 10MB)."""
    (tmp_path / "small.bin").write_bytes(b"\x00" * 100)
    results, _ = scan_model_files(tmp_path)
    assert len(results) == 0  # Too small


def test_scan_multiple_formats(tmp_path: Path):
    """Multiple model formats in same directory."""
    (tmp_path / "model.onnx").write_bytes(b"\x00" * 100)
    (tmp_path / "model.pt").write_bytes(b"\x00" * 100)
    (tmp_path / "model.h5").write_bytes(b"\x00" * 100)
    results, _ = scan_model_files(tmp_path)
    assert len(results) == 3
    formats = {r["format"] for r in results}
    assert "ONNX" in formats
    assert "PyTorch" in formats
    assert "HDF5/Keras" in formats


def test_scan_hidden_dirs_excluded(tmp_path: Path):
    """Files in hidden directories should be skipped."""
    hidden = tmp_path / ".cache"
    hidden.mkdir()
    (hidden / "model.safetensors").write_bytes(b"\x00" * 100)
    results, _ = scan_model_files(tmp_path)
    assert len(results) == 0


def test_human_size_formatting():
    """Test human-readable size formatting."""
    assert _human_size(0) == "0 B"
    assert _human_size(500) == "500 B"
    assert _human_size(1024) == "1.0 KB"
    assert _human_size(1024 * 1024) == "1.0 MB"
    assert _human_size(1024 * 1024 * 1024) == "1.0 GB"


def test_scan_model_files_rejects_outside_safe_roots():
    """Unsafe scan roots should be rejected before traversal."""
    results, warnings = scan_model_files("/etc")
    assert results == []
    assert warnings
    assert "escapes safe scan roots" in warnings[0]


def test_scan_model_weight_index_manifest(tmp_path: Path):
    """Sharded weight indexes should surface manifest lineage metadata."""
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps(
            {
                "metadata": {"total_size": 1234},
                "weight_map": {
                    "layer1": "model-00001-of-00002.safetensors",
                    "layer2": "model-00002-of-00002.safetensors",
                },
            }
        )
    )
    manifests, warnings = scan_model_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "weight_index"
    assert manifests[0]["shard_count"] == 2
    assert manifests[0]["total_size_bytes"] == 1234
    assert warnings == []


def test_scan_adapter_manifest_with_base_model(tmp_path: Path):
    """Adapter manifests should surface base-model lineage references."""
    (tmp_path / "adapter_config.json").write_text(json.dumps({"base_model_name_or_path": "meta-llama/Llama-3.1-8B"}))
    manifests, warnings = scan_model_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "adapter"
    assert manifests[0]["base_model_id"] == "meta-llama/Llama-3.1-8B"
    assert warnings == []


def test_scan_adapter_manifest_without_base_model_flags(tmp_path: Path):
    """Adapter manifests without lineage should be flagged."""
    (tmp_path / "adapter_config.json").write_text(json.dumps({"r": 8}))
    manifests, warnings = scan_model_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "adapter"
    assert manifests[0]["security_flags"][0]["type"] == "MISSING_BASE_MODEL"
    assert any("MISSING_BASE_MODEL" in warning for warning in warnings)


def test_scan_model_manifests_rejects_outside_safe_roots():
    """Manifest scans should refuse roots outside the safe set."""
    manifests, warnings = scan_model_manifests("/etc")
    assert manifests == []
    assert warnings
    assert "escapes safe scan roots" in warnings[0]


def test_scan_config_manifest_with_repo_id(tmp_path: Path):
    """Model config should surface repo references and model type."""
    (tmp_path / "config.json").write_text(
        json.dumps({"_name_or_path": "Qwen/Qwen2.5-7B-Instruct", "model_type": "qwen2", "architectures": ["Qwen2ForCausalLM"]})
    )
    manifests, _ = scan_model_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0]["repo_id"] == "Qwen/Qwen2.5-7B-Instruct"
    assert manifests[0]["model_type"] == "qwen2"
    assert manifests[0]["architectures"] == ["Qwen2ForCausalLM"]


def test_scan_config_manifest_flags_explicit_floating_revision(tmp_path: Path):
    """Explicit branch-style model revisions should be policy evidence."""
    (tmp_path / "config.json").write_text(json.dumps({"_name_or_path": "Qwen/Qwen2.5-7B-Instruct", "revision": "main"}))
    manifests, warnings = scan_model_manifests(tmp_path)

    assert len(manifests) == 1
    assert manifests[0]["revision"] == "main"
    assert manifests[0]["security_flags"][0]["type"] == "FLOATING_MODEL_REFERENCE"
    assert any("FLOATING_MODEL_REFERENCE" in warning for warning in warnings)
