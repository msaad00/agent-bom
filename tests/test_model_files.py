"""Tests for model binary file detection."""

from pathlib import Path

from agent_bom.model_files import _human_size, scan_model_files


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
