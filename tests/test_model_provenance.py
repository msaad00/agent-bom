"""Tests for model weight provenance — hash, signature, HuggingFace metadata."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.model_files import (
    check_huggingface_provenance,
    check_sigstore_signature,
    verify_model_hash,
)


# ── verify_model_hash ───────────────────────────────────────────


class TestVerifyModelHash:
    def test_computes_sha256(self, tmp_path: Path):
        model = tmp_path / "model.safetensors"
        model.write_bytes(b"fake model weights")
        result = verify_model_hash(model)
        assert result["sha256"] is not None
        assert len(result["sha256"]) == 64  # SHA-256 hex length
        assert result["size_bytes"] == len(b"fake model weights")
        assert result["match"] is None  # no expected hash provided
        assert result["security_flags"] == []

    def test_hash_match(self, tmp_path: Path):
        model = tmp_path / "model.gguf"
        content = b"consistent weights"
        model.write_bytes(content)
        # Compute expected
        import hashlib
        expected = hashlib.sha256(content).hexdigest()
        result = verify_model_hash(model, expected_sha256=expected)
        assert result["match"] is True
        assert result["security_flags"] == []

    def test_hash_mismatch(self, tmp_path: Path):
        model = tmp_path / "model.pt"
        model.write_bytes(b"actual weights")
        result = verify_model_hash(model, expected_sha256="0" * 64)
        assert result["match"] is False
        assert len(result["security_flags"]) == 1
        assert result["security_flags"][0]["type"] == "HASH_MISMATCH"
        assert result["security_flags"][0]["severity"] == "CRITICAL"

    def test_file_not_found(self, tmp_path: Path):
        result = verify_model_hash(tmp_path / "nonexistent.bin")
        assert result["sha256"] is None
        assert len(result["security_flags"]) == 1
        assert result["security_flags"][0]["type"] == "FILE_NOT_FOUND"

    def test_expected_sha_case_insensitive(self, tmp_path: Path):
        model = tmp_path / "model.onnx"
        content = b"onnx data"
        model.write_bytes(content)
        import hashlib
        expected = hashlib.sha256(content).hexdigest().upper()
        result = verify_model_hash(model, expected_sha256=expected)
        assert result["match"] is True


# ── check_sigstore_signature ─────────────────────────────────────


class TestCheckSigstoreSignature:
    def test_signed_with_sig(self, tmp_path: Path):
        model = tmp_path / "model.safetensors"
        model.write_bytes(b"weights")
        sig = tmp_path / "model.safetensors.sig"
        sig.write_bytes(b"signature")
        result = check_sigstore_signature(model)
        assert result["signed"] is True
        assert result["signature_path"] == str(sig)
        assert result["security_flags"] == []

    def test_signed_with_sigstore_bundle(self, tmp_path: Path):
        model = tmp_path / "model.gguf"
        model.write_bytes(b"weights")
        bundle = tmp_path / "model.gguf.bundle"
        bundle.write_bytes(b"bundle")
        result = check_sigstore_signature(model)
        assert result["signed"] is True
        assert result["signature_path"] == str(bundle)

    def test_signed_with_sigstore_ext(self, tmp_path: Path):
        model = tmp_path / "model.pt"
        model.write_bytes(b"weights")
        sigstore = tmp_path / "model.pt.sigstore"
        sigstore.write_bytes(b"sigstore bundle")
        result = check_sigstore_signature(model)
        assert result["signed"] is True

    def test_unsigned_model(self, tmp_path: Path):
        model = tmp_path / "model.onnx"
        model.write_bytes(b"weights")
        result = check_sigstore_signature(model)
        assert result["signed"] is False
        assert result["signature_path"] is None
        assert len(result["security_flags"]) == 1
        assert result["security_flags"][0]["type"] == "UNSIGNED"
        assert result["security_flags"][0]["severity"] == "MEDIUM"

    def test_nonexistent_file(self, tmp_path: Path):
        result = check_sigstore_signature(tmp_path / "nope.bin")
        assert result["signed"] is False
        assert result["security_flags"] == []  # silently skip, no model found


# ── check_huggingface_provenance ─────────────────────────────────


class TestCheckHuggingFaceProvenance:
    def _mock_response(self, data: dict):
        """Create a mock urllib response."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(data).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    @patch("agent_bom.model_files.urllib.request.urlopen")
    def test_success_full_metadata(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_response({
            "author": "meta-llama",
            "cardData": {"license": "llama3.1"},
            "gated": True,
            "downloads": 500000,
            "tags": ["text-generation", "llama"],
            "siblings": [
                {"rfilename": "model.safetensors", "lfs": {"sha256": "abc123"}},
            ],
        })
        result = check_huggingface_provenance("meta-llama/Llama-3.1-8B")
        assert result["author"] == "meta-llama"
        assert result["license"] == "llama3.1"
        assert result["has_model_card"] is True
        assert result["sha256_available"] is True
        assert result["gated"] is True
        assert result["downloads"] == 500000
        assert result["security_flags"] == []

    @patch("agent_bom.model_files.urllib.request.urlopen")
    def test_no_model_card_flags(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_response({
            "author": "someone",
            "gated": False,
            "downloads": 10,
            "tags": [],
            "siblings": [],
        })
        result = check_huggingface_provenance("someone/model")
        assert result["has_model_card"] is False
        flag_types = [f["type"] for f in result["security_flags"]]
        assert "NO_MODEL_CARD" in flag_types

    @patch("agent_bom.model_files.urllib.request.urlopen")
    def test_no_author_flags(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_response({
            "cardData": {"license": "mit"},
            "gated": False,
            "downloads": 5,
            "tags": [],
            "siblings": [],
        })
        result = check_huggingface_provenance("unknown/model")
        assert result["author"] is None
        flag_types = [f["type"] for f in result["security_flags"]]
        assert "NO_AUTHOR" in flag_types

    @patch("agent_bom.model_files.urllib.request.urlopen")
    def test_model_not_found_404(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://huggingface.co/api/models/nope/nope",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )
        result = check_huggingface_provenance("nope/nope")
        assert result["author"] is None
        assert len(result["security_flags"]) == 1
        assert result["security_flags"][0]["type"] == "NO_PROVENANCE"

    @patch("agent_bom.model_files.urllib.request.urlopen")
    def test_api_error_500(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://huggingface.co/api/models/err/err",
            code=500,
            msg="Internal Server Error",
            hdrs=None,
            fp=None,
        )
        result = check_huggingface_provenance("err/err")
        assert len(result["security_flags"]) == 1
        assert result["security_flags"][0]["type"] == "PROVENANCE_CHECK_FAILED"

    @patch("agent_bom.model_files.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        result = check_huggingface_provenance("some/model")
        assert len(result["security_flags"]) == 1
        assert result["security_flags"][0]["type"] == "PROVENANCE_CHECK_FAILED"

    @patch("agent_bom.model_files.urllib.request.urlopen")
    def test_sha256_not_available(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_response({
            "author": "test",
            "cardData": {"license": "mit"},
            "gated": False,
            "downloads": 100,
            "tags": [],
            "siblings": [
                {"rfilename": "model.bin"},  # no lfs sha256
            ],
        })
        result = check_huggingface_provenance("test/model")
        assert result["sha256_available"] is False


# ── Integration: scan_model_files with provenance ────────────────


class TestScanWithProvenance:
    def test_model_files_with_hash_and_sig(self, tmp_path: Path):
        """verify_model_hash + check_sigstore_signature integrate with scan results."""
        model = tmp_path / "test.safetensors"
        model.write_bytes(b"safetensor data")
        sig = tmp_path / "test.safetensors.sig"
        sig.write_bytes(b"sig")

        from agent_bom.model_files import scan_model_files

        results, _ = scan_model_files(tmp_path)
        assert len(results) == 1

        # Add provenance data (mimics CLI flow)
        for mf in results:
            hash_result = verify_model_hash(mf["path"])
            mf["sha256"] = hash_result["sha256"]
            sig_result = check_sigstore_signature(mf["path"])
            mf["signed"] = sig_result["signed"]

        assert results[0]["sha256"] is not None
        assert results[0]["signed"] is True

    def test_unsigned_model_gets_flag(self, tmp_path: Path):
        model = tmp_path / "test.onnx"
        model.write_bytes(b"onnx data")

        from agent_bom.model_files import scan_model_files

        results, _ = scan_model_files(tmp_path)
        for mf in results:
            sig_result = check_sigstore_signature(mf["path"])
            mf["security_flags"].extend(sig_result["security_flags"])

        assert any(f["type"] == "UNSIGNED" for f in results[0]["security_flags"])


# ── CLI flag existence ───────────────────────────────────────────


class TestCLIFlags:
    def test_model_provenance_in_help(self):
        from click.testing import CliRunner
        from agent_bom.cli import scan
        runner = CliRunner()
        result = runner.invoke(scan, ["--help"])
        assert "--model-provenance" in result.output

    def test_hf_model_in_help(self):
        from click.testing import CliRunner
        from agent_bom.cli import scan
        runner = CliRunner()
        result = runner.invoke(scan, ["--help"])
        assert "--hf-model" in result.output
