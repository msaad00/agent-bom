"""Tests for instruction file provenance verification (Sigstore bundles)."""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from agent_bom.integrity import (
    InstructionFileVerification,
    _compute_sha256,
    _find_sigstore_bundle,
    _parse_sigstore_bundle,
    discover_instruction_files,
    verify_instruction_file,
    verify_instruction_files_batch,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_temp_file(content: str, suffix: str = ".md") -> Path:
    """Write content to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return Path(path)


def _make_sigstore_bundle(sha256: str, signer: str = "", rekor_index: int = 42) -> dict:
    """Create a minimal Sigstore bundle dict with a DSSE envelope."""
    # Build in-toto statement with subject digest
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "instruction-file",
                "digest": {"sha256": sha256},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "builder": {"id": signer} if signer else {},
        },
    }
    payload_b64 = base64.b64encode(json.dumps(statement).encode()).decode()

    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "logIndex": str(rekor_index),
                    "logId": {"keyId": "test-log-id"},
                }
            ],
            "x509CertificateChain": {"certificates": [{"rawBytes": "dGVzdC1jZXJ0"}]},
        },
        "dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload_b64,
            "signatures": [{"sig": "dGVzdC1zaWc=", "keyid": ""}],
        },
    }


# ---------------------------------------------------------------------------
# SHA-256 computation
# ---------------------------------------------------------------------------


class TestComputeSHA256:
    def test_known_content(self):
        path = _write_temp_file("hello world\n")
        try:
            digest = _compute_sha256(path)
            assert len(digest) == 64
            assert all(c in "0123456789abcdef" for c in digest)
        finally:
            path.unlink()

    def test_deterministic(self):
        path = _write_temp_file("test content")
        try:
            d1 = _compute_sha256(path)
            d2 = _compute_sha256(path)
            assert d1 == d2
        finally:
            path.unlink()

    def test_different_content_different_hash(self):
        p1 = _write_temp_file("content A")
        p2 = _write_temp_file("content B")
        try:
            assert _compute_sha256(p1) != _compute_sha256(p2)
        finally:
            p1.unlink()
            p2.unlink()


# ---------------------------------------------------------------------------
# Bundle discovery
# ---------------------------------------------------------------------------


class TestFindSigstoreBundle:
    def test_sigstore_extension(self, tmp_path):
        target = tmp_path / "CLAUDE.md"
        target.write_text("# Instructions")
        bundle = tmp_path / "CLAUDE.md.sigstore"
        bundle.write_text("{}")
        assert _find_sigstore_bundle(target) == bundle

    def test_sigstore_json_extension(self, tmp_path):
        target = tmp_path / "SKILL.md"
        target.write_text("# Skill")
        bundle = tmp_path / "SKILL.md.sigstore.json"
        bundle.write_text("{}")
        assert _find_sigstore_bundle(target) == bundle

    def test_sig_extension(self, tmp_path):
        target = tmp_path / ".cursorrules"
        target.write_text("rules")
        bundle = tmp_path / ".cursorrules.sig"
        bundle.write_text("{}")
        assert _find_sigstore_bundle(target) == bundle

    def test_no_bundle(self, tmp_path):
        target = tmp_path / "CLAUDE.md"
        target.write_text("# Instructions")
        assert _find_sigstore_bundle(target) is None

    def test_priority_order(self, tmp_path):
        """`.sigstore` takes priority over `.sigstore.json` and `.sig`."""
        target = tmp_path / "CLAUDE.md"
        target.write_text("# Instructions")
        (tmp_path / "CLAUDE.md.sigstore").write_text("{}")
        (tmp_path / "CLAUDE.md.sigstore.json").write_text("{}")
        (tmp_path / "CLAUDE.md.sig").write_text("{}")
        assert _find_sigstore_bundle(target) == tmp_path / "CLAUDE.md.sigstore"


# ---------------------------------------------------------------------------
# Bundle parsing
# ---------------------------------------------------------------------------


class TestParseSigstoreBundle:
    def test_valid_bundle(self, tmp_path):
        sha = "a" * 64
        bundle_data = _make_sigstore_bundle(sha, signer="https://github.com/org/repo", rekor_index=99)
        bundle_path = tmp_path / "test.sigstore"
        bundle_path.write_text(json.dumps(bundle_data))

        parsed = _parse_sigstore_bundle(bundle_path)
        assert parsed["subject_digest"] == sha
        assert parsed["rekor_log_index"] == 99
        assert parsed["signer_identity"] == "https://github.com/org/repo"

    def test_empty_bundle(self, tmp_path):
        bundle_path = tmp_path / "empty.sigstore"
        bundle_path.write_text("{}")
        parsed = _parse_sigstore_bundle(bundle_path)
        assert parsed["subject_digest"] == ""
        assert parsed["rekor_log_index"] == -1

    def test_invalid_json(self, tmp_path):
        bundle_path = tmp_path / "bad.sigstore"
        bundle_path.write_text("not json")
        parsed = _parse_sigstore_bundle(bundle_path)
        assert parsed["subject_digest"] == ""

    def test_no_dsse_envelope(self, tmp_path):
        bundle_data = {
            "verificationMaterial": {
                "tlogEntries": [{"logIndex": "7"}],
            },
        }
        bundle_path = tmp_path / "nodsse.sigstore"
        bundle_path.write_text(json.dumps(bundle_data))
        parsed = _parse_sigstore_bundle(bundle_path)
        assert parsed["rekor_log_index"] == 7
        assert parsed["subject_digest"] == ""

    def test_public_key_hint(self, tmp_path):
        bundle_data = {
            "verificationMaterial": {
                "publicKey": {"hint": "test-signer@example.com"},
                "tlogEntries": [],
            },
        }
        bundle_path = tmp_path / "pk.sigstore"
        bundle_path.write_text(json.dumps(bundle_data))
        parsed = _parse_sigstore_bundle(bundle_path)
        assert parsed["signer_identity"] == "test-signer@example.com"


# ---------------------------------------------------------------------------
# Full verification
# ---------------------------------------------------------------------------


class TestVerifyInstructionFile:
    def test_file_not_found(self, tmp_path):
        result = verify_instruction_file(tmp_path / "missing.md")
        assert result.sha256 == ""
        assert result.reason == "file_not_found"
        assert result.verified is False

    def test_no_bundle(self, tmp_path):
        f = tmp_path / "CLAUDE.md"
        f.write_text("# My instructions")
        result = verify_instruction_file(f)
        assert result.sha256 != ""
        assert result.has_sigstore_bundle is False
        assert result.reason == "no_sigstore_bundle"
        assert result.verified is False

    def test_valid_bundle_digest_match(self, tmp_path):
        f = tmp_path / "SKILL.md"
        f.write_text("# Skill file content")
        sha = _compute_sha256(f)

        bundle_data = _make_sigstore_bundle(sha, signer="test-signer", rekor_index=123)
        (tmp_path / "SKILL.md.sigstore").write_text(json.dumps(bundle_data))

        with patch("agent_bom.integrity._try_cosign_verify", return_value=False):
            result = verify_instruction_file(f)

        assert result.has_sigstore_bundle is True
        assert result.bundle_valid is True
        assert result.verified is True
        assert result.reason == "digest_verified"
        assert result.signer_identity == "test-signer"
        assert result.rekor_log_index == 123

    def test_digest_mismatch(self, tmp_path):
        f = tmp_path / "CLAUDE.md"
        f.write_text("# Real content")

        wrong_sha = "b" * 64
        bundle_data = _make_sigstore_bundle(wrong_sha)
        (tmp_path / "CLAUDE.md.sigstore").write_text(json.dumps(bundle_data))

        result = verify_instruction_file(f)
        assert result.has_sigstore_bundle is True
        assert result.bundle_valid is False
        assert result.reason == "digest_mismatch"
        assert result.verified is False

    def test_cosign_verified(self, tmp_path):
        f = tmp_path / "SKILL.md"
        f.write_text("# Signed skill")
        sha = _compute_sha256(f)

        bundle_data = _make_sigstore_bundle(sha, signer="ci@github.com")
        (tmp_path / "SKILL.md.sigstore").write_text(json.dumps(bundle_data))

        with patch("agent_bom.integrity._try_cosign_verify", return_value=True):
            result = verify_instruction_file(f)

        assert result.verified is True
        assert result.reason == "cosign_verified"

    def test_bundle_no_subject_digest(self, tmp_path):
        f = tmp_path / "CLAUDE.md"
        f.write_text("# Instructions")

        # Bundle without DSSE envelope (no subject digest)
        bundle_data = {
            "verificationMaterial": {
                "tlogEntries": [{"logIndex": "5"}],
            },
        }
        (tmp_path / "CLAUDE.md.sigstore").write_text(json.dumps(bundle_data))

        result = verify_instruction_file(f)
        assert result.has_sigstore_bundle is True
        assert result.reason == "no_subject_digest_in_bundle"
        assert result.verified is False


# ---------------------------------------------------------------------------
# Batch verification
# ---------------------------------------------------------------------------


class TestBatchVerification:
    def test_batch_all_unsigned(self, tmp_path):
        f1 = tmp_path / "CLAUDE.md"
        f1.write_text("# A")
        f2 = tmp_path / "SKILL.md"
        f2.write_text("# B")

        results = verify_instruction_files_batch([f1, f2])
        assert len(results) == 2
        assert all(not r.verified for r in results)
        assert all(r.reason == "no_sigstore_bundle" for r in results)

    def test_batch_mixed(self, tmp_path):
        # One unsigned, one signed
        f1 = tmp_path / "CLAUDE.md"
        f1.write_text("# Unsigned")

        f2 = tmp_path / "SKILL.md"
        f2.write_text("# Signed")
        sha = _compute_sha256(f2)
        bundle = _make_sigstore_bundle(sha, signer="signer")
        (tmp_path / "SKILL.md.sigstore").write_text(json.dumps(bundle))

        with patch("agent_bom.integrity._try_cosign_verify", return_value=False):
            results = verify_instruction_files_batch([f1, f2])

        assert len(results) == 2
        assert not results[0].verified
        assert results[1].verified

    def test_empty_batch(self):
        assert verify_instruction_files_batch([]) == []


# ---------------------------------------------------------------------------
# Discover instruction files
# ---------------------------------------------------------------------------


class TestDiscoverInstructionFiles:
    def test_discovers_claude_md(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("# Claude")
        found = discover_instruction_files(tmp_path)
        assert any(p.name == "CLAUDE.md" for p in found)

    def test_discovers_cursorrules(self, tmp_path):
        (tmp_path / ".cursorrules").write_text("rules")
        found = discover_instruction_files(tmp_path)
        assert any(p.name == ".cursorrules" for p in found)

    def test_discovers_skill_md(self, tmp_path):
        (tmp_path / "SKILL.md").write_text("# Skill")
        found = discover_instruction_files(tmp_path)
        assert any(p.name == "SKILL.md" for p in found)

    def test_discovers_claude_subdir(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "CLAUDE.md").write_text("# Sub-claude")
        found = discover_instruction_files(tmp_path)
        assert any("CLAUDE.md" in str(p) and ".claude" in str(p) for p in found)

    def test_discovers_skills_subdir(self, tmp_path):
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "search.md").write_text("# Search skill")
        (skills_dir / "review.md").write_text("# Review skill")
        found = discover_instruction_files(tmp_path)
        assert len([p for p in found if "skills" in str(p)]) == 2

    def test_empty_directory(self, tmp_path):
        found = discover_instruction_files(tmp_path)
        assert found == []

    def test_all_types(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("a")
        (tmp_path / ".cursorrules").write_text("b")
        (tmp_path / "SKILL.md").write_text("c")
        found = discover_instruction_files(tmp_path)
        # On case-insensitive FS (macOS), SKILL.md also matches skill.md check
        assert len(found) >= 3


# ---------------------------------------------------------------------------
# InstructionFileVerification dataclass
# ---------------------------------------------------------------------------


class TestDataclass:
    def test_default_values(self):
        v = InstructionFileVerification(file_path="/tmp/test", sha256="abc")
        assert v.has_sigstore_bundle is False
        assert v.bundle_valid is False
        assert v.signer_identity == ""
        assert v.rekor_log_index == -1
        assert v.verified is False
        assert v.reason == ""

    def test_all_fields(self):
        v = InstructionFileVerification(
            file_path="/tmp/test",
            sha256="abc123",
            has_sigstore_bundle=True,
            bundle_valid=True,
            signer_identity="user@example.com",
            rekor_log_index=42,
            certificate_expiry="2026-12-31",
            verified=True,
            reason="cosign_verified",
        )
        assert v.verified is True
        assert v.rekor_log_index == 42
        assert v.signer_identity == "user@example.com"
