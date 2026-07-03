"""Tests for agent_bom.integrity to improve coverage."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from agent_bom.integrity import (
    _DEFAULT_COSIGN_CERTIFICATE_IDENTITY_REGEXP,
    _DEFAULT_COSIGN_CERTIFICATE_OIDC_ISSUER,
    _try_cosign_verify,
    check_npm_provenance,
    check_pypi_provenance,
    verify_instruction_file,
    verify_npm_integrity,
    verify_package_integrity,
    verify_pypi_integrity,
)
from agent_bom.models import Package

# ---------------------------------------------------------------------------
# verify_npm_integrity
# ---------------------------------------------------------------------------


def test_verify_npm_integrity_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "dist": {
            "integrity": "sha512-abc123",
            "shasum": "deadbeef",
            "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        }
    }

    mock_client = AsyncMock()

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(verify_npm_integrity("lodash", "4.17.21", mock_client))
        assert result is not None
        assert result["verified"] is True
        assert result["sha512_sri"] == "sha512-abc123"


def test_verify_npm_integrity_not_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(verify_npm_integrity("nonexistent", "1.0.0", AsyncMock()))
        assert result is None


def test_verify_npm_integrity_no_response():
    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=None):
        result = asyncio.run(verify_npm_integrity("pkg", "1.0.0", AsyncMock()))
        assert result is None


# ---------------------------------------------------------------------------
# verify_pypi_integrity
# ---------------------------------------------------------------------------


def test_verify_pypi_integrity_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "urls": [
            {
                "digests": {"sha256": "abc123def456"},
                "filename": "requests-2.31.0-py3-none-any.whl",
                "requires_python": ">=3.7",
            }
        ]
    }

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(verify_pypi_integrity("requests", "2.31.0", AsyncMock()))
        assert result is not None
        assert result["verified"] is True
        assert result["sha256"] == "abc123def456"


def test_verify_pypi_integrity_no_digest():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"urls": [{"digests": {}, "filename": "test.whl"}]}

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(verify_pypi_integrity("pkg", "1.0.0", AsyncMock()))
        assert result is None


def test_verify_pypi_integrity_not_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(verify_pypi_integrity("nonexistent", "1.0.0", AsyncMock()))
        assert result is None


# ---------------------------------------------------------------------------
# verify_package_integrity
# ---------------------------------------------------------------------------


def test_verify_package_integrity_npm():
    pkg = Package(name="lodash", version="4.17.21", ecosystem="npm")
    mock_result = {"verified": True, "sha512_sri": "sha512-abc"}

    with patch("agent_bom.integrity.verify_npm_integrity", new_callable=AsyncMock, return_value=mock_result):
        result = asyncio.run(verify_package_integrity(pkg, AsyncMock()))
        assert result is not None
        assert result["verified"] is True


def test_verify_package_integrity_pypi():
    pkg = Package(name="requests", version="2.31.0", ecosystem="pypi")
    mock_result = {"verified": True, "sha256": "abc"}

    with patch("agent_bom.integrity.verify_pypi_integrity", new_callable=AsyncMock, return_value=mock_result):
        result = asyncio.run(verify_package_integrity(pkg, AsyncMock()))
        assert result is not None


def test_verify_package_integrity_unsupported():
    pkg = Package(name="pkg", version="1.0.0", ecosystem="cargo")
    result = asyncio.run(verify_package_integrity(pkg, AsyncMock()))
    assert result is None


def test_verify_package_integrity_unknown_version():
    pkg = Package(name="lodash", version="unknown", ecosystem="npm")
    result = asyncio.run(verify_package_integrity(pkg, AsyncMock()))
    assert result is None


def test_verify_package_integrity_latest():
    pkg = Package(name="lodash", version="latest", ecosystem="npm")
    result = asyncio.run(verify_package_integrity(pkg, AsyncMock()))
    assert result is None


# ---------------------------------------------------------------------------
# check_npm_provenance
# ---------------------------------------------------------------------------


def test_check_npm_provenance_with_slsa():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"attestations": [{"predicateType": "https://slsa.dev/provenance/v1"}]}

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(check_npm_provenance("lodash", "4.17.21", AsyncMock()))
        assert result is not None
        assert result["has_provenance"] is True


def test_check_npm_provenance_non_slsa():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"attestations": [{"predicateType": "https://example.com/custom"}]}

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(check_npm_provenance("pkg", "1.0.0", AsyncMock()))
        assert result is not None
        assert result["has_provenance"] is False


def test_check_npm_provenance_none():
    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=None):
        result = asyncio.run(check_npm_provenance("pkg", "1.0.0", AsyncMock()))
        assert result == {"has_provenance": False, "status": "unavailable"}


# ---------------------------------------------------------------------------
# check_pypi_provenance
# ---------------------------------------------------------------------------


def test_check_pypi_provenance_success():
    metadata_resp = MagicMock()
    metadata_resp.status_code = 200
    metadata_resp.json.return_value = {
        "urls": [
            {
                "filename": "requests-2.31.0-py3-none-any.whl",
            }
        ]
    }
    provenance_resp = MagicMock()
    provenance_resp.status_code = 200
    provenance_resp.json.return_value = {"attestation_bundles": [{"attestations": [{"envelope": {}, "verification_material": {}}]}]}

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, side_effect=[metadata_resp, provenance_resp]) as req:
        result = asyncio.run(check_pypi_provenance("requests", "2.31.0", AsyncMock()))
        assert result is not None
        assert result["has_provenance"] is True
        assert result["attestation_count"] == 1
        assert result["files"] == ["requests-2.31.0-py3-none-any.whl"]
        assert req.await_args_list[1].kwargs["headers"]["Accept"] == "application/vnd.pypi.integrity.v1+json"


def test_check_pypi_provenance_no_attestations():
    metadata_resp = MagicMock()
    metadata_resp.status_code = 200
    metadata_resp.json.return_value = {"urls": [{"filename": "pkg-1.0.0.tar.gz"}]}
    provenance_resp = MagicMock()
    provenance_resp.status_code = 404

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, side_effect=[metadata_resp, provenance_resp]):
        result = asyncio.run(check_pypi_provenance("pkg", "1.0.0", AsyncMock()))
        assert result == {
            "has_provenance": False,
            "status": "not_published",
            "attestation_count": 0,
            "missing_files": ["pkg-1.0.0.tar.gz"],
        }


def test_check_pypi_provenance_partial_release_is_not_verified():
    metadata_resp = MagicMock()
    metadata_resp.status_code = 200
    metadata_resp.json.return_value = {"urls": [{"filename": "pkg-1.0.0-py3-none-any.whl"}, {"filename": "pkg-1.0.0.tar.gz"}]}
    wheel_resp = MagicMock()
    wheel_resp.status_code = 200
    wheel_resp.json.return_value = {"attestation_bundles": [{"attestations": [{}]}]}
    sdist_resp = MagicMock()
    sdist_resp.status_code = 404

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, side_effect=[metadata_resp, wheel_resp, sdist_resp]):
        result = asyncio.run(check_pypi_provenance("pkg", "1.0.0", AsyncMock()))

    assert result["has_provenance"] is False
    assert result["status"] == "partial"
    assert result["attestation_count"] == 1
    assert result["missing_files"] == ["pkg-1.0.0.tar.gz"]


# ---------------------------------------------------------------------------
# Cosign defaults + no-cosign fallback
# ---------------------------------------------------------------------------


def test_cosign_defaults_pin_release_workflow_identity():
    assert _DEFAULT_COSIGN_CERTIFICATE_IDENTITY_REGEXP == (
        r"https://github\.com/msaad00/agent-bom/\.github/workflows/release\.yml@.*"
    )
    assert _DEFAULT_COSIGN_CERTIFICATE_OIDC_ISSUER == "https://token.actions.githubusercontent.com"


def test_instruction_file_digest_match_without_cosign_is_not_verified(tmp_path):
    from agent_bom.integrity import _compute_sha256

    f = tmp_path / "SKILL.md"
    f.write_text("# Skill file content", encoding="utf-8")
    sha = _compute_sha256(f)
    bundle_data = {
        "dsseEnvelope": {
            "payload": __import__("base64").b64encode(
                json.dumps({"subject": [{"digest": {"sha256": sha}}]}).encode("utf-8")
            ).decode("ascii")
        }
    }
    (tmp_path / "SKILL.md.sigstore").write_text(json.dumps(bundle_data), encoding="utf-8")

    with patch("agent_bom.integrity._try_cosign_verify", return_value=False):
        result = verify_instruction_file(f)

    assert result.bundle_valid is True
    assert result.verified is False
    assert result.reason == "cosign_verification_failed"


def test_try_cosign_verify_uses_release_identity_by_default(tmp_path, monkeypatch):
    f = tmp_path / "SKILL.md"
    f.write_text("# Signed skill", encoding="utf-8")
    bundle = tmp_path / "SKILL.md.sigstore"
    bundle.write_text("{}", encoding="utf-8")
    calls: list[list[str]] = []

    class _Proc:
        returncode = 0

    def _run(cmd, **kwargs):
        calls.append(cmd)
        return _Proc()

    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/cosign" if name == "cosign" else None)
    monkeypatch.setattr("subprocess.run", _run)
    monkeypatch.delenv("AGENT_BOM_COSIGN_CERTIFICATE_IDENTITY_REGEXP", raising=False)
    monkeypatch.delenv("AGENT_BOM_COSIGN_CERTIFICATE_OIDC_ISSUER", raising=False)

    assert _try_cosign_verify(f, bundle) is True
    cmd = calls[0]
    assert cmd[cmd.index("--certificate-identity-regexp") + 1] == _DEFAULT_COSIGN_CERTIFICATE_IDENTITY_REGEXP
    assert cmd[cmd.index("--certificate-oidc-issuer") + 1] == _DEFAULT_COSIGN_CERTIFICATE_OIDC_ISSUER
