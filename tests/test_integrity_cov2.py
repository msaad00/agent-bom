"""Tests for agent_bom.integrity to improve coverage."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from agent_bom.integrity import (
    check_npm_provenance,
    check_pypi_provenance,
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
        assert result is None


# ---------------------------------------------------------------------------
# check_pypi_provenance
# ---------------------------------------------------------------------------


def test_check_pypi_provenance_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "attestations": [
            {
                "provenance": {"predicate_type": "https://slsa.dev/provenance/v1"},
                "verification_status": "verified",
            }
        ]
    }

    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(check_pypi_provenance("requests", "2.31.0", AsyncMock()))
        assert result is not None


def test_check_pypi_provenance_no_attestations():
    with patch("agent_bom.integrity.request_with_retry", new_callable=AsyncMock, return_value=None):
        result = asyncio.run(check_pypi_provenance("pkg", "1.0.0", AsyncMock()))
        assert result is None
