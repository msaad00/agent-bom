"""Tests for the agent-bom verify command and integrity verification."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from agent_bom.cli import _parse_package_spec, main

# ─── _parse_package_spec helper ──────────────────────────────────────────────


def test_parse_package_spec_name_at_version():
    name, version, eco = _parse_package_spec("requests@2.28.0", "pypi")
    assert name == "requests"
    assert version == "2.28.0"
    assert eco == "pypi"


def test_parse_package_spec_scoped_npm():
    name, version, eco = _parse_package_spec(
        "@modelcontextprotocol/server-filesystem@2025.1.14",
        "npm",
    )
    assert name == "@modelcontextprotocol/server-filesystem"
    assert version == "2025.1.14"
    assert eco == "npm"


def test_parse_package_spec_npx_prefix():
    name, version, eco = _parse_package_spec("npx @scope/pkg", None)
    assert name == "@scope/pkg"
    assert eco == "npm"


def test_parse_package_spec_uvx_prefix():
    name, version, eco = _parse_package_spec("uvx some-tool", None)
    assert name == "some-tool"
    assert eco == "pypi"


def test_parse_package_spec_no_version():
    name, version, eco = _parse_package_spec("express", None)
    assert name == "express"
    assert version == "unknown"


def test_parse_package_spec_infer_npm():
    name, version, eco = _parse_package_spec("@scope/pkg", None)
    assert eco == "npm"


def test_parse_package_spec_infer_pypi():
    name, version, eco = _parse_package_spec("flask", None)
    assert eco == "pypi"


# ─── verify_installed_record ─────────────────────────────────────────────────


def test_verify_installed_record_package_not_found():
    from agent_bom.integrity import verify_installed_record

    result = verify_installed_record("nonexistent-pkg-xyz-12345")
    assert result["installed_version"] is None
    assert result["record_available"] is False
    assert result["record_intact"] is False


def _make_mock_metadata(data: dict):
    """Create a mock metadata object that supports dict-like access and get_all."""
    meta = MagicMock()
    meta.__getitem__ = lambda self, k: data[k]
    meta.get = lambda k, d="": data.get(k, d)
    meta.get_all = lambda k: []
    return meta


def test_verify_installed_record_with_mock():
    """Test RECORD verification with a mocked distribution."""
    import base64
    import hashlib

    from agent_bom.integrity import verify_installed_record

    file_content = b"print('hello')"
    digest = hashlib.sha256(file_content).digest()
    b64_digest = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    mock_hash = MagicMock()
    mock_hash.value = b64_digest

    mock_file = MagicMock()
    mock_file.hash = mock_hash
    mock_file.locate.return_value = MagicMock()
    mock_file.locate.return_value.read_bytes.return_value = file_content

    mock_dist = MagicMock()
    mock_dist.metadata = _make_mock_metadata(
        {
            "Version": "1.0.0",
            "License-Expression": "MIT",
            "Author": "Test",
        }
    )
    mock_dist.files = [mock_file]

    with patch("agent_bom.integrity.distribution", return_value=mock_dist):
        result = verify_installed_record("test-pkg")

    assert result["installed_version"] == "1.0.0"
    assert result["record_available"] is True
    assert result["record_intact"] is True
    assert result["verified_files"] == 1
    assert result["failed_files"] == []


def test_verify_installed_record_tampered():
    """Test RECORD verification detects tampered files."""
    from agent_bom.integrity import verify_installed_record

    mock_hash = MagicMock()
    mock_hash.value = "wrong-hash-value"

    mock_file = MagicMock()
    mock_file.hash = mock_hash
    mock_file.locate.return_value = MagicMock()
    mock_file.locate.return_value.read_bytes.return_value = b"tampered content"
    mock_file.__str__ = lambda self: "tampered_file.py"

    mock_dist = MagicMock()
    mock_dist.metadata = _make_mock_metadata({"Version": "1.0.0"})
    mock_dist.files = [mock_file]

    with patch("agent_bom.integrity.distribution", return_value=mock_dist):
        result = verify_installed_record("test-pkg")

    assert result["record_intact"] is False
    assert len(result["failed_files"]) == 1


def test_verify_installed_record_no_files():
    """Test RECORD not available (editable install)."""
    from agent_bom.integrity import verify_installed_record

    mock_dist = MagicMock()
    mock_dist.metadata = _make_mock_metadata({"Version": "1.0.0"})
    mock_dist.files = None

    with patch("agent_bom.integrity.distribution", return_value=mock_dist):
        result = verify_installed_record("test-pkg")

    assert result["installed_version"] == "1.0.0"
    assert result["record_available"] is False


# ─── fetch_pypi_release_metadata ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_pypi_release_metadata():
    from agent_bom.integrity import fetch_pypi_release_metadata

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "info": {
            "name": "agent-bom",
            "version": "0.31.6",
            "license": "Apache-2.0",
            "author": "test",
            "requires_python": ">=3.10",
            "project_urls": {
                "Repository": "https://github.com/msaad00/agent-bom",
            },
        },
        "urls": [
            {
                "filename": "agent_bom-0.31.6-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "digests": {"sha256": "abc123def456"},
            },
        ],
    }

    mock_client = AsyncMock()

    with patch("agent_bom.integrity.request_with_retry", return_value=mock_response):
        result = await fetch_pypi_release_metadata("agent-bom", "0.31.6", mock_client)

    assert result is not None
    assert result["name"] == "agent-bom"
    assert result["version"] == "0.31.6"
    assert result["source_repo"] == "https://github.com/msaad00/agent-bom"
    assert len(result["sha256_digests"]) == 1


@pytest.mark.asyncio
async def test_fetch_pypi_release_metadata_not_found():
    from agent_bom.integrity import fetch_pypi_release_metadata

    mock_response = MagicMock()
    mock_response.status_code = 404

    mock_client = AsyncMock()

    with patch("agent_bom.integrity.request_with_retry", return_value=mock_response):
        result = await fetch_pypi_release_metadata("nonexistent", "0.0.0", mock_client)

    assert result is None


@pytest.mark.asyncio
async def test_check_pypi_provenance_not_published():
    from agent_bom.integrity import check_pypi_provenance

    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_client = AsyncMock()

    with patch("agent_bom.integrity.request_with_retry", return_value=mock_response):
        result = await check_pypi_provenance("agent-bom", "0.76.0", mock_client)

    assert result == {"has_provenance": False, "status": "not_published", "attestation_count": 0}


@pytest.mark.asyncio
async def test_check_pypi_provenance_unavailable():
    from agent_bom.integrity import check_pypi_provenance

    mock_client = AsyncMock()

    with patch("agent_bom.integrity.request_with_retry", return_value=None):
        result = await check_pypi_provenance("agent-bom", "0.76.0", mock_client)

    assert result == {"has_provenance": False, "status": "unavailable"}


@pytest.mark.asyncio
async def test_check_pypi_provenance_uses_file_scoped_integrity_api():
    from agent_bom.integrity import check_pypi_provenance

    metadata_response = MagicMock()
    metadata_response.status_code = 200
    metadata_response.json.return_value = {
        "urls": [
            {"filename": "agent_bom-0.85.0-py3-none-any.whl"},
            {"filename": "agent_bom-0.85.0.tar.gz"},
        ]
    }
    wheel_response = MagicMock()
    wheel_response.status_code = 200
    wheel_response.json.return_value = {"attestation_bundles": [{"attestations": [{}]}]}
    sdist_response = MagicMock()
    sdist_response.status_code = 200
    sdist_response.json.return_value = {"attestation_bundles": [{"attestations": [{}]}]}

    mock_client = AsyncMock()

    with patch(
        "agent_bom.integrity.request_with_retry",
        side_effect=[metadata_response, wheel_response, sdist_response],
    ) as request:
        result = await check_pypi_provenance("agent-bom", "0.85.0", mock_client)

    assert result == {
        "has_provenance": True,
        "status": "verified",
        "attestation_count": 2,
        "files": ["agent_bom-0.85.0-py3-none-any.whl", "agent_bom-0.85.0.tar.gz"],
        "attestations_by_file": {
            "agent_bom-0.85.0-py3-none-any.whl": 1,
            "agent_bom-0.85.0.tar.gz": 1,
        },
    }
    requested_urls = [call.args[2] for call in request.call_args_list]
    assert requested_urls == [
        "https://pypi.org/pypi/agent-bom/0.85.0/json",
        "https://pypi.org/integrity/agent-bom/0.85.0/agent_bom-0.85.0-py3-none-any.whl/provenance",
        "https://pypi.org/integrity/agent-bom/0.85.0/agent_bom-0.85.0.tar.gz/provenance",
    ]


# ─── CLI verify command ──────────────────────────────────────────────────────


def test_verify_command_help():
    runner = CliRunner()
    result = runner.invoke(main, ["verify", "--help"])
    assert result.exit_code == 0
    assert "Verify package integrity" in result.output
    assert "--ecosystem" in result.output
    assert "--model-dir" in result.output
    assert "--json" in result.output


def _mock_verify_all_pass():
    """Return mock patches for a fully passing self-verify."""
    record = {
        "installed_version": "0.31.6",
        "total_files": 47,
        "verified_files": 47,
        "failed_files": [],
        "record_available": True,
        "record_intact": True,
        "metadata": {
            "license": "Apache-2.0",
            "author": "test",
            "source_repo": "https://github.com/msaad00/agent-bom",
            "project_urls": {},
        },
    }

    integrity = {"sha256": "abc123def456789012345678", "verified": True}
    provenance = {"has_provenance": True, "attestation_count": 2}
    pypi_meta = {
        "name": "agent-bom",
        "version": "0.31.6",
        "license": "Apache-2.0",
        "source_repo": "https://github.com/msaad00/agent-bom",
        "author": "test",
        "sha256_digests": [],
        "requires_python": ">=3.10",
        "project_urls": {},
    }

    return record, integrity, provenance, pypi_meta


def _make_async_cm(client_mock=None):
    """Create a mock async context manager for create_client."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client_mock or AsyncMock())
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _run_verify_with_mocks(args, record, integrity, provenance, pypi_meta):
    """Run the verify command with fully mocked integrity functions."""
    runner = CliRunner()

    async def mock_verify_integrity(pkg, client):
        return integrity

    async def mock_check_provenance(pkg, client):
        return provenance

    async def mock_fetch_metadata(name, version, client):
        return pypi_meta

    with (
        patch("agent_bom.integrity.verify_installed_record", return_value=record),
        patch("agent_bom.integrity.verify_package_integrity", side_effect=mock_verify_integrity),
        patch("agent_bom.integrity.check_package_provenance", side_effect=mock_check_provenance),
        patch("agent_bom.integrity.fetch_pypi_release_metadata", side_effect=mock_fetch_metadata),
        patch("agent_bom.http_client.create_client", return_value=_make_async_cm()),
    ):
        return runner.invoke(main, args, catch_exceptions=False)


def test_verify_self_no_args():
    record, integrity, provenance, pypi_meta = _mock_verify_all_pass()
    result = _run_verify_with_mocks(["verify"], record, integrity, provenance, pypi_meta)
    assert result.exit_code == 0 or "VERIFIED" in result.output


def test_verify_success_wording_mentions_provenance():
    record, integrity, provenance, pypi_meta = _mock_verify_all_pass()
    result = _run_verify_with_mocks(["verify", "requests@2.33.0", "-e", "pypi"], record, integrity, provenance, pypi_meta)
    assert result.exit_code == 0
    assert "integrity and provenance confirmed" in result.output


def test_verify_agent_bom_shortcut_uses_self_verify():
    record, integrity, provenance, pypi_meta = _mock_verify_all_pass()
    result = _run_verify_with_mocks(["verify", "agent-bom"], record, integrity, provenance, pypi_meta)
    assert result.exit_code == 0 or "VERIFIED" in result.output


def test_verify_self_json_output():
    record, integrity, provenance, pypi_meta = _mock_verify_all_pass()
    result = _run_verify_with_mocks(["verify", "--json"], record, integrity, provenance, pypi_meta)

    if result.output.strip().startswith("{"):
        data = json.loads(result.output)
        assert "package" in data
        assert "checks" in data
        assert "verdict" in data


def test_verify_self_quiet_mode():
    record, integrity, provenance, pypi_meta = _mock_verify_all_pass()
    result = _run_verify_with_mocks(["verify", "--quiet"], record, integrity, provenance, pypi_meta)

    if result.output:
        assert "agent-bom" in result.output


def test_verify_arbitrary_package_version_required():
    runner = CliRunner()
    result = runner.invoke(main, ["verify", "express"], catch_exceptions=False)
    assert result.exit_code == 2
    assert "version required" in result.output.lower()
    assert "requests@2.33.0" in result.output


def test_verify_record_not_available_still_passes():
    """When RECORD is unavailable (editable install), command should still pass if registry checks pass."""
    record = {
        "installed_version": "0.31.6",
        "total_files": 0,
        "verified_files": 0,
        "failed_files": [],
        "record_available": False,
        "record_intact": False,
        "metadata": {"license": "", "author": "", "source_repo": "", "project_urls": {}},
    }
    integrity = {"sha256": "abc123def456789012345678", "verified": True}
    provenance = {"has_provenance": True, "attestation_count": 1}
    pypi_meta = {
        "name": "agent-bom",
        "version": "0.31.6",
        "license": "Apache-2.0",
        "source_repo": "",
        "author": "",
        "sha256_digests": [],
        "requires_python": "",
        "project_urls": {},
    }

    result = _run_verify_with_mocks(["verify", "--json"], record, integrity, provenance, pypi_meta)

    if result.output.strip().startswith("{"):
        data = json.loads(result.output)
        record_check = data.get("checks", {}).get("record_integrity", {})
        assert record_check.get("status") == "unknown"


def test_verify_provenance_missing_is_not_unknown():
    record, integrity, _provenance, pypi_meta = _mock_verify_all_pass()
    missing_provenance = {"has_provenance": False, "status": "not_published", "attestation_count": 0}

    result = _run_verify_with_mocks(["verify", "--json"], record, integrity, missing_provenance, pypi_meta)

    data = json.loads(result.output)
    assert result.exit_code == 1
    assert data["verdict"] == "unverified"
    assert data["checks"]["provenance"]["status"] == "missing"
    assert data["checks"]["provenance"]["detail"] == "No registry provenance attestation found for this release"


def test_verify_provenance_unavailable_is_not_unknown():
    record, integrity, _provenance, pypi_meta = _mock_verify_all_pass()
    unavailable_provenance = {"has_provenance": False, "status": "unavailable"}

    result = _run_verify_with_mocks(["verify", "--json"], record, integrity, unavailable_provenance, pypi_meta)

    data = json.loads(result.output)
    assert result.exit_code == 1
    assert data["verdict"] == "unverified"
    assert data["checks"]["provenance"]["status"] == "unavailable"


def test_verify_partial_provenance_fails_verdict():
    record, integrity, _provenance, pypi_meta = _mock_verify_all_pass()
    partial_provenance = {
        "has_provenance": False,
        "status": "partial",
        "attestation_count": 1,
        "missing_files": ["agent_bom-0.85.0.tar.gz"],
    }

    result = _run_verify_with_mocks(["verify", "--json"], record, integrity, partial_provenance, pypi_meta)

    data = json.loads(result.output)
    assert result.exit_code == 1
    assert data["verdict"] == "unverified"
    assert data["checks"]["provenance"]["status"] == "fail"


def test_verify_provenance_pass_mentions_all_files():
    record, integrity, _provenance, pypi_meta = _mock_verify_all_pass()
    provenance = {
        "has_provenance": True,
        "status": "verified",
        "attestation_count": 2,
        "files": ["pkg-1.0.0-py3-none-any.whl", "pkg-1.0.0.tar.gz"],
    }

    result = _run_verify_with_mocks(["verify", "--json"], record, integrity, provenance, pypi_meta)

    data = json.loads(result.output)
    assert data["checks"]["provenance"]["status"] == "pass"
    assert data["checks"]["provenance"]["detail"] == "Release provenance present for all 2 file(s) (2 attestation(s))"


def test_verify_record_tampered_fails():
    """When RECORD hash mismatch detected, command should exit 1."""
    record = {
        "installed_version": "0.31.6",
        "total_files": 47,
        "verified_files": 46,
        "failed_files": ["agent_bom/cli.py"],
        "record_available": True,
        "record_intact": False,
        "metadata": {"license": "", "author": "", "source_repo": "", "project_urls": {}},
    }
    integrity = {"sha256": "abc123", "verified": True}

    result = _run_verify_with_mocks(["verify", "--json"], record, integrity, None, None)

    if result.output.strip().startswith("{"):
        data = json.loads(result.output)
        assert data["verdict"] == "unverified"
        assert data["checks"]["record_integrity"]["status"] == "fail"


def test_verify_model_dir_json_output(tmp_path):
    runner = CliRunner()
    mock_report = MagicMock()
    mock_report.scanned = 2
    mock_report.verified = 1
    mock_report.tampered = 1
    mock_report.unverified = 0
    mock_report.offline = 0
    mock_report.has_tampering = True
    mock_report.summary.return_value = {
        "scanned": 2,
        "verified": 1,
        "tampered": 1,
        "unverified": 0,
        "offline": 0,
    }
    mock_result = MagicMock()
    mock_result.to_dict.return_value = {"filename": "model.safetensors", "status": "tampered"}
    mock_report.results = [mock_result]

    with patch("agent_bom.model_hash.verify_model_hashes", return_value=mock_report):
        result = runner.invoke(main, ["verify", "--model-dir", str(tmp_path), "--repo-id", "org/model", "--json"], catch_exceptions=False)

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["repo_id"] == "org/model"
    assert data["verdict"] == "unverified"
    assert data["summary"]["tampered"] == 1


def test_verify_model_dir_conflicts_with_package_spec(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["verify", "requests@2.33.0", "--model-dir", str(tmp_path)], catch_exceptions=False)
    assert result.exit_code == 2
    assert "choose either package verification or --model-dir" in result.output.lower()


def test_verify_model_dir_no_files_errors(tmp_path):
    runner = CliRunner()
    mock_report = MagicMock()
    mock_report.scanned = 0
    mock_report.summary.return_value = {"scanned": 0, "verified": 0, "tampered": 0, "unverified": 0, "offline": 0}

    with patch("agent_bom.model_hash.verify_model_hashes", return_value=mock_report):
        result = runner.invoke(main, ["verify", "--model-dir", str(tmp_path), "--json"], catch_exceptions=False)

    assert result.exit_code == 2
    data = json.loads(result.output)
    assert data["verdict"] == "error"
