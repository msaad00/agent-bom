"""CLI delegates evidence writes to the authenticated API, without credential flags."""

import json
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli._cloud_group import cloud_group
from agent_bom.cloud.runtime_source_auth import SourceAuthenticationError


def _invoke(tmp_path, *extra):
    path = tmp_path / "signals.json"
    path.write_text(json.dumps([{"workload_ref": "i-test"}]))
    return CliRunner().invoke(cloud_group, ["runtime-evidence-ingest", "--source-id", "edr-1", "--file", str(path), *extra])


def test_cli_ingest_uses_api_and_keeps_validation_only(tmp_path):
    response = dict(
        source_id="edr-1", tenant_id="tenant-alpha", accepted=1, persisted=0, deduped=0, rejected_stale=0, rejected_incomplete=0
    )
    with patch("agent_bom.cloud.runtime_evidence_client.push_runtime_evidence", return_value=response) as push:
        result = _invoke(tmp_path, "--no-persist")
    assert result.exit_code == 0, result.output
    assert push.call_args.kwargs["validate_only"] is True
    assert push.call_args.kwargs["source_id"] == "edr-1"
    assert "persisted=0" in result.output


def test_cli_ingest_fails_closed_without_configured_auth(tmp_path):
    with patch("agent_bom.cloud.runtime_evidence_client.push_runtime_evidence", side_effect=SourceAuthenticationError("denied")):
        result = _invoke(tmp_path)
    assert result.exit_code == 1
    assert "authentication failed" in result.output


def test_cli_ingest_does_not_disclose_api_failure_details(tmp_path):
    with patch("agent_bom.cloud.runtime_evidence_client.push_runtime_evidence", side_effect=RuntimeError("token=private-value")):
        result = _invoke(tmp_path)
    assert result.exit_code == 1
    assert "private-value" not in result.output


def test_cli_ingest_rejects_legacy_secret_flag(tmp_path):
    result = _invoke(tmp_path, "--secret", "private-value")
    assert result.exit_code == 2
    assert "No such option" in result.output


def test_cli_ingest_reports_partial_audit_failure(tmp_path):
    response = dict(
        source_id="edr-1",
        tenant_id="tenant-alpha",
        accepted=1,
        persisted=1,
        deduped=0,
        rejected_stale=0,
        rejected_incomplete=0,
        status="partial",
        audit_status="unavailable",
    )
    with patch("agent_bom.cloud.runtime_evidence_client.push_runtime_evidence", return_value=response):
        result = _invoke(tmp_path)
    assert result.exit_code == 1
    assert "persisted=1" in result.output
    assert "audit" in result.output.lower()
