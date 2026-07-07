"""Tests for credential reference live validation."""

from __future__ import annotations

from agent_bom.api.credential_ref_validation import validate_credential_ref
from agent_bom.api.models import CredentialRefRecord, CredentialRefStatus


def test_invalid_aws_role_arn_is_degraded(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_bom.api.credential_ref_validation.verify_credentials",
        lambda _provider: (True, "sts: ok"),
    )
    credential = CredentialRefRecord(
        credential_ref_id="c1",
        tenant_id="default",
        display_name="bad role",
        provider="aws",
        mode="role_arn",
        external_ref="not-an-arn",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    status, message = validate_credential_ref(credential)
    assert status is CredentialRefStatus.DEGRADED
    assert "valid IAM role ARN" in message


def test_cloud_probe_failure_is_degraded(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_bom.api.credential_ref_validation.verify_credentials",
        lambda _provider: (False, "no credentials"),
    )
    credential = CredentialRefRecord(
        credential_ref_id="c2",
        tenant_id="default",
        display_name="aws role",
        provider="aws",
        mode="role_arn",
        external_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    status, message = validate_credential_ref(credential)
    assert status is CredentialRefStatus.DEGRADED
    assert "probe failed" in message
