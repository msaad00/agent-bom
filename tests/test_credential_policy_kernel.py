"""Explicit policy/time inputs keep credential decisions independent of adapters."""

from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.core.credential_policy import CredentialPolicy, classify_credential_record, credential_governance_summary

NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


def test_core_ignores_environment_and_policy_is_immutable(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_CRED_NEAR_EXPIRY_DAYS", "100")
    policy = CredentialPolicy(near_days=1)
    record = {"credential_expires_at": (NOW + timedelta(days=2)).isoformat()}
    result = classify_credential_record(record, policy=policy, now=NOW)
    assert result["state"] == "ok"
    assert result["near_expiry_days"] == 1
    with pytest.raises(AttributeError):
        policy.near_days = 100


def test_summary_does_not_mutate_input_order_or_policy():
    policy = CredentialPolicy(rotation_days=90)
    records = [
        classify_credential_record({"id": "z"}, policy=policy, now=NOW),
        classify_credential_record({"id": "a", "rotation_days": 0}, policy=policy, now=NOW),
    ]
    summary = credential_governance_summary(records, policy=policy)
    assert [item["id"] for item in records] == ["z", "a"]
    assert [item["id"] for item in summary["credentials"]] == ["a", "z"]
    assert policy.rotation_days == 90
    assert summary["thresholds"]["rotation_days"] == 90
