"""Credential-policy behavior pinned before separating rules from API/config I/O."""

from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.api.credential_expiry import classify_credential, evaluate_credentials

NOW = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)
ENV = ("AGENT_BOM_CRED_NEAR_EXPIRY_DAYS", "AGENT_BOM_CRED_ROTATION_DAYS", "AGENT_BOM_CRED_MAX_AGE_DAYS")


@pytest.fixture(autouse=True)
def _policy_environment(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("seconds", "state", "days"),
    [(-1, "expired", -1), (0, "near_expiry", 0), (14 * 86400 + 86399, "near_expiry", 14), (15 * 86400, "ok", 15)],
)
def test_expiry_uses_floor_days_including_the_current_instant(seconds, state, days):
    result = classify_credential({"credential_expires_at": (NOW + timedelta(seconds=seconds)).isoformat()}, now=NOW)
    assert (result["state"], result["days_until_expiry"]) == (state, days)


@pytest.mark.parametrize("raw", ["", "invalid", "-1"])
def test_invalid_environment_thresholds_keep_existing_defaults(monkeypatch, raw):
    for name in ENV:
        monkeypatch.setenv(name, raw)
    assert evaluate_credentials([], now=NOW)["thresholds"] == {
        "near_expiry_days": 14,
        "rotation_days": None,
        "max_age_days": None,
    }


def test_record_then_call_then_environment_precedence_and_zero(monkeypatch):
    for name in ENV:
        monkeypatch.setenv(name, "90")
    record = {"last_rotated": NOW.isoformat(), "rotation_days": 0, "max_age_days": 0}
    result = classify_credential(record, near_days=0, rotation_days=10, hard_max_age_days=20, now=NOW)
    assert (result["near_expiry_days"], result["rotation_days"], result["max_age_days"]) == (0, 0, 0)
    assert result["state"] == "overdue"
    assert result["reasons"] == ["age 0d exceeds max age 0d"]
    result = classify_credential({"rotation_days": "0", "max_age_days": "0"}, rotation_days=10, hard_max_age_days=20, now=NOW)
    assert (result["rotation_days"], result["max_age_days"]) == (10, 20)


def test_expiry_and_max_age_reasons_are_retained_in_order():
    result = classify_credential(
        {"last_rotated": (NOW - timedelta(days=100)).isoformat(), "credential_expires_at": (NOW - timedelta(seconds=1)).isoformat()},
        hard_max_age_days=90,
        now=NOW,
    )
    assert result["state"] == "overdue"
    assert result["reasons"] == ["credential expired 1 day(s) ago", "age 100d exceeds max age 90d"]


def test_future_rotation_invalid_expiry_and_secret_fields_stay_unknown():
    record = {
        "identity_id": 12,
        "last_rotated_at": (NOW + timedelta(days=1)).isoformat(),
        "credential_expires_at": "bad",
        "secret": "synthetic-secret",
    }
    result = classify_credential(record, now=NOW)
    assert result["id"] == "12"
    assert result["name"] == "12"
    assert result["state"] == "unknown_age"
    assert result["age_days"] is None
    assert result["credential_expires_at"] is None
    assert "synthetic-secret" not in str(result)
    assert record["credential_expires_at"] == "bad"


def test_naive_and_offset_timestamps_preserve_output_normalization():
    for timestamp in ("2026-09-27T12:00:00", "2026-09-27T12:00:00Z", "2026-09-27T14:00:00+02:00"):
        result = classify_credential({"credential_expires_at": timestamp}, now=NOW)
        assert result["days_until_expiry"] == 0
        assert result["state"] == "near_expiry"
        assert result["credential_expires_at"].endswith("+02:00" if timestamp.endswith("+02:00") else "+00:00")


def test_collection_sorts_by_priority_then_name_and_retains_duplicates():
    records = [{"id": "b", "name": "z"}, None, {"id": "a", "name": "a"}, {"id": "a", "name": "a"}]
    report = evaluate_credentials(iter(records), now=NOW)
    assert report["status"] == "attention_required"
    assert report["evaluated"] == 4
    assert report["counts"] == {"overdue": 0, "expired": 0, "rotation_due": 0, "near_expiry": 0, "unknown_age": 4, "ok": 0}
    assert report["warnings"] == [None, "a", "a", "z"]
    assert report["action_required"] == report["credentials"]
    assert report["secret_values_included"] is False


def test_environment_is_resolved_per_record_and_again_for_summary(monkeypatch):
    def records():
        monkeypatch.setenv(ENV[0], "0")
        yield {"id": "narrow", "credential_expires_at": (NOW + timedelta(days=5)).isoformat()}
        monkeypatch.setenv(ENV[0], "10")
        yield {"id": "wide", "credential_expires_at": (NOW + timedelta(days=5)).isoformat()}

    report = evaluate_credentials(records(), now=NOW)
    assert report["thresholds"]["near_expiry_days"] == 10
    assert [(c["id"], c["state"]) for c in report["credentials"]] == [("wide", "near_expiry"), ("narrow", "ok")]
