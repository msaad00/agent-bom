"""Secret scanning explicitly opts in without retaining matched credential bytes."""

import json
from dataclasses import asdict

import pytest

from agent_bom.finding import secret_dict_to_finding
from agent_bom.scanners.credential_validation import CredentialValidator
from agent_bom.secret_scanner import scan_secrets


def plant(tmp_path):
    value = "ghp_" + "Ab9Xz2Kp7Qr4Mn8Tv6Ws1Yc5Hd3Ef0Gj9La2B"
    (tmp_path / "settings.env").write_text(f'TOKEN="{value}"\n')
    return value


def test_default_scan_never_instantiates_validator(tmp_path, monkeypatch):
    from agent_bom import secret_scanner

    plant(tmp_path)

    def forbidden():
        pytest.fail("Default scan must not create a validator")

    monkeypatch.setattr(secret_scanner, "CredentialValidator", forbidden)
    result = scan_secrets(tmp_path)
    assert result.total > 0
    assert all("validation_status" not in item for item in result.to_dict()["findings"])


@pytest.mark.parametrize("status", ["valid", "invalid", "unknown"])
def test_opt_in_preserves_verdict_without_secret_bytes(tmp_path, monkeypatch, status):
    value = plant(tmp_path)
    calls = []

    def validate(self, kind, candidate):
        calls.append((kind, candidate))
        return status

    monkeypatch.setattr(CredentialValidator, "validate", validate)
    result = scan_secrets(tmp_path, validate_credentials=True)
    finding = next(f for f in result.findings if f.secret_type == "GitHub Token")
    assert finding.validation_status == status
    assert finding.severity == "critical"
    assert calls == [("GitHub Token", value)]
    assert value not in json.dumps(asdict(result))
    assert value not in repr(result)
    assert secret_dict_to_finding(finding.to_dict()).evidence["validation_status"] == status


def test_unsupported_credentials_stay_unknown_and_pii_is_unset(tmp_path):
    (tmp_path / "settings.env").write_text('AWS_ACCESS_KEY_ID="AKIA' + "A" * 16 + '"\nEMAIL="person@example.com"\n')
    result = scan_secrets(tmp_path, validate_credentials=True)
    assert next(f for f in result.findings if f.secret_type == "AWS Access Key").validation_status == "unknown"
    assert all(f.validation_status is None for f in result.findings if f.category == "pii")
