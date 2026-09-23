"""AWS live secret validation is opt-in, fail-open, and never leaks the pair.

Covers the scan_secrets(..., aws_live_validation=...) wiring: the flag off by
default, on with a valid/invalid/unreachable STS response, pairing an AWS
Access Key finding with a nearby AWS Secret Key value in the same file, and
the audit log carrying an outcome but never a secret value or STS response
field.
"""

import logging

import pytest

from agent_bom import config
from agent_bom.scanners import aws_secret_validation
from agent_bom.secret_scanner import scan_secrets

ACCESS_KEY = "AKIA" + "A" * 16
SECRET_KEY = "s" * 40
ACCOUNT_ID = "111111111111"
ARN = "arn:aws:iam::111111111111:user/x"


def plant_pair(tmp_path, access_key=ACCESS_KEY, secret_key=SECRET_KEY):
    (tmp_path / "settings.env").write_text(f'AWS_ACCESS_KEY_ID="{access_key}"\nAWS_SECRET_ACCESS_KEY="{secret_key}"\n')


class _FakeSts:
    def __init__(self, outcome, code=None):
        self.outcome = outcome
        self.code = code

    def get_caller_identity(self):
        if self.outcome == "ok":
            return {"Account": ACCOUNT_ID, "Arn": ARN}
        if self.outcome == "client_error":
            exc = Exception("rejected")
            exc.response = {"Error": {"Code": self.code}}
            raise exc
        raise TimeoutError("connect timed out")


def _patch_client(monkeypatch, fake):
    calls = []

    def build(access_key_id, secret_access_key):
        calls.append((access_key_id, secret_access_key))
        return fake

    monkeypatch.setattr(aws_secret_validation, "_build_sts_client", build)
    return calls


def _aws_finding(result):
    return next(f for f in result.findings if f.secret_type == "AWS Access Key")


def test_flag_off_by_default_no_call_and_no_field(tmp_path, monkeypatch):
    plant_pair(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("Live validation must not run unless explicitly enabled")

    monkeypatch.setattr(aws_secret_validation, "_build_sts_client", forbidden)
    result = scan_secrets(tmp_path)
    finding = _aws_finding(result)
    assert finding.validation_status is None
    assert "validation_status" not in finding.to_dict()


def test_flag_on_valid_key(tmp_path, monkeypatch):
    plant_pair(tmp_path)
    calls = _patch_client(monkeypatch, _FakeSts("ok"))
    result = scan_secrets(tmp_path, aws_live_validation=True)
    assert _aws_finding(result).validation_status == "valid"
    assert calls == [(ACCESS_KEY, SECRET_KEY)]


def test_flag_on_invalid_key(tmp_path, monkeypatch):
    plant_pair(tmp_path)
    _patch_client(monkeypatch, _FakeSts("client_error", "InvalidClientTokenId"))
    result = scan_secrets(tmp_path, aws_live_validation=True)
    assert _aws_finding(result).validation_status == "invalid"


def test_flag_on_network_error_is_unknown_and_scan_still_completes(tmp_path, monkeypatch):
    plant_pair(tmp_path)
    _patch_client(monkeypatch, _FakeSts("timeout"))
    result = scan_secrets(tmp_path, aws_live_validation=True)
    assert _aws_finding(result).validation_status == "unknown"
    payload = result.to_dict()
    assert payload["complete"] is True
    assert payload["warnings"] == []


def test_flag_on_without_a_paired_secret_key_stays_unknown_and_makes_no_call(tmp_path, monkeypatch):
    (tmp_path / "settings.env").write_text(f'AWS_ACCESS_KEY_ID="{ACCESS_KEY}"\n')

    def forbidden(*args, **kwargs):
        pytest.fail("No secret key to pair with — must not attempt a call")

    monkeypatch.setattr(aws_secret_validation, "_build_sts_client", forbidden)
    result = scan_secrets(tmp_path, aws_live_validation=True)
    assert _aws_finding(result).validation_status == "unknown"


def test_env_var_flag_defaults_off(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_SECRET_LIVE_VALIDATION_ENABLED", raising=False)
    assert config.SECRET_LIVE_VALIDATION_ENABLED is False
    plant_pair(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("Config default is off; must not attempt a call")

    monkeypatch.setattr(aws_secret_validation, "_build_sts_client", forbidden)
    result = scan_secrets(tmp_path)
    assert _aws_finding(result).validation_status is None


def test_config_flag_drives_the_default_without_an_explicit_param(tmp_path, monkeypatch):
    plant_pair(tmp_path)
    monkeypatch.setattr(config, "SECRET_LIVE_VALIDATION_ENABLED", True)
    calls = _patch_client(monkeypatch, _FakeSts("ok"))
    result = scan_secrets(tmp_path)
    assert _aws_finding(result).validation_status == "valid"
    assert calls


def test_generic_validate_credentials_flag_does_not_trigger_aws_live_validation(tmp_path, monkeypatch):
    """The pre-existing --validate-credentials (GitHub/Stripe) opt-in is a
    separate mechanism; it must not itself make an AWS STS call."""
    plant_pair(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("validate_credentials=True alone must not call AWS STS")

    monkeypatch.setattr(aws_secret_validation, "_build_sts_client", forbidden)
    result = scan_secrets(tmp_path, validate_credentials=True)
    assert _aws_finding(result).validation_status == "unknown"  # unsupported by the generic validator


def test_audit_log_never_contains_secret_values_or_sts_response(tmp_path, monkeypatch, caplog):
    plant_pair(tmp_path)
    _patch_client(monkeypatch, _FakeSts("ok"))
    # CLI/API setup may leave the package logger at WARNING; capture the emitter.
    with caplog.at_level(logging.INFO, logger="agent_bom.secret_scanner"):
        scan_secrets(tmp_path, aws_live_validation=True)
    text = caplog.text
    assert ACCESS_KEY not in text
    assert SECRET_KEY not in text
    assert ACCOUNT_ID not in text
    assert ARN not in text
    assert "provider=aws" in text
    assert "outcome=valid" in text
    assert "settings.env" in text


def test_audit_log_records_outcome_for_invalid_and_unknown_too(tmp_path, monkeypatch, caplog):
    plant_pair(tmp_path)
    _patch_client(monkeypatch, _FakeSts("client_error", "InvalidClientTokenId"))
    with caplog.at_level(logging.INFO, logger="agent_bom.secret_scanner"):
        scan_secrets(tmp_path, aws_live_validation=True)
    assert "outcome=invalid" in caplog.text
    assert ACCESS_KEY not in caplog.text
    assert SECRET_KEY not in caplog.text
