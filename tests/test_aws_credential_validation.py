"""AWS live-credential validation runs only against a mocked STS seam.

Never opens a real network connection — every test patches
``aws_secret_validation._build_sts_client`` with a fake STS client.
"""

import pytest

from agent_bom.scanners import aws_secret_validation as validation

ACCESS_KEY = "AKIA" + "A" * 16
SECRET_KEY = "s" * 40


class _FakeSts:
    def __init__(self, outcome, code=None):
        self.outcome = outcome
        self.code = code
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        if self.outcome == "ok":
            return {"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:user/x"}
        if self.outcome == "client_error":
            exc = Exception("rejected")
            exc.response = {"Error": {"Code": self.code}}
            raise exc
        raise TimeoutError("connect timed out")


def _patch(monkeypatch, fake):
    calls = []

    def build(access_key_id, secret_access_key):
        calls.append((access_key_id, secret_access_key))
        return fake

    monkeypatch.setattr(validation, "_build_sts_client", build)
    return calls


@pytest.mark.parametrize(
    "code,expected",
    [
        ("InvalidClientTokenId", "invalid"),
        ("SignatureDoesNotMatch", "invalid"),
        ("InvalidAccessKeyId", "invalid"),
        ("AccessDenied", "invalid"),
        ("Throttling", "unknown"),
        (None, "unknown"),
    ],
)
def test_client_error_classification(monkeypatch, code, expected):
    _patch(monkeypatch, _FakeSts("client_error", code))
    validator = validation.AwsCredentialValidator()
    assert validator.validate(ACCESS_KEY, SECRET_KEY) == expected


def test_success_is_valid(monkeypatch):
    calls = _patch(monkeypatch, _FakeSts("ok"))
    validator = validation.AwsCredentialValidator()
    assert validator.validate(ACCESS_KEY, SECRET_KEY) == "valid"
    assert calls == [(ACCESS_KEY, SECRET_KEY)]


def test_transport_error_is_unknown_and_secret_free(monkeypatch, caplog):
    _patch(monkeypatch, _FakeSts("timeout"))
    validator = validation.AwsCredentialValidator()
    assert validator.validate(ACCESS_KEY, SECRET_KEY) == "unknown"
    assert SECRET_KEY not in caplog.text
    assert ACCESS_KEY not in caplog.text


def test_cache_avoids_a_second_call_for_the_same_pair(monkeypatch):
    fake = _FakeSts("ok")
    _patch(monkeypatch, fake)
    validator = validation.AwsCredentialValidator()
    for _ in range(3):
        assert validator.validate(ACCESS_KEY, SECRET_KEY) == "valid"
    assert fake.calls == 1


def test_budget_caps_total_checks_per_scan(monkeypatch):
    _patch(monkeypatch, _FakeSts("ok"))
    validator = validation.AwsCredentialValidator()
    for index in range(validation._MAX_CHECKS + 5):
        validator.validate("AKIA" + str(index).zfill(16), SECRET_KEY)
    assert validator._checks == validation._MAX_CHECKS


def test_blocked_after_transport_error_stops_further_checks(monkeypatch):
    calls = _patch(monkeypatch, _FakeSts("timeout"))
    validator = validation.AwsCredentialValidator()
    assert validator.validate(ACCESS_KEY, SECRET_KEY) == "unknown"
    assert validator.validate("AKIA" + "B" * 16, SECRET_KEY) == "unknown"
    assert len(calls) == 1


def test_not_blocked_after_a_merely_invalid_credential(monkeypatch):
    calls = _patch(monkeypatch, _FakeSts("client_error", "InvalidClientTokenId"))
    validator = validation.AwsCredentialValidator()
    assert validator.validate(ACCESS_KEY, SECRET_KEY) == "invalid"
    assert validator.validate("AKIA" + "B" * 16, SECRET_KEY) == "invalid"
    assert len(calls) == 2


def test_import_error_fails_open(monkeypatch):
    def raise_import_error(access_key_id, secret_access_key):
        raise ImportError("boto3 is not installed")

    monkeypatch.setattr(validation, "_build_sts_client", raise_import_error)
    validator = validation.AwsCredentialValidator()
    assert validator.validate(ACCESS_KEY, SECRET_KEY) == "unknown"


def test_secret_values_never_stored_on_validator(monkeypatch):
    _patch(monkeypatch, _FakeSts("ok"))
    validator = validation.AwsCredentialValidator()
    validator.validate(ACCESS_KEY, SECRET_KEY)
    assert SECRET_KEY not in repr(vars(validator))
    assert ACCESS_KEY not in repr(vars(validator))


def test_client_setup_error_is_unknown_and_blocks_scan_budget(monkeypatch):
    calls = []

    def fail_setup(*args):
        calls.append(args)
        raise ValueError("invalid SDK configuration")

    monkeypatch.setattr(validation, "_build_sts_client", fail_setup)
    validator = validation.AwsCredentialValidator()
    assert validator.validate(ACCESS_KEY, SECRET_KEY) == "unknown"
    assert validator.validate("AKIA" + "B" * 16, SECRET_KEY) == "unknown"
    assert len(calls) == 1


def test_sts_client_uses_fixed_endpoint_and_one_attempt(monkeypatch):
    import sys
    from types import SimpleNamespace

    captured = {}

    def client(service, **kwargs):
        captured.update(kwargs)
        return _FakeSts("ok")

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=client))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kwargs: SimpleNamespace(**kwargs)))
    validation._build_sts_client(ACCESS_KEY, SECRET_KEY)
    assert captured["endpoint_url"] == "https://sts.us-east-1.amazonaws.com"
    assert captured["config"].retries == {"total_max_attempts": 1}
    assert captured["config"].proxies == {}
