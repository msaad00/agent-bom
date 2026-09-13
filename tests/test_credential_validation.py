"""Provider checks run only against controlled transports, never real tokens."""

import httpx
import pytest

from agent_bom.scanners import credential_validation as validation


def token(prefix="ghp_", suffix="A"):
    return prefix + suffix * 36


def transport(monkeypatch, handler):
    original = httpx.Client
    options = []

    def client(**kwargs):
        options.append(kwargs)
        return original(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(validation.httpx, "Client", client)
    return options


@pytest.mark.parametrize(
    "status,expected", [(200, "valid"), (401, "invalid"), (403, "unknown"), (429, "unknown"), (500, "unknown"), (302, "unknown")]
)
@pytest.mark.parametrize(
    "kind,value,url",
    [("GitHub Token", token(), "https://api.github.com/user"), ("Stripe Key", token("sk_test_"), "https://api.stripe.com/v1/balance")],
)
def test_read_only_verdicts(monkeypatch, status, expected, kind, value, url):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(status, headers={"Location": "https://untrusted.example/"})

    options = transport(monkeypatch, handle)
    validator = validation.CredentialValidator()
    assert validator.validate(kind, value) == expected
    assert len(requests) == 1
    assert requests[0].method == "GET" and str(requests[0].url) == url
    assert requests[0].headers["Authorization"] == f"Bearer {value}"
    assert options == [{"timeout": 2.0, "follow_redirects": False, "trust_env": False}]
    assert value not in repr(vars(validator))


def test_cache_and_budget(monkeypatch):
    requests = []
    transport(monkeypatch, lambda request: requests.append(request) or httpx.Response(200))
    validator = validation.CredentialValidator()
    for _ in range(3):
        assert validator.validate("GitHub Token", token()) == "valid"
    assert len(requests) == 1
    for index in range(validation._MAX_CHECKS + 5):
        validator.validate("GitHub Token", token(suffix=str(index)))
    assert len(requests) == validation._MAX_CHECKS


def test_unsupported_or_injected_values_never_open_client(monkeypatch):
    def forbidden(**kwargs):
        pytest.fail("Unsupported credentials must not initiate network I/O")

    monkeypatch.setattr(validation.httpx, "Client", forbidden)
    validator = validation.CredentialValidator()
    for kind, value in [
        ("AWS Access Key", "AKIA" + "A" * 16),
        ("GitHub Token", token("ghs_")),
        ("GitHub Token", token() + "\r\nHost: attacker"),
        ("Generic API Key", token()),
    ]:
        assert validator.validate(kind, value) == "unknown"


def test_transport_error_is_unknown_and_secret_free(monkeypatch, caplog):
    def fail(request):
        raise httpx.ConnectError(token(), request=request)

    transport(monkeypatch, fail)
    validator = validation.CredentialValidator()
    assert validator.validate("GitHub Token", token()) == "unknown"
    assert token() not in caplog.text


def test_response_body_is_never_read(monkeypatch):
    class UnreadableBody(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("Provider account data must not be read")
            yield b""  # pragma: no cover

    transport(monkeypatch, lambda request: httpx.Response(200, stream=UnreadableBody()))
    assert validation.CredentialValidator().validate("GitHub Token", token()) == "valid"


@pytest.mark.parametrize("status", [403, 429, 503])
def test_provider_circuit_stops_additional_checks_but_not_other_provider(monkeypatch, status):
    requests = []
    transport(monkeypatch, lambda request: requests.append(request) or httpx.Response(status))
    validator = validation.CredentialValidator()
    assert validator.validate("GitHub Token", token()) == "unknown"
    assert validator.validate("GitHub Token", token(suffix="B")) == "unknown"
    assert len(requests) == 1
    assert validator.validate("Stripe Key", token("sk_test_")) == "unknown"
    assert len(requests) == 2


def test_validator_instances_do_not_share_credential_state(monkeypatch):
    requests = []
    transport(monkeypatch, lambda request: requests.append(request) or httpx.Response(200))
    for _ in range(2):
        assert validation.CredentialValidator().validate("GitHub Token", token()) == "valid"
    assert len(requests) == 2
