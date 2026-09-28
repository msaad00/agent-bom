"""Characterize gateway request boundaries before extracting their owners."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import agent_bom.gateway_server as gateway
from agent_bom.gateway_upstreams import UpstreamRegistry


def request(headers):
    return Request({"type": "http", "headers": [(k.encode(), v.encode()) for k, v in headers.items()], "client": ("192.0.2.1", 1)})


def test_request_context_is_bounded_and_cost_center_precedence_is_stable():
    req = request(
        {
            "x-agent-environment": "e" * 90,
            "x-agent-device-id": "d" * 250,
            "x-agent-client-id": "c" * 250,
            "x-agent-groups": "a,a,," + ",".join(str(n) for n in range(90)),
            "x-cost-center": " header ",
            **{f"x-agent-ctx-{n}": "v" * 250 for n in range(40)},
        }
    )
    assert gateway._request_environment(req) == "e" * 60
    assert gateway._request_device_id(req) == "d" * 200
    assert gateway._request_client_id(req) == "c" * 200
    assert gateway._request_groups(req) == ["a", *(str(n) for n in range(63))]
    assert gateway._request_context_attributes(req) == {str(n): "v" * 200 for n in range(32)}
    message = {"params": {"_meta": {"cost_center": "nested"}}, "_meta": {"cost_center": "top"}}
    assert gateway._request_cost_center(req, message) == "header"
    assert gateway._request_cost_center(request({}), message) == "nested"
    assert gateway._request_cost_center(request({}), {"params": [], "_meta": {"cost_center": "top"}}) == "top"


@pytest.mark.parametrize(
    "headers,expected",
    [
        ({"authorization": "Bearer selected", "x-api-key": "ignored"}, "selected"),
        ({"authorization": "Bearer ", "x-api-key": "ignored"}, ""),
        ({"authorization": "Basic ignored", "x-api-key": " selected "}, "selected"),
    ],
)
def test_token_parser_preserves_precedence(headers, expected):
    assert gateway._extract_request_token(request(headers)) == expected


@pytest.mark.parametrize("stage", ["factory", "status", "verify"])
def test_key_storage_failure_is_closed_and_public_error_is_generic(monkeypatch, stage):
    def unavailable(*_):
        raise RuntimeError("test-only-secret-internal-diagnostic")

    store = SimpleNamespace(has_keys=unavailable if stage == "status" else lambda: True, verify=unavailable)
    monkeypatch.setattr(gateway, "get_key_store", unavailable if stage == "factory" else lambda: store)
    settings = gateway.GatewaySettings(registry=UpstreamRegistry([]), policy={})
    assert gateway._gateway_requires_auth(settings)
    with pytest.raises(HTTPException) as error:
        gateway._authenticate_gateway_request(request({"x-api-key": "synthetic"}), settings)
    assert error.value.status_code == 503
    assert error.value.detail == "gateway authentication unavailable"


def test_disabled_rate_limit_does_not_construct_backend(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fixture.invalid/db")
    settings = gateway.GatewaySettings(registry=UpstreamRegistry([]), policy={}, runtime_rate_limit_per_tenant_per_minute=0)
    assert gateway._build_gateway_rate_limit_store(settings) is None
    assert gateway._gateway_rate_limit_runtime_status(settings)["backend"] == "disabled"


def test_configured_shared_rate_limit_failure_never_falls_back(monkeypatch):
    def unavailable(**_):
        raise RuntimeError("test-only-database-diagnostic")

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fixture.invalid/db")
    monkeypatch.setattr(gateway, "PostgresRateLimitStore", unavailable)
    settings = gateway.GatewaySettings(registry=UpstreamRegistry([]), policy={}, runtime_rate_limit_per_tenant_per_minute=10)
    with pytest.raises(RuntimeError, match="refusing to fall back to process-local state"):
        gateway._build_gateway_rate_limit_store(settings)
