"""Static gateway credentials retain an absolute, bounded expiry across restarts."""

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

import agent_bom.gateway_server as gateway
from agent_bom.gateway_upstreams import UpstreamRegistry

NOW = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)


class Clock(datetime):
    moment = NOW

    @classmethod
    def now(cls, tz=None):
        return cls.moment if tz else cls.moment.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    Clock.moment = NOW
    monkeypatch.setattr(gateway, "datetime", Clock)


def settings(expiry=None):
    result = gateway.GatewaySettings(registry=UpstreamRegistry([]), policy={}, bearer_token="synthetic-token")
    result.bearer_token_expires_at = expiry
    return result


@pytest.mark.parametrize(
    "expiry", [None, "", "not-a-time", "2026-09-07T12:30:00", "2026-09-07T12:00:00Z", "2026-09-07T11:00:00Z", "2026-09-07T13:00:01Z"]
)
def test_rejects_missing_invalid_or_unbounded_static_expiry(expiry):
    with pytest.raises(ValueError, match="timezone-aware ISO-8601 expiry in the next hour"):
        gateway.create_gateway_app(settings(expiry))


@pytest.mark.parametrize("header", ["Authorization", "X-API-Key"])
def test_static_auth_expires_at_absolute_deadline(header):
    config = settings("2026-09-07T12:30:00Z")
    client = TestClient(gateway.create_gateway_app(config))
    credential = "Bearer synthetic-token" if header == "Authorization" else "synthetic-token"
    assert client.get("/metrics", headers={header: credential}).status_code == 200
    Clock.moment = NOW + timedelta(minutes=30)
    assert client.get("/metrics", headers={header: credential}).status_code == 401


def test_restart_does_not_renew_static_deadline():
    expiry = "2026-09-07T13:00:00+01:00"  # Noon UTC, already expired.
    with pytest.raises(ValueError):
        gateway.create_gateway_app(settings(expiry))
    expiry = "2026-09-07T12:30:00Z"
    gateway.create_gateway_app(settings(expiry))
    Clock.moment = NOW + timedelta(minutes=20)
    client = TestClient(gateway.create_gateway_app(settings(expiry)))
    Clock.moment = NOW + timedelta(minutes=30)
    assert client.get("/metrics", headers={"Authorization": "Bearer synthetic-token"}).status_code == 401


def test_no_static_token_needs_no_static_expiry():
    gateway.create_gateway_app(gateway.GatewaySettings(registry=UpstreamRegistry([]), policy={}))


def test_cli_reads_expiry_from_environment(monkeypatch, tmp_path):
    from unittest.mock import patch

    from click.testing import CliRunner

    from agent_bom.cli._gateway import gateway_group

    source = tmp_path / "upstreams.yaml"
    source.write_text("upstreams: []\n")
    monkeypatch.setenv("AGENT_BOM_GATEWAY_BEARER_TOKEN", "synthetic-token")
    monkeypatch.setenv("AGENT_BOM_GATEWAY_BEARER_TOKEN_EXPIRES_AT", "2026-09-07T12:30:00Z")
    with patch("uvicorn.run") as run:
        result = CliRunner().invoke(gateway_group, ["serve", "--upstreams", str(source)])
    assert result.exit_code == 0, result.output
    assert run.call_count == 1
    app = run.call_args.args[0]
    client = TestClient(app)
    assert client.get("/metrics", headers={"Authorization": "Bearer synthetic-token"}).status_code == 200
    Clock.moment = NOW + timedelta(minutes=30)
    assert client.get("/metrics", headers={"Authorization": "Bearer synthetic-token"}).status_code == 401


def test_cli_missing_expiry_fails_with_actionable_error(tmp_path):
    from click.testing import CliRunner

    from agent_bom.cli._gateway import gateway_group

    source = tmp_path / "upstreams.yaml"
    source.write_text("upstreams: []\n")
    result = CliRunner().invoke(gateway_group, ["serve", "--upstreams", str(source), "--bearer-token", "synthetic-token"])
    assert result.exit_code != 0
    assert "--bearer-token-expires-at" in result.output
    assert "synthetic-token" not in result.output
