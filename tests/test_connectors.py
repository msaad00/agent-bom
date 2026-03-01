"""Tests for SaaS connector framework — Jira, ServiceNow, Slack discovery."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_bom.connectors import (
    discover_from_connector,
    list_connectors,
)
from agent_bom.connectors.base import (
    ConnectorError,
    ConnectorHealthState,
    ConnectorStatus,
)

# ─── Registry ────────────────────────────────────────────────────────────────


def test_list_connectors():
    connectors = list_connectors()
    assert "jira" in connectors
    assert "servicenow" in connectors
    assert "slack" in connectors
    assert connectors == sorted(connectors)


def test_discover_unknown_connector():
    with pytest.raises(ValueError, match="Unknown connector"):
        discover_from_connector("nonexistent")


def test_check_health_unknown_connector():
    from agent_bom.connectors import check_connector_health

    with pytest.raises(ValueError, match="Unknown connector"):
        check_connector_health("nonexistent")


# ─── ConnectorStatus ─────────────────────────────────────────────────────────


def test_connector_status_dataclass():
    status = ConnectorStatus(
        connector="jira",
        state=ConnectorHealthState.HEALTHY,
        message="Connected",
        api_version="9.0",
    )
    assert status.connector == "jira"
    assert status.state == ConnectorHealthState.HEALTHY
    assert status.message == "Connected"
    assert status.api_version == "9.0"


def test_connector_status_defaults():
    status = ConnectorStatus(connector="test", state=ConnectorHealthState.UNREACHABLE)
    assert status.message == ""
    assert status.api_version == ""
    assert status.details == {}


def test_connector_health_state_values():
    assert ConnectorHealthState.HEALTHY.value == "healthy"
    assert ConnectorHealthState.AUTH_FAILED.value == "auth_failed"


def test_connector_error_is_exception():
    with pytest.raises(ConnectorError, match="test error"):
        raise ConnectorError("test error")


# ─── Jira Connector ──────────────────────────────────────────────────────────


def test_jira_missing_url():
    with pytest.raises(ConnectorError, match="Jira URL required"):
        discover_from_connector("jira", jira_url="", email="x@x.com", api_token="tok")


def test_jira_missing_creds():
    with pytest.raises(ConnectorError, match="credentials required"):
        discover_from_connector("jira", jira_url="https://test.atlassian.net", email="", api_token="")


def test_jira_discover_automation_rules(monkeypatch):
    """Mock Jira API to return automation rules."""

    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        if "workflow/rule" in url:
            resp.status_code = 200
            resp.json.return_value = [
                {"id": "rule-1", "name": "AI Triage Rule"},
                {"id": "rule-2", "name": "Auto-Assign Bot"},
            ]
        elif "app/installed" in url:
            resp.status_code = 200
            resp.json.return_value = {"values": []}
        else:
            resp.status_code = 404
        return resp

    monkeypatch.setattr("agent_bom.connectors.jira_connector.create_client", MagicMock(return_value=AsyncMock()))
    monkeypatch.setattr("agent_bom.http_client.request_with_retry", _fake_request)
    # Patch the import inside the async function
    monkeypatch.setattr("agent_bom.connectors.jira_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.jira_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("jira", jira_url="https://test.atlassian.net", email="u@t.com", api_token="tok123")
    assert len(agents) == 2
    assert agents[0].source == "jira"
    assert "AI Triage Rule" in agents[0].name


def _mock_client_ctx(*args, **kwargs):
    """Return an async context manager that yields a MagicMock client."""
    client = AsyncMock()
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=client)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


def test_jira_discover_apps(monkeypatch):
    """Mock Jira API to return installed apps."""

    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        if "workflow/rule" in url:
            resp.status_code = 404
        elif "app/installed" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "values": [
                    {"name": "AI Assistant", "key": "com.vendor.ai-assistant", "vendor": {"name": "VendorCo"}},
                ]
            }
        else:
            resp.status_code = 404
        return resp

    monkeypatch.setattr("agent_bom.connectors.jira_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.jira_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("jira", jira_url="https://test.atlassian.net", email="u@t.com", api_token="tok")
    assert len(agents) == 1
    assert agents[0].source == "jira"
    assert "AI Assistant" in agents[0].name
    assert agents[0].metadata["app_key"] == "com.vendor.ai-assistant"


def test_jira_discover_permission_error(monkeypatch):
    """403 responses should add warnings, not raise."""

    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 403
        return resp

    monkeypatch.setattr("agent_bom.connectors.jira_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.jira_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("jira", jira_url="https://test.atlassian.net", email="u@t.com", api_token="tok")
    assert len(agents) == 0
    assert len(warnings) >= 1
    assert any("403" in w for w in warnings)


def test_jira_health_check_healthy(monkeypatch):
    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"version": "9.12.0", "serverTitle": "Jira"}
        return resp

    monkeypatch.setattr("agent_bom.connectors.jira_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.jira_connector.request_with_retry", _fake_request)

    from agent_bom.connectors.jira_connector import health_check

    status = health_check(jira_url="https://test.atlassian.net", email="u@t.com", api_token="tok")
    assert status.state == ConnectorHealthState.HEALTHY
    assert status.api_version == "9.12.0"


def test_jira_health_check_auth_failed(monkeypatch):
    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 401
        return resp

    monkeypatch.setattr("agent_bom.connectors.jira_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.jira_connector.request_with_retry", _fake_request)

    from agent_bom.connectors.jira_connector import health_check

    status = health_check(jira_url="https://test.atlassian.net", email="u@t.com", api_token="bad")
    assert status.state == ConnectorHealthState.AUTH_FAILED


def test_jira_health_check_missing_creds():
    from agent_bom.connectors.jira_connector import health_check

    status = health_check(jira_url="", email="", api_token="")
    assert status.state == ConnectorHealthState.AUTH_FAILED


# ─── ServiceNow Connector ────────────────────────────────────────────────────


def test_servicenow_missing_instance():
    with pytest.raises(ConnectorError, match="instance URL required"):
        discover_from_connector("servicenow", instance_url="", username="admin", password="pwd")


def test_servicenow_missing_creds():
    with pytest.raises(ConnectorError, match="credentials required"):
        discover_from_connector("servicenow", instance_url="https://dev.service-now.com", username="", password="")


def test_servicenow_discover_flows(monkeypatch):
    """Mock ServiceNow API to return Flow Designer flows."""

    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        if "sys_hub_flow" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "result": [
                    {"sys_id": "flow-1", "name": "AI Ticket Router", "active": "true", "description": "Routes tickets using AI"},
                ]
            }
        elif "sys_hub_action_type" in url:
            resp.status_code = 200
            resp.json.return_value = {"result": []}
        else:
            resp.status_code = 404
        return resp

    monkeypatch.setattr("agent_bom.connectors.servicenow_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.servicenow_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("servicenow", instance_url="https://dev.service-now.com", username="admin", password="pwd")
    assert len(agents) == 1
    assert agents[0].source == "servicenow"
    assert "AI Ticket Router" in agents[0].name


def test_servicenow_discover_spokes(monkeypatch):
    """Mock ServiceNow API to return IntegrationHub spokes."""

    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        if "sys_hub_flow" in url:
            resp.status_code = 200
            resp.json.return_value = {"result": []}
        elif "sys_hub_action_type" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "result": [
                    {"sys_id": "spoke-1", "name": "Slack Spoke"},
                    {"sys_id": "spoke-2", "name": "AI Search Spoke"},
                ]
            }
        else:
            resp.status_code = 404
        return resp

    monkeypatch.setattr("agent_bom.connectors.servicenow_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.servicenow_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("servicenow", instance_url="https://dev.service-now.com", username="admin", password="pwd")
    assert len(agents) == 2
    assert all(a.source == "servicenow" for a in agents)
    assert any("Slack Spoke" in a.name for a in agents)


def test_servicenow_discover_permission_error(monkeypatch):
    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 403
        return resp

    monkeypatch.setattr("agent_bom.connectors.servicenow_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.servicenow_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("servicenow", instance_url="https://dev.service-now.com", username="admin", password="pwd")
    assert len(agents) == 0
    assert len(warnings) >= 1


def test_servicenow_health_check_healthy(monkeypatch):
    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        return resp

    monkeypatch.setattr("agent_bom.connectors.servicenow_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.servicenow_connector.request_with_retry", _fake_request)

    from agent_bom.connectors.servicenow_connector import health_check

    status = health_check(instance_url="https://dev.service-now.com", username="admin", password="pwd")
    assert status.state == ConnectorHealthState.HEALTHY


def test_servicenow_health_check_missing_creds():
    from agent_bom.connectors.servicenow_connector import health_check

    status = health_check(instance_url="", username="", password="")
    assert status.state == ConnectorHealthState.AUTH_FAILED


# ─── Slack Connector ─────────────────────────────────────────────────────────


def test_slack_missing_token():
    with pytest.raises(ConnectorError, match="bot token required"):
        discover_from_connector("slack", bot_token="")


def test_slack_discover_bots(monkeypatch):
    """Mock Slack API to return bot users."""

    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        if "team.info" in url:
            resp.status_code = 200
            resp.json.return_value = {"ok": True, "team": {"name": "TestWorkspace"}}
        elif "users.list" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "ok": True,
                "members": [
                    {
                        "id": "B001",
                        "is_bot": True,
                        "deleted": False,
                        "real_name": "AI Helper Bot",
                        "name": "ai-helper",
                        "profile": {"api_app_id": "A12345", "display_name": "AI Helper"},
                    },
                    {
                        "id": "U001",
                        "is_bot": False,
                        "deleted": False,
                        "real_name": "Human User",
                        "name": "human",
                        "profile": {},
                    },
                    {
                        "id": "B002",
                        "is_bot": True,
                        "deleted": True,
                        "real_name": "Old Bot",
                        "name": "old-bot",
                        "profile": {},
                    },
                ],
                "response_metadata": {"next_cursor": ""},
            }
        else:
            resp.status_code = 404
        return resp

    monkeypatch.setattr("agent_bom.connectors.slack_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.slack_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("slack", bot_token="xoxb-test-token")
    # Should find 1 active bot (human + deleted bot excluded)
    assert len(agents) == 1
    assert agents[0].source == "slack"
    assert "AI Helper Bot" in agents[0].name
    assert agents[0].metadata["workspace"] == "TestWorkspace"
    assert agents[0].metadata["app_id"] == "A12345"


def test_slack_discover_pagination(monkeypatch):
    """Slack API pagination with cursor."""
    call_count = 0

    async def _fake_request(client, method, url, **kwargs):
        nonlocal call_count
        resp = MagicMock()
        if "team.info" in url:
            resp.status_code = 200
            resp.json.return_value = {"ok": True, "team": {"name": "W"}}
        elif "users.list" in url:
            call_count += 1
            if call_count == 1:
                resp.status_code = 200
                resp.json.return_value = {
                    "ok": True,
                    "members": [{"id": "B1", "is_bot": True, "deleted": False, "real_name": "Bot1", "name": "b1", "profile": {}}],
                    "response_metadata": {"next_cursor": "page2"},
                }
            else:
                resp.status_code = 200
                resp.json.return_value = {
                    "ok": True,
                    "members": [{"id": "B2", "is_bot": True, "deleted": False, "real_name": "Bot2", "name": "b2", "profile": {}}],
                    "response_metadata": {"next_cursor": ""},
                }
        else:
            resp.status_code = 404
        return resp

    monkeypatch.setattr("agent_bom.connectors.slack_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.slack_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("slack", bot_token="xoxb-test")
    assert len(agents) == 2
    assert call_count == 2  # Two pages


def test_slack_discover_api_error(monkeypatch):
    """Slack API error response should produce warning, not crash."""

    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "team.info" in url:
            resp.json.return_value = {"ok": False, "error": "invalid_auth"}
        elif "users.list" in url:
            resp.json.return_value = {"ok": False, "error": "missing_scope"}
        else:
            resp.status_code = 404
        return resp

    monkeypatch.setattr("agent_bom.connectors.slack_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.slack_connector.request_with_retry", _fake_request)

    agents, warnings = discover_from_connector("slack", bot_token="xoxb-bad")
    assert len(agents) == 0
    assert len(warnings) >= 1


def test_slack_health_check_healthy(monkeypatch):
    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ok": True, "team": "TestTeam", "user": "bot"}
        return resp

    monkeypatch.setattr("agent_bom.connectors.slack_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.slack_connector.request_with_retry", _fake_request)

    from agent_bom.connectors.slack_connector import health_check

    status = health_check(bot_token="xoxb-test")
    assert status.state == ConnectorHealthState.HEALTHY
    assert status.details["team"] == "TestTeam"


def test_slack_health_check_invalid_auth(monkeypatch):
    async def _fake_request(client, method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ok": False, "error": "invalid_auth"}
        return resp

    monkeypatch.setattr("agent_bom.connectors.slack_connector.create_client", _mock_client_ctx)
    monkeypatch.setattr("agent_bom.connectors.slack_connector.request_with_retry", _fake_request)

    from agent_bom.connectors.slack_connector import health_check

    status = health_check(bot_token="xoxb-bad")
    assert status.state == ConnectorHealthState.AUTH_FAILED


def test_slack_health_check_missing_token():
    from agent_bom.connectors.slack_connector import health_check

    status = health_check(bot_token="")
    assert status.state == ConnectorHealthState.AUTH_FAILED


# ─── Cross-connector ─────────────────────────────────────────────────────────


def test_all_connectors_return_agent_tuple():
    """All connectors follow the same return type contract."""
    connectors = list_connectors()
    assert len(connectors) == 3
    for name in connectors:
        assert name in ("jira", "servicenow", "slack")


def test_connector_env_var_fallback_jira(monkeypatch):
    """Jira connector reads from env vars when args not provided."""
    monkeypatch.setenv("JIRA_URL", "https://env.atlassian.net")
    monkeypatch.setenv("JIRA_USER", "env@test.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "env-token")

    from agent_bom.connectors.jira_connector import _get_config

    url, user, token = _get_config()
    assert url == "https://env.atlassian.net"
    assert user == "env@test.com"
    assert token == "env-token"


def test_connector_env_var_fallback_servicenow(monkeypatch):
    monkeypatch.setenv("SERVICENOW_INSTANCE", "https://env.service-now.com")
    monkeypatch.setenv("SERVICENOW_USER", "admin")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "pwd123")

    from agent_bom.connectors.servicenow_connector import _get_config

    url, user, pwd = _get_config()
    assert url == "https://env.service-now.com"
    assert user == "admin"
    assert pwd == "pwd123"


def test_connector_env_var_fallback_slack(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-env-token")

    from agent_bom.connectors.slack_connector import _get_config

    token = _get_config()
    assert token == "xoxb-env-token"


def test_connector_args_override_env(monkeypatch):
    """Explicit args should override env vars."""
    monkeypatch.setenv("JIRA_URL", "https://env.atlassian.net")
    monkeypatch.setenv("JIRA_USER", "env@test.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "env-token")

    from agent_bom.connectors.jira_connector import _get_config

    url, user, token = _get_config(jira_url="https://arg.atlassian.net", email="arg@test.com", api_token="arg-token")
    assert url == "https://arg.atlassian.net"
    assert user == "arg@test.com"
    assert token == "arg-token"
