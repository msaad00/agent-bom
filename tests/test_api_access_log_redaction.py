"""Both API launchers must remove request queries before access-log formatting."""

import copy
import logging.config
from unittest.mock import patch

import pytest
import uvicorn
from click.testing import CliRunner

from agent_bom.cli._server import api_cmd, serve_cmd


@pytest.mark.parametrize("command", [api_cmd, serve_cmd])
def test_api_access_logging_omits_query_credentials(command, monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY_FILE", str(tmp_path / "connections.key"))
    monkeypatch.setenv("AGENT_BOM_NO_AUTO_CONNECTIONS_KEY", "1")
    with patch("agent_bom.api.server.configure_api"), patch("uvicorn.run") as run:
        result = CliRunner().invoke(command, ["--api-key", "synthetic-test-only-key"])
    assert result.exit_code == 0, result.output
    config = run.call_args.kwargs.get("log_config", uvicorn.config.LOGGING_CONFIG)
    # Exercise the actual formatter/filter configuration without changing the
    # test process's global logging handlers.
    configuration = logging.config.DictConfigurator(copy.deepcopy(config))
    for name, definition in configuration.config.get("formatters", {}).items():
        configuration.config["formatters"][name] = configuration.configure_formatter(definition)
    for name, definition in configuration.config.get("filters", {}).items():
        configuration.config["filters"][name] = configuration.configure_filter(definition)
    handler = configuration.configure_handler(configuration.config["handlers"]["access"])
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        "",
        0,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1234", "GET", "/v1/jobs?api_key=synthetic-query-secret&limit=20", "1.1", 401),
        None,
    )
    handler.filter(record)
    rendered = handler.format(record)
    assert "synthetic-query-secret" not in rendered
    assert "GET /v1/jobs HTTP/1.1" in rendered
    assert "401" in rendered


def test_access_log_config_preserves_uvicorn_defaults():
    from agent_bom.logging_config import AccessLogPathFilter, api_log_config

    before = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)
    configured = api_log_config(uvicorn.config.LOGGING_CONFIG)
    assert uvicorn.config.LOGGING_CONFIG == before
    assert configured["handlers"]["access"]["filters"] == ["access_path"]
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d', ("127.0.0.1:1234", "GET", "/v1/jobs", "1.1", 200), None
    )
    original = record.getMessage()
    assert AccessLogPathFilter().filter(record)
    assert record.getMessage() == original
