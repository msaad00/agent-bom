"""Tests for SIEM push — wiring blast_radii findings to SIEM connectors.

Tests cover:
- SIEMConfig and create_connector factory
- SplunkHEC, DatadogLogs, ElasticsearchConnector send_event / send_batch
- format_event with 'raw' and 'ocsf' formats
- create_from_env auto-configuration
- list_connectors / list_formats
- Graceful failure (connector.send_event returns False on HTTP error)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.siem import (
    DatadogLogs,
    ElasticsearchConnector,
    SIEMConfig,
    SplunkHEC,
    create_connector,
    create_from_env,
    format_event,
    list_connectors,
    list_formats,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def splunk_config() -> SIEMConfig:
    return SIEMConfig(name="splunk", url="http://splunk.test:8088", token="splunk-token-123", index="main")


@pytest.fixture()
def datadog_config() -> SIEMConfig:
    return SIEMConfig(name="datadog", url="", token="dd-api-key-abc")


@pytest.fixture()
def elastic_config() -> SIEMConfig:
    return SIEMConfig(name="elasticsearch", url="http://elastic.test:9200", token="es-token", index="agent-bom-alerts")


@pytest.fixture()
def sample_event() -> dict:
    return {
        "type": "scan_alert",
        "severity": "high",
        "message": "CVE-2025-1234 in flask@1.0.0",
        "vulnerability_id": "CVE-2025-1234",
        "package": "flask",
        "version": "1.0.0",
        "ecosystem": "pypi",
        "is_kev": False,
        "affected_agents": ["agent1"],
        "exposed_credentials": [],
    }


# ─── create_connector ─────────────────────────────────────────────────────────


def test_create_splunk_connector(splunk_config):
    connector = create_connector("splunk", splunk_config)
    assert isinstance(connector, SplunkHEC)


def test_create_datadog_connector(datadog_config):
    connector = create_connector("datadog", datadog_config)
    assert isinstance(connector, DatadogLogs)


def test_create_elasticsearch_connector(elastic_config):
    connector = create_connector("elasticsearch", elastic_config)
    assert isinstance(connector, ElasticsearchConnector)


def test_create_opensearch_connector(elastic_config):
    connector = create_connector("opensearch", elastic_config)
    assert isinstance(connector, ElasticsearchConnector)


def test_create_unknown_connector_raises():
    config = SIEMConfig(name="unknown", url="http://test")
    with pytest.raises(ValueError, match="Unknown SIEM connector"):
        create_connector("unknown-siem", config)


# ─── list_connectors / list_formats ───────────────────────────────────────────


def test_list_connectors_returns_known_types():
    connectors = list_connectors()
    assert "splunk" in connectors
    assert "datadog" in connectors
    assert "elasticsearch" in connectors
    assert "opensearch" in connectors
    assert "syslog" in connectors


def test_list_formats():
    formats = list_formats()
    assert "raw" in formats
    assert "ocsf" in formats


# ─── format_event ─────────────────────────────────────────────────────────────


def test_format_raw_passthrough(sample_event):
    result = format_event(sample_event, "raw")
    assert result == sample_event


def test_format_ocsf_has_class_uid(sample_event):
    result = format_event(sample_event, "ocsf")
    assert "class_uid" in result
    assert result["class_uid"] == 2004  # OCSF Detection Finding


def test_format_ocsf_has_severity(sample_event):
    result = format_event(sample_event, "ocsf")
    assert "severity_id" in result


def test_format_ocsf_has_timestamp(sample_event):
    result = format_event(sample_event, "ocsf")
    assert "time" in result or "start_time" in result or "metadata" in result


# ─── SplunkHEC.send_event ─────────────────────────────────────────────────────


def test_splunk_send_event_success(splunk_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        connector = SplunkHEC(splunk_config)
        result = connector.send_event(sample_event)

    assert result is True
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert "Splunk splunk-token-123" in call_kwargs.kwargs.get("headers", {}).get("Authorization", "")


def test_splunk_send_event_failure(splunk_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 400

    with patch("httpx.post", return_value=mock_resp):
        connector = SplunkHEC(splunk_config)
        result = connector.send_event(sample_event)

    assert result is False


def test_splunk_send_event_network_error(splunk_config, sample_event):
    with patch("httpx.post", side_effect=ConnectionError("refused")):
        connector = SplunkHEC(splunk_config)
        result = connector.send_event(sample_event)

    assert result is False


def test_splunk_send_batch(splunk_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.post", return_value=mock_resp):
        connector = SplunkHEC(splunk_config)
        n = connector.send_batch([sample_event, dict(sample_event)])

    assert n == 2


def test_splunk_index_included_in_payload(splunk_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        SplunkHEC(splunk_config).send_event(sample_event)

    call_kwargs = mock_post.call_args.kwargs
    payload = call_kwargs.get("json", {})
    assert payload.get("index") == "main"


def test_splunk_health_check_success(splunk_config):
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.get", return_value=mock_resp):
        result = SplunkHEC(splunk_config).health_check()

    assert result is True


def test_splunk_health_check_failure(splunk_config):
    with patch("httpx.get", side_effect=ConnectionError):
        result = SplunkHEC(splunk_config).health_check()

    assert result is False


# ─── DatadogLogs.send_event ───────────────────────────────────────────────────


def test_datadog_send_event_success(datadog_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 202

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        connector = DatadogLogs(datadog_config)
        result = connector.send_event(sample_event)

    assert result is True
    headers = mock_post.call_args.kwargs.get("headers", {})
    assert headers.get("DD-API-KEY") == "dd-api-key-abc"


def test_datadog_send_event_failure(datadog_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 403

    with patch("httpx.post", return_value=mock_resp):
        result = DatadogLogs(datadog_config).send_event(sample_event)

    assert result is False


def test_datadog_send_event_network_error(datadog_config, sample_event):
    with patch("httpx.post", side_effect=ConnectionError("refused")):
        result = DatadogLogs(datadog_config).send_event(sample_event)

    assert result is False


# ─── ElasticsearchConnector.send_event ────────────────────────────────────────


def test_elastic_send_event_success(elastic_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 201

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        connector = ElasticsearchConnector(elastic_config)
        result = connector.send_event(sample_event)

    assert result is True
    url = mock_post.call_args.args[0]
    assert "agent-bom-alerts" in url


def test_elastic_send_event_adds_timestamp(elastic_config, sample_event):
    sent_payload = {}

    def _capture_post(url, *, json=None, **kwargs):
        sent_payload.update(json or {})
        m = MagicMock()
        m.status_code = 201
        return m

    with patch("httpx.post", side_effect=_capture_post):
        ElasticsearchConnector(elastic_config).send_event(sample_event)

    assert "@timestamp" in sent_payload


def test_elastic_bearer_token_in_headers(elastic_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 201

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        ElasticsearchConnector(elastic_config).send_event(sample_event)

    headers = mock_post.call_args.kwargs.get("headers", {})
    assert "Bearer es-token" in headers.get("Authorization", "")


def test_elastic_send_event_failure(elastic_config, sample_event):
    mock_resp = MagicMock()
    mock_resp.status_code = 500

    with patch("httpx.post", return_value=mock_resp):
        result = ElasticsearchConnector(elastic_config).send_event(sample_event)

    assert result is False


# ─── create_from_env ──────────────────────────────────────────────────────────


def test_create_from_env_returns_none_when_no_type():
    with patch.dict("os.environ", {}, clear=True):
        result = create_from_env()
    assert result is None


def test_create_from_env_splunk(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SIEM_TYPE", "splunk")
    monkeypatch.setenv("AGENT_BOM_SIEM_URL", "http://splunk:8088")
    monkeypatch.setenv("AGENT_BOM_SIEM_TOKEN", "hec-token")
    monkeypatch.setenv("AGENT_BOM_SIEM_INDEX", "main")

    connector = create_from_env()
    assert isinstance(connector, SplunkHEC)


def test_create_from_env_elasticsearch(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SIEM_TYPE", "elasticsearch")
    monkeypatch.setenv("AGENT_BOM_SIEM_URL", "http://elastic:9200")
    monkeypatch.setenv("AGENT_BOM_SIEM_TOKEN", "es-token")

    connector = create_from_env()
    assert isinstance(connector, ElasticsearchConnector)


# ─── SIEMConfig ───────────────────────────────────────────────────────────────


def test_siem_config_defaults():
    config = SIEMConfig(name="splunk", url="http://test")
    assert config.token == ""
    assert config.index == ""
    assert config.source_type == "agent-bom"
    assert config.verify_ssl is True


def test_siem_config_custom_values():
    config = SIEMConfig(name="splunk", url="http://test", token="tok", index="idx", verify_ssl=False)
    assert config.token == "tok"
    assert config.index == "idx"
    assert config.verify_ssl is False
