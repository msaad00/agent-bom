"""Tests for OCSF v1.1 Detection Finding format + syslog transport."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent_bom.siem import (
    SIEMConfig,
    create_connector,
    format_event,
    list_connectors,
    list_formats,
)
from agent_bom.siem.ocsf import (
    SyslogConnector,
    _format_rfc5424,
    _parse_host_port,
    to_ocsf_batch,
    to_ocsf_detection_finding,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample_alert(**overrides) -> dict:
    alert = {
        "type": "runtime_alert",
        "severity": "high",
        "message": "Prompt injection detected in tool call",
        "detector": "scanner:injection",
        "details": {
            "rule_id": "ignore_previous_instructions",
            "excerpt": "ignore a***",
            "confidence": "high",
            "description": "Prompt injection pattern matched in tool arguments",
        },
    }
    alert.update(overrides)
    return alert


# ---------------------------------------------------------------------------
# OCSF field structure
# ---------------------------------------------------------------------------


class TestOCSFFormat:
    def test_class_uid(self):
        ocsf = to_ocsf_detection_finding(_sample_alert())
        assert ocsf["class_uid"] == 2004

    def test_category_uid(self):
        ocsf = to_ocsf_detection_finding(_sample_alert())
        assert ocsf["category_uid"] == 2

    def test_type_uid(self):
        ocsf = to_ocsf_detection_finding(_sample_alert())
        assert ocsf["type_uid"] == 200401

    def test_activity_id(self):
        ocsf = to_ocsf_detection_finding(_sample_alert())
        assert ocsf["activity_id"] == 1

    def test_status_id(self):
        ocsf = to_ocsf_detection_finding(_sample_alert())
        assert ocsf["status_id"] == 1

    def test_time_is_milliseconds(self):
        ocsf = to_ocsf_detection_finding(_sample_alert())
        assert ocsf["time"] > 1_000_000_000_000  # ms since epoch

    def test_finding_info(self):
        ocsf = to_ocsf_detection_finding(_sample_alert())
        fi = ocsf["finding_info"]
        assert fi["title"] == "Prompt injection detected in tool call"
        assert "uid" in fi
        assert isinstance(fi["types"], list)

    def test_metadata_product(self):
        ocsf = to_ocsf_detection_finding(_sample_alert(), product_version="0.40.0")
        meta = ocsf["metadata"]
        assert meta["product"]["name"] == "agent-bom"
        assert meta["product"]["vendor_name"] == "msaad00"
        assert meta["product"]["version"] == "0.40.0"
        assert meta["version"] == "1.1.0"

    def test_evidences(self):
        ocsf = to_ocsf_detection_finding(_sample_alert())
        assert len(ocsf["evidences"]) == 1
        assert "data" in ocsf["evidences"][0]

    def test_empty_details_no_evidences(self):
        alert = _sample_alert(details={})
        ocsf = to_ocsf_detection_finding(alert)
        assert ocsf["evidences"] == []


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_critical(self):
        ocsf = to_ocsf_detection_finding(_sample_alert(severity="critical"))
        assert ocsf["severity_id"] == 5

    def test_high(self):
        ocsf = to_ocsf_detection_finding(_sample_alert(severity="high"))
        assert ocsf["severity_id"] == 4

    def test_medium(self):
        ocsf = to_ocsf_detection_finding(_sample_alert(severity="medium"))
        assert ocsf["severity_id"] == 3

    def test_low(self):
        ocsf = to_ocsf_detection_finding(_sample_alert(severity="low"))
        assert ocsf["severity_id"] == 2

    def test_info(self):
        ocsf = to_ocsf_detection_finding(_sample_alert(severity="info"))
        assert ocsf["severity_id"] == 1

    def test_unknown_defaults_to_medium(self):
        ocsf = to_ocsf_detection_finding(_sample_alert(severity="unknown"))
        assert ocsf["severity_id"] == 3


# ---------------------------------------------------------------------------
# Batch conversion
# ---------------------------------------------------------------------------


class TestOCSFBatch:
    def test_batch_converts_all(self):
        alerts = [_sample_alert(severity=s) for s in ("critical", "high", "low")]
        batch = to_ocsf_batch(alerts, "0.40.0")
        assert len(batch) == 3
        assert all(b["class_uid"] == 2004 for b in batch)

    def test_empty_batch(self):
        assert to_ocsf_batch([]) == []


# ---------------------------------------------------------------------------
# RFC 5424 formatting
# ---------------------------------------------------------------------------


class TestRFC5424:
    def test_format_structure(self):
        msg = _format_rfc5424(1, 4, "agent-bom", "test message")
        # Should start with <PRI>1
        assert msg.startswith("<")
        assert ">1 " in msg
        assert "agent-bom" in msg
        assert "test message" in msg

    def test_pri_calculation(self):
        # facility=1, severity=4 → PRI = 1*8 + 4 = 12
        msg = _format_rfc5424(1, 4, "agent-bom", "test")
        assert msg.startswith("<12>1 ")

    def test_custom_hostname(self):
        msg = _format_rfc5424(1, 4, "agent-bom", "test", hostname="my-host")
        assert "my-host" in msg


# ---------------------------------------------------------------------------
# Host/port parsing
# ---------------------------------------------------------------------------


class TestParseHostPort:
    def test_host_and_port(self):
        assert _parse_host_port("syslog.example.com:1514") == ("syslog.example.com", 1514)

    def test_syslog_scheme(self):
        assert _parse_host_port("syslog://logs.corp.net:514") == ("logs.corp.net", 514)

    def test_tcp_scheme(self):
        assert _parse_host_port("tcp://logs.corp.net:514") == ("logs.corp.net", 514)

    def test_bare_host_defaults_514(self):
        assert _parse_host_port("syslog.example.com") == ("syslog.example.com", 514)


# ---------------------------------------------------------------------------
# SyslogConnector
# ---------------------------------------------------------------------------


class TestSyslogConnector:
    def test_send_event_mock(self):
        config = SIEMConfig(name="syslog", url="syslog://localhost:1514")
        conn = SyslogConnector(config)

        with patch.object(conn, "_send_tcp", return_value=True) as mock_tcp:
            result = conn.send_event(_sample_alert())
            assert result is True
            mock_tcp.assert_called_once()
            sent_msg = mock_tcp.call_args[0][0]
            assert "agent-bom" in sent_msg
            assert "2004" in sent_msg  # class_uid in OCSF JSON

    def test_send_batch(self):
        config = SIEMConfig(name="syslog", url="localhost:514")
        conn = SyslogConnector(config)

        with patch.object(conn, "_send_tcp", return_value=True):
            count = conn.send_batch([_sample_alert(), _sample_alert()])
            assert count == 2

    def test_health_check_success(self):
        config = SIEMConfig(name="syslog", url="localhost:514")
        conn = SyslogConnector(config)

        mock_sock = MagicMock()
        with patch("agent_bom.siem.ocsf.socket.create_connection", return_value=mock_sock):
            assert conn.health_check() is True
            mock_sock.close.assert_called_once()

    def test_health_check_failure(self):
        config = SIEMConfig(name="syslog", url="unreachable:514")
        conn = SyslogConnector(config)

        with patch("agent_bom.siem.ocsf.socket.create_connection", side_effect=ConnectionRefusedError):
            assert conn.health_check() is False


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


class TestRegistryIntegration:
    def test_syslog_in_connector_list(self):
        connectors = list_connectors()
        assert "syslog" in connectors

    def test_create_syslog_connector(self):
        config = SIEMConfig(name="syslog", url="localhost:514")
        conn = create_connector("syslog", config)
        assert isinstance(conn, SyslogConnector)

    def test_format_event_ocsf(self):
        result = format_event(_sample_alert(), fmt="ocsf")
        assert result["class_uid"] == 2004

    def test_format_event_raw_passthrough(self):
        alert = _sample_alert()
        result = format_event(alert, fmt="raw")
        assert result is alert

    def test_list_formats(self):
        fmts = list_formats()
        assert "raw" in fmts
        assert "ocsf" in fmts
