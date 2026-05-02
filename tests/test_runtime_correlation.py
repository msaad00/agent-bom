"""Tests for runtime ↔ scan correlation (agent_bom.runtime_correlation)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from agent_bom.runtime_correlation import (
    CorrelatedFinding,
    CorrelationReport,
    ToolCallRecord,
    _aggregate_calls,
    _compute_amplifier,
    correlate,
    load_audit_log,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_severity(value: str):
    sev = MagicMock()
    sev.value = value
    return sev


def _make_tool(name: str):
    tool = MagicMock()
    tool.name = name
    return tool


def _make_server(name: str):
    server = MagicMock()
    server.name = name
    return server


def _make_agent(name: str):
    agent = MagicMock()
    agent.name = name
    return agent


def _make_blast_radius(
    vuln_id="CVE-2024-0001",
    severity="high",
    cvss_score=7.5,
    epss_score=0.5,
    is_kev=False,
    pkg_name="langchain",
    pkg_version="0.1.0",
    risk_score=6.0,
    tool_names=None,
    server_names=None,
    agent_names=None,
    credentials=None,
):
    br = MagicMock()
    br.vulnerability.id = vuln_id
    br.vulnerability.severity = _make_severity(severity)
    br.vulnerability.cvss_score = cvss_score
    br.vulnerability.epss_score = epss_score
    br.vulnerability.is_kev = is_kev
    br.vulnerability.fixed_version = "0.2.0"
    br.package.name = pkg_name
    br.package.version = pkg_version
    br.risk_score = risk_score
    br.exposed_tools = [_make_tool(n) for n in (tool_names or ["read_file"])]
    br.affected_servers = [_make_server(n) for n in (server_names or ["filesystem-server"])]
    br.affected_agents = [_make_agent(n) for n in (agent_names or ["claude-desktop"])]
    br.exposed_credentials = credentials or []
    return br


def _make_audit_line(tool="read_file", policy="allowed", ts=None):
    return json.dumps(
        {
            "ts": ts or datetime.now(timezone.utc).isoformat(),
            "type": "tools/call",
            "tool": tool,
            "args": {"path": "/tmp/test"},
            "policy": policy,
        }
    )


# ---------------------------------------------------------------------------
# ToolCallRecord & parsing
# ---------------------------------------------------------------------------


class TestLoadAuditLog:
    def test_load_valid_log(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(
            _make_audit_line("read_file")
            + "\n"
            + _make_audit_line("write_file")
            + "\n"
            + _make_audit_line("read_file", policy="blocked")
            + "\n"
        )
        records = load_audit_log(log)
        assert len(records) == 3
        assert records[0].tool_name == "read_file"
        assert records[2].policy_result == "blocked"

    def test_skips_non_tool_call(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({"ts": "2024-01-01", "type": "metrics", "data": {}}) + "\n" + _make_audit_line("read_file") + "\n")
        records = load_audit_log(log)
        assert len(records) == 1

    def test_skips_invalid_json(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text("not json\n" + _make_audit_line("read_file") + "\n")
        records = load_audit_log(log)
        assert len(records) == 1

    def test_skips_invalid_tools_call_records_with_warning(self, tmp_path, caplog):
        log = tmp_path / "audit.jsonl"
        valid = json.loads(_make_audit_line("read_file"))
        invalid_records = [
            {"type": "tools/call", "tool": "missing_ts", "args": {}, "policy": "allowed"},
            {"type": "tools/call", "ts": "2026-04-25T00:00:00Z", "tool": "", "args": {}, "policy": "allowed"},
            {"type": "tools/call", "ts": "2026-04-25T00:00:01Z", "tool": "bad_args", "args": [], "policy": "allowed"},
            {"type": "tools/call", "ts": "2026-04-25T00:00:02Z", "tool": "bad_policy", "args": {}, "policy": "warn"},
        ]
        log.write_text("\n".join(json.dumps(record) for record in [*invalid_records, valid]) + "\n")

        records = load_audit_log(log)

        assert len(records) == 1
        assert records[0].tool_name == "read_file"
        assert caplog.text.count("Skipping invalid proxy tools/call audit record") == 4

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_audit_log("/nonexistent/path.jsonl")


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


class TestAggregation:
    def test_aggregate_counts(self):
        records = [
            ToolCallRecord(timestamp="2024-01-01T00:00:00Z", tool_name="read_file", arguments={}, policy_result="allowed"),
            ToolCallRecord(timestamp="2024-01-01T00:01:00Z", tool_name="read_file", arguments={}, policy_result="allowed"),
            ToolCallRecord(timestamp="2024-01-01T00:02:00Z", tool_name="write_file", arguments={}, policy_result="blocked"),
        ]
        agg = _aggregate_calls(records)
        assert agg["read_file"]["count"] == 2
        assert agg["write_file"]["count"] == 1
        assert agg["write_file"]["was_blocked"] is True
        assert agg["read_file"]["was_blocked"] is False


# ---------------------------------------------------------------------------
# Risk amplification
# ---------------------------------------------------------------------------


class TestRiskAmplification:
    def test_basic_amplifier(self):
        call_info = {"count": 1, "last_called": "2020-01-01T00:00:00Z", "was_blocked": False}
        amp = _compute_amplifier(call_info, is_kev=False)
        assert amp == 1.5  # RISK_AMPLIFIER_CALLED

    def test_frequent_amplifier(self):
        call_info = {"count": 15, "last_called": "2020-01-01T00:00:00Z", "was_blocked": False}
        amp = _compute_amplifier(call_info, is_kev=False)
        assert amp == 2.0  # RISK_AMPLIFIER_FREQUENT

    def test_kev_amplifier(self):
        call_info = {"count": 1, "last_called": "2020-01-01T00:00:00Z", "was_blocked": False}
        amp = _compute_amplifier(call_info, is_kev=True)
        assert amp == 2.5  # RISK_AMPLIFIER_KEV_CALLED

    def test_recent_amplifier(self):
        now = datetime.now(timezone.utc).isoformat()
        call_info = {"count": 1, "last_called": now, "was_blocked": False}
        amp = _compute_amplifier(call_info, is_kev=False)
        assert amp == 1.8  # RISK_AMPLIFIER_RECENT

    def test_max_cap(self):
        now = datetime.now(timezone.utc).isoformat()
        call_info = {"count": 100, "last_called": now, "was_blocked": False}
        amp = _compute_amplifier(call_info, is_kev=True)
        assert amp <= 3.0  # RISK_AMPLIFIER_MAX


# ---------------------------------------------------------------------------
# Core correlation
# ---------------------------------------------------------------------------


class TestCorrelate:
    def test_correlate_finds_called_tools(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_audit_line("read_file") + "\n" + _make_audit_line("read_file") + "\n")
        brs = [_make_blast_radius(tool_names=["read_file", "write_file"])]
        report = correlate(brs, audit_log_path=log)

        assert report.total_tool_calls == 2
        assert report.vulnerable_tools_called == 1
        assert len(report.correlated_findings) == 1
        assert report.correlated_findings[0].tool_name == "read_file"
        assert report.correlated_findings[0].call_count == 2
        assert len(report.uncalled_vulnerable_tools) == 1
        assert report.uncalled_vulnerable_tools[0]["tool_name"] == "write_file"

    def test_correlate_no_audit_log(self):
        brs = [_make_blast_radius()]
        report = correlate(brs)
        assert report.total_tool_calls == 0
        assert report.vulnerable_tools_called == 0

    def test_correlate_no_matches(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_audit_line("safe_tool") + "\n")
        brs = [_make_blast_radius(tool_names=["read_file"])]
        report = correlate(brs, audit_log_path=log)
        assert report.vulnerable_tools_called == 0
        assert len(report.uncalled_vulnerable_tools) == 1

    def test_correlate_risk_amplification(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_audit_line("read_file") + "\n")
        brs = [_make_blast_radius(risk_score=5.0, tool_names=["read_file"])]
        report = correlate(brs, audit_log_path=log)
        finding = report.correlated_findings[0]
        assert finding.correlated_risk_score > finding.original_risk_score
        assert finding.risk_amplifier >= 1.5

    def test_correlate_kev_amplification(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_audit_line("read_file") + "\n")
        brs = [_make_blast_radius(is_kev=True, risk_score=4.0, tool_names=["read_file"])]
        report = correlate(brs, audit_log_path=log)
        finding = report.correlated_findings[0]
        assert finding.risk_amplifier >= 2.5  # KEV + called (additive stacking)

    def test_correlate_sorted_by_risk(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_audit_line("tool_a") + "\n" + _make_audit_line("tool_b") + "\n")
        brs = [
            _make_blast_radius(vuln_id="CVE-LOW", risk_score=2.0, tool_names=["tool_a"]),
            _make_blast_radius(vuln_id="CVE-HIGH", risk_score=8.0, tool_names=["tool_b"]),
        ]
        report = correlate(brs, audit_log_path=log)
        assert report.correlated_findings[0].vulnerability_id == "CVE-HIGH"

    def test_correlate_with_records(self):
        records = [
            ToolCallRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                tool_name="read_file",
                arguments={},
                policy_result="allowed",
            ),
        ]
        brs = [_make_blast_radius(tool_names=["read_file"])]
        report = correlate(brs, audit_records=records)
        assert report.vulnerable_tools_called == 1


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_correlated_finding_to_dict(self):
        f = CorrelatedFinding(
            vulnerability_id="CVE-2024-0001",
            severity="high",
            cvss_score=7.5,
            epss_score=0.5,
            is_kev=False,
            package_name="langchain",
            package_version="0.1.0",
            tool_name="read_file",
            server_name="fs-server",
            call_count=5,
            last_called="2024-01-01T00:00:00Z",
            first_called="2024-01-01T00:00:00Z",
            was_blocked=False,
            risk_amplifier=1.5,
            original_risk_score=6.0,
            correlated_risk_score=9.0,
        )
        d = f.to_dict()
        assert d["vulnerability_id"] == "CVE-2024-0001"
        assert d["call_count"] == 5
        assert d["correlated_risk_score"] == 9.0

    def test_correlation_report_to_dict(self):
        report = CorrelationReport(
            total_tool_calls=10,
            unique_tools_called=3,
            vulnerable_tools_called=1,
            correlated_findings=[],
            uncalled_vulnerable_tools=[],
        )
        d = report.to_dict()
        assert d["total_tool_calls"] == 10
        assert "summary" in d
