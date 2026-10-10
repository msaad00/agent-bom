from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, MCPServer


@pytest.fixture(autouse=True)
def deterministic_doctor_environment(monkeypatch, tmp_path):
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", tmp_path / "no-vulns.db")
    monkeypatch.delenv("AGENT_BOM_DB_STALE_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: object())
    monkeypatch.setattr("agent_bom.discovery.discover_global_configs", lambda **kwargs: [])
    monkeypatch.setattr("agent_bom.cloud_sdk_freshness.cloud_sdk_posture", lambda: {"sdks": []})
    monkeypatch.setattr("agent_bom.cloud_sdk_freshness.cloud_api_deprecation_posture", lambda: {"apis": []})
    monkeypatch.setattr("agent_bom.cloud_sdk_freshness.cloud_sdk_pin_drift", lambda: {"sdks": [], "last_checked": None})


@pytest.mark.parametrize("offline", [False, True])
def test_doctor_counts_visible_sdk_warnings_in_readiness(monkeypatch, offline):
    monkeypatch.setattr(
        "agent_bom.cloud_sdk_freshness.cloud_sdk_posture",
        lambda: {
            "sdks": [
                {
                    "status": "outdated",
                    "installed_version": "1.0",
                    "recommended_floor": "2.0",
                    "distribution": "example-sdk",
                    "provider": "aws",
                }
            ]
        },
    )
    result = CliRunner().invoke(main, ["--agent-mode", "doctor"] + (["--offline"] if offline else []))
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)["data"]
    assert data["warnings"] == 1
    assert data["checks_passed"] is False
    assert data["ready"] is False


@pytest.mark.parametrize("database_variable", ["AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB"])
@pytest.mark.parametrize("agent_mode", [False, True])
def test_offline_doctor_never_probes_network_or_database(monkeypatch, database_variable, agent_mode):
    attempts = []

    def forbidden_probe(*args, **kwargs):
        attempts.append("network or database probe")
        raise AssertionError("offline doctor must not connect")

    monkeypatch.setenv(database_variable, "postgresql://private-user:private-password@private-host/app")
    monkeypatch.setattr("urllib.request.urlopen", forbidden_probe)
    monkeypatch.setattr("socket.socket.connect", forbidden_probe)
    monkeypatch.setattr("agent_bom.storage.postgres_capabilities.probe_postgres_portability", forbidden_probe)
    monkeypatch.setattr("agent_bom.discovery.discover_global_configs", lambda **kwargs: [])
    args = (["--agent-mode"] if agent_mode else []) + ["doctor", "--offline"]

    result = CliRunner().invoke(main, args)

    assert result.exit_code == 0, result.output
    assert attempts == []
    assert "private-password" not in result.output
    assert "private-host" not in result.output
    if agent_mode:
        envelope = json.loads(result.stdout)
        data = envelope["data"]
        assert data["readiness_scope"] == "local_only"
        assert data["ready"] is False  # Skipped probes cannot certify full readiness.
        assert data["checks_passed"] is True
        assert data["postgres_portability"]["status"] == "not_assessed"
        assert data["postgres_portability"]["evidence"] == "offline"
        assert any(row["label"] == "Network" and row["status"] == "info" for row in data["core"])
        assert envelope["summary"]["ready"] is False
    else:
        assert "Local checks complete" in result.output
        assert "not assessed" in result.output
        assert "Ready to scan." not in result.output


def _write_vuln_db(path, *, age_days: int) -> None:
    synced = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE sync_meta (source TEXT PRIMARY KEY, last_synced TEXT, record_count INTEGER)")
    conn.execute("INSERT INTO sync_meta VALUES ('osv', ?, 1200)", (synced,))
    conn.commit()
    conn.close()


@pytest.mark.parametrize(("age_days", "status", "warnings"), [(42, "stale", 1), (2, "fresh", 0)])
def test_offline_doctor_reports_vuln_db_freshness_used_by_scans(monkeypatch, tmp_path, age_days, status, warnings):
    db_path = tmp_path / "vulns.db"
    _write_vuln_db(db_path, age_days=age_days)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db_path)

    result = CliRunner().invoke(main, ["--agent-mode", "doctor", "--offline"])

    assert result.exit_code == 0, result.output
    assert data_warnings(result) == warnings
    assert f"{status} (1,200 records, {age_days}d old; threshold 14d)" in result.stdout


def test_doctor_does_not_warn_when_vuln_db_was_never_synced():
    result = CliRunner().invoke(main, ["--agent-mode", "doctor", "--offline"])

    assert result.exit_code == 0, result.output
    assert data_warnings(result) == 0
    assert "scans query OSV/GHSA/NVD live" in result.stdout


def data_warnings(result) -> int:
    return json.loads(result.stdout)["data"]["warnings"]


def test_offline_doctor_preserves_local_warnings(monkeypatch):
    def failing_discovery(**kwargs):
        raise RuntimeError("private local path")

    monkeypatch.setattr("agent_bom.discovery.discover_global_configs", failing_discovery)
    result = CliRunner().invoke(main, ["--agent-mode", "doctor", "--offline"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)["data"]
    assert data["checks_passed"] is False
    assert data["ready"] is False
    assert data["warnings"] >= 1
    assert "private local path" not in result.output


@pytest.mark.parametrize(
    ("configuration", "label", "value", "status"),
    [
        (
            {"AGENT_BOM_POSTGRES_URL": "postgresql://private-user:private-password@private-host/app"},
            "Control-plane store",
            "postgres — supported",
            "ok",
        ),
        (
            {"SNOWFLAKE_ACCOUNT": "synthetic-account"},
            "Control-plane store",
            "snowflake — experimental; see docs/STORAGE_BACKENDS.md",
            "warn",
        ),
        ({"AGENT_BOM_GRAPH_BACKEND": "neptune"}, "Graph store", "neptune — experimental; see docs/STORAGE_BACKENDS.md", "warn"),
        ({"AGENT_BOM_CLICKHOUSE_URL": "http://clickhouse.local:8123"}, "Analytics sink", "clickhouse — analytics sink", "ok"),
    ],
)
def test_offline_doctor_reports_storage_support_tier(monkeypatch, configuration, label, value, status):
    for name in ("SNOWFLAKE_ACCOUNT", "AGENT_BOM_GRAPH_BACKEND", "AGENT_BOM_CLICKHOUSE_URL", "AGENT_BOM_ANALYTICS_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    for name, setting in configuration.items():
        monkeypatch.setenv(name, setting)

    result = CliRunner().invoke(main, ["--agent-mode", "doctor", "--offline"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)["data"]
    assert {"label": label, "value": value, "status": status} in data["platform"]
    assert data["warnings"] == (1 if status == "warn" else 0)
    assert "private-password" not in result.output


def test_doctor_uses_supported_osv_health_probe(monkeypatch):
    captured: dict[str, object] = {}

    def fake_urlopen(request, *, timeout: int):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["data"] = request.data
        captured["timeout"] = timeout
        return object()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = CliRunner().invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert captured == {
        "url": "https://api.osv.dev/v1/query",
        "method": "POST",
        "data": b'{"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "3.1.4"}',
        "timeout": 5,
    }
    assert "api.osv.dev reachable" in result.output


def test_doctor_groups_output_and_shows_next_steps():
    result = CliRunner().invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert "Core readiness" in result.output
    assert "Runtime surfaces" in result.output
    assert "Platform integrations" in result.output
    assert "Next commands" in result.output
    assert "agent-bom scan --demo --offline" in result.output


def test_doctor_suppresses_raw_discovery_output(monkeypatch):
    def noisy_discovery(*, quiet: bool = False):
        assert quiet is True
        print("raw discovery line before banner")
        return [
            Agent(
                name="Claude Desktop",
                agent_type=AgentType.CLAUDE_DESKTOP,
                config_path="/tmp/claude.json",
                mcp_servers=[MCPServer(name="filesystem"), MCPServer(name="git")],
            )
        ]

    monkeypatch.setattr("agent_bom.discovery.discover_global_configs", noisy_discovery)

    result = CliRunner().invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert "raw discovery line before banner" not in result.output
    assert "agent-bom doctor" in result.output
    assert "MCP discovery" in result.output
    assert "1 client config(s), 2 MCP server(s) (Claude Desktop)" in result.output


def test_doctor_reports_mcp_discovery_error_without_raw_parser_line(monkeypatch):
    def failing_discovery(*, quiet: bool = False):
        assert quiet is True
        print("raw parser warning")
        raise RuntimeError("boom")

    monkeypatch.setattr("agent_bom.discovery.discover_global_configs", failing_discovery)

    result = CliRunner().invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert "raw parser warning" not in result.output
    assert "MCP discovery" in result.output
    assert "discovery error" in result.output
