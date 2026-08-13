from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner

from agent_bom.cli import main


class FakeGraphClient:
    calls: list[tuple[str, dict[str, Any]]] = []
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        pass

    def close(self) -> None:
        self.__class__.calls.append(("close", {}))

    def attack_paths(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("attack_paths", kwargs))
        return {
            "scan_id": "scan-9",
            "attack_paths": [
                {
                    "source": "internet",
                    "target": "db-prod",
                    "hops": ["internet", "web", "db-prod"],
                    "composite_risk": 88.0,
                    "summary": "Internet to prod database",
                    "vuln_ids": ["CVE-2026-1"],
                    "mitre_technique_ids": ["T1190"],
                }
            ],
            "pagination": {"total": 3, "offset": 0, "limit": 20},
        }

    def exposure_paths(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("exposure_paths", kwargs))
        return {
            "scan_id": "scan-9",
            "total": 5,
            "count": 1,
            "paths": [
                {
                    "rank": 1,
                    "riskScore": 74.0,
                    "severity": "high",
                    "summary": "Agent reaches shell tool",
                    "source": {"label": "agent-x"},
                    "target": {"label": "shell-tool"},
                    "hops": [{"label": "agent-x"}, {"label": "identity-y"}, {"label": "shell-tool"}],
                }
            ],
        }


def _install(monkeypatch) -> type[FakeGraphClient]:
    FakeGraphClient.calls = []
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", FakeGraphClient)
    return FakeGraphClient


def test_graph_paths_attack_table(monkeypatch) -> None:
    fake = _install(monkeypatch)
    result = CliRunner().invoke(main, ["graph-paths", "attack", "--scan-id", "scan-9", "--limit", "20"])
    assert result.exit_code == 0, result.output
    assert "1 of 3 attack paths" in result.output
    lines = result.output.strip().splitlines()
    header = next(line for line in lines if line.startswith("#\t"))
    assert header == "#\trisk\tsource\ttarget\thops\ttechniques\tsummary"
    row = next(line for line in lines if line.startswith("1\t"))
    assert "88" in row
    assert "internet" in row
    assert "db-prod" in row
    assert "T1190" in row
    assert fake.calls[0] == ("attack_paths", {"scan_id": "scan-9", "offset": 0, "limit": 20})


def test_graph_paths_exposure_table(monkeypatch) -> None:
    fake = _install(monkeypatch)
    result = CliRunner().invoke(main, ["graph-paths", "exposure", "--scan-id", "scan-9", "--min-risk", "10"])
    assert result.exit_code == 0, result.output
    assert "1 of 5 exposure paths" in result.output
    lines = result.output.strip().splitlines()
    header = next(line for line in lines if line.startswith("rank\t"))
    assert header == "rank\trisk\tseverity\tsource\ttarget\thops\tsummary"
    row = next(line for line in lines if line.startswith("1\t"))
    assert "74" in row
    assert "agent-x" in row
    assert "shell-tool" in row
    assert fake.calls[0] == ("exposure_paths", {"scan_id": "scan-9", "limit": 20, "min_risk": 10.0})


def test_graph_paths_attack_json(monkeypatch) -> None:
    _install(monkeypatch)
    result = CliRunner().invoke(main, ["graph-paths", "attack", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["attack_paths"][0]["target"] == "db-prod"


class ConnRefusedClient:
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        pass

    def close(self) -> None:
        pass

    def _refuse(self, *args: Any, **kwargs: Any):
        import httpx

        raise httpx.ConnectError("[Errno 61] Connection refused")

    attack_paths = _refuse
    exposure_paths = _refuse


def test_graph_paths_connection_refused_is_friendly(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", ConnRefusedClient)
    result = CliRunner().invoke(main, ["graph-paths", "attack"])
    assert result.exit_code != 0
    assert "Connection refused" not in result.output
    assert "requires the API server" in result.output
