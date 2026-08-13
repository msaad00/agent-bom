from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner

from agent_bom.cli import main


class FakeComplianceClient:
    calls: list[tuple[str, dict[str, Any]]] = []
    status = "pass"
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        pass

    def close(self) -> None:
        self.__class__.calls.append(("close", {}))

    def compliance_framework(self, framework: str, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("compliance_framework", {"framework": framework, **kwargs}))
        return {
            "framework": framework,
            "status": self.__class__.status,
            "score": 87.5,
            "summary": {"pass": 7, "warning": 1, "fail": 2 if self.__class__.status == "fail" else 0},
            "evaluated_controls": 10,
            "total_controls": 12,
            "controls": [],
        }


def _install(monkeypatch, status: str) -> type[FakeComplianceClient]:
    FakeComplianceClient.calls = []
    FakeComplianceClient.status = status
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", FakeComplianceClient)
    return FakeComplianceClient


def test_compliance_eval_pass_exits_zero_and_prints_posture(monkeypatch) -> None:
    fake = _install(monkeypatch, "pass")
    result = CliRunner().invoke(main, ["compliance", "eval", "--framework", "soc2"])
    assert result.exit_code == 0, result.output
    assert "soc2" in result.output
    assert "PASS" in result.output.upper()
    assert "87.5" in result.output
    assert fake.calls[0] == ("compliance_framework", {"framework": "soc2"})


def test_compliance_eval_fail_exits_nonzero(monkeypatch) -> None:
    _install(monkeypatch, "fail")
    result = CliRunner().invoke(main, ["compliance", "eval", "--framework", "cis"])
    assert result.exit_code != 0, result.output
    assert "FAIL" in result.output.upper()


def test_compliance_eval_fail_exit_zero_escape_hatch(monkeypatch) -> None:
    _install(monkeypatch, "fail")
    result = CliRunner().invoke(main, ["compliance", "eval", "--framework", "cis", "--exit-zero"])
    assert result.exit_code == 0, result.output
    assert "FAIL" in result.output.upper()


def test_compliance_eval_no_data_does_not_imply_pass(monkeypatch) -> None:
    _install(monkeypatch, "no_data")
    result = CliRunner().invoke(main, ["compliance", "eval", "--framework", "soc2"])
    # no_data is not a failure, but must never render as a pass.
    assert result.exit_code == 0, result.output
    assert "NO_DATA" in result.output.upper() or "NO DATA" in result.output.upper()


def test_compliance_eval_json(monkeypatch) -> None:
    _install(monkeypatch, "pass")
    result = CliRunner().invoke(main, ["compliance", "eval", "--framework", "soc2", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "pass"


class ConnRefusedClient:
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        pass

    def close(self) -> None:
        pass

    def compliance_framework(self, *args: Any, **kwargs: Any):
        import httpx

        raise httpx.ConnectError("[Errno 61] Connection refused")


def test_compliance_eval_connection_refused_is_friendly(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", ConnRefusedClient)
    result = CliRunner().invoke(main, ["compliance", "eval", "--framework", "soc2"])
    assert result.exit_code != 0
    assert "Connection refused" not in result.output
    assert "requires the API server" in result.output
