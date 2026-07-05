from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner

from agent_bom.cli import main


class FakeFindingsClient:
    calls: list[tuple[str, dict[str, Any]]] = []
    init_kwargs: dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        self.__class__.init_kwargs = kwargs

    def close(self) -> None:
        self.__class__.calls.append(("close", {}))

    def ingest_findings(self, findings: list[dict[str, object]], **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("ingest_findings", {"findings": findings, **kwargs}))
        return {"ingested": len(findings), "reconciled": 0}

    def list_findings(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("list_findings", kwargs))
        return {
            "findings": [
                {
                    "id": "finding-1",
                    "severity": "high",
                    "status": "open",
                    "package": "requests",
                    "first_seen": "2026-07-01T00:00:00Z",
                    "last_seen": "2026-07-03T00:00:00Z",
                    "title": "Reachable CVE",
                }
            ],
            "total": 1,
        }

    def list_finding_triage(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("list_finding_triage", kwargs))
        return {
            "triage": [
                {
                    "id": "triage-1",
                    "vulnerability_id": "CVE-2026-0101",
                    "package": "requests",
                    "queue_state": "open",
                    "decision": "under_investigation",
                    "assignee": "secops@example.com",
                }
            ],
            "total": 1,
        }

    def create_finding_triage(self, vulnerability_id: str, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("create_finding_triage", {"vulnerability_id": vulnerability_id, **kwargs}))
        return {"id": "triage-1", "vulnerability_id": vulnerability_id, **kwargs}

    def update_finding_triage_decision(self, triage_id: str, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("update_finding_triage_decision", {"triage_id": triage_id, **kwargs}))
        return {"id": triage_id, **kwargs}

    def export_finding_triage_vex(self) -> dict[str, object]:
        self.__class__.calls.append(("export_finding_triage_vex", {}))
        return {"schema_version": "findings.triage.vex.v1", "count": 1, "vex": {"statements": []}}


def _install_fake_client(monkeypatch) -> type[FakeFindingsClient]:
    FakeFindingsClient.calls = []
    FakeFindingsClient.init_kwargs = {}
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", FakeFindingsClient)
    return FakeFindingsClient


def test_findings_push_ingests_json_file(monkeypatch, tmp_path) -> None:
    fake = _install_fake_client(monkeypatch)
    payload_path = tmp_path / "findings.json"
    payload_path.write_text(
        json.dumps([{"id": "finding-push-1", "severity": "high", "package": "requests"}]),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        [
            "findings",
            "push",
            str(payload_path),
            "--api-url",
            "https://agent-bom.example.com",
            "--api-key",
            "key",
            "--source",
            "ci-trivy",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["ingested"] == 1
    assert fake.calls[0][0] == "ingest_findings"
    assert fake.calls[0][1]["source"] == "ci-trivy"
    assert fake.calls[0][1]["findings"][0]["id"] == "finding-push-1"


def test_findings_list_table_includes_lifecycle_columns(monkeypatch) -> None:
    _install_fake_client(monkeypatch)

    result = CliRunner().invoke(main, ["findings", "list"])

    assert result.exit_code == 0, result.output
    lines = result.output.strip().splitlines()
    assert lines[0].startswith("id\tseverity\tstatus\tpackage\tfirst_seen\tlast_seen\ttitle")
    assert "open" in lines[1]
    assert "2026-07-01T00:00:00Z" in lines[1]


def test_findings_list_outputs_json_and_passes_filters(monkeypatch) -> None:
    fake = _install_fake_client(monkeypatch)

    result = CliRunner().invoke(
        main,
        [
            "findings",
            "list",
            "--api-url",
            "https://agent-bom.example.com",
            "--api-key",
            "key",
            "--tenant",
            "tenant-a",
            "--severity",
            "high",
            "--limit",
            "10",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["findings"][0]["id"] == "finding-1"
    assert fake.init_kwargs["base_url"] == "https://agent-bom.example.com"
    assert fake.init_kwargs["api_key"] == "key"
    assert fake.init_kwargs["tenant_id"] == "tenant-a"
    assert fake.calls[0] == (
        "list_findings",
        {"severity": "high", "sort": "effective_reach", "limit": 10, "offset": 0},
    )


def test_findings_triage_create_and_decide(monkeypatch) -> None:
    fake = _install_fake_client(monkeypatch)
    runner = CliRunner()

    create = runner.invoke(
        main,
        [
            "findings",
            "triage",
            "create",
            "CVE-2026-0101",
            "--package",
            "requests",
            "--assignee",
            "secops@example.com",
            "--reason",
            "needs owner",
        ],
    )
    decide = runner.invoke(
        main,
        [
            "findings",
            "triage",
            "decide",
            "triage-1",
            "--decision",
            "not_affected",
            "--justification",
            "vulnerable_code_not_in_execute_path",
            "--reason",
            "not reachable",
        ],
    )

    assert create.exit_code == 0, create.output
    assert decide.exit_code == 0, decide.output
    assert fake.calls[0] == (
        "create_finding_triage",
        {
            "vulnerability_id": "CVE-2026-0101",
            "package": "requests",
            "server_name": "",
            "assignee": "secops@example.com",
            "queue_state": "open",
            "decision": "under_investigation",
            "justification": None,
            "decision_reason": "needs owner",
            "expires_at": "",
        },
    )
    assert fake.calls[2] == (
        "update_finding_triage_decision",
        {
            "triage_id": "triage-1",
            "decision": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "decision_reason": "not reachable",
            "assignee": None,
            "expires_at": None,
        },
    )


def test_findings_triage_export_vex_writes_file(monkeypatch, tmp_path) -> None:
    fake = _install_fake_client(monkeypatch)
    output = tmp_path / "triage.vex.json"

    result = CliRunner().invoke(main, ["findings", "triage", "export-vex", "-o", str(output)])

    assert result.exit_code == 0, result.output
    assert "Wrote" in result.output
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "findings.triage.vex.v1"
    assert fake.calls[0] == ("export_finding_triage_vex", {})
