from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner

from agent_bom.cli import main


class FakeTicketClient:
    calls: list[tuple[str, dict[str, Any]]] = []
    init_kwargs: dict[str, Any] = {}
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        self.__class__.init_kwargs = kwargs

    def close(self) -> None:
        self.__class__.calls.append(("close", {}))

    def list_tickets(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("list_tickets", kwargs))
        return {
            "schema_version": "ticketing.tickets.v1",
            "tenant_id": "tenant-a",
            "count": 1,
            "tickets": [
                {
                    "id": "tl-1",
                    "provider": "jira",
                    "status": "open",
                    "key": "SEC-42",
                    "external_id": "10042",
                    "connection_id": "conn-1",
                    "url": "https://jira.example.com/browse/SEC-42",
                }
            ],
        }

    def create_ticket(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("create_ticket", kwargs))
        return {"id": "tl-1", "provider": "jira", "key": "SEC-42", "status": "open"}

    def sync_ticket(self, ticket_id: str, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("sync_ticket", {"ticket_id": ticket_id, **kwargs}))
        return {"id": ticket_id, "status": "in_progress"}


def _install_fake(monkeypatch) -> type[FakeTicketClient]:
    FakeTicketClient.calls = []
    FakeTicketClient.init_kwargs = {}
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", FakeTicketClient)
    return FakeTicketClient


def test_ticket_list_table_has_provider_status_key(monkeypatch) -> None:
    _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["ticket", "list"])
    assert result.exit_code == 0, result.output
    assert "1 ticket (tenant tenant-a)" in result.output
    lines = result.output.strip().splitlines()
    header = next(line for line in lines if line.startswith("id\t"))
    assert header == "id\tprovider\tstatus\tkey\texternal_id\tconnection\turl"
    row = next(line for line in lines if line.startswith("tl-1\t"))
    assert "jira" in row
    assert "open" in row
    assert "SEC-42" in row
    assert "conn-1" in row


def test_ticket_list_json_passes_client_args(monkeypatch) -> None:
    fake = _install_fake(monkeypatch)
    result = CliRunner().invoke(
        main,
        ["ticket", "list", "--api-url", "https://abom.example.com", "--api-key", "key", "--tenant", "tenant-a", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["tickets"][0]["id"] == "tl-1"
    assert fake.init_kwargs["base_url"] == "https://abom.example.com"
    assert fake.init_kwargs["api_key"] == "key"
    assert fake.init_kwargs["tenant_id"] == "tenant-a"
    assert fake.calls[0][0] == "list_tickets"


def test_ticket_create_reads_finding_file_and_passes_no_credential(monkeypatch, tmp_path) -> None:
    fake = _install_fake(monkeypatch)
    finding_file = tmp_path / "finding.json"
    finding_file.write_text(json.dumps({"vulnerability_id": "CVE-2024-1", "package": "left-pad", "severity": "high"}))
    result = CliRunner().invoke(
        main,
        ["ticket", "create", "--finding-file", str(finding_file), "--connection-id", "conn-1", "--project", "SEC"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["key"] == "SEC-42"
    name, kwargs = fake.calls[0]
    assert name == "create_ticket"
    assert kwargs["finding"]["vulnerability_id"] == "CVE-2024-1"
    assert kwargs["connection_id"] == "conn-1"
    assert kwargs["project"] == "SEC"
    # Connect-once: no credential/token/base-URL is ever an argument.
    assert not any(k in kwargs for k in ("secret", "token", "api_token", "endpoint", "url"))


def test_ticket_create_rejects_non_object_finding(monkeypatch, tmp_path) -> None:
    _install_fake(monkeypatch)
    finding_file = tmp_path / "finding.json"
    finding_file.write_text(json.dumps(["not", "an", "object"]))
    result = CliRunner().invoke(main, ["ticket", "create", "--finding-file", str(finding_file)])
    assert result.exit_code != 0
    assert "single JSON object" in result.output


def test_ticket_sync_posts_ticket_id(monkeypatch) -> None:
    fake = _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["ticket", "sync", "tl-1"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "in_progress"
    assert fake.calls[0] == ("sync_ticket", {"ticket_id": "tl-1"})


class ConnRefusedClient:
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        pass

    def close(self) -> None:
        pass

    def _refuse(self, *args: Any, **kwargs: Any):
        import httpx

        raise httpx.ConnectError("[Errno 61] Connection refused")

    list_tickets = _refuse
    create_ticket = _refuse
    sync_ticket = _refuse


def test_ticket_list_connection_refused_is_friendly(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", ConnRefusedClient)
    result = CliRunner().invoke(main, ["ticket", "list"])
    assert result.exit_code != 0
    assert "Connection refused" not in result.output
    assert "requires the API server" in result.output
