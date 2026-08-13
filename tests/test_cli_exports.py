from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner

from agent_bom.cli import main


class FakeExportClient:
    calls: list[tuple[str, dict[str, Any]]] = []
    init_kwargs: dict[str, Any] = {}
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        self.__class__.init_kwargs = kwargs

    def close(self) -> None:
        self.__class__.calls.append(("close", {}))

    def list_export_destinations(self, **kwargs: Any) -> list[dict[str, object]]:
        self.__class__.calls.append(("list_export_destinations", kwargs))
        return [
            {
                "id": "dest-1",
                "kind": "s3",
                "display_name": "Lake",
                "status": "active",
                "has_secret": False,
                "last_run_status": "success",
                "last_run_at": "2026-08-13T00:00:00+00:00",
            }
        ]

    def create_export_destination(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("create_export_destination", kwargs))
        return {"id": "dest-1", "kind": kwargs.get("kind"), "status": "pending", "has_secret": False}

    def run_export_destination(self, destination_id: str, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("run_export_destination", {"destination_id": destination_id, **kwargs}))
        return {"status": "accepted", "destination_id": destination_id, "run_id": "run-1"}

    def list_export_schedules(self, **kwargs: Any) -> list[dict[str, object]]:
        self.__class__.calls.append(("list_export_schedules", kwargs))
        return [
            {
                "schedule_id": "sch-1",
                "name": "Nightly",
                "cron_expression": "0 3 * * *",
                "destination_id": "dest-1",
                "enabled": True,
                "next_run": "2026-08-14T03:00:00+00:00",
            }
        ]

    def create_export_schedule(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("create_export_schedule", kwargs))
        return {"schedule_id": "sch-1", "name": kwargs.get("name"), "enabled": kwargs.get("enabled")}


def _install_fake(monkeypatch) -> type[FakeExportClient]:
    FakeExportClient.calls = []
    FakeExportClient.init_kwargs = {}
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", FakeExportClient)
    return FakeExportClient


def test_export_destinations_list_table(monkeypatch) -> None:
    _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["export", "destinations", "list"])
    assert result.exit_code == 0, result.output
    assert "1 export destination" in result.output
    lines = result.output.strip().splitlines()
    header = next(line for line in lines if line.startswith("id\t"))
    assert header == "id\tkind\tdisplay_name\tstatus\thas_secret\tlast_run_status\tlast_run_at"
    row = next(line for line in lines if line.startswith("dest-1\t"))
    assert "s3" in row
    assert "active" in row


def test_export_destinations_list_json_is_array(monkeypatch) -> None:
    _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["export", "destinations", "list", "--format", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert data[0]["id"] == "dest-1"


def test_export_destinations_create_sends_config_no_secret(monkeypatch) -> None:
    fake = _install_fake(monkeypatch)
    result = CliRunner().invoke(
        main,
        [
            "export",
            "destinations",
            "create",
            "--kind",
            "s3",
            "--display-name",
            "Lake",
            "--config",
            json.dumps({"bucket": "b", "region": "us-east-1"}),
        ],
    )
    assert result.exit_code == 0, result.output
    name, kwargs = fake.calls[0]
    assert name == "create_export_destination"
    assert kwargs["kind"] == "s3"
    assert kwargs["config"] == {"bucket": "b", "region": "us-east-1"}
    # No per-action credential is accepted by the command.
    assert "secret" not in kwargs


def test_export_destinations_create_rejects_bad_config(monkeypatch) -> None:
    _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["export", "destinations", "create", "--kind", "s3", "--display-name", "Lake", "--config", "[1,2]"])
    assert result.exit_code != 0
    assert "must be a JSON object" in result.output


def test_export_destinations_run_posts_destination_id(monkeypatch) -> None:
    fake = _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["export", "destinations", "run", "dest-1"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["run_id"] == "run-1"
    assert fake.calls[0] == ("run_export_destination", {"destination_id": "dest-1"})


def test_export_schedules_list_table(monkeypatch) -> None:
    _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["export", "schedules", "list"])
    assert result.exit_code == 0, result.output
    assert "1 export schedule" in result.output
    row = next(line for line in result.output.strip().splitlines() if line.startswith("sch-1\t"))
    assert "0 3 * * *" in row
    assert "dest-1" in row


def test_export_schedules_create_passes_cron_and_enabled(monkeypatch) -> None:
    fake = _install_fake(monkeypatch)
    result = CliRunner().invoke(
        main,
        ["export", "schedules", "create", "--name", "Nightly", "--cron", "0 3 * * *", "--destination-id", "dest-1"],
    )
    assert result.exit_code == 0, result.output
    name, kwargs = fake.calls[0]
    assert name == "create_export_schedule"
    assert kwargs["cron_expression"] == "0 3 * * *"
    assert kwargs["destination_id"] == "dest-1"
    assert kwargs["enabled"] is True


def test_export_schedules_create_disabled_flag(monkeypatch) -> None:
    fake = _install_fake(monkeypatch)
    result = CliRunner().invoke(
        main,
        ["export", "schedules", "create", "--name", "N", "--cron", "0 3 * * *", "--destination-id", "dest-1", "--disabled"],
    )
    assert result.exit_code == 0, result.output
    assert fake.calls[0][1]["enabled"] is False


class ConnRefusedClient:
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        pass

    def close(self) -> None:
        pass

    def _refuse(self, *args: Any, **kwargs: Any):
        import httpx

        raise httpx.ConnectError("[Errno 61] Connection refused")

    list_export_destinations = _refuse
    list_export_schedules = _refuse


def test_export_destinations_list_connection_refused_is_friendly(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", ConnRefusedClient)
    result = CliRunner().invoke(main, ["export", "destinations", "list"])
    assert result.exit_code != 0
    assert "Connection refused" not in result.output
    assert "requires the API server" in result.output
