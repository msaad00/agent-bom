from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner

from agent_bom.cli import main


class FakeCampaignsClient:
    calls: list[tuple[str, dict[str, Any]]] = []
    init_kwargs: dict[str, Any] = {}
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        self.__class__.init_kwargs = kwargs

    def close(self) -> None:
        self.__class__.calls.append(("close", {}))

    def list_campaigns(self, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("list_campaigns", kwargs))
        return {
            "schema_version": "risk-campaigns.v1",
            "tenant_id": "tenant-a",
            "count": 1,
            "campaigns": [
                {
                    "id": "camp-1",
                    "title": "Reachable RCE cluster",
                    "finding_count": 4,
                    "severity": "critical",
                    "priority_score": 92.5,
                    "owner": "secops@example.com",
                    "sla_due_at": "2026-08-31T00:00:00+00:00",
                    "state": "in_progress",
                    "verification_status": "unverified",
                    "version": 3,
                }
            ],
            "total_findings": 12,
        }

    def verify_campaign(self, campaign_id: str, **kwargs: Any) -> dict[str, object]:
        self.__class__.calls.append(("verify_campaign", {"campaign_id": campaign_id, **kwargs}))
        return {
            "schema_version": "risk-campaign-verification.v1",
            "campaign_id": campaign_id,
            "verification_status": "verified",
            "state": "done",
            "remaining_count": 0,
            "remaining_finding_ids": [],
            "version": 4,
        }


def _install_fake(monkeypatch) -> type[FakeCampaignsClient]:
    FakeCampaignsClient.calls = []
    FakeCampaignsClient.init_kwargs = {}
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", FakeCampaignsClient)
    return FakeCampaignsClient


def test_campaigns_list_table_has_owner_sla_priority_status(monkeypatch) -> None:
    _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["campaigns", "list"])
    assert result.exit_code == 0, result.output
    # Leads with a summary line (dense, cloud-CLI readability pattern).
    assert "1 campaign" in result.output
    lines = result.output.strip().splitlines()
    header = next(line for line in lines if line.startswith("id\t"))
    assert header == "id\tpriority\tseverity\tstate\tverification\towner\tsla_due_at\tfindings\ttitle"
    row = next(line for line in lines if line.startswith("camp-1\t"))
    assert "92.5" in row
    assert "critical" in row
    assert "in_progress" in row
    assert "unverified" in row
    assert "secops@example.com" in row
    assert "2026-08-31T00:00:00+00:00" in row
    assert "Reachable RCE cluster" in row


def test_campaigns_list_json_and_passes_client_args(monkeypatch) -> None:
    fake = _install_fake(monkeypatch)
    result = CliRunner().invoke(
        main,
        [
            "campaigns",
            "list",
            "--api-url",
            "https://agent-bom.example.com",
            "--api-key",
            "key",
            "--tenant",
            "tenant-a",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["campaigns"][0]["id"] == "camp-1"
    assert fake.init_kwargs["base_url"] == "https://agent-bom.example.com"
    assert fake.init_kwargs["api_key"] == "key"
    assert fake.init_kwargs["tenant_id"] == "tenant-a"
    assert fake.calls[0][0] == "list_campaigns"


def test_campaigns_verify_posts_version(monkeypatch) -> None:
    fake = _install_fake(monkeypatch)
    result = CliRunner().invoke(main, ["campaigns", "verify", "camp-1", "--version", "3"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["verification_status"] == "verified"
    assert fake.calls[0] == ("verify_campaign", {"campaign_id": "camp-1", "version": 3})


class ConnRefusedClient:
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        pass

    def close(self) -> None:
        pass

    def _refuse(self, *args: Any, **kwargs: Any):
        import httpx

        raise httpx.ConnectError("[Errno 61] Connection refused")

    list_campaigns = _refuse
    verify_campaign = _refuse


def test_campaigns_list_connection_refused_is_friendly(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", ConnRefusedClient)
    result = CliRunner().invoke(main, ["campaigns", "list"])
    assert result.exit_code != 0
    assert "Connection refused" not in result.output
    assert "requires the API server" in result.output
    assert "agent-bom api" in result.output
