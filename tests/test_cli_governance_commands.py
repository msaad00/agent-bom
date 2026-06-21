"""CLI tests for the human-facing governance / FinOps posture commands.

Covers the new ``cost``, ``identity``, and ``cloud inventory`` commands that
expose API-only governance capabilities to humans. Each command must run,
exit 0, render a compact summary, emit valid JSON under ``--format json``,
and degrade to a clean status (not a crash) when a gated capability is off.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from agent_bom.api.access_review import (
    create_campaign,
    get_access_review_store,
    set_access_review_store,
)
from agent_bom.api.cost_store import LLMCostRecord, get_cost_store, set_cost_store
from agent_bom.cli import main


@pytest.fixture(autouse=True)
def _reset_stores():
    """Each test starts from fresh in-memory cost + access-review stores."""
    set_cost_store(None)
    set_access_review_store(None)
    yield
    set_cost_store(None)
    set_access_review_store(None)


@pytest.fixture(autouse=True)
def _discovery_off(monkeypatch):
    """Default the NHI discovery + cloud inventory flags OFF for gated-path tests."""
    for flag in (
        "AGENT_BOM_OKTA_DISCOVERY",
        "AGENT_BOM_ENTRA_DISCOVERY",
        "AGENT_BOM_CLOUD_INVENTORY",
        "AGENT_BOM_AZURE_INVENTORY",
        "AGENT_BOM_GCP_INVENTORY",
    ):
        monkeypatch.delenv(flag, raising=False)


def _seed_cost_records():
    store = get_cost_store()
    store.record_cost(
        LLMCostRecord(
            tenant_id="default",
            call_id="c1",
            agent="planner",
            session_id="s1",
            provider="openai",
            model="gpt-4o",
            input_tokens=100,
            output_tokens=50,
            cost_usd=1.25,
            priced=True,
            observed_at="2026-06-20T00:00:00+00:00",
            cost_center="research",
            allocation_tags={"team": "ml"},
        )
    )


# ── cost forecast ──────────────────────────────────────────────────────────


def test_cost_forecast_runs_compact():
    result = CliRunner().invoke(main, ["cost", "forecast"])
    assert result.exit_code == 0
    assert "LLM spend forecast" in result.output
    assert "status" in result.output


def test_cost_forecast_json_valid():
    _seed_cost_records()
    result = CliRunner().invoke(main, ["cost", "forecast", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["tenant_id"] == "default"
    assert "status" in payload
    assert "burn_rate_usd_per_day" in payload


# ── cost allocation / chargeback ───────────────────────────────────────────


def test_cost_allocation_runs_compact():
    _seed_cost_records()
    result = CliRunner().invoke(main, ["cost", "allocation"])
    assert result.exit_code == 0
    assert "LLM spend allocation" in result.output
    assert "By cost center" in result.output
    assert "research" in result.output


def test_cost_allocation_json_valid_with_tag():
    _seed_cost_records()
    result = CliRunner().invoke(main, ["cost", "allocation", "--tag", "team", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["total_calls"] == 1
    assert "by_cost_center" in payload
    assert payload["tag_rollup"]["tag_key"] == "team"


def test_cost_chargeback_alias_runs():
    result = CliRunner().invoke(main, ["cost", "chargeback"])
    assert result.exit_code == 0
    assert "LLM spend allocation" in result.output


# ── identity credential-expiry ─────────────────────────────────────────────


def test_credential_expiry_runs_compact():
    result = CliRunner().invoke(main, ["identity", "credential-expiry"])
    assert result.exit_code == 0
    assert "Credential expiry posture" in result.output


def test_credential_expiry_json_valid_and_no_secrets():
    result = CliRunner().invoke(main, ["identity", "credential-expiry", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["secret_values_included"] is False
    assert "status" in payload
    assert "credentials" in payload


# ── identity discover (gated) ──────────────────────────────────────────────


def test_identity_discover_gated_off_shows_disabled():
    result = CliRunner().invoke(main, ["identity", "discover"])
    assert result.exit_code == 0
    assert "disabled" in result.output.lower()
    assert "AGENT_BOM_OKTA_DISCOVERY" in result.output


def test_identity_discover_json_valid_when_disabled():
    result = CliRunner().invoke(main, ["identity", "discover", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["count"] == 0
    assert all(p["status"] == "disabled" for p in payload["providers"])
    # Provider labels are filled in from the request order even when empty.
    assert {p["provider"] for p in payload["providers"]} == {"okta", "entra"}


# ── identity access-review ─────────────────────────────────────────────────


def test_access_review_list_empty():
    result = CliRunner().invoke(main, ["identity", "access-review"])
    assert result.exit_code == 0
    assert "Access-review campaigns" in result.output
    assert "No access-review campaigns" in result.output


def test_access_review_list_and_get_one():
    store = get_access_review_store()
    campaign, _items = create_campaign(
        store,
        tenant_id="default",
        name="Q3 recert",
        subjects=[
            {
                "id": "okta:sa1",
                "name": "svc-deploy",
                "identity_type": "service_account",
                "permissions": ["repo:write"],
                "privileged": True,
            }
        ],
        created_by="cli-test",
        due_days=14,
    )

    listed = CliRunner().invoke(main, ["identity", "access-review"])
    assert listed.exit_code == 0
    assert "Q3 recert" in listed.output

    got = CliRunner().invoke(main, ["identity", "access-review", "--campaign", campaign.campaign_id, "--format", "json"])
    assert got.exit_code == 0
    payload = json.loads(got.output)
    assert payload["found"] is True
    assert payload["campaign"]["name"] == "Q3 recert"
    assert payload["count"] == 1


def test_access_review_get_missing_is_clean():
    result = CliRunner().invoke(main, ["identity", "access-review", "--campaign", "does-not-exist", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["found"] is False


# ── cloud inventory (gated) ────────────────────────────────────────────────


def test_cloud_inventory_gated_off_shows_disabled():
    result = CliRunner().invoke(main, ["cloud", "inventory"])
    assert result.exit_code == 0
    assert "disabled" in result.output.lower()
    assert "AGENT_BOM_CLOUD_INVENTORY" in result.output


def test_cloud_inventory_json_valid_when_disabled():
    result = CliRunner().invoke(main, ["cloud", "inventory", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    providers = {p["provider"]: p["status"] for p in payload["providers"]}
    assert providers == {"aws": "disabled", "azure": "disabled", "gcp": "disabled"}


def test_cloud_inventory_single_provider():
    result = CliRunner().invoke(main, ["cloud", "inventory", "--provider", "aws", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert len(payload["providers"]) == 1
    assert payload["providers"][0]["provider"] == "aws"
