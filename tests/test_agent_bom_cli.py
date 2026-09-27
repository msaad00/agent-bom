"""User-facing single-agent export and offline validation contracts."""

import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.evidence.agent_bom import build_agent_bom, validate_agent_bom_json
from agent_bom.models import Agent, AgentType, MCPServer


def agents():
    return [
        Agent(name="same-name", agent_type=AgentType.CUSTOM, source_id=key, config_path="", mcp_servers=[MCPServer(name=key)])
        for key in ("a", "b")
    ]


def test_exact_agent_selection_and_file_roundtrip(monkeypatch, tmp_path):
    rows = agents()
    monkeypatch.setattr("agent_bom.cli._agent_manifest._discover_manifest_agents", lambda *args: rows)
    dest = tmp_path / "agent.bom.json"
    result = CliRunner().invoke(main, ["manifest", "--agent-id", rows[1].stable_id, "--output", str(dest)])
    assert result.exit_code == 0, result.output
    doc = validate_agent_bom_json(dest.read_bytes())
    assert doc.content.subject.agent_id == rows[1].stable_id
    assert {component.name for component in doc.content.components} == {"b"}
    monkeypatch.setattr(
        "agent_bom.cli._agent_manifest._discover_manifest_agents", lambda *args: pytest.fail("validation must not discover")
    )
    result = CliRunner().invoke(main, ["manifest", "--validate", str(dest)])
    assert result.exit_code == 0, result.output
    assert "not authenticated" in result.output


@pytest.mark.parametrize("options", [["--single-agent"], ["--agent-id", "same-name"], ["--agent-id", "unknown"]])
def test_no_name_matching_or_ambiguous_selection(monkeypatch, tmp_path, options):
    monkeypatch.setattr("agent_bom.cli._agent_manifest._discover_manifest_agents", lambda *args: agents())
    dest = tmp_path / "agent.bom.json"
    result = CliRunner().invoke(main, ["manifest", *options, "-o", str(dest)])
    assert result.exit_code != 0
    assert not dest.exists()


def test_single_agent_and_legacy_manifest(monkeypatch):
    monkeypatch.setattr("agent_bom.cli._agent_manifest._discover_manifest_agents", lambda *args: agents()[:1])
    runner = CliRunner()
    single = runner.invoke(main, ["manifest", "--single-agent", "--compact"])
    assert single.exit_code == 0, single.output
    assert json.loads(single.output)["schema_version"] == "agent-bom.profile/v1"
    legacy = runner.invoke(main, ["manifest"])
    assert legacy.exit_code == 0, legacy.output
    assert json.loads(legacy.output)["schema_version"] == "agent-bom.manifest/v1"


@pytest.mark.parametrize("invalid", [b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff", b"[" * 2000, b" " * (8 * 1024 * 1024 + 1)])
def test_import_rejects_ambiguous_or_unbounded_json(invalid):
    with pytest.raises(ValueError):
        validate_agent_bom_json(invalid)


def test_invalid_file_does_not_echo_values_or_discover(monkeypatch, tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text('{"private":"customer-content"}')
    monkeypatch.setattr("agent_bom.cli._agent_manifest._discover_manifest_agents", lambda *args: pytest.fail("must not discover"))
    result = CliRunner().invoke(main, ["manifest", "--validate", str(path)])
    assert result.exit_code == 1
    assert "customer-content" not in result.output


def test_validation_refuses_mixed_modes(tmp_path):
    path = tmp_path / "agent.json"
    path.write_text(build_agent_bom(agents()[0]).model_dump_json())
    result = CliRunner().invoke(main, ["manifest", "--validate", str(path), "--single-agent"])
    assert result.exit_code == 2


def test_export_does_not_write_a_document_exceeding_import_limit(monkeypatch, tmp_path):
    monkeypatch.setattr("agent_bom.cli._agent_manifest._discover_manifest_agents", lambda *args: agents()[:1])
    monkeypatch.setattr("agent_bom.evidence.agent_bom.MAX_AGENT_BOM_BYTES", 500)
    target = tmp_path / "agent.json"
    result = CliRunner().invoke(main, ["manifest", "--single-agent", "-o", str(target)])
    assert result.exit_code == 1
    assert not target.exists()


def test_real_inventory_file_preserves_identity_evidence(tmp_path):
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    assert json.loads((root / "config/schemas/inventory.schema.json").read_text()) == json.loads(
        (root / "src/agent_bom/data/inventory.schema.json").read_text()
    )
    (tmp_path / "inventory.json").write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "name": "example",
                        "agent_type": "custom",
                        "source_id": "deployment-a",
                        "mcp_servers": [{"name": "tools", "command": "example-tools"}],
                    }
                ]
            }
        )
    )
    result = CliRunner().invoke(main, ["manifest", "--project", str(tmp_path), "--single-agent"])
    assert result.exit_code == 0, result.output
    document = validate_agent_bom_json(result.output)
    assert document.content.subject.source_id == "deployment-a"
