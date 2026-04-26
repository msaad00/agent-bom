from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport
from agent_bom.output import to_json

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "v1"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_contract_schemas_are_valid_draft_2020_12() -> None:
    schemas = sorted(CONTRACTS.glob("*.schema.json"))
    assert schemas, "expected versioned contract schemas"
    for schema_path in schemas:
        schema = _load(schema_path)
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["$id"].endswith(f"/{schema_path.name}")


def test_contract_examples_match_their_schema() -> None:
    examples = sorted((CONTRACTS / "examples").glob("*.minimal.json"))
    assert examples, "expected contract example fixtures"
    for example_path in examples:
        schema_path = CONTRACTS / example_path.name.replace(".minimal.json", ".schema.json")
        assert schema_path.exists(), f"missing schema for {example_path.name}"
        jsonschema.validate(_load(example_path), _load(schema_path))


def test_scan_report_serializer_matches_contract_schema() -> None:
    """Guard the public scan-report contract boundary.

    The Python/UI model uses ``agent_type``. The v1 scan report keeps ``type``
    as a compatibility alias so old and new consumers can validate safely.
    """
    report = AIBOMReport(
        agents=[
            Agent(
                name="demo-agent",
                agent_type=AgentType.CLAUDE_DESKTOP,
                config_path="/tmp/claude.json",
                status=AgentStatus.CONFIGURED,
            )
        ],
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scan_id="scan-contract-001",
        tool_version="0.81.3",
    )

    payload = to_json(report)
    jsonschema.validate(payload, _load(CONTRACTS / "scan-report.schema.json"))

    agent_payload = payload["agents"][0]
    assert agent_payload["agent_type"] == "claude-desktop"
    assert agent_payload["type"] == "claude-desktop"


def test_scan_report_contract_accepts_agent_type_without_legacy_type() -> None:
    payload = _load(CONTRACTS / "examples" / "scan-report.minimal.json")
    payload["agents"][0].pop("type")

    jsonschema.validate(payload, _load(CONTRACTS / "scan-report.schema.json"))
