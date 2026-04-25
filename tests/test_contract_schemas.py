from __future__ import annotations

import json
from pathlib import Path

import jsonschema

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
