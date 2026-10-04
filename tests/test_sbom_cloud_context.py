"""Cloud evidence travels with the SBOM without inventing software topology."""

import copy
import json

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import to_cyclonedx, to_spdx, to_spdx2

KEY = "agent-bom:cloud-inventory:v1"
EXPORTERS = {"cyclonedx": to_cyclonedx, "spdx": to_spdx, "spdx2": to_spdx2}


def context(document, fmt):
    if fmt == "cyclonedx":
        return json.loads(next(p["value"] for p in document["metadata"]["properties"] if p["name"] == KEY))
    annotations = document["@graph"] if fmt == "spdx" else document.get("annotations", [])
    for annotation in annotations:
        text = annotation.get("statement", annotation.get("comment", ""))
        if text.startswith('{"' + KEY + '"'):
            return json.loads(text)[KEY]
    raise AssertionError("Cloud context missing from standard export")


def inventory():
    return [
        {
            "provider": "aws",
            "account_id": "example-a",
            "status": "ok",
            "region": "us-east-1",
            "lambda_functions": [
                {"name": "shared", "arn": "arn:aws:lambda:us-east-1:example-a:function:shared", "tags": {"environment": "production"}}
            ],
        },
        {
            "provider": "azure",
            "subscription_id": "example-b",
            "status": "ok",
            "key_vaults": [
                {
                    "name": "shared",
                    "id": "/subscriptions/example-b/providers/Microsoft.KeyVault/vaults/shared",
                    "tags": {"environment": "test"},
                }
            ],
            "warnings": ["Compute collection denied"],
        },
        {"provider": "gcp", "project_id": "example-c", "status": "access_denied", "instances": [], "warnings": ["Inventory unavailable"]},
    ]


@pytest.mark.parametrize("fmt", EXPORTERS)
@pytest.mark.parametrize("mixed", [False, True])
def test_cloud_inventory_preserved_with_native_scope_and_collection_gaps(fmt, mixed):
    report = AIBOMReport(cloud_inventory_data=inventory())
    if mixed:
        report.agents = [
            Agent(
                name="repo",
                agent_type=AgentType.CUSTOM,
                config_path="example",
                mcp_servers=[
                    MCPServer(name="server", command="node", packages=[Package(name="example", version="1.0.0", ecosystem="npm")])
                ],
            )
        ]
    before = copy.deepcopy(report)
    document = EXPORTERS[fmt](report)
    evidence = context(document, fmt)
    assert evidence["inventory"] == inventory()
    assert evidence["schema_version"] == 1
    assert evidence["coverage"] == "not_assessed"
    assert report == before
    entries = document.get("components", document.get("packages", document.get("@graph", [])))
    assert not any(e.get("name") == "shared" for e in entries)


@pytest.mark.parametrize("fmt", EXPORTERS)
@pytest.mark.parametrize("payload", [{}, [], {"status": "disabled"}, {"provider": "future", "status": "partial"}])
def test_explicit_empty_or_unavailable_inventory_never_becomes_complete(fmt, payload):
    evidence = context(EXPORTERS[fmt](AIBOMReport(cloud_inventory_data=payload)), fmt)
    assert evidence["inventory"] == payload
    assert evidence["coverage"] == "not_assessed"


@pytest.mark.parametrize("fmt", EXPORTERS)
def test_absent_inventory_does_not_add_extension(fmt):
    assert KEY not in json.dumps(EXPORTERS[fmt](AIBOMReport()))


@pytest.mark.parametrize("fmt", EXPORTERS)
def test_context_redacts_nested_credentials_and_paths_before_encoding(fmt):
    token = "ghp_" + "aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"
    payload = inventory()
    payload[0]["credentials"] = {"password": "do-not-export", "token": token}
    payload[0]["path"] = "/Users/private/project/credential-file"
    payload[1]["key_vaults"].append({"id": "/subscriptions/example/providers/Microsoft.KeyVault/vaults/" + token})
    evidence = context(EXPORTERS[fmt](AIBOMReport(cloud_inventory_data=payload)), fmt)
    encoded = json.dumps(evidence)
    assert "do-not-export" not in encoded and token not in encoded and "/Users/private" not in encoded
    assert evidence["inventory"][1]["key_vaults"][0]["id"] == inventory()[1]["key_vaults"][0]["id"]


@pytest.mark.parametrize("fmt", EXPORTERS)
def test_large_extension_is_parseable_and_keeps_distinct_accounts(fmt):
    payload = [{"provider": "aws", "account_id": f"example-{i}", "instances": [{"id": "same", "name": "same"}]} for i in range(100)]
    report = AIBOMReport(cloud_inventory_data=payload)
    first = context(EXPORTERS[fmt](report), fmt)
    assert first["inventory"] == payload
    assert first == context(EXPORTERS[fmt](report), fmt)


def test_spdx_tagvalue_preserves_context_without_markup_injection():
    from agent_bom.output import to_spdx2_tagvalue

    report = AIBOMReport(cloud_inventory_data={"status": "partial", "warnings": ["</text>\nSPDXID: injected"]})
    text = to_spdx2_tagvalue(report)
    comment = next(line for line in text.splitlines() if line.startswith("DocumentComment: <text>"))
    assert comment.count("</text>") == 1
    assert json.loads(comment.removeprefix("DocumentComment: <text>").removesuffix("</text>"))[KEY]["coverage"] == "not_assessed"


@pytest.mark.parametrize("fmt", EXPORTERS)
def test_cloud_context_validates_against_official_schemas(fmt):
    from pathlib import Path

    from jsonschema import Draft7Validator, Draft201909Validator, Draft202012Validator
    from referencing import Registry, Resource

    document = EXPORTERS[fmt](AIBOMReport(cloud_inventory_data=inventory()))
    fixtures = Path(__file__).parent / "fixtures"
    if fmt == "cyclonedx":
        names = ["cyclonedx-1.7.schema.json", "spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json"]
        schemas = [json.loads((fixtures / name).read_text()) for name in names]
        registry = Registry().with_resources([(schema["$id"], Resource.from_contents(schema)) for schema in schemas])
        validator = Draft7Validator(schemas[0], registry=registry)
    else:
        filename = "spdx-3.0.1.schema.json" if fmt == "spdx" else "spdx-2.3.schema.json"
        validator_type = Draft202012Validator if fmt == "spdx" else Draft201909Validator
        validator = validator_type(json.loads((fixtures / filename).read_text()))
    assert [f"{error.json_path}: {error.message}" for error in validator.iter_errors(document)] == []
    if fmt == "spdx":
        annotation = next(n for n in document["@graph"] if n.get("contentType") == "application/json")
        assert any(n.get("spdxId") == annotation["subject"] and n.get("type") == "SpdxDocument" for n in document["@graph"])
