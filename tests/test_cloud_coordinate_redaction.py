"""Provider coordinates remain usable after structured report redaction."""

import pytest

from agent_bom.security import sanitize_sensitive_payload

REFERENCES = [
    "/subscriptions/example-a/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/shared",
    "/subscriptions/example-b/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/shared",
    "arn:aws:lambda:us-east-1:example-a:function:shared",
    "projects/example-a/locations/us-central1/services/shared",
    "//compute.googleapis.com/projects/example-a/zones/us-central1-a/instances/shared",
    "https://www.googleapis.com/compute/v1/projects/example-a/zones/us-central1-a/instances/shared",
    "/subscriptions/12345678-9abc-4def-8123-456789abcdef/resourceGroups/rg/providers/Microsoft.Web/sites/shared",
    "/providers/Microsoft.Management/managementGroups/example",
    "https://compute.googleapis.com/compute/v1/projects/example-a/zones/us-central1-a/instances/shared",
    "//storage.googleapis.com/example-bucket",
    "arn:aws:s3:::example-bucket",
    "arn:aws-us-gov:iam::111122223333:role/example/team-role",
]


@pytest.mark.parametrize("key", ["id", "resource_id", "resource_ids", "target_id", "self_link", "scope", "resourceIds"])
@pytest.mark.parametrize("reference", REFERENCES)
def test_native_cloud_coordinates_survive_redaction(key, reference):
    value = [reference] if key.endswith("_ids") else reference
    assert sanitize_sensitive_payload({key: value}) == {key: value}


@pytest.mark.parametrize("key", ["id", "resource_ids", "target_id", "self_link"])
@pytest.mark.parametrize(
    "template",
    [
        "/subscriptions/example/providers/Microsoft.KeyVault/vaults/{}",
        "arn:aws:lambda:us-east-1:example:function:{}",
        "//compute.googleapis.com/projects/example/zones/zone/instances/{}",
        "https://compute.googleapis.com/compute/v1/projects/example/zones/zone/instances/{}",
    ],
)
@pytest.mark.parametrize("secret", ["ghp_" + "aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5", "q7V9mK2xR8pL4nT6wY1cF3hJ5sD0aB2eG8uN9zQ6XkI="])
def test_native_shape_never_exempts_secret_segments(key, template, secret):
    from urllib.parse import quote

    for encoded in [secret, quote(secret, safe=""), "".join(f"%{ord(c):02x}" for c in secret)]:
        reference = template.format(encoded)
        assert sanitize_sensitive_payload({key: reference})[key] == "***REDACTED***"


@pytest.mark.parametrize(
    "reference", ["/Users/private/file", "/subscriptions/private/file", "//private-host/share/file", "C:\\private\\file"]
)
@pytest.mark.parametrize("key", ["id", "resource_id", "self_link", "source_id"])
def test_local_paths_do_not_become_cloud_identifiers(key, reference):
    assert sanitize_sensitive_payload({key: reference})[key] != reference


def test_sensitive_keys_override_native_coordinate_shape():
    assert sanitize_sensitive_payload({"password": REFERENCES[0]})["password"] == "***REDACTED***"


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_redacted_scan_json_and_graph_keep_same_name_resources_in_distinct_scopes(provider):
    from agent_bom.models import AIBOMReport
    from agent_bom.output.graph_export import build_graph_from_scan_data, to_json
    from agent_bom.output.json_fmt import to_redacted_json

    inventories = []
    for scope in ["example-a", "example-b"]:
        collection, field, native = {
            "aws": ("lambda_functions", "arn", f"arn:aws:lambda:us-east-1:{scope}:function:shared"),
            "azure": ("key_vaults", "id", f"/subscriptions/{scope}/providers/Microsoft.KeyVault/vaults/shared"),
            "gcp": ("cloud_sql_instances", "id", f"projects/{scope}/instances/shared"),
        }[provider]
        inventories.append(
            {
                "provider": provider,
                "account_id": scope,
                "subscription_id": scope,
                "project_id": scope,
                "status": "ok",
                collection: [{"name": "shared", field: native, "labels": {"environment": "test"}}],
            }
        )
    scan = to_redacted_json(AIBOMReport(cloud_inventory_data=inventories))
    assert scan["cloud_inventory"] == inventories
    graph = to_json(build_graph_from_scan_data(scan))
    resources = [n for n in graph["nodes"] if n.get("attributes", {}).get("resource_name") == "shared"]
    assert len({n["id"] for n in resources}) == 2
    assert {n["attributes"]["resource_id"] for n in resources} == {row[collection][0][field] for row in inventories}
    assert {n["attributes"]["account_id"] for n in resources} == {"example-a", "example-b"}


def test_coordinate_redaction_is_idempotent_and_cache_remains_field_sensitive():
    payload = {"id": REFERENCES[0], "password": REFERENCES[0], "resource_id": "C:\\private\\file"}
    first = sanitize_sensitive_payload(payload)
    assert first == sanitize_sensitive_payload(first)
    assert first["id"] == REFERENCES[0]
    assert first["password"] == "***REDACTED***"
