"""Warehouse rows preserve identity and evidence boundaries across graph consumers."""

from copy import deepcopy

import pytest

from agent_bom.graph import UnifiedGraph
from agent_bom.graph.warehouse_evidence import build_warehouse_graph


def fixture():
    mapping = {
        "schema_version": "agent-bom.warehouse-mapping/v1",
        "provider": "snowflake",
        "source_instance": "sample-account/security.assets",
        "exported_at": "2026-09-30T12:00:00Z",
        "nodes": {"id": "ASSET_ID", "entity_type": "KIND", "label": "NAME", "observed_at": "SEEN"},
    }
    rows = {
        "nodes": [
            {"ASSET_ID": "A", "KIND": "agent", "NAME": "Assistant", "SEEN": "2026-09-29T12:00:00Z"},
            {"ASSET_ID": "a", "KIND": "data_store", "NAME": "Orders", "SEEN": "2026-09-29T13:00:00Z"},
        ],
        "edges": [{"source": "A", "target": "a", "relationship": "uses", "observed_at": "2026-09-29T14:00:00Z"}],
    }
    return rows, mapping


def test_identity_is_case_sensitive_order_independent_and_tenant_scoped():
    rows, mapping = fixture()
    graph = build_warehouse_graph(rows, mapping, tenant_id="acme")
    assert len(graph.nodes) == 2
    reversed_rows = deepcopy(rows)
    reversed_rows["nodes"].reverse()
    other = build_warehouse_graph(reversed_rows, mapping, tenant_id="acme")
    assert set(graph.nodes) == set(other.nodes)
    assert set(graph.nodes).isdisjoint(build_warehouse_graph(rows, mapping, tenant_id="other").nodes)


def test_round_trip_preserves_observation_and_unknown_execution():
    rows, mapping = fixture()
    graph = UnifiedGraph.from_dict(build_warehouse_graph(rows, mapping, tenant_id="acme").to_dict())
    node = next(n for n in graph.nodes.values() if n.label == "Assistant")
    assert node.first_seen == "2026-09-29T12:00:00+00:00"
    assert node.attributes["warehouse_receipt"]["exported_at"] == "2026-09-30T12:00:00+00:00"
    assert node.to_dict()["evidence_provenance"]["execution"] == "not_established"
    assert not graph.edges[0].traversable
    assert graph.analysis_status["warehouse_collection"].status.value == "not_recorded"


@pytest.mark.parametrize("mutation", ["duplicate", "dangling", "bad_kind", "naive_time", "string_bool", "nul"])
def test_invalid_evidence_is_rejected_before_output(mutation):
    rows, mapping = fixture()
    if mutation == "duplicate":
        rows["nodes"].append(deepcopy(rows["nodes"][0]))
    elif mutation == "dangling":
        rows["edges"][0]["target"] = "missing"
    elif mutation == "bad_kind":
        rows["nodes"][0]["KIND"] = "fake-admin-proof"
    elif mutation == "naive_time":
        rows["nodes"][0]["SEEN"] = "2026-09-29T12:00:00"
    elif mutation == "string_bool":
        rows["edges"][0]["traversable"] = "false"
    elif mutation == "nul":
        rows["nodes"][0]["ASSET_ID"] = "A\x00"
    with pytest.raises(ValueError):
        build_warehouse_graph(rows, mapping, tenant_id="acme")


def test_row_limit_rejects_instead_of_silently_truncating():
    rows, mapping = fixture()
    with pytest.raises(ValueError):
        build_warehouse_graph(rows, mapping, tenant_id="acme", max_rows=1)


def test_cli_writes_private_artifact_and_preserves_existing_evidence(tmp_path):
    import json
    import stat

    from click.testing import CliRunner

    from agent_bom.cli._warehouse_ingest import warehouse_cmd

    rows, mapping = fixture()
    source, config, output = tmp_path / "rows.json", tmp_path / "mapping.json", tmp_path / "graph.json"
    source.write_text(json.dumps(rows))
    config.write_text(json.dumps(mapping))
    args = [str(source), "--mapping", str(config), "--tenant", "acme", "-o", str(output)]
    runner = CliRunner()
    result = runner.invoke(warehouse_cmd, args)
    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    saved = output.read_bytes()
    assert len(UnifiedGraph.from_dict(json.loads(saved)).nodes) == 2
    assert runner.invoke(warehouse_cmd, args).exit_code == 1
    assert output.read_bytes() == saved


def test_cli_rejects_invalid_rows_without_partial_or_secret_output(tmp_path):
    import json

    from click.testing import CliRunner

    from agent_bom.cli._warehouse_ingest import warehouse_cmd

    rows, mapping = fixture()
    rows["nodes"][0]["KIND"] = "private-token-must-not-be-echoed"
    source, config, output = tmp_path / "rows.json", tmp_path / "mapping.json", tmp_path / "graph.json"
    source.write_text(json.dumps(rows))
    config.write_text(json.dumps(mapping))
    result = CliRunner().invoke(warehouse_cmd, [str(source), "--mapping", str(config), "--tenant", "acme", "-o", str(output)])
    assert result.exit_code == 1 and not output.exists()
    assert "private-token" not in result.output


def test_optional_context_survives_storage_and_private_columns_are_not_copied(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    rows, mapping = fixture()
    rows["nodes"][0].update(
        account_id="account-one", organization_id="org-one", environment="prod", repository="owner/repo", private_password="omit-me"
    )
    graph = build_warehouse_graph(rows, mapping, tenant_id="acme")
    store = SQLiteGraphStore(tmp_path / "import.db")
    store.save_graph(graph)
    restored = store.load_graph(tenant_id="acme", scan_id=graph.scan_id)
    assert len(restored.nodes) == 2 and len(restored.edges) == 1
    node = next(n for n in restored.nodes.values() if n.label == "Assistant")
    assert node.dimensions.environment == "prod"
    assert node.attributes["account_id"] == "account-one"
    assert node.attributes["repository"] == "owner/repo"
    assert "private_password" not in node.attributes
    assert not store.load_graph(tenant_id="other", scan_id=graph.scan_id).nodes
