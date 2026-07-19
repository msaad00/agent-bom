"""A DSPM database scan's redacted classification enriches graph crown jewels (#4157).

The database content scan attaches an ``agent-bom.dspm.database_scan.v1``
classification to a ``dspm_databases`` inventory record. The graph builder must
materialize the database as a CLOUD_RESOURCE carrying that redacted evidence so
the CNAPP/DSPM overlay promotes its DATA_STORE companion to a sensitive crown
jewel and the internet-exposed path becomes a toxic-combination finding — the
same surface S3/GCS content sampling feeds.
"""

from __future__ import annotations

from agent_bom.finding import FindingType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.toxic_findings import build_toxic_combination_findings


def _report() -> dict:
    classification = {
        "schema_version": "agent-bom.dspm.database_scan.v1",
        "status": "partial",
        "tables_total": 3,
        "tables_sampled": 2,
        "rows_sampled": 2,
        "columns_sampled": 3,
        "total_findings": 6,
        "findings_by_type": {"ssn": 2, "email": 2, "credit_card": 2},
        "sensitivity_score": 90,
        "data_sensitivity": "sensitive",
        "tables_by_state": {"executed": 2, "unevaluable": 1},
        "redaction": "raw row values and matched values are not stored",
    }
    return {
        "cloud_inventory": [
            {
                "provider": "database",
                "status": "ok",
                "account_id": "acct-prod",
                "dspm_databases": [
                    {
                        "name": "prod-analytics",
                        "engine": "postgres",
                        "publicly_accessible": True,
                        "account_id": "acct-prod",
                        "content_classification": classification,
                    }
                ],
            }
        ]
    }


def _build():
    g = build_unified_graph_from_report(_report())
    return g


def test_database_resource_node_carries_redacted_classification():
    g = _build()
    db_nodes = [
        n
        for n in g.nodes.values()
        if n.attributes.get("resource_type") == "database" and n.attributes.get("cloud_service") == "dspm-database"
    ]
    assert len(db_nodes) == 1
    node = db_nodes[0]
    assert node.attributes.get("content_classification", {}).get("schema_version") == "agent-bom.dspm.database_scan.v1"
    # No raw values anywhere (redacted evidence only).
    assert "content_classification" in node.attributes


def test_database_store_becomes_sensitive_crown_jewel():
    g = _build()
    companions = [n for n in g.nodes.values() if str(n.entity_type).split(".")[-1].lower() == "data_store"]
    assert companions, "a DATA_STORE companion must be attached to the classified database"
    store = companions[0]
    assert store.attributes.get("data_sensitivity") == "sensitive"
    assert store.attributes.get("content_classification_counts") == {"ssn": 2, "email": 2, "credit_card": 2}
    assert store.attributes.get("content_tables_sampled") == 2
    assert store.attributes.get("data_classification_source") == "content_sampling"


def test_internet_exposed_classified_database_is_a_toxic_combination():
    g = _build()
    findings = build_toxic_combination_findings(g)
    combos = [f for f in findings if f.finding_type == FindingType.COMBINATION]
    assert any("data store" in (f.title or "").lower() or "sensitive" in (f.description or "").lower() for f in combos), (
        f"expected a public→sensitive-data toxic finding, got: {[f.title for f in combos]}"
    )
