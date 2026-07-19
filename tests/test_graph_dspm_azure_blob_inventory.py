"""Azure Blob DSPM classification enriches graph crown jewels (#4157).

An Azure storage account carrying an ``agent-bom.dspm.azure_blob_account.v1``
classification must materialize as a data-store-signalling resource so the
CNAPP/DSPM overlay promotes its DATA_STORE companion to a sensitive crown jewel —
the same surface S3/GCS/database content sampling feeds.
"""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _report() -> dict:
    classification = {
        "schema_version": "agent-bom.dspm.azure_blob_account.v1",
        "account": "prodstorage",
        "status": "ok",
        "containers_total": 2,
        "containers_sampled": 2,
        "objects_sampled": 2,
        "total_findings": 3,
        "findings_by_type": {"ssn": 1, "email": 1, "credit_card": 1},
        "sensitivity_score": 90,
        "data_sensitivity": "sensitive",
        "redaction": "raw object bytes and matched values are not stored",
    }
    return {
        "cloud_inventory": [
            {
                "provider": "azure",
                "status": "ok",
                "subscription_id": "sub-prod",
                "storage_accounts": [
                    {
                        "name": "prodstorage",
                        "id": "/subscriptions/sub-prod/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/prodstorage",
                        "location": "eastus",
                        "publicly_accessible": True,
                        "subscription_id": "sub-prod",
                        "content_classification": classification,
                    }
                ],
            }
        ]
    }


def test_storage_account_carries_redacted_classification():
    g = build_unified_graph_from_report(_report())
    nodes = [n for n in g.nodes.values() if n.attributes.get("content_classification")]
    assert nodes, "storage account must carry content_classification"
    cc = nodes[0].attributes["content_classification"]
    assert cc.get("schema_version") == "agent-bom.dspm.azure_blob_account.v1"


def test_storage_account_becomes_sensitive_crown_jewel():
    g = build_unified_graph_from_report(_report())
    companions = [n for n in g.nodes.values() if str(n.entity_type).split(".")[-1].lower() == "data_store"]
    assert companions, "a DATA_STORE companion must be attached to the classified storage account"
    assert any(c.attributes.get("data_sensitivity") == "sensitive" for c in companions)
