"""Cloud inventory graph edges: cross-account trust + scheduled-scan drift (#3742)."""

from __future__ import annotations

import sqlite3

from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.db.graph_store import changed_edges_between_scans, diff_snapshots, save_graph
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.toxic_findings import build_toxic_combination_findings
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_graph_api import _init_db


def _minimal_aws_inventory(*, sg_exposed: bool) -> dict:
    return {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "instances": [
            {
                "instance_id": "i-1",
                "name": "web",
                "vpc_id": "vpc-1",
                "subnet_id": "subnet-1",
                "security_group_ids": ["sg-1"],
            }
        ],
        "security_groups": [
            {
                "group_id": "sg-1",
                "name": "web-sg",
                "vpc_id": "vpc-1",
                "internet_exposed": sg_exposed,
                "network_exposure": (
                    [{"scope": "internet", "from_port": 443, "to_port": 443, "protocol": "tcp"}]
                    if sg_exposed
                    else []
                ),
            }
        ],
        "buckets": [],
        "roles": [],
        "users": [],
    }


def test_inventory_emits_cross_account_trust_edges() -> None:
    payload = {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "instances": [],
        "security_groups": [],
        "buckets": [],
        "users": [],
        "roles": [
            {
                "name": "cross-account-role",
                "arn": "arn:aws:iam::111122223333:role/cross-account-role",
                "principal_type": "role",
                "privilege_level": "admin",
                "policies": [],
                "trust_principals": [
                    {
                        "principal_type": "account",
                        "principal_id": "210987654321",
                        "principal_name": "210987654321",
                        "relationship": "cross_account_trust",
                    }
                ],
            }
        ],
    }
    graph = build_unified_graph_from_report({"cloud_inventory": payload})
    role_id = "role:aws:arn:aws:iam::111122223333:role/cross-account-role"
    external_account_id = "account:aws:210987654321"

    assert role_id in graph.nodes
    assert external_account_id in graph.nodes
    assert graph.nodes[external_account_id].entity_type == EntityType.ACCOUNT
    assert any(
        edge.source == role_id
        and edge.target == external_account_id
        and edge.relationship == RelationshipType.CROSS_ACCOUNT_TRUST
        for edge in graph.edges
    )


def test_cloud_inventory_snapshots_diff_exposed_edges(tmp_path) -> None:
    """Scheduled scans surface EXPOSED_TO lifecycle changes between snapshots."""
    conn = sqlite3.connect(tmp_path / "cloud-edge-diff.db")
    conn.row_factory = sqlite3.Row
    _init_db(conn)

    baseline = build_unified_graph_from_report(
        {"cloud_inventory": _minimal_aws_inventory(sg_exposed=False)}
    )
    baseline.scan_id = "cloud-scan-baseline"
    baseline.created_at = "2026-06-01T12:00:00+00:00"
    save_graph(conn, baseline)

    current = build_unified_graph_from_report(
        {"cloud_inventory": _minimal_aws_inventory(sg_exposed=True)}
    )
    current.scan_id = "cloud-scan-current"
    current.created_at = "2026-06-08T12:00:00+00:00"
    save_graph(conn, current)

    sg_id = "cloud_resource:aws:ec2:security-group:sg-1"
    inst_id = "cloud_resource:aws:ec2:instance:i-1"

    diff = diff_snapshots(conn, "cloud-scan-baseline", "cloud-scan-current", tenant_id="default")
    assert diff["edges_added"], "expected new edges when SG exposure opens"
    added_keys = {(row[0], row[1], row[2]) for row in diff["edges_added"]}
    assert (sg_id, inst_id, "exposed_to") in added_keys

    changes = changed_edges_between_scans(
        conn,
        "cloud-scan-baseline",
        "cloud-scan-current",
        tenant_id="default",
    )
    assert changes["summary"]["added"] >= 1
    assert any(
        edge["source_id"] == sg_id
        and edge["target_id"] == inst_id
        and edge["relationship"] == "exposed_to"
        for edge in changes["edges_added"]
    )

    store = SQLiteGraphStore(tmp_path / "cloud-edge-diff.db")
    original = api_stores._graph_store
    try:
        set_graph_store(store)
        client = TestClient(app)
        diff_resp = client.get(
            "/v1/graph/diff",
            params={"old": "cloud-scan-baseline", "new": "cloud-scan-current"},
        )
        assert diff_resp.status_code == 200
        diff_body = diff_resp.json()
        index = diff_body.get("change_kind_index") or {}
        assert index.get("edges", {}).get(f"{sg_id}|{inst_id}|exposed_to") == "new"

        changes_resp = client.get(
            "/v1/graph/edges/changes",
            params={"old": "cloud-scan-baseline", "new": "cloud-scan-current"},
        )
        assert changes_resp.status_code == 200
        changes_body = changes_resp.json()
        assert changes_body["summary"]["added"] >= 1
    finally:
        set_graph_store(original)
        conn.close()


def _cross_account_foothold_inventory() -> dict:
    """Public EC2 + instance-profile role with cross-account trust and a PII bucket."""
    return {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "instances": [
            {
                "instance_id": "i-foothold",
                "name": "web",
                "vpc_id": "vpc-1",
                "subnet_id": "subnet-1",
                "security_group_ids": ["sg-1"],
                "iam_instance_profile": "arn:aws:iam::111122223333:role/cross-account-role",
            }
        ],
        "network_interfaces": [
            {
                "id": "eni-1",
                "instance_id": "i-foothold",
                "vpc_id": "vpc-1",
                "subnet_id": "subnet-1",
                "public_ip": "52.1.2.3",
            }
        ],
        "security_groups": [
            {
                "group_id": "sg-1",
                "name": "web-sg",
                "vpc_id": "vpc-1",
                "internet_exposed": True,
                "network_exposure": [{"scope": "internet", "from_port": 443, "to_port": 443, "protocol": "tcp"}],
            }
        ],
        "buckets": [
            {
                "name": "pii-lake",
                "arn": "arn:aws:s3:::pii-lake",
                "publicly_accessible": True,
                "tags": {"data-classification": "pii"},
            }
        ],
        "users": [],
        "roles": [
            {
                "name": "cross-account-role",
                "arn": "arn:aws:iam::111122223333:role/cross-account-role",
                "principal_type": "role",
                "privilege_level": "admin",
                "policies": [],
                "trust_principals": [
                    {
                        "principal_type": "account",
                        "principal_id": "210987654321",
                        "principal_name": "210987654321",
                        "relationship": "cross_account_trust",
                    }
                ],
            }
        ],
    }


def test_inventory_instance_profile_assumes_role_and_marks_exposed() -> None:
    graph = build_unified_graph_from_report({"cloud_inventory": _cross_account_foothold_inventory()})
    inst_id = "cloud_resource:aws:ec2:instance:i-foothold"
    role_id = "role:aws:arn:aws:iam::111122223333:role/cross-account-role"

    assert any(
        edge.source == inst_id and edge.target == role_id and edge.relationship == RelationshipType.ASSUMES
        for edge in graph.edges
    )
    assert graph.nodes[role_id].attributes.get("internet_exposed") is True


def test_inventory_public_foothold_triggers_public_permission_lateral() -> None:
    graph = build_unified_graph_from_report({"cloud_inventory": _cross_account_foothold_inventory()})
    instance_id = "cloud_resource:aws:ec2:instance:i-foothold"
    role_id = "role:aws:arn:aws:iam::111122223333:role/cross-account-role"
    external_account_id = "account:aws:210987654321"

    hits = [f for f in build_toxic_combination_findings(graph) if f.evidence.get("rule_id") == "PUBLIC_PERMISSION_LATERAL"]

    # True positive: an internet-exposed instance can pivot to the same-account
    # admin role it is allowed to assume (a genuine outbound lateral move).
    assert hits, "expected PUBLIC_PERMISSION_LATERAL from exposed foothold to same-account role"
    same_account = [f for f in hits if instance_id in f.evidence["node_ids"] and role_id in f.evidence["node_ids"]]
    assert same_account, "expected same-account instance→role lateral finding"

    # Regression guard: the role→external-account edge is INBOUND trust (the
    # external account is allowed to assume the role, not vice-versa). It must
    # NOT be walked as an outbound pivot, so no lateral finding may claim the
    # exposed role moves INTO the external account.
    assert not any(external_account_id in f.evidence["node_ids"] for f in hits), (
        "cross-account trust is inbound and must not fabricate a lateral pivot into the trusting account"
    )
    # The trust edge itself is still present in the graph — we stopped walking
    # it as a lateral vector, we did not delete the relationship.
    assert any(
        edge.source == role_id
        and edge.target == external_account_id
        and edge.relationship == RelationshipType.CROSS_ACCOUNT_TRUST
        for edge in graph.edges
    )


def test_inventory_fusion_reaches_sensitive_data_store() -> None:
    """Live inventory → overlays → attack-path fusion end-to-end (#3742)."""
    graph = build_unified_graph_from_report({"cloud_inventory": _cross_account_foothold_inventory()})
    role_id = "role:aws:arn:aws:iam::111122223333:role/cross-account-role"
    bucket_id = "cloud_resource:aws:s3:bucket:pii-lake"
    data_store_id = f"data_store:{bucket_id}"

    assert data_store_id in graph.nodes
    assert graph.nodes[data_store_id].attributes.get("data_sensitivity") == "sensitive"
    assert any(
        edge.source == role_id
        and edge.target == "account:aws:210987654321"
        and edge.relationship == RelationshipType.CROSS_ACCOUNT_TRUST
        for edge in graph.edges
    )

    fused = [path for path in graph.attack_paths if path.summary.startswith("Internet-exposed ")]
    assert fused, "expected fused kill-chain from inventory-built graph"
    assert any(path.target == data_store_id for path in fused)
    assert any(role_id in path.hops for path in fused)
