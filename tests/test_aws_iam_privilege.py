"""IAM policy privilege classification (action-level) and graph wiring."""

from __future__ import annotations

from unittest.mock import MagicMock

from agent_bom.cloud.aws import _classify_policy_actions, _policy_actions_from_document, _policy_privilege


def test_classify_actions_admin_write_read():
    assert _classify_policy_actions(["*"]) == "admin"
    assert _classify_policy_actions(["iam:*"]) == "admin"
    assert _classify_policy_actions(["s3:PutObject", "s3:GetObject"]) == "write"
    assert _classify_policy_actions(["s3:DeleteBucket"]) == "write"
    assert _classify_policy_actions(["s3:GetObject", "s3:ListBucket"]) == "read"


def test_policy_actions_from_document_allow_only():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"]},
            {"Effect": "Deny", "Action": "iam:*"},
            {"Effect": "Allow", "Action": "logs:CreateLogGroup"},
        ]
    }
    actions = _policy_actions_from_document(doc)
    assert "s3:GetObject" in actions and "logs:CreateLogGroup" in actions
    assert "iam:*" not in actions  # Deny excluded


def test_aws_managed_policy_classified_by_name_without_fetch():
    iam = MagicMock()
    level, actions = _policy_privilege(iam, "arn:aws:iam::aws:policy/AdministratorAccess", "AdministratorAccess", warnings=[])
    assert level == "admin" and actions == []
    iam.get_policy.assert_not_called()  # AWS-managed → no API call


def test_customer_managed_policy_fetched_and_classified():
    iam = MagicMock()
    iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v3"}}
    iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": ["dynamodb:DeleteTable"]}]}}
    }
    level, actions = _policy_privilege(iam, "arn:aws:iam::123:policy/team-custom", "team-custom", warnings=[])
    assert level == "write"
    assert "dynamodb:DeleteTable" in actions


def test_policy_lookup_failure_degrades_gracefully():
    iam = MagicMock()
    iam.get_policy.side_effect = RuntimeError("AccessDenied")
    warnings: list[str] = []
    level, actions = _policy_privilege(iam, "arn:aws:iam::123:policy/x", "x", warnings=warnings)
    assert level == "unknown" and actions == []
    assert warnings  # warning recorded, no raise


def test_effective_permissions_uses_action_derived_admin():
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.effective_permissions import apply_effective_permissions
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType, RelationshipType

    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="role:r", entity_type=EntityType.ROLE, label="team-role"))  # benign name
    # Policy NAME is not admin-keyword, but action-derived privilege_level is admin.
    g.add_node(UnifiedNode(id="pol:c", entity_type=EntityType.POLICY, label="team-custom", attributes={"privilege_level": "admin"}))
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="user:dev", target="role:r", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:r", target="pol:c", relationship=RelationshipType.ATTACHED))
    g.add_edge(UnifiedEdge(source="role:r", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    apply_effective_permissions(g)
    assert g.nodes["user:dev"].attributes.get("escalates_to_admin") is True
