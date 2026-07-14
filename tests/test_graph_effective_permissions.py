"""Effective permissions + privilege-escalation detection over identity edges."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.effective_permissions import apply_effective_permissions
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _perm(graph, src):
    return {
        e.target: e.evidence.get("access") for e in graph.edges if e.relationship == RelationshipType.HAS_PERMISSION and e.source == src
    }


def test_assume_chain_yields_effective_permission_and_escalation():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="role:admin", entity_type=EntityType.ROLE, label="admin-role"))
    g.add_node(
        UnifiedNode(id="cloud:bucket", entity_type=EntityType.CLOUD_RESOURCE, label="prod bucket", attributes={"internet_exposed": True})
    )
    g.add_node(UnifiedNode(id="cloud:logs", entity_type=EntityType.CLOUD_RESOURCE, label="logs"))
    # dev can directly access logs, and can assume admin-role which can access the bucket.
    # ASSUMES (principal -> role) is the genuine OUTBOUND assume vector; inbound
    # TRUSTS / CROSS_ACCOUNT_TRUST must NOT fold another principal's access into dev.
    g.add_edge(UnifiedEdge(source="user:dev", target="cloud:logs", relationship=RelationshipType.CAN_ACCESS))
    g.add_edge(UnifiedEdge(source="user:dev", target="role:admin", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:admin", target="cloud:bucket", relationship=RelationshipType.CAN_ACCESS))

    stats = apply_effective_permissions(g)
    assert stats["has_permission_edges"] >= 2
    assert stats["privilege_escalations"] == 1

    dev_perms = _perm(g, "user:dev")
    assert dev_perms.get("cloud:logs") == "direct"
    assert dev_perms.get("cloud:bucket") == "assume_chain"  # reachable only via assume

    dev = g.nodes["user:dev"]
    assert dev.attributes.get("can_escalate_privilege") is True
    # escalation to an internet-exposed resource raises the risk to the top band
    esc = [r for r in g.interaction_risks if r.pattern == "privilege_escalation"]
    assert esc and esc[0].risk_score == 9.5


def test_no_assume_chain_is_direct_only_no_escalation():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:a", entity_type=EntityType.USER, label="a"))
    g.add_node(UnifiedNode(id="cloud:r", entity_type=EntityType.CLOUD_RESOURCE, label="r"))
    g.add_edge(UnifiedEdge(source="user:a", target="cloud:r", relationship=RelationshipType.CAN_ACCESS))

    stats = apply_effective_permissions(g)
    assert stats["privilege_escalations"] == 0
    assert _perm(g, "user:a") == {"cloud:r": "direct"}
    assert g.nodes["user:a"].attributes.get("can_escalate_privilege") is None


def test_assume_cycle_is_bounded():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="role:a", entity_type=EntityType.ROLE, label="a"))
    g.add_node(UnifiedNode(id="role:b", entity_type=EntityType.ROLE, label="b"))
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="role:a", target="role:b", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:b", target="role:a", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:b", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    apply_effective_permissions(g)  # must terminate
    assert _perm(g, "role:a").get("cloud:x") == "assume_chain"


def test_escalation_to_admin_role_is_higher_risk():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="role:admin", entity_type=EntityType.ROLE, label="prod-admin-role"))
    g.add_node(UnifiedNode(id="pol:admin", entity_type=EntityType.POLICY, label="AdministratorAccess"))
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="user:dev", target="role:admin", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:admin", target="pol:admin", relationship=RelationshipType.ATTACHED))
    g.add_edge(UnifiedEdge(source="role:admin", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    apply_effective_permissions(g)
    assert g.nodes["user:dev"].attributes.get("escalates_to_admin") is True
    esc = [r for r in g.interaction_risks if r.pattern == "privilege_escalation"]
    assert esc and esc[0].risk_score == 9.0 and "admin-privileged" in esc[0].description


def test_group_membership_inherits_access_without_escalation():
    # A user with no direct access of its own reaches a resource only because the
    # GROUP it belongs to can access it. The user must surface that effective
    # permission, marked "group", and NOT be flagged as privilege escalation.
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:alice", entity_type=EntityType.USER, label="alice"))
    g.add_node(UnifiedNode(id="group:admins", entity_type=EntityType.GROUP, label="admins"))
    g.add_node(UnifiedNode(id="cloud:bucket", entity_type=EntityType.CLOUD_RESOURCE, label="bucket"))
    g.add_edge(UnifiedEdge(source="user:alice", target="group:admins", relationship=RelationshipType.MEMBER_OF))
    g.add_edge(UnifiedEdge(source="group:admins", target="cloud:bucket", relationship=RelationshipType.CAN_ACCESS))

    stats = apply_effective_permissions(g)
    assert stats["privilege_escalations"] == 0
    assert _perm(g, "user:alice").get("cloud:bucket") == "group"
    assert g.nodes["user:alice"].attributes.get("can_escalate_privilege") is None


def test_nested_group_membership_is_bounded_and_inherited():
    # alice → team → org-admins (nested groups); org-admins can access the secret.
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:alice", entity_type=EntityType.USER, label="alice"))
    g.add_node(UnifiedNode(id="group:team", entity_type=EntityType.GROUP, label="team"))
    g.add_node(UnifiedNode(id="group:org-admins", entity_type=EntityType.GROUP, label="org-admins"))
    g.add_node(UnifiedNode(id="data:secret", entity_type=EntityType.DATA_STORE, label="secret"))
    g.add_edge(UnifiedEdge(source="user:alice", target="group:team", relationship=RelationshipType.MEMBER_OF))
    g.add_edge(UnifiedEdge(source="group:team", target="group:org-admins", relationship=RelationshipType.MEMBER_OF))
    g.add_edge(UnifiedEdge(source="group:org-admins", target="data:secret", relationship=RelationshipType.CAN_ACCESS))

    apply_effective_permissions(g)
    assert _perm(g, "user:alice").get("data:secret") == "group"


def test_inbound_trust_edge_is_not_folded_into_assume_chain():
    # Regression (complete #3761): a CROSS_ACCOUNT_TRUST edge role R -> principal P
    # is INBOUND (P is allowed to assume R). It must NOT make R inherit P's access,
    # which would mint a false HAS_PERMISSION{assume_chain} R -> ds:X edge and set
    # can_escalate_privilege on the exposed R — a fabricated cross-account chain.
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="role:R", entity_type=EntityType.ROLE, label="exposed-R", attributes={"internet_exposed": True}))
    g.add_node(UnifiedNode(id="prin:P", entity_type=EntityType.ROLE, label="P"))
    g.add_node(UnifiedNode(id="ds:X", entity_type=EntityType.DATA_STORE, label="ds-X"))
    g.add_edge(UnifiedEdge(source="role:R", target="prin:P", relationship=RelationshipType.CROSS_ACCOUNT_TRUST))
    g.add_edge(UnifiedEdge(source="prin:P", target="ds:X", relationship=RelationshipType.CAN_ACCESS))

    stats = apply_effective_permissions(g)
    # R gains nothing; only P's own direct access is recorded.
    assert _perm(g, "role:R") == {}
    assert _perm(g, "prin:P").get("ds:X") == "direct"
    assert g.nodes["role:R"].attributes.get("can_escalate_privilege") is None
    assert stats["privilege_escalations"] == 0


def test_plain_trusts_edge_is_not_walked_as_assume():
    # Same rule for the intra-account TRUSTS edge (also inbound).
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="role:R", entity_type=EntityType.ROLE, label="R", attributes={"internet_exposed": True}))
    g.add_node(UnifiedNode(id="role:P", entity_type=EntityType.ROLE, label="P"))
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="role:R", target="role:P", relationship=RelationshipType.TRUSTS))
    g.add_edge(UnifiedEdge(source="role:P", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    apply_effective_permissions(g)
    assert _perm(g, "role:R") == {}
    assert g.nodes["role:R"].attributes.get("can_escalate_privilege") is None


_ALLOW_STAR = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
_ALLOW_IAM_SELF_ESCALATE = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:PutUserPolicy", "Resource": "*"}],
}


def test_benign_named_policy_with_wildcard_document_is_admin_via_evaluation():
    # A policy whose NAME carries no admin keyword ("team-utility-policy") but whose
    # DOCUMENT allows *:* is admin-equivalent. The keyword heuristic (name/label
    # match) would MISS this; real IAM evaluation catches it.
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="role:helper", entity_type=EntityType.ROLE, label="batch-helper-role"))
    g.add_node(
        UnifiedNode(
            id="pol:custom",
            entity_type=EntityType.POLICY,
            label="team-utility-policy",
            attributes={"policy_document": _ALLOW_STAR},
        )
    )
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="user:dev", target="role:helper", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:helper", target="pol:custom", relationship=RelationshipType.ATTACHED))
    g.add_edge(UnifiedEdge(source="role:helper", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    stats = apply_effective_permissions(g)
    assert g.nodes["role:helper"].attributes.get("admin_equivalent") is True
    assert g.nodes["role:helper"].attributes.get("admin_equivalence_basis") == "policy_evaluation"
    assert g.nodes["user:dev"].attributes.get("escalates_to_admin") is True
    assert stats["admin_via_evaluation"] >= 1
    esc = [r for r in g.interaction_risks if r.pattern == "privilege_escalation"]
    assert esc and "admin-privileged" in esc[0].description


def test_keyword_heuristic_alone_misses_benign_named_wildcard_policy():
    # Control for the test above: the SAME benign-named policy with NO document is
    # invisible to both the scanner classification and the evaluator, so only the
    # name heuristic remains — and it does not fire (no admin keyword in the name).
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="role:helper", entity_type=EntityType.ROLE, label="batch-helper-role"))
    g.add_node(UnifiedNode(id="pol:custom", entity_type=EntityType.POLICY, label="team-utility-policy"))
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="user:dev", target="role:helper", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:helper", target="pol:custom", relationship=RelationshipType.ATTACHED))
    g.add_edge(UnifiedEdge(source="role:helper", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    apply_effective_permissions(g)
    assert g.nodes["role:helper"].attributes.get("admin_equivalent") is not True
    assert g.nodes["user:dev"].attributes.get("escalates_to_admin") is not True


def test_iam_self_escalation_action_is_admin_via_evaluation():
    # iam:PutUserPolicy on * lets an identity grant itself any permission — an
    # admin-equivalent escalation primitive with no "admin" substring anywhere.
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="role:pipe", entity_type=EntityType.ROLE, label="data-pipeline"))
    g.add_node(
        UnifiedNode(
            id="pol:pipe",
            entity_type=EntityType.POLICY,
            label="pipeline-permissions",
            attributes={"policy_document": _ALLOW_IAM_SELF_ESCALATE},
        )
    )
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="user:dev", target="role:pipe", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:pipe", target="pol:pipe", relationship=RelationshipType.ATTACHED))
    g.add_edge(UnifiedEdge(source="role:pipe", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    apply_effective_permissions(g)
    assert g.nodes["role:pipe"].attributes.get("admin_equivalent") is True
    assert g.nodes["user:dev"].attributes.get("escalates_to_admin") is True


def test_resource_scoped_admin_action_is_not_flagged_admin():
    # iam:PutUserPolicy scoped to ONE user ARN is not admin-equivalence; real
    # evaluation (unlike a bare action/name match) respects resource scope.
    scoped = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PutUserPolicy", "Resource": "arn:aws:iam::111122223333:user/self-service"}
        ],
    }
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="role:scoped", entity_type=EntityType.ROLE, label="scoped-role"))
    g.add_node(
        UnifiedNode(id="pol:scoped", entity_type=EntityType.POLICY, label="scoped-policy", attributes={"policy_document": scoped})
    )
    g.add_edge(UnifiedEdge(source="role:scoped", target="pol:scoped", relationship=RelationshipType.ATTACHED))

    apply_effective_permissions(g)
    assert g.nodes["role:scoped"].attributes.get("admin_equivalent") is not True


def test_explicit_deny_overrides_wildcard_allow_in_evaluation():
    # Allow *:* with an explicit Deny *:* is NOT admin: explicit deny wins. A
    # name/keyword match on such a policy would false-positive.
    deny_over_allow = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
        ],
    }
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="role:locked", entity_type=EntityType.ROLE, label="AdministratorAccess-lookalike"))
    g.add_node(
        UnifiedNode(
            id="pol:locked", entity_type=EntityType.POLICY, label="locked", attributes={"policy_document": deny_over_allow}
        )
    )
    g.add_edge(UnifiedEdge(source="role:locked", target="pol:locked", relationship=RelationshipType.ATTACHED))

    apply_effective_permissions(g)
    assert g.nodes["role:locked"].attributes.get("admin_equivalent") is not True
    assert g.nodes["role:locked"].attributes.get("admin_equivalence_basis") == "policy_evaluation"


def test_keyword_fallback_still_fires_when_no_document_available():
    # No policy document anywhere: the overlay degrades to the prior name signal
    # and notes the basis as heuristic (preserving pre-evaluator behavior).
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="role:admin", entity_type=EntityType.ROLE, label="prod-admin-role"))
    g.add_node(UnifiedNode(id="pol:admin", entity_type=EntityType.POLICY, label="AdministratorAccess"))
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="user:dev", target="role:admin", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:admin", target="pol:admin", relationship=RelationshipType.ATTACHED))
    g.add_edge(UnifiedEdge(source="role:admin", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    stats = apply_effective_permissions(g)
    assert g.nodes["user:dev"].attributes.get("escalates_to_admin") is True
    assert g.nodes["role:admin"].attributes.get("admin_equivalence_basis") == "name_heuristic"
    assert stats["admin_via_heuristic"] >= 1


def test_scanner_privilege_level_admin_is_honored_without_document():
    # The scanner's action-derived privilege_level == "admin" on an attached policy
    # is a real signal (not a keyword) and is basis "scanner_actions".
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="role:svc", entity_type=EntityType.ROLE, label="svc-role"))
    g.add_node(
        UnifiedNode(id="pol:x", entity_type=EntityType.POLICY, label="custom-x", attributes={"privilege_level": "admin"})
    )
    g.add_edge(UnifiedEdge(source="role:svc", target="pol:x", relationship=RelationshipType.ATTACHED))

    apply_effective_permissions(g)
    assert g.nodes["role:svc"].attributes.get("admin_equivalent") is True
    assert g.nodes["role:svc"].attributes.get("admin_equivalence_basis") == "scanner_actions"


def test_capped_graph_surfaces_skipped_signal():
    # Past the principal cap, the overlay returns 0 escalations but must mark the
    # result 'skipped' so consumers do not read a large estate as 'genuinely none'.
    from agent_bom.graph.effective_permissions import _MAX_PRINCIPALS

    g = UnifiedGraph(scan_id="s", tenant_id="t")
    for i in range(_MAX_PRINCIPALS + 1):
        g.add_node(UnifiedNode(id=f"user:{i}", entity_type=EntityType.USER, label=f"u{i}"))
    stats = apply_effective_permissions(g)
    assert stats["privilege_escalations"] == 0
    assert stats["skipped"] is True
    assert "principal_cap_exceeded" in stats["skipped_reason"]
