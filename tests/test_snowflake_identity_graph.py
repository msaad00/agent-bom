"""Snowflake login-anomaly + auth-posture enrich user nodes with threat signal + MITRE.

Closes the gap where these surfaces reached JSON but never the graph.
"""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _report() -> dict:
    return {
        # GRC_INGEST_USER exists in the object graph via a role membership.
        "snowflake_object_graph": {
            "status": "ok",
            "account": "acct1",
            "objects": [{"fqn": "DB.PUBLIC.T0", "object_type": "table"}],
            "dependencies": [],
            "grants": [{"role": "ANALYST", "privilege": "SELECT", "object_fqn": "DB.PUBLIC.T0", "object_type": "table"}],
            "role_memberships": [{"user": "GRC_INGEST_USER", "role": "ANALYST"}],
        },
        "snowflake_login_anomalies": {
            "status": "ok",
            "account": "acct1",
            "per_user": [
                {"user": "GRC_INGEST_USER", "distinct_ips": 50, "logins": 120, "failed": 0},
                {"user": "BRUTE_TARGET", "distinct_ips": 2, "logins": 4, "failed": 5},
            ],
            "impossible_travel": [{"user": "GRC_INGEST_USER", "rapid_switches": 4}],
            "failed_bursts": [{"user": "BRUTE_TARGET", "failed": 5}],
        },
        "snowflake_auth_posture": {
            "status": "ok",
            "account": "acct1",
            "account_network_policy": None,
            "users": [
                {"name": "WSAAD", "disabled": False, "auth_methods": ["password"], "has_mfa": False, "user_type": "PERSON"},
                {"name": "SVC_PIPE", "disabled": False, "auth_methods": ["key_pair"], "has_mfa": False, "user_type": "SERVICE"},
            ],
            "network_policies": [],
        },
    }


def _node(report=None):
    g = build_unified_graph_from_report(report if report is not None else _report())
    return g


def test_impossible_travel_marks_user_high_with_t1078() -> None:
    n = _node().nodes.get("user:snowflake:GRC_INGEST_USER")
    assert n is not None
    assert n.severity == "high"
    assert "T1078" in (n.compliance_tags or [])
    assert n.attributes["impossible_travel"] is True
    assert n.attributes["identity_threat"] is True
    assert n.attributes["distinct_login_ips"] == 50


def test_failed_burst_tags_t1110() -> None:
    n = _node().nodes.get("user:snowflake:BRUTE_TARGET")
    assert n is not None
    assert "T1110" in (n.compliance_tags or [])
    assert n.attributes["failed_logins"] == 5


def test_weak_auth_person_marked_high_with_t1078_thin_node_created() -> None:
    # WSAAD appears only in auth posture (not in any grant) → thin node created.
    n = _node().nodes.get("user:snowflake:WSAAD")
    assert n is not None
    assert n.attributes["weak_auth"] is True
    assert n.attributes["has_mfa"] is False
    assert n.severity == "high"
    assert "T1078" in (n.compliance_tags or [])


def test_service_identity_without_mfa_not_flagged_weak() -> None:
    # Key-pair service identities legitimately have no interactive MFA.
    n = _node().nodes.get("user:snowflake:SVC_PIPE")
    assert n is not None
    assert n.attributes["weak_auth"] is False
    assert "T1078" not in (n.compliance_tags or [])


def test_enrichment_merges_onto_existing_grant_user_node() -> None:
    # GRC_INGEST_USER was first created by the object graph (role membership);
    # identity enrichment must merge, not duplicate.
    g = _node()
    matching = [k for k in g.nodes if k == "user:snowflake:GRC_INGEST_USER"]
    assert len(matching) == 1
    # Both the ASSUMES edge (from grants) and the threat attrs survive.
    n = g.nodes["user:snowflake:GRC_INGEST_USER"]
    assert n.attributes["user_name"] == "GRC_INGEST_USER"
    assert n.attributes["identity_threat"] is True


def test_non_ok_payloads_are_noop() -> None:
    g = build_unified_graph_from_report(
        {
            "snowflake_login_anomalies": {"status": "no_account"},
            "snowflake_auth_posture": {"status": "no_account"},
        }
    )
    assert not [k for k in g.nodes if "snowflake" in k]
