"""NHI governance: right-sizing, dormant/orphan detection, per-identity risk score."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.nhi_governance import (
    apply_nhi_governance,
    apply_nhi_governance_with_findings,
    build_nhi_governance_findings,
    describe_nhi_governance_posture,
    evaluate_identity_governance,
)
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

NOW = datetime(2026, 6, 20, tzinfo=timezone.utc)


def _iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def _identity(nid: str, label: str, **attrs) -> UnifiedNode:
    return UnifiedNode(id=nid, entity_type=EntityType.MANAGED_IDENTITY, label=label, attributes=attrs)


def _resource(nid: str, label: str, **attrs) -> UnifiedNode:
    return UnifiedNode(id=nid, entity_type=EntityType.CLOUD_RESOURCE, label=label, attributes=attrs)


def _grant(src: str, tgt: str) -> UnifiedEdge:
    return UnifiedEdge(source=src, target=tgt, relationship=RelationshipType.HAS_PERMISSION)


def _verdict(verdicts, node_id):
    return next(v for v in verdicts if v.node_id == node_id)


def test_unused_permission_flagged_via_usage_map():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(_identity("managed_identity:svc", "svc-account", identity_id="svc", owner="alice", last_used_at=_iso(1)))
    g.add_node(_resource("res:used", "bucket-used"))
    g.add_node(_resource("res:unused", "bucket-unused"))
    g.add_edge(_grant("managed_identity:svc", "res:used"))
    g.add_edge(_grant("managed_identity:svc", "res:unused"))

    # Observed usage covers only the "used" resource; the other is an over-grant.
    verdicts = evaluate_identity_governance(g, usage={"svc": {"res:used"}}, now=NOW)
    v = _verdict(verdicts, "managed_identity:svc")
    assert v.granted_count == 2
    assert v.used_count == 1
    assert v.unused_targets == ["res:unused"]

    findings = build_nhi_governance_findings(g, verdicts)
    over = [f for f in findings if f.evidence.get("nhi_governance") == "over_grant"]
    assert len(over) == 1
    assert "bucket-unused" in over[0].evidence["unused_targets"]


def test_unused_permission_via_edge_last_used_marker():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(_identity("managed_identity:svc", "svc", identity_id="svc", owner="alice", last_used_at=_iso(1)))
    g.add_node(_resource("res:a", "a"))
    g.add_node(_resource("res:b", "b"))
    # Edge to res:a carries a usage marker → observed; res:b has none → unused.
    g.add_edge(
        UnifiedEdge(
            source="managed_identity:svc",
            target="res:a",
            relationship=RelationshipType.HAS_PERMISSION,
            evidence={"last_used_at": _iso(2)},
        )
    )
    g.add_edge(_grant("managed_identity:svc", "res:b"))

    v = _verdict(evaluate_identity_governance(g, now=NOW), "managed_identity:svc")
    assert v.unused_targets == ["res:b"]
    assert v.used_count == 1


def test_dormant_and_orphaned_identity_flagged():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    # No owner (orphaned) and last used 200 days ago (dormant, default window 90).
    g.add_node(_identity("managed_identity:old", "stale-token", identity_id="old", owner=None, last_used_at=_iso(200)))

    verdicts = evaluate_identity_governance(g, now=NOW)
    v = _verdict(verdicts, "managed_identity:old")
    assert v.is_dormant is True
    assert v.dormant_days == 200
    assert v.is_orphaned is True

    findings = build_nhi_governance_findings(g, verdicts)
    unattended = [f for f in findings if f.evidence.get("nhi_governance") == "unattended_identity"]
    assert len(unattended) == 1
    assert unattended[0].evidence["is_dormant"] and unattended[0].evidence["is_orphaned"]


def test_no_usage_timestamp_is_dormant():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(_identity("managed_identity:never", "never-used", identity_id="never", owner="bob"))
    v = _verdict(evaluate_identity_governance(g, now=NOW), "managed_identity:never")
    assert v.is_dormant is True
    assert v.dormant_days is None
    assert v.is_orphaned is False


def test_risk_score_ranks_privileged_exposed_stale_above_benign():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    # Risky: admin-privileged, reaches an internet-exposed resource, expired
    # credential, dormant, orphaned.
    g.add_node(
        _identity(
            "managed_identity:risky",
            "prod-admin",
            identity_id="risky",
            owner=None,
            last_used_at=_iso(300),
            escalates_to_admin=True,
            credential_expires_at=_iso(30),  # expired 30 days ago
        )
    )
    g.add_node(_resource("res:public", "public-bucket", internet_exposed=True))
    g.add_edge(_grant("managed_identity:risky", "res:public"))

    # Benign: owned, used yesterday, no privilege, no exposure, fresh credential.
    g.add_node(
        _identity(
            "managed_identity:benign",
            "ci-runner",
            identity_id="benign",
            owner="team-ci",
            last_used_at=_iso(1),
            credential_expires_at=_iso(-180),  # expires in 180 days
        )
    )
    g.add_node(_resource("res:internal", "internal-bucket"))
    g.add_edge(
        UnifiedEdge(
            source="managed_identity:benign",
            target="res:internal",
            relationship=RelationshipType.HAS_PERMISSION,
            evidence={"last_used_at": _iso(1)},
        )
    )

    verdicts = evaluate_identity_governance(g, now=NOW)
    risky = _verdict(verdicts, "managed_identity:risky")
    benign = _verdict(verdicts, "managed_identity:benign")

    assert risky.risk_score > benign.risk_score
    assert risky.risk_band in {"high", "critical"}
    assert benign.risk_band == "low"
    # Verdicts are returned worst-first.
    assert verdicts[0].node_id == "managed_identity:risky"
    assert risky.is_privileged and risky.internet_exposed and risky.credential_state == "expired"


def test_apply_writes_risk_score_onto_node():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        _identity(
            "managed_identity:x",
            "x",
            identity_id="x",
            owner=None,
            last_used_at=_iso(400),
            escalates_to_admin=True,
        )
    )
    summary = apply_nhi_governance(g, now=NOW)
    node = g.nodes["managed_identity:x"]
    assert node.attributes["nhi_risk_score"] > 0
    assert node.attributes["nhi_risk_band"] in {"low", "medium", "high", "critical"}
    assert node.attributes["nhi_is_dormant"] is True
    assert node.attributes["nhi_is_orphaned"] is True
    assert node.risk_score == round(node.attributes["nhi_risk_score"] / 10.0, 2)
    assert summary["dormant"] == 1 and summary["orphaned"] == 1


def test_clean_input_produces_no_findings():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    # Owned, used yesterday, every grant observed → no over-grant, dormancy, or orphan.
    g.add_node(
        _identity(
            "managed_identity:clean",
            "clean",
            identity_id="clean",
            owner="alice",
            last_used_at=_iso(1),
            credential_expires_at=_iso(-365),
        )
    )
    g.add_node(_resource("res:r", "r"))
    g.add_edge(
        UnifiedEdge(
            source="managed_identity:clean",
            target="res:r",
            relationship=RelationshipType.HAS_PERMISSION,
            evidence={"last_used_at": _iso(1)},
        )
    )

    summary, findings = apply_nhi_governance_with_findings(g, now=NOW)
    assert findings == []
    assert summary["over_granted"] == 0
    assert summary["dormant"] == 0
    assert summary["orphaned"] == 0


def test_empty_graph_is_a_noop():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    summary, findings = apply_nhi_governance_with_findings(g, now=NOW)
    assert summary["identities"] == 0
    assert findings == []


def test_describe_posture_shape_and_status():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        _identity(
            "managed_identity:risky",
            "prod-admin",
            identity_id="risky",
            owner=None,
            last_used_at=_iso(300),
            escalates_to_admin=True,
            internet_exposed=True,
            credential_expires_at=_iso(30),
        )
    )
    posture = describe_nhi_governance_posture(g, now=NOW)
    assert posture["secret_values_included"] is False
    assert posture["evaluated"] == 1
    assert posture["status"] in {"attention_required", "blocked"}
    assert posture["identities"][0]["risk_score"] > 0
    assert posture["generated_from"] == "/v1/auth/nhi/governance"
