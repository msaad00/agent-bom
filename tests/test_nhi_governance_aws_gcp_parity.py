"""CIEM parity: AWS IAM roles + GCP service accounts get governance verdicts.

Before this change ``evaluate_identity_governance`` iterated only
``MANAGED_IDENTITY`` (Azure), so AWS ``ROLE`` and GCP ``SERVICE_ACCOUNT``
identities produced no over-grant / dormant / orphan finding at all. These
tests pin two things:

1. GAP 1 — the evaluator now scores ROLE + SERVICE_ACCOUNT with correct
   provider attribution, driven by the same node attributes/edges the Azure
   path uses, and FAIL-CLOSED: an identity with no usage evidence never
   fabricates a dormant / over-grant / orphan verdict.
2. GAP 2 — real AWS Access Advisor / RoleLastUsed ``usage_evidence`` collected
   during inventory is threaded onto the ROLE node's ``last_used_at`` so
   dormancy uses real last-used telemetry (and absent telemetry stays
   not-evaluated).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.graph.builder import _role_last_used_at, build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.nhi_governance import (
    build_nhi_governance_findings,
    evaluate_identity_governance,
)
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

NOW = datetime(2026, 6, 20, tzinfo=timezone.utc)


def _iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def _role(nid: str, label: str, **attrs: Any) -> UnifiedNode:
    return UnifiedNode(id=nid, entity_type=EntityType.ROLE, label=label, attributes=attrs)


def _sa(nid: str, label: str, **attrs: Any) -> UnifiedNode:
    return UnifiedNode(id=nid, entity_type=EntityType.SERVICE_ACCOUNT, label=label, attributes=attrs)


def _resource(nid: str, label: str, **attrs: Any) -> UnifiedNode:
    return UnifiedNode(id=nid, entity_type=EntityType.CLOUD_RESOURCE, label=label, attributes=attrs)


def _grant(src: str, tgt: str) -> UnifiedEdge:
    return UnifiedEdge(source=src, target=tgt, relationship=RelationshipType.HAS_PERMISSION)


def _verdict(verdicts: list[Any], node_id: str) -> Any:
    return next(v for v in verdicts if v.node_id == node_id)


# ── GAP 1: AWS ROLE parity ───────────────────────────────────────────────────
def test_aws_role_over_grant_and_dormant_emitted_with_provider() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    rid = "role:aws:arn:aws:iam::111122223333:role/app"
    g.add_node(_role(rid, "app-role", cloud_provider="aws", last_used_at=_iso(200)))
    g.add_node(_resource("res:used", "used-bucket"))
    g.add_node(_resource("res:unused", "unused-bucket"))
    g.add_edge(_grant(rid, "res:used"))
    g.add_edge(_grant(rid, "res:unused"))

    verdicts = evaluate_identity_governance(g, usage={rid: {"res:used"}}, now=NOW)
    v = _verdict(verdicts, rid)
    assert v.provider == "aws"
    assert v.is_dormant is True
    assert v.dormant_days == 200
    assert v.unused_targets == ["res:unused"]

    findings = build_nhi_governance_findings(g, verdicts)
    over = [f for f in findings if f.evidence.get("nhi_governance") == "over_grant"]
    unattended = [f for f in findings if f.evidence.get("nhi_governance") == "unattended_identity"]
    assert len(over) == 1
    assert len(unattended) == 1
    assert over[0].asset.location == "aws"
    assert unattended[0].asset.location == "aws"
    assert "unused-bucket" in over[0].evidence["unused_targets"]


# ── GAP 1: GCP SERVICE_ACCOUNT parity ────────────────────────────────────────
def test_gcp_service_account_dormant_emitted_with_provider() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    sid = "service_account:gcp:svc@proj.iam.gserviceaccount.com"
    g.add_node(_sa(sid, "svc@proj", cloud_provider="gcp", last_used_at=_iso(200), escalates_to_admin=True))

    verdicts = evaluate_identity_governance(g, now=NOW)
    v = _verdict(verdicts, sid)
    assert v.provider == "gcp"
    assert v.is_dormant is True
    assert v.is_privileged is True

    findings = build_nhi_governance_findings(g, verdicts)
    unattended = [f for f in findings if f.evidence.get("nhi_governance") == "unattended_identity"]
    assert len(unattended) == 1
    assert unattended[0].asset.location == "gcp"
    # Privileged + dormant → high severity.
    assert unattended[0].severity == "high"


# ── GAP 1: fail-closed on absent evidence ────────────────────────────────────
def test_aws_role_without_evidence_is_not_fabricated() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    rid = "role:aws:arn:aws:iam::111122223333:role/bare"
    # No last_used_at, no owner key, granted to two resources, NO usage signal.
    g.add_node(_role(rid, "bare-role", cloud_provider="aws"))
    g.add_node(_resource("res:a", "a"))
    g.add_node(_resource("res:b", "b"))
    g.add_edge(_grant(rid, "res:a"))
    g.add_edge(_grant(rid, "res:b"))

    verdicts = evaluate_identity_governance(g, now=NOW)
    v = _verdict(verdicts, rid)
    # Absent evidence must never become a dormant / over-grant / orphan verdict.
    assert v.is_dormant is False
    assert v.dormant_days is None
    assert v.is_orphaned is False
    assert v.unused_targets == []

    findings = build_nhi_governance_findings(g, verdicts)
    node_findings = [f for f in findings if f.asset.identifier == v.identity_id]
    assert node_findings == []


# ── Regression: MANAGED_IDENTITY behavior unchanged ──────────────────────────
def test_managed_identity_over_grant_without_signal_unchanged() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        UnifiedNode(
            id="managed_identity:m",
            entity_type=EntityType.MANAGED_IDENTITY,
            label="m",
            attributes={"identity_id": "m", "owner": "alice", "last_used_at": _iso(1)},
        )
    )
    g.add_node(_resource("res:x", "x"))
    g.add_edge(_grant("managed_identity:m", "res:x"))

    v = _verdict(evaluate_identity_governance(g, now=NOW), "managed_identity:m")
    # Legacy: a grant with no observed usage is still an over-grant for a
    # MANAGED_IDENTITY (the NHI overlay supplies the usage contract). The
    # fail-closed gate applies ONLY to the newly-governed ROLE/SERVICE_ACCOUNT.
    assert v.unused_targets == ["res:x"]


# ── GAP 2: usage_evidence → last_used_at helper ──────────────────────────────
def test_role_last_used_at_picks_newest_real_timestamp() -> None:
    evidence = {
        "state": "available",
        "records": [
            {"service_namespace": "s3", "last_accessed_at": "2020-01-01T00:00:00+00:00"},
            {"service_namespace": "*", "last_accessed_at": "2021-05-01T00:00:00+00:00"},
        ],
    }
    assert _role_last_used_at(evidence) == "2021-05-01T00:00:00+00:00"


def test_role_last_used_at_absent_stays_none() -> None:
    # Access Advisor available but never used → no timestamp, never a false date.
    assert _role_last_used_at({"state": "available", "records": [{"last_accessed_at": None}]}) is None
    assert _role_last_used_at({"state": "unavailable", "records": []}) is None
    assert _role_last_used_at(None) is None


# ── GAP 2: end-to-end inventory → ROLE node last_used_at → dormancy ───────────
def _role_report(usage_evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_sources": ["aws-inventory"],
        "cloud_inventory": {
            "status": "ok",
            "provider": "aws",
            "account_id": "111122223333",
            "roles": [
                {
                    "name": "old-role",
                    "arn": "arn:aws:iam::111122223333:role/old-role",
                    "principal_type": "role",
                    "privilege_level": "unknown",
                    "policies": [],
                    "usage_evidence": usage_evidence,
                }
            ],
        },
    }


def test_role_usage_evidence_threads_last_used_and_marks_dormant() -> None:
    evidence = {
        "principal_arn": "arn:aws:iam::111122223333:role/old-role",
        "state": "available",
        "diagnostic": "access_advisor_available",
        "collected_at": "2026-06-20T00:00:00+00:00",
        "records": [
            {
                "service_namespace": "s3",
                "state": "available",
                "observed": True,
                "last_accessed_at": "2020-01-02T00:00:00+00:00",
                "source": "access_advisor",
            },
            {
                "service_namespace": "*",
                "state": "available",
                "observed": True,
                "last_accessed_at": "2020-03-15T00:00:00+00:00",
                "source": "role_last_used",
            },
        ],
    }
    graph = build_unified_graph_from_report(_role_report(evidence))
    role = next(n for n in graph.nodes.values() if n.entity_type == EntityType.ROLE)
    # Newest real Access-Advisor / RoleLastUsed timestamp lands on the node.
    assert role.attributes.get("last_used_at") == "2020-03-15T00:00:00+00:00"
    # ...and dormancy (real "now" is years later) reflects real telemetry.
    assert role.attributes.get("nhi_is_dormant") is True


def test_role_without_usage_timestamp_stays_not_evaluated() -> None:
    evidence = {
        "principal_arn": "arn:aws:iam::111122223333:role/old-role",
        "state": "unavailable",
        "diagnostic": "access_advisor_unavailable",
        "collected_at": "2026-06-20T00:00:00+00:00",
        "records": [],
    }
    graph = build_unified_graph_from_report(_role_report(evidence))
    role = next(n for n in graph.nodes.values() if n.entity_type == EntityType.ROLE)
    # Fail-closed: no real last-used telemetry → no fabricated timestamp/dormancy.
    assert "last_used_at" not in role.attributes
    assert role.attributes.get("nhi_is_dormant") is False
