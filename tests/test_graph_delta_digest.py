"""Delta-alert equivalence: bounded prior-snapshot digest vs full prior graph.

The streamed write path (#4075) computes graph delta alerts from a bounded
:class:`PriorSnapshotDigest` instead of loading the previous snapshot into a
second full ``UnifiedGraph``. These tests pin that the digest path produces
*byte-identical* alerts to the full-graph path across every delta branch.
"""

from __future__ import annotations

from agent_bom.graph.container import AttackPath, InteractionRisk, UnifiedGraph
from agent_bom.graph.delta_digest import (
    PriorSnapshotDigestBuilder,
    compute_delta_alerts_from_digest,
    digest_from_graph,
)
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus
from agent_bom.graph.webhooks import compute_delta_alerts


def _agent(node_id: str, label: str = "a", severity: str = "", risk: float = 1.0) -> UnifiedNode:
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.AGENT,
        label=label,
        severity=severity,
        risk_score=risk,
        status=NodeStatus.ACTIVE,
    )


def _vuln(node_id: str, severity: str, label: str = "CVE-x") -> UnifiedNode:
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.VULNERABILITY,
        label=label,
        severity=severity,
        risk_score=9.0,
        attributes={"cvss_score": 9.1, "is_kev": True, "affected_agent_count": 3},
    )


def _misconfig(node_id: str, severity: str, label: str = "CIS-1.1") -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=EntityType.MISCONFIGURATION, label=label, severity=severity)


def _old_graph() -> UnifiedGraph:
    g = UnifiedGraph(scan_id="scan-old", tenant_id="t1")
    g.add_node(_agent("agent:keep", "keep-agent"))
    g.add_node(_agent("agent:gone", "gone-agent", severity="high", risk=7.5))
    g.add_node(_vuln("vuln:old", "critical", "CVE-OLD"))
    g.add_node(_misconfig("mis:old", "high"))
    g.attack_paths.append(AttackPath(source="agent:keep", target="vuln:old", hops=["agent:keep", "vuln:old"], composite_risk=8.0))
    g.interaction_risks.append(
        InteractionRisk(pattern="loop", agents=["keep", "gone"], risk_score=8.0, description="d", owasp_agentic_tag="AA1")
    )
    return g


def _new_graph() -> UnifiedGraph:
    g = UnifiedGraph(scan_id="scan-new", tenant_id="t1")
    # keep-agent stays; gone-agent removed
    g.add_node(_agent("agent:keep", "keep-agent"))
    # brand-new critical vuln + high misconfig (should alert)
    g.add_node(_vuln("vuln:new", "critical", "CVE-NEW"))
    g.add_node(_misconfig("mis:new", "critical"))
    # carried-over old vuln (present in old -> no new-vuln alert)
    g.add_node(_vuln("vuln:old", "critical", "CVE-OLD"))
    # new high-risk attack path + interaction risk (exercise those branches)
    g.attack_paths.append(AttackPath(source="agent:keep", target="vuln:new", hops=["agent:keep", "vuln:new"], composite_risk=9.5))
    g.attack_paths.append(AttackPath(source="agent:keep", target="vuln:old", hops=["agent:keep", "vuln:old"], composite_risk=8.0))
    g.interaction_risks.append(
        InteractionRisk(pattern="new-loop", agents=["keep"], risk_score=9.1, description="d2", owasp_agentic_tag="AA2")
    )
    g.interaction_risks.append(
        InteractionRisk(pattern="loop", agents=["keep", "gone"], risk_score=8.0, description="d", owasp_agentic_tag="AA1")
    )
    return g


def test_digest_delta_matches_full_graph_delta_across_all_branches() -> None:
    old = _old_graph()
    new = _new_graph()

    full_alerts = compute_delta_alerts(old, new)
    digest_alerts = compute_delta_alerts_from_digest(digest_from_graph(old), new)

    # Byte-identical, order-preserving.
    assert digest_alerts == full_alerts
    # Sanity: the fixture actually exercised multiple branches.
    kinds = {a["type"] for a in full_alerts}
    assert {"new_vulnerability", "new_misconfiguration", "new_attack_path", "new_interaction_risk", "agent_removed"} <= kinds


def test_digest_delta_matches_when_no_prior_snapshot() -> None:
    new = _new_graph()
    assert compute_delta_alerts_from_digest(None, new) == compute_delta_alerts(None, new)


def test_builder_streams_rows_into_equivalent_digest() -> None:
    old = _old_graph()
    builder = PriorSnapshotDigestBuilder()
    # Simulate a backend streaming persisted rows (entity_type as stored string).
    for node in old.nodes.values():
        builder.add_node(
            node.id,
            node.entity_type.value,
            label=node.label,
            severity=node.severity,
            status=node.status.value,
            risk_score=node.risk_score,
        )
    for path in old.attack_paths:
        builder.add_attack_path(path.source, path.target)
    for risk in old.interaction_risks:
        builder.add_interaction_risk(risk.pattern, risk.agents)

    new = _new_graph()
    assert compute_delta_alerts_from_digest(builder.build(), new) == compute_delta_alerts(old, new)
