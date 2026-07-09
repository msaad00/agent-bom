"""Tests for the declarative graph toxic-combination rule evaluator.

Builds small synthetic ``UnifiedGraph`` instances that trigger each rule and
asserts the right ``Finding`` is emitted with correct severity escalation, MITRE
tag, and evidence node ids — then that findings flow through
``AIBOMReport.to_findings()`` and would trip a ``--fail-on-severity`` gate.
"""

from __future__ import annotations

from agent_bom.finding import FindingSource, FindingType
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.toxic_findings import (
    TOXIC_RULES,
    build_toxic_combination_findings,
    build_toxic_combination_findings_data,
    toxic_combination_findings_from_data,
)
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.models import AIBOMReport

# ── Helpers ──────────────────────────────────────────────────────────────────


def _node(node_id: str, et: EntityType, *, severity: str = "low", **attrs: object) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=et, label=node_id, severity=severity, attributes=dict(attrs))


def _edge(source: str, target: str, rel: RelationshipType, **evidence: object) -> UnifiedEdge:
    return UnifiedEdge(source=source, target=target, relationship=rel, evidence=dict(evidence))


def _graph(nodes: list[UnifiedNode], edges: list[UnifiedEdge]) -> UnifiedGraph:
    g = UnifiedGraph(scan_id="test")
    for n in nodes:
        g.add_node(n)
    for e in edges:
        g.add_edge(e)
    return g


def _by_rule(findings: list, rule_id: str) -> list:
    return [f for f in findings if f.evidence.get("rule_id") == rule_id]


# ── Per-rule graphs ──────────────────────────────────────────────────────────


def _graph_public_exposed_vulnerable() -> UnifiedGraph:
    res = _node("res:web", EntityType.CLOUD_RESOURCE, severity="high", toxic_exposed_vulnerable=True, internet_exposed=True)
    vuln = _node("vuln:cve", EntityType.VULNERABILITY, severity="critical")
    return _graph([res, vuln], [_edge("res:web", "vuln:cve", RelationshipType.VULNERABLE_TO)])


def _graph_public_exposed_kev() -> UnifiedGraph:
    res = _node("res:web", EntityType.CLOUD_RESOURCE, severity="high", toxic_exposed_vulnerable=True, internet_exposed=True)
    vuln = _node("vuln:cve", EntityType.VULNERABILITY, severity="critical", is_kev=True)
    return _graph([res, vuln], [_edge("res:web", "vuln:cve", RelationshipType.VULNERABLE_TO)])


def _graph_public_exposed_rce() -> UnifiedGraph:
    res = _node("res:web", EntityType.CLOUD_RESOURCE, severity="high", toxic_exposed_vulnerable=True, internet_exposed=True)
    vuln = _node("vuln:cve", EntityType.VULNERABILITY, severity="critical", impact_category="code-execution")
    return _graph([res, vuln], [_edge("res:web", "vuln:cve", RelationshipType.VULNERABLE_TO)])


def _graph_public_exposed_network_exploitable() -> UnifiedGraph:
    res = _node("res:web", EntityType.CLOUD_RESOURCE, severity="high", toxic_exposed_vulnerable=True, internet_exposed=True)
    vuln = _node(
        "vuln:cve",
        EntityType.VULNERABILITY,
        severity="critical",
        attack_vector="network",
        attack_complexity="low",
        privileges_required="none",
        user_interaction="none",
        network_exploitable=True,
    )
    return _graph([res, vuln], [_edge("res:web", "vuln:cve", RelationshipType.VULNERABLE_TO)])


def _graph_public_to_sensitive() -> UnifiedGraph:
    res = _node("res:bucket", EntityType.CLOUD_RESOURCE, severity="high", internet_exposed=True)
    store = _node(
        "data_store:res:bucket",
        EntityType.DATA_STORE,
        severity="high",
        data_sensitivity="sensitive",
        data_regulatory_frameworks=["GDPR"],
        backed_by="res:bucket",
    )
    return _graph([res, store], [_edge("res:bucket", "data_store:res:bucket", RelationshipType.STORES)])


def _graph_overpermissioned_to_sensitive() -> UnifiedGraph:
    principal = _node("role:analytics", EntityType.ROLE, severity="medium")
    store = _node("data_store:pii", EntityType.DATA_STORE, severity="high", data_sensitivity="sensitive")
    return _graph(
        [principal, store],
        [_edge("role:analytics", "data_store:pii", RelationshipType.HAS_PERMISSION, access="admin", privileged=True)],
    )


def _graph_agent_reaches_privileged() -> UnifiedGraph:
    agent = _node("agent:assistant", EntityType.AGENT, severity="medium")
    server = _node("server:files", EntityType.SERVER, severity="low")
    cred = _node("cred:api_key", EntityType.CREDENTIAL, severity="high")
    return _graph(
        [agent, server, cred],
        [
            _edge("agent:assistant", "server:files", RelationshipType.USES),
            _edge("server:files", "cred:api_key", RelationshipType.EXPOSES_CRED),
        ],
    )


def _graph_public_permission_lateral() -> UnifiedGraph:
    entry = _node("role:public_fn", EntityType.ROLE, severity="medium", internet_exposed=True)
    other = _node("account:prod", EntityType.ACCOUNT, severity="high")
    # ASSUMES is a genuine OUTBOUND lateral capability: the exposed role can
    # assume into account:prod. (CROSS_ACCOUNT_TRUST is inbound and must NOT
    # count as lateral — see test_cross_account_trust_is_not_lateral.)
    return _graph(
        [entry, other],
        [_edge("role:public_fn", "account:prod", RelationshipType.ASSUMES)],
    )


def _graph_cross_account_trust_only() -> UnifiedGraph:
    entry = _node("role:public_fn", EntityType.ROLE, severity="medium", internet_exposed=True)
    other = _node("account:external", EntityType.ACCOUNT, severity="high")
    # role -> account CROSS_ACCOUNT_TRUST encodes that the external account may
    # assume the role (INBOUND). It is not an outbound pivot the role can walk.
    return _graph(
        [entry, other],
        [_edge("role:public_fn", "account:external", RelationshipType.CROSS_ACCOUNT_TRUST)],
    )


# ── Per-rule assertions ──────────────────────────────────────────────────────


def test_public_exposed_vulnerable_rule():
    findings = build_toxic_combination_findings(_graph_public_exposed_vulnerable())
    hits = _by_rule(findings, "PUBLIC_EXPOSED_VULNERABLE")
    assert len(hits) == 1
    f = hits[0]
    assert f.finding_type == FindingType.COMBINATION
    assert f.source == FindingSource.GRAPH_ANALYSIS
    # max component severity = critical (vuln) → escalation caps at critical.
    assert f.severity == "critical"
    assert "T1190" in f.attack_tags
    assert set(f.evidence["node_ids"]) == {"res:web", "vuln:cve"}
    assert f.asset.name == "res:web"


def test_public_exposed_kev_rule():
    findings = build_toxic_combination_findings(_graph_public_exposed_kev())
    hits = _by_rule(findings, "PUBLIC_EXPOSED_KEV")
    assert len(hits) == 1
    f = hits[0]
    assert f.severity == "critical"
    assert "T1190" in f.attack_tags
    assert "CISA KEV" in f.title
    assert set(f.evidence["node_ids"]) == {"res:web", "vuln:cve"}


def test_public_exposed_rce_rule_requires_cwe_backed_impact():
    findings = build_toxic_combination_findings(_graph_public_exposed_rce())
    hits = _by_rule(findings, "PUBLIC_EXPOSED_RCE")
    assert len(hits) == 1
    f = hits[0]
    assert f.severity == "critical"
    assert {"T1190", "T1059"}.issubset(set(f.attack_tags))
    assert "RCE" in f.title


def test_public_exposed_network_exploitable_rule_uses_cvss_attack_vector():
    findings = build_toxic_combination_findings(_graph_public_exposed_network_exploitable())
    hits = _by_rule(findings, "PUBLIC_EXPOSED_NETWORK_EXPLOITABLE")
    assert len(hits) == 1
    f = hits[0]
    assert f.severity == "critical"
    assert "CVSS AV:N" in f.title
    assert set(f.evidence["node_ids"]) == {"res:web", "vuln:cve"}


def test_public_to_sensitive_data_rule():
    findings = build_toxic_combination_findings(_graph_public_to_sensitive())
    hits = _by_rule(findings, "PUBLIC_TO_SENSITIVE_DATA")
    assert len(hits) == 1
    f = hits[0]
    assert "T1530" in f.attack_tags
    # max component = high → escalates to critical.
    assert f.severity == "critical"
    assert "data_store:res:bucket" in f.evidence["node_ids"]
    assert f.asset.name == "res:bucket"


def test_overpermissioned_to_sensitive_rule():
    findings = build_toxic_combination_findings(_graph_overpermissioned_to_sensitive())
    hits = _by_rule(findings, "OVERPERMISSIONED_TO_SENSITIVE")
    assert len(hits) == 1
    f = hits[0]
    assert "T1078" in f.attack_tags
    # max component = high (store) → critical.
    assert f.severity == "critical"
    assert set(f.evidence["node_ids"]) == {"role:analytics", "data_store:pii"}


def test_overpermissioned_read_only_does_not_trigger():
    principal = _node("role:reader", EntityType.ROLE, severity="medium")
    store = _node("data_store:pii", EntityType.DATA_STORE, severity="high", data_sensitivity="sensitive")
    g = _graph(
        [principal, store],
        [_edge("role:reader", "data_store:pii", RelationshipType.HAS_PERMISSION, access="read", privilege="select")],
    )
    findings = build_toxic_combination_findings(g)
    assert _by_rule(findings, "OVERPERMISSIONED_TO_SENSITIVE") == []


def test_agent_reaches_privileged_rule():
    findings = build_toxic_combination_findings(_graph_agent_reaches_privileged())
    hits = _by_rule(findings, "AGENT_REACHES_PRIVILEGED")
    assert len(hits) == 1
    f = hits[0]
    assert "T1552" in f.attack_tags
    # max component = high (credential) → critical.
    assert f.severity == "critical"
    assert "cred:api_key" in f.evidence["node_ids"]
    assert f.asset.name == "agent:assistant"


def test_public_permission_lateral_rule():
    findings = build_toxic_combination_findings(_graph_public_permission_lateral())
    hits = _by_rule(findings, "PUBLIC_PERMISSION_LATERAL")
    assert len(hits) == 1
    f = hits[0]
    assert "T1078.004" in f.attack_tags
    # max component = high (account) → critical.
    assert f.severity == "critical"
    assert "account:prod" in f.evidence["node_ids"]


def test_cross_account_trust_is_not_lateral():
    """Regression: a role→account CROSS_ACCOUNT_TRUST edge is INBOUND trust
    (the account may assume the role), so an internet-exposed role must NOT be
    reported as pivoting laterally into the trusting account."""
    findings = build_toxic_combination_findings(_graph_cross_account_trust_only())
    assert _by_rule(findings, "PUBLIC_PERMISSION_LATERAL") == []


def test_severity_escalation_one_tier_above_max():
    # Max component = medium; escalation = one tier above (high). The rule's
    # "high" floor is also satisfied, so the escalation drives the result.
    res = _node("res:web", EntityType.CLOUD_RESOURCE, severity="medium", toxic_exposed_vulnerable=True, internet_exposed=True)
    vuln = _node("vuln:cve", EntityType.VULNERABILITY, severity="medium")
    g = _graph([res, vuln], [_edge("res:web", "vuln:cve", RelationshipType.VULNERABLE_TO)])
    f = _by_rule(build_toxic_combination_findings(g), "PUBLIC_EXPOSED_VULNERABLE")[0]
    assert f.severity == "high"


def test_severity_escalation_caps_at_critical():
    # Max component already critical → escalation caps at critical (no overflow).
    res = _node("res:web", EntityType.CLOUD_RESOURCE, severity="critical", toxic_exposed_vulnerable=True, internet_exposed=True)
    vuln = _node("vuln:cve", EntityType.VULNERABILITY, severity="critical")
    g = _graph([res, vuln], [_edge("res:web", "vuln:cve", RelationshipType.VULNERABLE_TO)])
    f = _by_rule(build_toxic_combination_findings(g), "PUBLIC_EXPOSED_VULNERABLE")[0]
    assert f.severity == "critical"


def test_severity_rule_floor_applies():
    # Components carry thin (info) severity, but the rule asserts an inherently
    # severe pattern, so the "high" floor still applies.
    res = _node("res:web", EntityType.CLOUD_RESOURCE, severity="info", toxic_exposed_vulnerable=True, internet_exposed=True)
    vuln = _node("vuln:cve", EntityType.VULNERABILITY, severity="info")
    g = _graph([res, vuln], [_edge("res:web", "vuln:cve", RelationshipType.VULNERABLE_TO)])
    f = _by_rule(build_toxic_combination_findings(g), "PUBLIC_EXPOSED_VULNERABLE")[0]
    assert f.severity == "high"


def test_clean_graph_produces_zero():
    res = _node("res:web", EntityType.CLOUD_RESOURCE, severity="low")
    pkg = _node("pkg:lib", EntityType.PACKAGE, severity="low")
    g = _graph([res, pkg], [_edge("res:web", "pkg:lib", RelationshipType.DEPENDS_ON)])
    assert build_toxic_combination_findings(g) == []
    assert build_toxic_combination_findings(UnifiedGraph()) == []


def test_dedupe_by_rule_and_node_set():
    g = _graph_public_exposed_vulnerable()
    # A duplicate VULNERABLE_TO edge (same triple) is collapsed by add_edge; the
    # rule must also dedupe by (rule_id, sorted node-id set) regardless.
    findings = build_toxic_combination_findings(g)
    keys = [(f.evidence["rule_id"], tuple(sorted(set(f.evidence["node_ids"])))) for f in findings]
    assert len(keys) == len(set(keys))


def test_all_rules_have_unique_ids_and_mitre():
    ids = [r.id for r in TOXIC_RULES]
    assert len(ids) == len(set(ids))
    assert len(TOXIC_RULES) == 8
    for rule in TOXIC_RULES:
        assert rule.mitre, f"{rule.id} missing MITRE tag"


# ── End-to-end: report.to_findings + fail-on-severity ────────────────────────


def _report_with_toxic_data(g: UnifiedGraph) -> AIBOMReport:
    report = AIBOMReport()
    report.toxic_combination_findings_data = build_toxic_combination_findings_data(g)
    return report


def test_findings_reach_report_to_findings():
    report = _report_with_toxic_data(_graph_public_exposed_vulnerable())
    combos = [f for f in report.to_findings() if f.finding_type == FindingType.COMBINATION]
    assert len(combos) == 1
    assert combos[0].severity == "critical"
    assert combos[0].source == FindingSource.GRAPH_ANALYSIS


def test_findings_trip_fail_on_severity_gate():
    report = _report_with_toxic_data(_graph_public_exposed_vulnerable())
    non_cve = [f for f in report.to_findings() if f.finding_type != FindingType.CVE]
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    # Mirrors cli/agents/_post.py gate logic for high/critical thresholds.
    assert any(order.get(f.severity, 0) >= order["high"] for f in non_cve)
    assert any(order.get(f.severity, 0) >= order["critical"] for f in non_cve)


def test_data_roundtrip_preserves_fields():
    data = build_toxic_combination_findings_data(_graph_overpermissioned_to_sensitive())
    rehydrated = toxic_combination_findings_from_data(data)
    assert len(rehydrated) == 1
    f = rehydrated[0]
    assert f.finding_type == FindingType.COMBINATION
    assert f.severity == "critical"
    assert "T1078" in f.attack_tags
    assert set(f.evidence["node_ids"]) == {"role:analytics", "data_store:pii"}


def test_clean_report_has_no_combination_findings():
    report = AIBOMReport()
    assert [f for f in report.to_findings() if f.finding_type == FindingType.COMBINATION] == []


# ── Perf regression: privileged-edge source set computed once ─────────────────


def _graph_multi_agent_privileged(n: int = 3) -> UnifiedGraph:
    nodes: list[UnifiedNode] = []
    edges: list[UnifiedEdge] = []
    for i in range(n):
        agent = _node(f"agent:{i}", EntityType.AGENT, severity="medium")
        server = _node(f"server:{i}", EntityType.SERVER, severity="low")
        cred = _node(f"cred:{i}", EntityType.CREDENTIAL, severity="high")
        nodes += [agent, server, cred]
        edges += [
            _edge(f"agent:{i}", f"server:{i}", RelationshipType.USES),
            _edge(f"server:{i}", f"cred:{i}", RelationshipType.EXPOSES_CRED),
        ]
    return _graph(nodes, edges)


class _CountingList(list):
    """List that counts how many times it is iterated."""

    iter_count = 0

    def __iter__(self):
        self.iter_count += 1
        return super().__iter__()


def test_agent_reaches_privileged_multi_agent_parity():
    from agent_bom.graph.toxic_findings import _match_agent_reaches_privileged

    g = _graph_multi_agent_privileged(3)
    matches = _match_agent_reaches_privileged(g)
    # Every agent that traverses a privileged edge to a credential is reported.
    assert {m.entry.id for m in matches} == {"agent:0", "agent:1", "agent:2"}


def test_agent_reaches_privileged_scans_edges_once():
    # Regression: the privileged-edge source set must be precomputed in a single
    # O(E) pass, not re-scanned per agent (O(agents x edges)). With the old
    # per-agent scan this iterates the edge list once per agent (3x); the fixed
    # single pass touches it exactly once regardless of agent count.
    from agent_bom.graph.toxic_findings import _match_agent_reaches_privileged

    g = _graph_multi_agent_privileged(3)
    g.edges = _CountingList(g.edges)
    _match_agent_reaches_privileged(g)
    assert g.edges.iter_count == 1
