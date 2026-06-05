"""End-to-end proof that every attack-path class derives and scores.

Builds one representative graph that exercises every attack-path class, runs the
REAL overlays (cnapp + effective-permissions + governance) and the REAL path
derivation + scoring, and asserts each class actually surfaces. This keeps the
"every class fires" claim provable in CI rather than asserted.
"""

from __future__ import annotations

from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, issue_identity, issue_jit_grant
from agent_bom.api.routes.graph import _derived_attack_paths, _fusion_signals_for_path
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.effective_permissions import apply_effective_permissions
from agent_bom.graph.governance_overlay import apply_governance_overlay
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


class _NoDrift:
    def list(self, *a, **k):
        return []


def _scenario() -> UnifiedGraph:
    g = UnifiedGraph(scan_id="e2e", tenant_id="default")

    def add(i, t, label, **attrs):
        g.add_node(UnifiedNode(id=i, entity_type=t, label=label, attributes=attrs))

    # vuln-anchored chain: agent → server → package → CVE (+ creds/tools)
    add("agent:a", EntityType.AGENT, "billing-agent")
    add("server:fs", EntityType.SERVER, "mcp-fs")
    add("pkg:express", EntityType.PACKAGE, "express")
    add("vuln:CVE-1", EntityType.VULNERABILITY, "CVE-2024-1", severity="critical", risk_score=9.0)
    add("tool:run_shell", EntityType.TOOL, "run_shell")
    add("cred:aws", EntityType.CREDENTIAL, "AWS_SECRET_ACCESS_KEY")
    g.add_edge(UnifiedEdge(source="agent:a", target="server:fs", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="server:fs", target="pkg:express", relationship=RelationshipType.DEPENDS_ON))
    g.add_edge(UnifiedEdge(source="pkg:express", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO))
    g.add_edge(UnifiedEdge(source="server:fs", target="tool:run_shell", relationship=RelationshipType.PROVIDES_TOOL))
    g.add_edge(UnifiedEdge(source="server:fs", target="cred:aws", relationship=RelationshipType.EXPOSES_CRED))
    # runtime-observed activity on the agent
    add("call:1", EntityType.TOOL_CALL, "observed-call")
    g.add_edge(UnifiedEdge(source="agent:a", target="call:1", relationship=RelationshipType.INVOKED))

    # public PII bucket that is also vulnerable, reached by a misconfiguration
    add("cloud:bucket", EntityType.CLOUD_RESOURCE, "customer-pii prod S3 bucket", resource_type="s3")
    add("mc:public", EntityType.MISCONFIGURATION, "S3 bucket is publicly accessible")
    add("vuln:CVE-2", EntityType.VULNERABILITY, "CVE-2024-2", severity="high")
    g.add_edge(UnifiedEdge(source="mc:public", target="cloud:bucket", relationship=RelationshipType.AFFECTS))
    g.add_edge(UnifiedEdge(source="cloud:bucket", target="vuln:CVE-2", relationship=RelationshipType.VULNERABLE_TO))

    # identity privilege escalation: dev can assume admin-role that reaches the bucket
    add("user:dev", EntityType.USER, "dev")
    add("role:admin", EntityType.ROLE, "prod-admin-role")
    add("pol:admin", EntityType.POLICY, "AdministratorAccess")
    g.add_edge(UnifiedEdge(source="user:dev", target="role:admin", relationship=RelationshipType.TRUSTS))
    g.add_edge(UnifiedEdge(source="role:admin", target="pol:admin", relationship=RelationshipType.ATTACHED))
    g.add_edge(UnifiedEdge(source="role:admin", target="cloud:bucket", relationship=RelationshipType.CAN_ACCESS))
    return g


def test_every_attack_path_class_fires_end_to_end():
    g = _scenario()
    store = InMemoryAgentIdentityStore()
    idn, _ = issue_identity(store, agent_id="billing-agent", tenant_id="default", allowed_tools=[])
    issue_jit_grant(
        store,
        identity_id=idn.identity_id,
        agent_id="billing-agent",
        tenant_id="default",
        tool_name="run_shell",
        ttl_seconds=300,
        approved_by="admin",
    )

    cnapp = apply_cnapp_overlay(g)
    eff = apply_effective_permissions(g)
    gov = apply_governance_overlay(g, tenant_id="default", identity_store=store, drift_store=_NoDrift())

    # Overlays produced the structure for every class.
    assert cnapp["exposed_nodes"] >= 1 and cnapp["data_stores_added"] >= 1
    assert cnapp["toxic_combinations"] >= 1 and cnapp["exposed_sensitive_data"] >= 1
    assert eff["has_permission_edges"] >= 1 and eff["privilege_escalations"] >= 1
    assert gov["nodes_added"] >= 1

    # Toxic combinations recorded.
    patterns = {r.pattern for r in g.interaction_risks}
    assert {"internet_exposed_vulnerable", "internet_exposed_sensitive_data", "privilege_escalation"} <= patterns

    # Every scored fusion signal class is reachable somewhere in the graph.
    all_signals = set()
    for node in g.nodes:
        all_signals |= {k for k, _l, _d, _b in _fusion_signals_for_path(g, [node])}
    for expected in (
        "toxic_exposed_vulnerable",
        "internet_exposed",
        "exposed_sensitive_data",
        "privilege_escalation_admin",
        "runtime_observed",
    ):
        assert expected in all_signals, f"missing fusion signal: {expected}"

    # Derived attack paths include the priv-esc and data-exposure chains, top-ranked.
    paths = _derived_attack_paths(g)
    assert paths
    top = sorted(paths, key=lambda p: -p.composite_risk)
    assert top[0].composite_risk >= 85
    summaries = " || ".join(p.summary for p in paths)
    assert "assuming" in summaries  # privilege escalation path
    assert "GDPR" in summaries  # path to sensitive data, regulation named (PII → GDPR)
    assert "no per-tool scope" in summaries  # broad-scope identity (pure governance)
