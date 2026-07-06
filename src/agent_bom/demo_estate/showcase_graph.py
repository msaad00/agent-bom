"""Dense showcase graph for demos, screenshots, and first-session proof."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    issue_identity,
    issue_jit_grant,
)
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.effective_permissions import apply_effective_permissions
from agent_bom.graph.governance_overlay import apply_governance_overlay
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

if TYPE_CHECKING:
    from agent_bom.api.graph_store import GraphStoreProtocol

SHOWCASE_TENANT = "default"
SHOWCASE_SCAN_ID = "showcase"


class _DriftIncident:
    """Shape the governance overlay expects (attribute access)."""

    def __init__(self, *, incident_id, blueprint_id, drift_score, violation_count, top_violations):
        self.incident_id = incident_id
        self.blueprint_id = blueprint_id
        self.drift_score = drift_score
        self.violation_count = violation_count
        self.occurrences = violation_count
        self.status = "open"
        self.top_violations = top_violations


class _DriftStore:
    """Minimal drift store projecting behavioral-drift incidents."""

    def __init__(self, incidents: list[_DriftIncident]) -> None:
        self._incidents = incidents

    def list(self, *_a, **_k) -> list[_DriftIncident]:
        return list(self._incidents)


def build_showcase_graph(
    *,
    tenant_id: str = SHOWCASE_TENANT,
    scan_id: str = SHOWCASE_SCAN_ID,
) -> tuple[UnifiedGraph, InMemoryAgentIdentityStore, _DriftStore]:
    g = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)

    def node(i: str, t: EntityType, label: str, **attrs) -> str:
        severity = attrs.pop("severity", "")
        risk_score = attrs.pop("risk_score", 0.0)
        g.add_node(
            UnifiedNode(
                id=i,
                entity_type=t,
                label=label,
                severity=severity,
                risk_score=risk_score,
                attributes=attrs,
            )
        )
        return i

    def edge(s: str, d: str, r: RelationshipType, **kw) -> None:
        g.add_edge(UnifiedEdge(source=s, target=d, relationship=r, **kw))

    agents = {
        "billing-agent": "Billing Copilot",
        "support-agent": "Support Copilot",
        "data-pipeline-agent": "Data Pipeline Agent",
        "devops-agent": "DevOps Agent",
        "analytics-agent": "Analytics Agent",
    }
    for aid, label in agents.items():
        node(f"agent:{aid}", EntityType.AGENT, label, environment="production")

    servers = {
        "mcp-fs": ("billing-agent", ["read_file", "write_file", "run_shell"]),
        "mcp-db": ("data-pipeline-agent", ["sql_query", "sql_exec"]),
        "mcp-http": ("support-agent", ["http_get", "http_post"]),
        "mcp-deploy": ("devops-agent", ["deploy", "rollback", "exec_remote"]),
        "mcp-warehouse": ("analytics-agent", ["query_warehouse"]),
    }
    for sid, (owner, tools) in servers.items():
        node(f"server:{sid}", EntityType.SERVER, sid)
        edge(f"agent:{owner}", f"server:{sid}", RelationshipType.USES)
        for tname in tools:
            tid = f"tool:{sid}:{tname}"
            node(tid, EntityType.TOOL, tname)
            edge(f"server:{sid}", tid, RelationshipType.PROVIDES_TOOL)

    pkgs = {
        "express@4.17.1": ("mcp-http", "CVE-2024-29041", "critical", 9.3),
        "pyyaml@5.3": ("mcp-db", "CVE-2020-14343", "critical", 9.8),
        "requests@2.19.0": ("mcp-fs", "CVE-2023-32681", "high", 7.5),
        "log4j@2.14.0": ("mcp-deploy", "CVE-2021-44228", "critical", 10.0),
        "pillow@9.0.0": ("mcp-warehouse", "CVE-2022-22817", "high", 8.1),
    }
    for purl, (sid, cve, sev, score) in pkgs.items():
        pid = f"pkg:{purl}"
        node(pid, EntityType.PACKAGE, purl)
        edge(f"server:{sid}", pid, RelationshipType.DEPENDS_ON)
        vid = f"vuln:{cve}"
        node(vid, EntityType.VULNERABILITY, cve, severity=sev, risk_score=score)
        edge(pid, vid, RelationshipType.VULNERABLE_TO)

    node("cred:aws-key", EntityType.CREDENTIAL, "AWS_SECRET_ACCESS_KEY")
    edge("server:mcp-deploy", "cred:aws-key", RelationshipType.EXPOSES_CRED)

    for i, (aid, tid) in enumerate(
        [
            ("billing-agent", "tool:mcp-fs:run_shell"),
            ("data-pipeline-agent", "tool:mcp-db:sql_exec"),
            ("devops-agent", "tool:mcp-deploy:exec_remote"),
        ]
    ):
        cid = f"call:{i}"
        node(cid, EntityType.TOOL_CALL, "observed invocation")
        edge(f"agent:{aid}", cid, RelationshipType.INVOKED)
        edge(cid, tid, RelationshipType.INVOKED)

    node(
        "cloud:pii-bucket",
        EntityType.CLOUD_RESOURCE,
        "customer-pii-prod (S3)",
        resource_type="s3",
        compliance_tags=["PII", "GDPR"],
    )
    node("mc:pii-public", EntityType.MISCONFIGURATION, "S3 bucket customer-pii-prod is publicly readable")
    node("vuln:bucket-acl", EntityType.VULNERABILITY, "CVE-2024-S3ACL", severity="high", risk_score=8.2)
    edge("mc:pii-public", "cloud:pii-bucket", RelationshipType.AFFECTS)
    edge("cloud:pii-bucket", "vuln:bucket-acl", RelationshipType.VULNERABLE_TO)

    node(
        "cloud:payments-db",
        EntityType.CLOUD_RESOURCE,
        "payments-db (RDS PostgreSQL)",
        resource_type="rds",
        compliance_tags=["PCI", "financial"],
    )

    node("cloud:bastion", EntityType.CLOUD_RESOURCE, "prod-bastion (EC2)", resource_type="ec2")
    node(
        "mc:sg-open",
        EntityType.MISCONFIGURATION,
        "Security group sg-prod allows 0.0.0.0/0 on port 22",
        network_exposure=[{"resource": "prod-bastion", "from_port": 22, "to_port": 22, "protocol": "tcp", "scope": "internet"}],
    )
    edge("mc:sg-open", "cloud:bastion", RelationshipType.AFFECTS)

    node("cloud:logs-bucket", EntityType.CLOUD_RESOURCE, "app-logs (S3)", resource_type="s3")

    node("user:alice", EntityType.USER, "alice@corp (developer)")
    node("user:bob", EntityType.USER, "bob@contractor (external)")
    node("role:prod-admin", EntityType.ROLE, "prod-admin-role")
    node("role:data-pipeline", EntityType.ROLE, "data-pipeline-role")
    node("role:readonly", EntityType.ROLE, "readonly-role")
    node("pol:admin", EntityType.POLICY, "AdministratorAccess", privilege_level="admin")
    node("pol:team-custom", EntityType.POLICY, "team-utility-policy", privilege_level="admin")
    node("pol:s3-write", EntityType.POLICY, "s3-write-policy", privilege_level="write")
    node("pol:readonly", EntityType.POLICY, "ViewOnlyAccess", privilege_level="read")

    edge("role:prod-admin", "pol:admin", RelationshipType.ATTACHED)
    edge("role:data-pipeline", "pol:team-custom", RelationshipType.ATTACHED)
    edge("role:data-pipeline", "pol:s3-write", RelationshipType.ATTACHED)
    edge("role:readonly", "pol:readonly", RelationshipType.ATTACHED)

    edge("user:alice", "role:prod-admin", RelationshipType.TRUSTS)
    edge("user:bob", "role:data-pipeline", RelationshipType.TRUSTS)

    edge("role:prod-admin", "cloud:pii-bucket", RelationshipType.CAN_ACCESS)
    edge("role:prod-admin", "cloud:payments-db", RelationshipType.CAN_ACCESS)
    edge("role:prod-admin", "cloud:bastion", RelationshipType.CAN_ACCESS)
    edge("role:data-pipeline", "cloud:payments-db", RelationshipType.CAN_ACCESS)
    edge("role:data-pipeline", "cloud:logs-bucket", RelationshipType.CAN_ACCESS)
    edge("role:readonly", "cloud:logs-bucket", RelationshipType.CAN_ACCESS)

    edge("agent:devops-agent", "role:prod-admin", RelationshipType.CAN_ACCESS)
    edge("agent:data-pipeline-agent", "role:data-pipeline", RelationshipType.CAN_ACCESS)

    store = InMemoryAgentIdentityStore()
    for aid, label in agents.items():
        idn, _ = issue_identity(store, agent_id=label, tenant_id=tenant_id, allowed_tools=[])
        if aid in ("billing-agent", "devops-agent", "data-pipeline-agent"):
            issue_jit_grant(
                store,
                identity_id=idn.identity_id,
                agent_id=label,
                tenant_id=tenant_id,
                tool_name="run_shell" if aid == "billing-agent" else "exec_remote",
                ttl_seconds=3600,
                approved_by="oncall@corp",
            )

    drift = _DriftStore(
        [
            _DriftIncident(
                incident_id="drift-001",
                blueprint_id="DevOps Agent",
                drift_score=0.78,
                violation_count=14,
                top_violations=[{"tool_name": "exec_remote"}],
            ),
            _DriftIncident(
                incident_id="drift-002",
                blueprint_id="Billing Copilot",
                drift_score=0.41,
                violation_count=5,
                top_violations=[{"tool_name": "run_shell"}],
            ),
        ]
    )
    return g, store, drift


def apply_showcase_overlays(
    graph: UnifiedGraph,
    *,
    tenant_id: str = SHOWCASE_TENANT,
    identity_store: InMemoryAgentIdentityStore,
    drift_store: _DriftStore,
) -> dict[str, object]:
    cnapp = apply_cnapp_overlay(graph)
    eff = apply_effective_permissions(graph)
    gov = apply_governance_overlay(graph, tenant_id=tenant_id, identity_store=identity_store, drift_store=drift_store)
    return {"cnapp": cnapp, "effective_permissions": eff, "governance": gov}


def seed_showcase_graph_if_empty(
    graph_store: GraphStoreProtocol,
    *,
    tenant_id: str = SHOWCASE_TENANT,
) -> bool:
    """Persist the showcase graph when the tenant has no snapshot yet."""
    latest_snapshot_id = getattr(graph_store, "latest_snapshot_id", None)
    if callable(latest_snapshot_id) and latest_snapshot_id(tenant_id=tenant_id):
        return False
    graph, identity_store, drift_store = build_showcase_graph(tenant_id=tenant_id)
    apply_showcase_overlays(graph, tenant_id=tenant_id, identity_store=identity_store, drift_store=drift_store)
    graph_store.save_graph(graph)
    return True
