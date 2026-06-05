#!/usr/bin/env python3
"""Seed a dense, realistic agentic-estate graph for UI screenshots / demos.

Builds a multi-cloud estate that exercises every attack-path class the graph
can derive — vuln-anchored chains, internet exposure (port-aware), toxic
exposed+vulnerable, path-to-sensitive-data, and privilege escalation to admin —
then runs the real CNAPP, effective-permission, and governance overlays so the
graph the API serves is identical to a real scan's. Save it into a graph DB and
point ``agent-bom api`` at the same DB (``AGENT_BOM_GRAPH_DB``).

    python scripts/seed_graph_showcase.py --sqlite-db /tmp/showcase-graph.db
    AGENT_BOM_GRAPH_DB=/tmp/showcase-graph.db agent-bom api
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.api.agent_identity_store import (  # noqa: E402
    InMemoryAgentIdentityStore,
    issue_identity,
    issue_jit_grant,
)
from agent_bom.api.graph_store import SQLiteGraphStore  # noqa: E402
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay  # noqa: E402
from agent_bom.graph.container import UnifiedGraph  # noqa: E402
from agent_bom.graph.edge import UnifiedEdge  # noqa: E402
from agent_bom.graph.effective_permissions import apply_effective_permissions  # noqa: E402
from agent_bom.graph.governance_overlay import apply_governance_overlay  # noqa: E402
from agent_bom.graph.node import UnifiedNode  # noqa: E402
from agent_bom.graph.types import EntityType, RelationshipType  # noqa: E402

TENANT = "default"
SCAN_ID = "showcase"


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


def _build_estate() -> tuple[UnifiedGraph, InMemoryAgentIdentityStore, _DriftStore]:
    g = UnifiedGraph(scan_id=SCAN_ID, tenant_id=TENANT)

    def node(i: str, t: EntityType, label: str, **attrs) -> str:
        # severity / risk_score are top-level node fields (severity_id derives
        # from severity); everything else is an attribute.
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

    # ── Agents (the fleet) ──────────────────────────────────────────────
    agents = {
        "billing-agent": "Billing Copilot",
        "support-agent": "Support Copilot",
        "data-pipeline-agent": "Data Pipeline Agent",
        "devops-agent": "DevOps Agent",
        "analytics-agent": "Analytics Agent",
    }
    for aid, label in agents.items():
        node(f"agent:{aid}", EntityType.AGENT, label, environment="production")

    # ── MCP servers + tools + packages + CVEs (supply-chain depth) ──────
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

    # Vulnerable packages anchoring real CVE chains.
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

    # Exposed credentials on the most privileged server.
    node("cred:aws-key", EntityType.CREDENTIAL, "AWS_SECRET_ACCESS_KEY")
    edge("server:mcp-deploy", "cred:aws-key", RelationshipType.EXPOSES_CRED)

    # ── Runtime-observed activity (confirmed reachability) ──────────────
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

    # ── Cloud estate: crown-jewel data + exposure + misconfig ───────────
    # Crown jewel: customer-PII S3 bucket that is BOTH public AND vulnerable.
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

    # Payments DB: sensitive RDS instance.
    node(
        "cloud:payments-db",
        EntityType.CLOUD_RESOURCE,
        "payments-db (RDS PostgreSQL)",
        resource_type="rds",
        compliance_tags=["PCI", "financial"],
    )

    # Internet-exposed bastion EC2 on port 22 (structured network_exposure).
    node("cloud:bastion", EntityType.CLOUD_RESOURCE, "prod-bastion (EC2)", resource_type="ec2")
    node(
        "mc:sg-open",
        EntityType.MISCONFIGURATION,
        "Security group sg-prod allows 0.0.0.0/0 on port 22",
        network_exposure=[{"resource": "prod-bastion", "from_port": 22, "to_port": 22, "protocol": "tcp", "scope": "internet"}],
    )
    edge("mc:sg-open", "cloud:bastion", RelationshipType.AFFECTS)

    # Logs bucket (non-sensitive, for contrast).
    node("cloud:logs-bucket", EntityType.CLOUD_RESOURCE, "app-logs (S3)", resource_type="s3")

    # ── IAM: users, roles, policies, trust chains (privilege escalation) ─
    node("user:alice", EntityType.USER, "alice@corp (developer)")
    node("user:bob", EntityType.USER, "bob@contractor (external)")
    node("role:prod-admin", EntityType.ROLE, "prod-admin-role")
    node("role:data-pipeline", EntityType.ROLE, "data-pipeline-role")
    node("role:readonly", EntityType.ROLE, "readonly-role")
    # Benign-named custom policy that actually grants iam:* (action-level admin).
    node("pol:admin", EntityType.POLICY, "AdministratorAccess", privilege_level="admin")
    node("pol:team-custom", EntityType.POLICY, "team-utility-policy", privilege_level="admin")
    node("pol:s3-write", EntityType.POLICY, "s3-write-policy", privilege_level="write")
    node("pol:readonly", EntityType.POLICY, "ViewOnlyAccess", privilege_level="read")

    edge("role:prod-admin", "pol:admin", RelationshipType.ATTACHED)
    edge("role:data-pipeline", "pol:team-custom", RelationshipType.ATTACHED)  # benign name, admin actions
    edge("role:data-pipeline", "pol:s3-write", RelationshipType.ATTACHED)
    edge("role:readonly", "pol:readonly", RelationshipType.ATTACHED)

    # alice (dev) can assume prod-admin → privilege escalation to admin.
    edge("user:alice", "role:prod-admin", RelationshipType.TRUSTS)
    # bob (external contractor) can assume data-pipeline role (admin-action custom policy).
    edge("user:bob", "role:data-pipeline", RelationshipType.TRUSTS)

    # What the roles can reach (direct access edges → effective permissions).
    edge("role:prod-admin", "cloud:pii-bucket", RelationshipType.CAN_ACCESS)
    edge("role:prod-admin", "cloud:payments-db", RelationshipType.CAN_ACCESS)
    edge("role:prod-admin", "cloud:bastion", RelationshipType.CAN_ACCESS)
    edge("role:data-pipeline", "cloud:payments-db", RelationshipType.CAN_ACCESS)
    edge("role:data-pipeline", "cloud:logs-bucket", RelationshipType.CAN_ACCESS)
    edge("role:readonly", "cloud:logs-bucket", RelationshipType.CAN_ACCESS)

    # Agents bind to managed identities / roles (governance label-match).
    edge("agent:devops-agent", "role:prod-admin", RelationshipType.CAN_ACCESS)
    edge("agent:data-pipeline-agent", "role:data-pipeline", RelationshipType.CAN_ACCESS)

    # ── Governance: managed identities, JIT grants, drift ───────────────
    store = InMemoryAgentIdentityStore()
    for aid, label in agents.items():
        idn, _ = issue_identity(store, agent_id=label, tenant_id=TENANT, allowed_tools=[])
        # One over-broad JIT grant per privileged agent.
        if aid in ("billing-agent", "devops-agent", "data-pipeline-agent"):
            issue_jit_grant(
                store,
                identity_id=idn.identity_id,
                agent_id=label,
                tenant_id=TENANT,
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sqlite-db", default="/tmp/showcase-graph.db", help="Graph DB path to seed")
    args = ap.parse_args()

    g, store, drift = _build_estate()

    cnapp = apply_cnapp_overlay(g)
    eff = apply_effective_permissions(g)
    gov = apply_governance_overlay(g, tenant_id=TENANT, identity_store=store, drift_store=drift)

    db_path = Path(args.sqlite_db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    graph_store = SQLiteGraphStore(db_path)
    graph_store.save_graph(g)

    print(f"Seeded {len(g.nodes)} nodes / {len(g.edges)} edges → {db_path}")
    print(f"  cnapp:  {cnapp}")
    print(f"  effperm:{eff}")
    print(f"  gov:    {gov}")
    print(f"  risks:  {len(g.interaction_risks)} interaction risks")
    print(f"\nBoot the API against it:\n  AGENT_BOM_GRAPH_DB={db_path} agent-bom api")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
