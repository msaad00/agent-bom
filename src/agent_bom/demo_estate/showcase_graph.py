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
        "cursor": "Cursor IDE Agent",
        "langchain-service": "LangChain Service Agent",
        "support-copilot": "Support Copilot",
        "data-pipeline": "Data Pipeline Agent",
        "claude-desktop": "Claude Desktop Agent",
    }
    for aid, label in agents.items():
        node(f"agent:{aid}", EntityType.AGENT, label, environment="production")

    servers = {
        "filesystem-server": ("cursor", ["read_file", "write_file", "list_directory"]),
        "shell-runner-server": ("cursor", ["run_shell", "exec_command", "read_file"]),
        "llm-orchestrator-server": ("langchain-service", ["run_chain", "eval_expression", "http_get"]),
        "vector-db-server": ("langchain-service", ["query_vectors", "upsert_vectors"]),
        "helpdesk-server": ("support-copilot", ["create_ticket", "search_tickets", "send_reply"]),
        "email-server": ("support-copilot", ["send_email", "list_inbox"]),
        "warehouse-server": ("data-pipeline", ["run_query", "execute_sql", "export_csv"]),
        "etl-server": ("data-pipeline", ["transform_image", "load_data"]),
        "github-server": ("claude-desktop", ["create_issue", "search_repos", "push_files"]),
        "team-chat-server": ("claude-desktop", ["send_message", "list_channels"]),
    }
    for sid, (owner, tools) in servers.items():
        node(f"server:{sid}", EntityType.SERVER, sid)
        edge(f"agent:{owner}", f"server:{sid}", RelationshipType.USES)
        for tname in tools:
            tid = f"tool:{sid}:{tname}"
            node(tid, EntityType.TOOL, tname)
            edge(f"server:{sid}", tid, RelationshipType.PROVIDES_TOOL)

    # Real CVEs on real package@versions — mirrors the demo advisory catalog.
    pkgs = {
        "pyyaml@5.3": ("shell-runner-server", "CVE-2020-14343", "critical", 9.8),
        "langchain@0.0.150": ("llm-orchestrator-server", "CVE-2023-36258", "critical", 9.8),
        "pillow@9.0.0": ("etl-server", "CVE-2023-4863", "high", 8.8),
        "jsonwebtoken@8.5.1": ("helpdesk-server", "CVE-2022-23529", "high", 7.6),
        "axios@1.4.0": ("helpdesk-server", "CVE-2023-45857", "high", 6.5),
        "cryptography@39.0.0": ("warehouse-server", "CVE-2023-50782", "high", 7.5),
        "ws@8.5.0": ("filesystem-server", "CVE-2024-37890", "high", 7.5),
        "flask@2.2.0": ("team-chat-server", "CVE-2023-30861", "high", 7.5),
        "certifi@2022.12.7": ("email-server", "CVE-2023-37920", "high", 7.5),
        "lodash@4.17.20": ("github-server", "CVE-2021-23337", "high", 7.2),
        "express@4.17.1": ("filesystem-server", "CVE-2024-29041", "medium", 6.1),
        "requests@2.28.0": ("vector-db-server", "CVE-2023-32681", "medium", 6.1),
        "jinja2@3.0.0": ("team-chat-server", "CVE-2024-22195", "medium", 5.4),
    }
    kev_cves = {"CVE-2023-4863"}
    for purl, (sid, cve, sev, score) in pkgs.items():
        pid = f"pkg:{purl}"
        node(pid, EntityType.PACKAGE, purl)
        edge(f"server:{sid}", pid, RelationshipType.DEPENDS_ON)
        vid = f"vuln:{cve}"
        node(vid, EntityType.VULNERABILITY, cve, severity=sev, risk_score=score, is_kev=cve in kev_cves)
        edge(pid, vid, RelationshipType.VULNERABLE_TO)

    # Malicious/typosquat package — the malicious-package differentiator.
    node(
        "pkg:reqeusts@2.99.0",
        EntityType.PACKAGE,
        "reqeusts@2.99.0",
        severity="critical",
        risk_score=9.1,
        is_malicious=True,
        malicious_reason="Possible typosquat of 'requests'",
    )
    edge("server:etl-server", "pkg:reqeusts@2.99.0", RelationshipType.DEPENDS_ON)
    node("vuln:MAL-2024-reqeusts", EntityType.VULNERABILITY, "MAL-2024-reqeusts", severity="critical", risk_score=9.1)
    edge("pkg:reqeusts@2.99.0", "vuln:MAL-2024-reqeusts", RelationshipType.VULNERABLE_TO)

    # Credential-backed env on servers — lights up credential-exposure edges.
    creds = {
        "cred:aws-secret": ("AWS_SECRET_ACCESS_KEY", "shell-runner-server"),
        "cred:openai-key": ("OPENAI_API_KEY", "llm-orchestrator-server"),
        "cred:db-url": ("DATABASE_URL", "vector-db-server"),
        "cred:jwt-secret": ("JWT_SECRET", "helpdesk-server"),
        "cred:snowflake-pw": ("SNOWFLAKE_PASSWORD", "warehouse-server"),
        "cred:gcs-key": ("GCS_SERVICE_ACCOUNT_KEY", "etl-server"),
        "cred:github-token": ("GITHUB_TOKEN", "github-server"),
        "cred:slack-token": ("SLACK_BOT_TOKEN", "team-chat-server"),
    }
    for cid, (label, sid) in creds.items():
        node(cid, EntityType.CREDENTIAL, label)
        edge(f"server:{sid}", cid, RelationshipType.EXPOSES_CRED)

    # Hero blast-radius chain: the PyYAML RCE on shell-runner-server reaches an
    # AWS credential AND the run_shell tool → potential RCE. This is the top
    # exposure path the graph/posture surfaces should headline.
    edge("vuln:CVE-2020-14343", "cred:aws-secret", RelationshipType.EXPLOITABLE_VIA, weight=9.8)
    edge("vuln:CVE-2020-14343", "tool:shell-runner-server:run_shell", RelationshipType.EXPLOITABLE_VIA, weight=9.8)
    edge("cred:aws-secret", "tool:shell-runner-server:run_shell", RelationshipType.REACHES_TOOL)
    # Second high-signal chain: LangChain RCE reaches the eval_expression tool.
    edge("vuln:CVE-2023-36258", "tool:llm-orchestrator-server:eval_expression", RelationshipType.EXPLOITABLE_VIA, weight=9.8)
    edge("vuln:CVE-2023-36258", "cred:openai-key", RelationshipType.EXPLOITABLE_VIA, weight=9.8)

    for i, (aid, tid) in enumerate(
        [
            ("cursor", "tool:shell-runner-server:run_shell"),
            ("data-pipeline", "tool:warehouse-server:execute_sql"),
            ("langchain-service", "tool:llm-orchestrator-server:eval_expression"),
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

    # cursor drives the shell-runner (AWS creds + run_shell) → toxic combo with
    # prod-admin; data-pipeline maps to the least-privilege pipeline role.
    edge("agent:cursor", "role:prod-admin", RelationshipType.CAN_ACCESS)
    edge("agent:data-pipeline", "role:data-pipeline", RelationshipType.CAN_ACCESS)

    store = InMemoryAgentIdentityStore()
    _jit_tools = {"cursor": "run_shell", "data-pipeline": "execute_sql", "langchain-service": "eval_expression"}
    for aid, label in agents.items():
        idn, _ = issue_identity(store, agent_id=label, tenant_id=tenant_id, allowed_tools=[])
        if aid in _jit_tools:
            issue_jit_grant(
                store,
                identity_id=idn.identity_id,
                agent_id=label,
                tenant_id=tenant_id,
                tool_name=_jit_tools[aid],
                ttl_seconds=3600,
                approved_by="oncall@corp",
            )

    drift = _DriftStore(
        [
            _DriftIncident(
                incident_id="drift-001",
                blueprint_id="Cursor IDE Agent",
                drift_score=0.78,
                violation_count=14,
                top_violations=[{"tool_name": "run_shell"}],
            ),
            _DriftIncident(
                incident_id="drift-002",
                blueprint_id="Data Pipeline Agent",
                drift_score=0.41,
                violation_count=5,
                top_violations=[{"tool_name": "execute_sql"}],
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
