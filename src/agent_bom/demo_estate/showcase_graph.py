"""Dense showcase graph for demos, screenshots, and first-session proof."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal

from agent_bom.api.agent_identity_store import (
    AgentIdentity,
    AgentJITGrant,
    InMemoryAgentIdentityStore,
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

ShowcaseProfile = Literal["baseline", "current"]

SHOWCASE_TENANT = "default"
SHOWCASE_SCAN_ID = "showcase"
SHOWCASE_BASELINE_SCAN_ID = "showcase-baseline"
SHOWCASE_BASELINE_CREATED_AT = "2026-06-01T12:00:00+00:00"
SHOWCASE_CURRENT_CREATED_AT = "2026-06-08T12:00:00+00:00"

_logger = logging.getLogger(__name__)

# Deterministic non-human-identity estate for the demo. Identity ids are stable
# across restarts so the persisted MANAGED_IDENTITY graph nodes and the live
# identity store agree — the governance overlay re-runs at request time and must
# not inject a *second*, duplicate set of identities. Each row is shaped to tell
# one clear NHI-governance story:
#   * an over-granted but owned + active identity (standing tool scopes it never
#     uses → right-size),
#   * a dormant + orphaned admin identity that reaches an exposed resource (the
#     textbook worst case → deprovision), and
#   * clean, owned, least-privilege identities for contrast.
_DEMO_IDENTITIES: tuple[dict[str, Any], ...] = (
    {
        "slug": "cursor",
        "agent_label": "Cursor IDE Agent",
        "role": "prod-admin",
        "owner": "platform-team@corp",
        "owner_type": "team",
        "allowed_tools": ["run_shell", "exec_command", "read_file", "execute_sql", "query_vectors"],
        "last_used_days": 1,
    },
    {
        "slug": "support-copilot",
        "agent_label": "Support Copilot",
        "role": "support-admin",
        "owner": "",  # orphaned — no accountable owner
        "owner_type": "",
        "allowed_tools": ["send_email", "create_ticket", "search_tickets"],
        "last_used_days": None,  # never observed → dormant
        "privileged": True,
        "internet_exposed": True,
    },
    {
        "slug": "data-pipeline",
        "agent_label": "Data Pipeline Agent",
        "role": "data-pipeline",
        "owner": "data-eng@corp",
        "owner_type": "team",
        "allowed_tools": [],  # least privilege — access is JIT-granted
        "last_used_days": 2,
    },
    {
        "slug": "langchain-service",
        "agent_label": "LangChain Service Agent",
        "role": "service",
        "owner": "ml-platform@corp",
        "owner_type": "team",
        "allowed_tools": [],
        "last_used_days": 3,
    },
    {
        "slug": "claude-desktop",
        "agent_label": "Claude Desktop Agent",
        "role": "agent",
        "owner": "",  # orphaned
        "owner_type": "",
        "allowed_tools": [],
        "last_used_days": None,  # dormant
    },
)

# JIT grants that light up ACCESS_GRANT nodes for the least-privilege identities.
_DEMO_JIT_GRANTS: tuple[tuple[str, str], ...] = (
    ("cursor", "run_shell"),
    ("data-pipeline", "execute_sql"),
    ("langchain-service", "eval_expression"),
)


def _demo_identity_id(slug: str) -> str:
    return f"demo-nhi-{slug}"


def demo_identity_records(tenant_id: str = SHOWCASE_TENANT) -> tuple[list[AgentIdentity], list[AgentJITGrant]]:
    """Return the deterministic enriched demo identities + JIT grants.

    Single source of truth shared by the persisted graph seed and the live
    identity-store seed so both carry identical ids and attributes.
    """
    now = datetime.now(timezone.utc)
    issued_at = (now - timedelta(days=120)).isoformat()
    expires_at = (now + timedelta(days=90)).isoformat()

    identities: list[AgentIdentity] = []
    by_slug: dict[str, str] = {}
    for spec in _DEMO_IDENTITIES:
        slug = str(spec["slug"])
        identity_id = _demo_identity_id(slug)
        by_slug[slug] = identity_id
        last_used_days = spec.get("last_used_days")
        last_used_at = "" if last_used_days is None else (now - timedelta(days=int(last_used_days))).isoformat()
        identities.append(
            AgentIdentity(
                identity_id=identity_id,
                agent_id=str(spec["agent_label"]),
                tenant_id=tenant_id,
                token_hash=f"demo-nhi-hash-{slug}",
                token_prefix="demo",
                role=str(spec.get("role") or "agent"),
                blueprint_id=str(spec["agent_label"]),
                status="active",
                issued_at=issued_at,
                expires_at=expires_at,
                allowed_tools=list(spec.get("allowed_tools") or []),
                owner=str(spec.get("owner") or ""),
                owner_type=str(spec.get("owner_type") or ""),
                last_used_at=last_used_at,
            )
        )

    grants: list[AgentJITGrant] = []
    approved_at = (now - timedelta(hours=2)).isoformat()
    grant_expiry = (now + timedelta(hours=1)).isoformat()
    for slug, tool_name in _DEMO_JIT_GRANTS:
        grant_identity_id = by_slug.get(slug)
        if not grant_identity_id:
            continue
        grants.append(
            AgentJITGrant(
                grant_id=f"demo-jit-{slug}-{tool_name}",
                identity_id=grant_identity_id,
                agent_id=next(str(s["agent_label"]) for s in _DEMO_IDENTITIES if s["slug"] == slug),
                tenant_id=tenant_id,
                tool_name=tool_name,
                status="active",
                requested_at=approved_at,
                requested_by="oncall@corp",
                approved_at=approved_at,
                approved_by="oncall@corp",
                starts_at=approved_at,
                expires_at=grant_expiry,
                ticket_id=f"OPS-{slug.upper()}",
            )
        )
    return identities, grants


def build_demo_identity_store(tenant_id: str = SHOWCASE_TENANT) -> InMemoryAgentIdentityStore:
    """A throwaway identity store pre-loaded with the demo NHI estate."""
    store = InMemoryAgentIdentityStore()
    identities, grants = demo_identity_records(tenant_id)
    for identity in identities:
        store.put(identity)
    for grant in grants:
        store.put_jit_grant(grant)
    return store


def seed_showcase_identities(tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Populate the LIVE agent-identity store with the demo NHI estate.

    Idempotent and independent of the graph seed so the NHI/Identity overview
    tile and the ``/v1/*/nhi/governance`` posture survive a restart even when the
    graph snapshot already exists. Only ever runs under demo-estate mode.
    """
    from agent_bom.api.agent_identity_store import get_agent_identity_store

    store = get_agent_identity_store()
    existing = {i.identity_id for i in store.list(tenant_id, include_inactive=True, limit=1000)}
    if any(iid.startswith("demo-nhi-") for iid in existing):
        return {"seeded": False, "reason": "identities_present", "count": len(existing)}

    identities, grants = demo_identity_records(tenant_id)
    for identity in identities:
        store.put(identity)
    for grant in grants:
        store.put_jit_grant(grant)
    return {"seeded": True, "identities": len(identities), "jit_grants": len(grants)}


def _annotate_demo_identity_risk(graph: UnifiedGraph) -> None:
    """Pin privilege / exposure signals the identity record cannot carry.

    ``AgentIdentity`` has no privilege or internet-exposure field, so the
    governance evaluator would otherwise only see dormancy/ownership. Stamp the
    curated signals directly onto the persisted MANAGED_IDENTITY node so the demo
    surfaces at least one clearly high/critical NHI (a dormant, orphaned, admin
    identity). Node ids are deterministic; safe to call on any showcase snapshot.
    """
    for spec in _DEMO_IDENTITIES:
        node = graph.nodes.get(f"managed_identity:{_demo_identity_id(str(spec['slug']))}")
        if node is None:
            continue
        if spec.get("privileged"):
            node.attributes["privilege_level"] = "admin"
            node.attributes["is_admin"] = True
        if spec.get("internet_exposed"):
            node.attributes["internet_exposed"] = True


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
    profile: ShowcaseProfile = "current",
    identity_store: InMemoryAgentIdentityStore | None = None,
) -> tuple[UnifiedGraph, InMemoryAgentIdentityStore, _DriftStore]:
    is_baseline = profile == "baseline"
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

    # Malicious/typosquat package — appears only in the current snapshot for drift.
    if not is_baseline:
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
        severity="" if is_baseline else "high",
        risk_score=0.0 if is_baseline else 8.2,
        internet_exposed=False if is_baseline else True,
    )
    if is_baseline:
        node(
            "mc:pii-private",
            EntityType.MISCONFIGURATION,
            "S3 bucket customer-pii-prod blocks public ACLs",
        )
        edge("mc:pii-private", "cloud:pii-bucket", RelationshipType.AFFECTS)
    else:
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

    # Cloud estate hierarchy — org → account → resources for rollup/containment demos.
    node("org:corp", EntityType.ORG, "Corp (root org)")
    node(
        "account:aws:123456789012",
        EntityType.ACCOUNT,
        "AWS prod (123456789012)",
        cloud_provider="aws",
        account_id="123456789012",
    )
    node("env:production", EntityType.ENVIRONMENT, "production")
    edge("org:corp", "account:aws:123456789012", RelationshipType.CONTAINS)
    edge("account:aws:123456789012", "env:production", RelationshipType.CONTAINS)
    for cloud_id in (
        "cloud:pii-bucket",
        "cloud:payments-db",
        "cloud:bastion",
        "cloud:logs-bucket",
    ):
        edge("account:aws:123456789012", cloud_id, RelationshipType.CONTAINS)

    # Hero exposure path: internet-facing bastion reaches the PII bucket.
    edge(
        "cloud:bastion",
        "cloud:pii-bucket",
        RelationshipType.EXPOSED_TO,
        evidence={"reason": "bastion_ssh_to_pii_bucket_network_path"},
    )

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
    if is_baseline:
        edge("user:bob", "role:readonly", RelationshipType.TRUSTS)
    else:
        edge("user:bob", "role:data-pipeline", RelationshipType.TRUSTS)
        edge("user:bob", "role:prod-admin", RelationshipType.TRUSTS)

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

    # Retired MCP server — removed in the current snapshot so drift shows a removal.
    if is_baseline:
        node("server:legacy-chat-server", EntityType.SERVER, "legacy-chat-server")
        edge("agent:support-copilot", "server:legacy-chat-server", RelationshipType.USES)
        node("tool:legacy-chat-server:send_message", EntityType.TOOL, "send_message")
        edge("server:legacy-chat-server", "tool:legacy-chat-server:send_message", RelationshipType.PROVIDES_TOOL)

    # Enriched, deterministic NHI estate (owner / last_used / standing scopes) so
    # the governance overlay projects a real identity story. Shared with the live
    # identity-store seed via ``demo_identity_records`` so ids/attributes match.
    store = identity_store if identity_store is not None else build_demo_identity_store(tenant_id)

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


def _ensure_showcase_edge(
    graph: UnifiedGraph,
    source: str,
    target: str,
    relationship: RelationshipType,
    **kwargs: Any,
) -> None:
    for edge in graph.edges:
        if edge.source == source and edge.target == target and edge.relationship == relationship:
            return
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, **kwargs))


def finalize_showcase_snapshot(graph: UnifiedGraph, *, profile: ShowcaseProfile) -> None:
    """Pin deliberate drift markers after overlays that may rewrite attributes."""
    _ensure_showcase_edge(
        graph,
        "cloud:bastion",
        "cloud:pii-bucket",
        RelationshipType.EXPOSED_TO,
        evidence={"reason": "bastion_ssh_to_pii_bucket_network_path"},
    )
    for cloud_id in (
        "cloud:pii-bucket",
        "cloud:payments-db",
        "cloud:bastion",
        "cloud:logs-bucket",
    ):
        _ensure_showcase_edge(
            graph,
            "account:aws:123456789012",
            cloud_id,
            RelationshipType.CONTAINS,
        )

    bucket = graph.nodes.get("cloud:pii-bucket")
    if bucket is None:
        return
    if profile == "baseline":
        bucket.attributes["internet_exposed"] = False
        bucket.attributes["encryption_at_rest"] = True
        bucket.severity = ""
        bucket.risk_score = 0.0
        bucket.compliance_tags = ["PII", "GDPR"]
        return
    bucket.attributes["internet_exposed"] = True
    bucket.attributes["encryption_at_rest"] = False
    bucket.severity = "high"
    bucket.risk_score = 8.2
    bucket.compliance_tags = ["PII", "GDPR", "public-exposure"]

    for node_id in ("call:0", "call:1", "call:2"):
        node = graph.nodes.get(node_id)
        if node is not None:
            node.attributes["evidence_tier"] = "runtime_observed"
    blocked_tool = graph.nodes.get("tool:shell-runner-server:run_shell")
    if blocked_tool is not None:
        blocked_tool.attributes["evidence_tier"] = "runtime_blocked"


def seed_showcase_graph_if_empty(
    graph_store: GraphStoreProtocol,
    *,
    tenant_id: str = SHOWCASE_TENANT,
) -> bool:
    """Persist baseline + current showcase snapshots when the tenant has none yet."""
    latest_snapshot_id = getattr(graph_store, "latest_snapshot_id", None)
    if callable(latest_snapshot_id) and latest_snapshot_id(tenant_id=tenant_id):
        return False

    # One shared, enriched identity estate feeds both snapshots so the persisted
    # MANAGED_IDENTITY node ids match the live identity store the API re-projects.
    identity_records = build_demo_identity_store(tenant_id)

    baseline_graph, baseline_identity, baseline_drift = build_showcase_graph(
        tenant_id=tenant_id,
        scan_id=SHOWCASE_BASELINE_SCAN_ID,
        profile="baseline",
        identity_store=identity_records,
    )
    baseline_graph.created_at = SHOWCASE_BASELINE_CREATED_AT
    apply_showcase_overlays(
        baseline_graph,
        tenant_id=tenant_id,
        identity_store=baseline_identity,
        drift_store=baseline_drift,
    )
    finalize_showcase_snapshot(baseline_graph, profile="baseline")
    _annotate_demo_identity_risk(baseline_graph)
    _materialize_showcase_attack_paths(baseline_graph)
    graph_store.save_graph(baseline_graph)

    current_graph, identity_store, drift_store = build_showcase_graph(
        tenant_id=tenant_id,
        scan_id=SHOWCASE_SCAN_ID,
        profile="current",
        identity_store=identity_records,
    )
    current_graph.created_at = SHOWCASE_CURRENT_CREATED_AT
    apply_showcase_overlays(
        current_graph,
        tenant_id=tenant_id,
        identity_store=identity_store,
        drift_store=drift_store,
    )
    finalize_showcase_snapshot(current_graph, profile="current")
    _annotate_demo_identity_risk(current_graph)
    _materialize_showcase_attack_paths(current_graph)
    graph_store.save_graph(current_graph)
    return True


def _materialize_showcase_attack_paths(graph: UnifiedGraph) -> None:
    """Persist derived attack paths so the materialized exposure-path queue is
    non-empty for the demo.

    ``/v1/graph/attack-paths`` derives paths on the fly, but
    ``/v1/graph/exposure-paths`` reads the materialized ``attack_paths`` table
    populated from ``graph.attack_paths`` at save time. The showcase graph never
    set that, so exposure paths came back empty. Reuse the exact same deriver the
    attack-path endpoint uses (pure seed-shaping — no algorithm change) and pin
    the hero chains onto the snapshot before it is saved.
    """
    if graph.attack_paths:
        return
    try:
        from agent_bom.api.routes.graph import _derived_attack_paths

        graph.attack_paths = _derived_attack_paths(graph)
    except Exception:  # noqa: BLE001 — never block the snapshot save on path shaping
        _logger.warning("demo estate attack-path materialization failed", exc_info=True)
