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
# Bumped when the seeded snapshot's *shape or content* changes so
# ``_showcase_seed_is_current`` treats an older seed as stale and refreshes it. A
# DB seeded before the enterprise estate was projected in still holds the
# 112-node showcase; without a bump it would keep it forever and the demo would
# silently under-report. The same applies to what the projection *writes*: the
# 08-01/08-08 pair shipped estate finding nodes whose ``recommendation`` was a
# ``Remediation`` object frozen to its Python repr, and a running demo would have
# served that snapshot forever. The seven-day gap is the drift lens's window and
# is preserved on every bump.
_SHOWCASE_CURRENT_TARGET = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
_SHOWCASE_IMPORT_NOW = datetime.now(timezone.utc)
# Preserve the deterministic target once it is in the past. Before then, clamp
# to the current UTC day's start so a release candidate never presents a
# snapshot from tomorrow. The seven-day baseline window remains intact.
_SHOWCASE_CURRENT_STAMP = (
    _SHOWCASE_CURRENT_TARGET
    if _SHOWCASE_CURRENT_TARGET <= _SHOWCASE_IMPORT_NOW
    else _SHOWCASE_IMPORT_NOW.replace(hour=0, minute=0, second=0, microsecond=0)
)
SHOWCASE_CURRENT_CREATED_AT = _SHOWCASE_CURRENT_STAMP.isoformat()
SHOWCASE_BASELINE_CREATED_AT = (_SHOWCASE_CURRENT_STAMP - timedelta(days=7)).isoformat()

# The estate's containment root, once projected, becomes the graph's single
# top-level container. The hand-built showcase org hangs off it so the demo reads
# as one estate rather than two unrelated roots.
SHOWCASE_ORG_ID = "org:corp"

# One shared definition for the hand-built vulnerability paths.  The graph
# seeder and the demo scan both consume these records so a path cannot render in
# the graph while the corresponding finding reports unknown reachability.
SHOWCASE_AGENTS: dict[str, str] = {
    "cursor": "Cursor IDE Agent",
    "langchain-service": "LangChain Service Agent",
    "support-copilot": "Support Copilot",
    "data-pipeline": "Data Pipeline Agent",
    "claude-desktop": "Claude Desktop Agent",
}
SHOWCASE_SERVERS: dict[str, tuple[str, list[str]]] = {
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
SHOWCASE_PACKAGES: dict[str, tuple[str, str, str, float]] = {
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


def seed_showcase_fleet_and_runtime(tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Populate the LIVE fleet and MCP-observation stores from the estate.

    ``/v1/agent-bom/manifest`` — the AI BOM page — is built from exactly two
    stores: the fleet registry and the MCP observation store. The demo bootstrap
    seeded the graph, the findings and the identities, but never those two, so
    the AI BOM read **0 agents / 0 MCP servers / 0 tools** on an estate holding
    48 agents, 25 servers and 97 tools. The page's own promise is "live
    inventory from connected agents… not a static upload", and it was showing
    nothing at all.

    Same contract as :func:`seed_showcase_identities`: idempotent, independent
    of the graph seed, and only ever under demo-estate mode, so a restart or an
    already-seeded graph still leaves the AI BOM populated.
    """
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.api.mcp_observation_store import MCPObservation
    from agent_bom.api.stores import _get_fleet_store, _get_mcp_observation_store
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate

    fleet_store = _get_fleet_store()
    observation_store = _get_mcp_observation_store()
    if any(a.agent_id.startswith("demo-fleet-") for a in fleet_store.list_by_tenant(tenant_id)):
        return {"seeded": False, "reason": "fleet_present"}

    estate = build_demo_estate(tenant_id=tenant_id)
    by_type: dict[str, list[Any]] = {}
    for asset in estate.assets:
        by_type.setdefault(asset.resource_type, []).append(asset)

    servers = by_type.get("server", [])
    tools_by_server: dict[str, list[Any]] = {}
    for tool in by_type.get("tool", []):
        tools_by_server.setdefault(str(tool.tags.get("mcp_server") or ""), []).append(tool)

    now = datetime.now(timezone.utc).isoformat()
    agents = by_type.get("agent", [])
    for index, asset in enumerate(agents):
        # Deterministic spread so the fleet reads like a managed estate rather
        # than one uniform block. A real fleet is mostly approved with a tail of
        # in-flight and problem agents; every row in one state is the tell that
        # nothing is actually being governed.
        bucket = index % 10
        if bucket == 0:
            state = FleetLifecycleState.QUARANTINED
        elif bucket in (1, 2):
            state = FleetLifecycleState.PENDING_REVIEW
        elif bucket == 3:
            state = FleetLifecycleState.DISCOVERED
        else:
            state = FleetLifecycleState.APPROVED
        fleet_store.put(
            FleetAgent(
                agent_id=f"demo-fleet-{asset.asset_id}",
                name=asset.display_name,
                agent_type=str(asset.tags.get("agent_framework") or "mcp-client"),
                lifecycle_state=state,
                owner=str(asset.tags.get("owner") or "platform-engineering"),
                environment=asset.environment or "production",
                tags=[t for t in (asset.environment, asset.provider) if t],
                trust_score=round(0.55 + ((index % 9) / 20.0), 2),
                server_count=len(servers[index % max(1, len(servers)) : index % max(1, len(servers)) + 2]),
                tenant_id=tenant_id,
                last_discovery=now,
                last_scan=now,
                created_at=now,
                updated_at=now,
            )
        )

    for index, asset in enumerate(servers):
        tools = tools_by_server.get(asset.asset_id, [])
        observation_store.put(
            MCPObservation(
                tenant_id=tenant_id,
                observation_id=f"demo-obs-{asset.asset_id}",
                server_stable_id=asset.asset_id,
                server_name=asset.display_name,
                agent_name=agents[index % len(agents)].display_name if agents else "",
                transport=str(asset.tags.get("transport") or "streamable-http"),
                url=asset.native_id if str(asset.native_id).startswith("http") else None,
                auth_mode=str(asset.tags.get("auth_mode") or "bearer"),
                credential_env_vars=[],
                observed_via=["demo-estate"],
                scan_sources=["demo-estate"],
                source_agents=[a.display_name for a in agents[index % max(1, len(agents)) : index % max(1, len(agents)) + 2]],
                configured_locally=False,
                fleet_present=True,
                gateway_registered=index % 3 != 0,
                runtime_observed=index % 4 != 0,
                observed_scopes=sorted({str(t.tags.get("scope") or "read") for t in tools}) or ["read"],
                first_seen=now,
                last_seen=now,
            )
        )

    return {
        "seeded": True,
        "fleet_agents": len(agents),
        "mcp_observations": len(servers),
        "tools": sum(len(v) for v in tools_by_server.values()),
    }


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

    for aid, label in SHOWCASE_AGENTS.items():
        node(f"agent:{aid}", EntityType.AGENT, label, environment="production")

    for sid, (owner, tools) in SHOWCASE_SERVERS.items():
        node(f"server:{sid}", EntityType.SERVER, sid)
        edge(f"agent:{owner}", f"server:{sid}", RelationshipType.USES)
        for tname in tools:
            tid = f"tool:{sid}:{tname}"
            node(tid, EntityType.TOOL, tname)
            edge(f"server:{sid}", tid, RelationshipType.PROVIDES_TOOL)

    # Real CVEs on real package@versions — mirrors the demo advisory catalog.
    kev_cves = {"CVE-2023-4863"}
    for purl, (sid, cve, sev, score) in SHOWCASE_PACKAGES.items():
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


def _existing_snapshots(graph_store: GraphStoreProtocol, tenant_id: str) -> list[dict[str, Any]]:
    """Return the tenant's snapshots (scan_id + created_at) for staleness checks.

    Prefers ``list_snapshots`` so we can tell a real scan and a stale demo seed
    apart. Minimal stores that only expose ``latest_snapshot_id`` degrade to a
    single-entry view with an unknown ``created_at`` (which reads as stale).
    """
    list_snapshots = getattr(graph_store, "list_snapshots", None)
    if callable(list_snapshots):
        try:
            return list(list_snapshots(tenant_id=tenant_id))
        except Exception:  # noqa: BLE001 — fall back rather than block seeding
            _logger.warning("showcase seed could not list snapshots", exc_info=True)
    latest_snapshot_id = getattr(graph_store, "latest_snapshot_id", None)
    if callable(latest_snapshot_id):
        scan_id = latest_snapshot_id(tenant_id=tenant_id)
        if scan_id:
            return [{"scan_id": scan_id, "created_at": ""}]
    return []


def _showcase_seed_is_current(snapshots: list[dict[str, Any]]) -> bool:
    """True when both showcase snapshots are present at the expected timestamps."""
    created_at_by_id = {str(row.get("scan_id")): str(row.get("created_at") or "") for row in snapshots}
    return (
        created_at_by_id.get(SHOWCASE_SCAN_ID) == SHOWCASE_CURRENT_CREATED_AT
        and created_at_by_id.get(SHOWCASE_BASELINE_SCAN_ID) == SHOWCASE_BASELINE_CREATED_AT
    )


def seed_showcase_graph_if_empty(
    graph_store: GraphStoreProtocol,
    *,
    tenant_id: str = SHOWCASE_TENANT,
    force: bool = False,
) -> bool:
    """Persist baseline + current showcase snapshots, stale-aware (issue #3964).

    Seeding is gated on *what* already occupies the tenant, not merely whether
    anything does:

    * A real (non-showcase) scan is never shadowed — if any snapshot has a
      scan id outside the showcase set, a fresh scan owns the graph and the demo
      seed is skipped. The read path already defaults to the newest snapshot, so
      the fresh scan stays the one served. This preservation boundary applies
      even when the demo ``force`` override is set: force may refresh showcase
      snapshots, never delete operator scan evidence.
    * A *current* showcase seed (both snapshots at the expected ``created_at``)
      is idempotent — nothing is rewritten.
    * A *stale* showcase seed (missing baseline, or an out-of-date ``created_at``
      left by an older build / polluted DB) is cleared and re-seeded so
      ``--demo-estate`` boots on today's curated estate.
    """
    showcase_ids = {SHOWCASE_SCAN_ID, SHOWCASE_BASELINE_SCAN_ID}
    snapshots = _existing_snapshots(graph_store, tenant_id)
    foreign = [row for row in snapshots if str(row.get("scan_id")) not in showcase_ids]
    if foreign and not force:
        # An ordinary boot never shadows a real scan.
        return False
    if not force and snapshots and _showcase_seed_is_current(snapshots):
        return False
    if snapshots and not foreign:
        # Only showcase snapshots remain. Wipe them so the refreshed seed does
        # not leave orphaned nodes/edges behind.
        delete_tenant = getattr(graph_store, "delete_tenant", None)
        if callable(delete_tenant):
            delete_tenant(tenant_id=tenant_id)
    # With a preserved operator scan present, the showcase snapshots are still
    # written -- an explicit demo request needs a graph to address -- but they
    # keep their fixed, older timestamps. The newest-wins read path therefore
    # still defaults to the operator's scan; only a caller that asks for the
    # showcase scan id by name is served the estate.

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
    baseline_analysis_complete = _materialize_showcase_attack_paths(baseline_graph)
    # After the showcase's own attack paths are derived, so the hand-built hero
    # chains stay first in the exposure-path queue and the estate's correlated
    # chains extend it rather than displacing it.
    project_estate_onto_showcase(baseline_graph, tenant_id=tenant_id, profile="baseline")
    if baseline_analysis_complete:
        _record_showcase_attack_path_analysis(baseline_graph)
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
    current_analysis_complete = _materialize_showcase_attack_paths(current_graph)
    project_estate_onto_showcase(current_graph, tenant_id=tenant_id, profile="current")
    if current_analysis_complete:
        _record_showcase_attack_path_analysis(current_graph)
    graph_store.save_graph(current_graph)
    return True


def project_estate_onto_showcase(
    graph: UnifiedGraph,
    *,
    tenant_id: str = SHOWCASE_TENANT,
    profile: ShowcaseProfile = "current",
) -> dict[str, object]:
    """Extend a showcase snapshot with the enterprise estate.

    *Extend*, not replace. The showcase's hand-built incident chain
    (``agent:cursor`` → ``server:shell-runner-server`` → ``pkg:pyyaml@5.3`` →
    ``vuln:CVE-2020-14343`` → ``cred:aws-secret``) is the demo's headline and is
    asserted by ``tests/test_demo_estate_bootstrap.py``; it is untouched here.
    Seeding the estate as a *separate* snapshot was the alternative and was
    rejected: the read path serves the newest snapshot, so a prospect would land
    on one of the two estates and the correlation between them — the AWS account
    the hand-built chain runs in is an account the estate inventories — would
    never be drawn.

    ``profile`` follows the estate's own stage semantics: the baseline snapshot
    predates the collection window, so it carries the inventory but neither the
    posture findings nor the correlated chain that the window's evidence
    produced. Both appear in ``current``, which is what makes the drift lens show
    posture arriving rather than a relabelling of the same set.
    """
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.enterprise_correlation import build_estate_correlations
    from agent_bom.demo_estate.enterprise_findings import build_estate_findings
    from agent_bom.demo_estate.estate_graph import (
        estate_org_node_id,
        project_estate_into_graph,
    )

    estate = build_demo_estate(tenant_id=tenant_id)
    is_baseline = profile == "baseline"
    summary = project_estate_into_graph(
        graph,
        estate,
        findings=() if is_baseline else build_estate_findings(estate),
        correlations=() if is_baseline else build_estate_correlations(estate),
    )
    _ensure_showcase_edge(
        graph,
        estate_org_node_id(estate),
        SHOWCASE_ORG_ID,
        RelationshipType.CONTAINS,
    )
    return summary


def _materialize_showcase_attack_paths(graph: UnifiedGraph) -> bool:
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
        return True
    try:
        from agent_bom.api.routes.graph import _derived_attack_paths

        graph.attack_paths = _derived_attack_paths(graph)
    except Exception:  # noqa: BLE001 — never block the snapshot save on path shaping
        _logger.warning("demo estate attack-path materialization failed", exc_info=True)
        return False

    return True


def _record_showcase_attack_path_analysis(graph: UnifiedGraph) -> None:
    """Record completion after estate projection has finalized the path queue."""

    # Persistence keys paths by source/target within a scan, so duplicate
    # in-memory variants collapse to one served path. Report the persisted
    # cardinality instead of the pre-upsert list length.
    persisted_path_count = len({(path.source, path.target) for path in graph.attack_paths})

    # Record that the run completed. Without this the snapshot reads
    # ``not_recorded`` and the graph header says "Analysis status unavailable"
    # while sitting on top of the paths this function just derived — the header
    # is right to distrust a snapshot that never claims one, so the seed has to
    # make the claim it has actually earned.
    from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus

    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(
        status=GraphAnalysisState.COMPLETE,
        observed={"paths": persisted_path_count},
    )
