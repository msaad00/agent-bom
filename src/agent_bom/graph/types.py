"""Graph enums — entity types, relationship types, node status."""

from __future__ import annotations

from enum import Enum

from agent_bom.entity_types import EntityType as EntityType


class GraphSemanticLayer(str, Enum):
    """Operator-facing AI system layers used to group graph entities."""

    USER = "user"
    IDENTITY = "identity"
    APP = "app"
    API_GATEWAY = "api_gateway"
    ORCHESTRATION = "orchestration"
    MCP_SERVER = "mcp_server"
    TOOL = "tool"
    PACKAGE = "package"
    RUNTIME_EVIDENCE = "runtime_evidence"
    ASSET = "asset"
    INFRA = "infra"
    FINDING = "finding"
    CODE = "code"
    CI = "ci"


class RelationshipType(str, Enum):
    """Edge relationship types across all graph surfaces."""

    # ── Static inventory ──
    HOSTS = "hosts"  # provider → agent
    USES = "uses"  # agent → server
    USES_FRAMEWORK = "uses_framework"  # agent → framework (LangChain/LangGraph/…)
    DEPENDS_ON = "depends_on"  # server → package; framework → package
    PROVIDES_TOOL = "provides_tool"  # server → tool
    EXPOSES_CRED = "exposes_cred"  # server → credential
    REACHES_TOOL = "reaches_tool"  # credential → tool
    SERVES_MODEL = "serves_model"  # server/agent/framework → model
    CONTAINS = "contains"  # container → package
    IMPORTS = "imports"  # source file/module → external import/module
    DEFINES = "defines"  # source file → module/component/tool
    RUNS = "runs"  # CI job → scanner/workflow/tool
    CONFIGURES = "configures"  # config file → agent/server/CI job
    OBSERVES = "observes"  # observability framework → agent/server (Langfuse-class)

    # ── Vulnerability ──
    AFFECTS = "affects"  # vulnerability → package (reverse)
    VULNERABLE_TO = "vulnerable_to"  # package/server → vulnerability
    EXPLOITABLE_VIA = "exploitable_via"  # vulnerability → tool/credential
    REMEDIATES = "remediates"  # package/fixed package → vulnerability
    TRIGGERS = "triggers"  # vulnerability → misconfiguration/risk condition

    # ── Lateral movement (computed) ──
    SHARES_SERVER = "shares_server"  # agent ↔ agent/shared-server hub
    SHARES_CRED = "shares_cred"  # agent ↔ agent/shared-credential node
    LATERAL_PATH = "lateral_path"  # agent → agent (precomputed)

    # ── Ownership & governance ──
    MANAGES = "manages"  # user/team → agent/fleet
    OWNS = "owns"  # org/team → environment/resource
    PART_OF = "part_of"  # agent → fleet, server → cluster
    MEMBER_OF = "member_of"  # user → group, package → dependency_group
    ASSUMES = "assumes"  # user/service principal → role
    TRUSTS = "trusts"  # role/account → principal/account
    ATTACHED = "attached"  # principal/role/group → policy
    INHERITS = "inherits"  # principal/group/role → policy/role
    CAN_ACCESS = "can_access"  # identity principal/account → resource
    CROSS_ACCOUNT_TRUST = "cross_account_trust"  # account/principal → external account/principal

    # ── Agent-identity governance (control plane → graph) ──
    AUTHENTICATES_AS = "authenticates_as"  # agent → managed_identity
    SCOPED_TO = "scoped_to"  # managed_identity/access_grant/drift_incident → tool
    GOVERNS = "governs"  # access_policy → agent/managed_identity/tool
    EXHIBITS_DRIFT = "exhibits_drift"  # agent ↔ drift_incident (bidirectional)

    # ── Cloud-CNAPP: network exposure, data reachability, effective permissions ──
    EXPOSED_TO = "exposed_to"  # resource/server/agent → network/resource (public/internet reach)
    STORES = "stores"  # cloud_resource/data_store/server → dataset/data_store (data at rest)
    HAS_PERMISSION = "has_permission"  # principal/managed_identity → resource/data_store/tool (effective)
    PROTECTS = "protects"  # waf/api_gateway → resource it fronts (mitigates internet exposure)

    # ── Runtime events (dynamic) ──
    ACTED_AS = "acted_as"  # user/service principal → agent (runtime identity)
    INVOKED = "invoked"  # agent/user → tool call (runtime)
    CALLED = "called"  # tool call → tool (runtime)
    USED_CREDENTIAL = "used_credential"  # tool call → credential reference (runtime)
    ACCESSED = "accessed"  # tool/tool call → resource (runtime)
    DELEGATED_TO = "delegated_to"  # agent → agent (runtime)

    # ── Cross-environment correlation (#1892) ──
    # CORRELATES_WITH is reserved for HIGH-confidence local↔cloud agent
    # matches (cloud account/subscription/project + region/location + model
    # ID all match). POSSIBLY_CORRELATES_WITH carries partial matches so
    # they stay visible without being conflated with the strict path.
    CORRELATES_WITH = "correlates_with"  # local agent ↔ cloud agent (high)
    POSSIBLY_CORRELATES_WITH = "possibly_correlates_with"  # local ↔ cloud (low)

    # ── Application Security Posture Management (ASPM) ──
    # Finding/component → application correlation. The ASPM overlay groups every
    # AppSec signal already in the graph around the application it belongs to.
    BELONGS_TO = "belongs_to"  # finding/component/asset → application


class NodeStatus(str, Enum):
    """Lifecycle status of a graph node."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    VULNERABLE = "vulnerable"
    REMEDIATED = "remediated"


class GraphLayout(str, Enum):
    """Layout algorithms for graph visualisation."""

    DAGRE = "dagre"
    FORCE = "force"
    RADIAL = "radial"
    SANKEY = "sankey"
    HIERARCHICAL = "hierarchical"
    GRID = "grid"
