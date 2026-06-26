"""Graph enums — entity types, relationship types, node status."""

from __future__ import annotations

from enum import Enum


class EntityType(str, Enum):
    """Node entity types, mapped to OCSF classes."""

    # Inventory entities (OCSF Category 5)
    AGENT = "agent"
    SERVER = "server"
    PACKAGE = "package"
    TOOL = "tool"
    TOOL_CALL = "tool_call"
    MODEL = "model"
    DATASET = "dataset"
    CONTAINER = "container"
    CLOUD_RESOURCE = "cloud_resource"
    RESOURCE = "resource"
    SOURCE_FILE = "source_file"
    CODE_MODULE = "code_module"
    CONFIG_FILE = "config_file"
    EXTERNAL_IMPORT = "external_import"
    CI_JOB = "ci_job"

    # Finding entities (OCSF Category 2)
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"

    # Inventory but security-relevant (OCSF Category 5, NOT findings)
    CREDENTIAL = "credential"
    CREDENTIAL_REF = "credential_ref"

    # Identity & governance (OCSF Category 5)
    ORG = "org"
    ACCOUNT = "account"
    USER = "user"
    GROUP = "group"
    ROLE = "role"
    POLICY = "policy"
    SERVICE_ACCOUNT = "service_account"
    SERVICE_PRINCIPAL = "service_principal"
    FEDERATED_IDENTITY = "federated_identity"

    # Agent-identity governance control plane (OCSF Category 3) — these make the
    # cost/identity/drift side stores traversable as first-class graph nodes so
    # attack paths can run agent → identity → grant → tool → vulnerable-package.
    MANAGED_IDENTITY = "managed_identity"  # an agent-bom-issued agent identity
    ACCESS_GRANT = "access_grant"  # a time-bound JIT access grant
    ACCESS_POLICY = "access_policy"  # a conditional/context-aware access policy

    # Behavioral drift (OCSF Category 2 — detection finding)
    DRIFT_INCIDENT = "drift_incident"

    # Cloud-CNAPP primitives (network exposure + data) — make internet exposure
    # and path-to-sensitive-data first-class for attack-path traversal.
    DATA_STORE = "data_store"  # database / bucket / data lake holding data at rest

    # Application Security Posture Management (ASPM) — an application is the
    # correlation root that AppSec findings (SCA / secrets / IaC / container /
    # CI-CD / AI-BOM) are grouped and rolled up around. Derived per
    # service/repo/manifest-root by the ASPM overlay (OCSF Category 5 inventory).
    APPLICATION = "application"

    # Organizational hierarchy
    PROVIDER = "provider"
    ENVIRONMENT = "environment"
    FLEET = "fleet"
    CLUSTER = "cluster"


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
    DEPENDS_ON = "depends_on"  # server → package
    PROVIDES_TOOL = "provides_tool"  # server → tool
    EXPOSES_CRED = "exposes_cred"  # server → credential
    REACHES_TOOL = "reaches_tool"  # credential → tool
    SERVES_MODEL = "serves_model"  # server → model
    CONTAINS = "contains"  # container → package
    IMPORTS = "imports"  # source file/module → external import/module
    DEFINES = "defines"  # source file → module/component/tool
    RUNS = "runs"  # CI job → scanner/workflow/tool
    CONFIGURES = "configures"  # config file → agent/server/CI job

    # ── Vulnerability ──
    AFFECTS = "affects"  # vulnerability → package (reverse)
    VULNERABLE_TO = "vulnerable_to"  # package/server → vulnerability
    EXPLOITABLE_VIA = "exploitable_via"  # vulnerability → tool/credential
    REMEDIATES = "remediates"  # package/fixed package → vulnerability
    TRIGGERS = "triggers"  # vulnerability → misconfiguration/risk condition

    # ── Lateral movement (computed) ──
    SHARES_SERVER = "shares_server"  # agent ↔ agent
    SHARES_CRED = "shares_cred"  # agent ↔ agent
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
