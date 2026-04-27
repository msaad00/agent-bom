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
    MODEL = "model"
    DATASET = "dataset"
    CONTAINER = "container"
    CLOUD_RESOURCE = "cloud_resource"

    # Finding entities (OCSF Category 2)
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"

    # Inventory but security-relevant (OCSF Category 5, NOT findings)
    CREDENTIAL = "credential"

    # Identity & governance (OCSF Category 5)
    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"

    # Organizational hierarchy
    PROVIDER = "provider"
    ENVIRONMENT = "environment"
    FLEET = "fleet"
    CLUSTER = "cluster"


class RelationshipType(str, Enum):
    """Edge relationship types across all graph surfaces."""

    # ── Static inventory ──
    HOSTS = "hosts"  # provider → agent
    USES = "uses"  # agent → server
    DEPENDS_ON = "depends_on"  # server → package
    PROVIDES_TOOL = "provides_tool"  # server → tool
    EXPOSES_CRED = "exposes_cred"  # server → credential
    SERVES_MODEL = "serves_model"  # server → model
    CONTAINS = "contains"  # container → package

    # ── Vulnerability ──
    AFFECTS = "affects"  # vulnerability → package (reverse)
    VULNERABLE_TO = "vulnerable_to"  # package/server → vulnerability
    EXPLOITABLE_VIA = "exploitable_via"  # vulnerability → tool/credential
    REMEDIATES = "remediates"  # fix_version → vulnerability
    TRIGGERS = "triggers"  # vulnerability → toxic_combination

    # ── Lateral movement (computed) ──
    SHARES_SERVER = "shares_server"  # agent ↔ agent
    SHARES_CRED = "shares_cred"  # agent ↔ agent
    LATERAL_PATH = "lateral_path"  # agent → agent (precomputed)

    # ── Ownership & governance ──
    MANAGES = "manages"  # user/team → agent/fleet
    OWNS = "owns"  # org/team → environment/resource
    PART_OF = "part_of"  # agent → fleet, server → cluster
    MEMBER_OF = "member_of"  # user → group, package → dependency_group

    # ── Runtime events (dynamic) ──
    INVOKED = "invoked"  # agent → tool (runtime)
    ACCESSED = "accessed"  # tool → resource (runtime)
    DELEGATED_TO = "delegated_to"  # agent → agent (runtime)

    # ── Cross-environment correlation (#1892) ──
    # local framework/project agent → cloud_resource (e.g., AWS Bedrock).
    # Edge attributes carry the matching signals and a confidence level
    # (exact / inferred / low) so dashboards can distinguish certain
    # matches from heuristic ones without merging the nodes.
    CORRELATES_WITH = "correlates_with"


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
    HIERARCHICAL = "hierarchical"
    GRID = "grid"
