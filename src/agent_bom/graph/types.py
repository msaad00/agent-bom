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

    # Grouping (virtual)
    PROVIDER = "provider"
    ENVIRONMENT = "environment"


class RelationshipType(str, Enum):
    """Edge relationship types across all graph surfaces."""

    # Static inventory
    HOSTS = "hosts"
    USES = "uses"
    DEPENDS_ON = "depends_on"
    PROVIDES_TOOL = "provides_tool"
    EXPOSES_CRED = "exposes_cred"
    SERVES_MODEL = "serves_model"
    CONTAINS = "contains"

    # Vulnerability
    AFFECTS = "affects"
    VULNERABLE_TO = "vulnerable_to"
    EXPLOITABLE_VIA = "exploitable_via"

    # Lateral movement (computed)
    SHARES_SERVER = "shares_server"
    SHARES_CRED = "shares_cred"
    LATERAL_PATH = "lateral_path"

    # Runtime events (dynamic)
    INVOKED = "invoked"
    ACCESSED = "accessed"
    DELEGATED_TO = "delegated_to"


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
