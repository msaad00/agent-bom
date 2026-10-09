"""Entity vocabulary shared by findings, inventory and the unified graph.

Graph nodes, OCSF mapping and finding assets all name entities with this
enum, so it sits below the graph layer that renders it.
"""

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
    # AI orchestration / observability stack (LangChain, LangGraph, Langfuse, …)
    # First-class BOM entity — not only metadata on agents/packages.
    FRAMEWORK = "framework"
    CONTAINER = "container"
    CLOUD_RESOURCE = "cloud_resource"
    RESOURCE = "resource"
    SOURCE_FILE = "source_file"
    CODE_MODULE = "code_module"
    CONFIG_FILE = "config_file"
    EXTERNAL_IMPORT = "external_import"
    CI_JOB = "ci_job"
    # Repository folder/file structure — a directory node forms the CODE-layer
    # containment backbone (repo root → sub-directory → file) so a code/project
    # scan renders folder structure the way the cloud graph renders the
    # org → account → resource hierarchy. Materialised by the repo-structure
    # overlay from the project inventory; CONTAINS edges build the tree and the
    # estate roll-up collapses deep trees the same way it collapses the cloud
    # CONTAINS hierarchy.
    DIRECTORY = "directory"

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
    BLUEPRINT = "blueprint"  # a persisted, approved AI-system blueprint (versioned)

    # Behavioral drift (OCSF Category 2 — detection finding)
    DRIFT_INCIDENT = "drift_incident"

    # Cloud-CNAPP primitives (network exposure + data) — make internet exposure
    # and path-to-sensitive-data first-class for attack-path traversal.
    DATA_STORE = "data_store"  # database / bucket / data lake holding data at rest

    # Network-edge primitive — an API gateway / managed front-door that fronts an
    # exposed resource. Populated from live cloud inventory (AWS API Gateway, GCP
    # API Gateway/Apigee, Azure API Management) so the API_GATEWAY semantic layer
    # carries real nodes and a WAF/gateway in front of a resource refines its
    # exposure verdict via the PROTECTS edge.
    API_GATEWAY = "api_gateway"

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
