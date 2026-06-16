// AUTO-GENERATED — do not edit. Run `npm run codegen:graph-schema` to refresh.
//
// Source of truth: agent_bom.graph.types.EntityType + RelationshipType.
// The Python API at GET /v1/graph/schema is the canonical taxonomy; this
// file is materialised by ui/scripts/codegen-graph-schema.mjs and the CI
// "UI Validate" job fails when it drifts (see #2255).

export const GRAPH_SCHEMA_VERSION = 1 as const;

// ═══════════════════════════════════════════════════════════════════════════
// Semantic layers
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphSemanticLayer {
  USER = "user",
  IDENTITY = "identity",
  APP = "app",
  API_GATEWAY = "api_gateway",
  ORCHESTRATION = "orchestration",
  MCP_SERVER = "mcp_server",
  TOOL = "tool",
  PACKAGE = "package",
  RUNTIME_EVIDENCE = "runtime_evidence",
  ASSET = "asset",
  INFRA = "infra",
  FINDING = "finding",
  CODE = "code",
  CI = "ci",
}

export type GraphSemanticLayerKey = "user" | "identity" | "app" | "api_gateway" | "orchestration" | "mcp_server" | "tool" | "package" | "runtime_evidence" | "asset" | "infra" | "finding" | "code" | "ci";

export const GRAPH_SEMANTIC_LAYERS: readonly GraphSemanticLayerKey[] = ["user", "identity", "app", "api_gateway", "orchestration", "mcp_server", "tool", "package", "runtime_evidence", "asset", "infra", "finding", "code", "ci"] as const;

export interface GraphSemanticLayerMeta {
  label: string;
}

export const GRAPH_SEMANTIC_LAYER_META: Record<GraphSemanticLayerKey, GraphSemanticLayerMeta> = {
  "user": {
    "label": "User"
  },
  "identity": {
    "label": "Identity"
  },
  "app": {
    "label": "Application"
  },
  "api_gateway": {
    "label": "API / Gateway"
  },
  "orchestration": {
    "label": "Orchestration"
  },
  "mcp_server": {
    "label": "MCP Server"
  },
  "tool": {
    "label": "Tool"
  },
  "package": {
    "label": "Package"
  },
  "runtime_evidence": {
    "label": "Runtime Evidence"
  },
  "asset": {
    "label": "Asset"
  },
  "infra": {
    "label": "Infrastructure"
  },
  "finding": {
    "label": "Finding"
  },
  "code": {
    "label": "Code"
  },
  "ci": {
    "label": "CI/CD"
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// Node kinds (entity types)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphNodeKind {
  ACCESS_GRANT = "access_grant",
  ACCESS_POLICY = "access_policy",
  ACCOUNT = "account",
  AGENT = "agent",
  CI_JOB = "ci_job",
  CLOUD_RESOURCE = "cloud_resource",
  CLUSTER = "cluster",
  CODE_MODULE = "code_module",
  CONFIG_FILE = "config_file",
  CONTAINER = "container",
  CREDENTIAL = "credential",
  CREDENTIAL_REF = "credential_ref",
  DATA_STORE = "data_store",
  DATASET = "dataset",
  DRIFT_INCIDENT = "drift_incident",
  ENVIRONMENT = "environment",
  EXTERNAL_IMPORT = "external_import",
  FEDERATED_IDENTITY = "federated_identity",
  FLEET = "fleet",
  GROUP = "group",
  MANAGED_IDENTITY = "managed_identity",
  MISCONFIGURATION = "misconfiguration",
  MODEL = "model",
  ORG = "org",
  PACKAGE = "package",
  POLICY = "policy",
  PROVIDER = "provider",
  RESOURCE = "resource",
  ROLE = "role",
  SERVER = "server",
  SERVICE_ACCOUNT = "service_account",
  SERVICE_PRINCIPAL = "service_principal",
  SOURCE_FILE = "source_file",
  TOOL = "tool",
  TOOL_CALL = "tool_call",
  USER = "user",
  VULNERABILITY = "vulnerability",
}

export type GraphNodeKindKey = "access_grant" | "access_policy" | "account" | "agent" | "ci_job" | "cloud_resource" | "cluster" | "code_module" | "config_file" | "container" | "credential" | "credential_ref" | "data_store" | "dataset" | "drift_incident" | "environment" | "external_import" | "federated_identity" | "fleet" | "group" | "managed_identity" | "misconfiguration" | "model" | "org" | "package" | "policy" | "provider" | "resource" | "role" | "server" | "service_account" | "service_principal" | "source_file" | "tool" | "tool_call" | "user" | "vulnerability";

export const GRAPH_NODE_KINDS: readonly GraphNodeKindKey[] = ["access_grant", "access_policy", "account", "agent", "ci_job", "cloud_resource", "cluster", "code_module", "config_file", "container", "credential", "credential_ref", "data_store", "dataset", "drift_incident", "environment", "external_import", "federated_identity", "fleet", "group", "managed_identity", "misconfiguration", "model", "org", "package", "policy", "provider", "resource", "role", "server", "service_account", "service_principal", "source_file", "tool", "tool_call", "user", "vulnerability"] as const;

export interface GraphNodeKindMeta {
  label: string;
  color: string;
  shape: string;
  layer: GraphSemanticLayerKey;
  icon: string;
  category_uid: number;
  class_uid: number;
  emission_status: "emitted" | "reserved";
  emission_surfaces: readonly string[];
  emission_notes: string;
}

export const GRAPH_NODE_KIND_META: Record<GraphNodeKindKey, GraphNodeKindMeta> = {
  "access_grant": {
    "label": "Access Grant",
    "color": "#ca8a04",
    "shape": "diamond",
    "layer": "identity",
    "icon": "diamond",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "access_policy": {
    "label": "Access Policy",
    "color": "#a16207",
    "shape": "diamond",
    "layer": "identity",
    "icon": "diamond",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "account": {
    "label": "Account",
    "color": "#0f766e",
    "shape": "square",
    "layer": "identity",
    "icon": "square",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "agent": {
    "label": "AI Agent",
    "color": "#10b981",
    "shape": "circle",
    "layer": "orchestration",
    "icon": "circle",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "ci_job": {
    "label": "CI/CD Job",
    "color": "#a855f7",
    "shape": "diamond",
    "layer": "ci",
    "icon": "diamond",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "reserved",
    "emission_surfaces": [
      "ci_graph"
    ],
    "emission_notes": "Reserved for CI/CD topology; scan jobs are tracked operationally but are not emitted as graph nodes yet."
  },
  "cloud_resource": {
    "label": "Cloud Resource",
    "color": "#0ea5e9",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "cluster": {
    "label": "Cluster",
    "color": "#4b5563",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "code_module": {
    "label": "Code Module",
    "color": "#06b6d4",
    "shape": "circle",
    "layer": "code",
    "icon": "circle",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "reserved",
    "emission_surfaces": [
      "code_graph"
    ],
    "emission_notes": "Reserved for source-code topology; static supply-chain scans do not emit module-level nodes yet."
  },
  "config_file": {
    "label": "Config File",
    "color": "#f97316",
    "shape": "square",
    "layer": "code",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "reserved",
    "emission_surfaces": [
      "code_graph"
    ],
    "emission_notes": "Reserved for configuration topology; static supply-chain scans do not emit config-file nodes yet."
  },
  "container": {
    "label": "Container",
    "color": "#6366f1",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "credential": {
    "label": "Credential",
    "color": "#f59e0b",
    "shape": "diamond",
    "layer": "identity",
    "icon": "diamond",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "credential_ref": {
    "label": "Credential Reference",
    "color": "#fbbf24",
    "shape": "diamond",
    "layer": "identity",
    "icon": "diamond",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "data_store": {
    "label": "Data Store",
    "color": "#0284c7",
    "shape": "square",
    "layer": "asset",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "dataset": {
    "label": "Dataset",
    "color": "#06b6d4",
    "shape": "square",
    "layer": "asset",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "drift_incident": {
    "label": "Drift Incident",
    "color": "#fb923c",
    "shape": "triangle",
    "layer": "finding",
    "icon": "triangle",
    "category_uid": 2,
    "class_uid": 2004,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "environment": {
    "label": "Environment",
    "color": "#9ca3af",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 0,
    "class_uid": 0,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "external_import": {
    "label": "External Import",
    "color": "#f59e0b",
    "shape": "circle",
    "layer": "code",
    "icon": "circle",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "reserved",
    "emission_surfaces": [
      "code_graph"
    ],
    "emission_notes": "Reserved for source-code import topology; static supply-chain scans do not emit import nodes yet."
  },
  "federated_identity": {
    "label": "Federated Identity",
    "color": "#0e7490",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "fleet": {
    "label": "Fleet",
    "color": "#6b7280",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "group": {
    "label": "Group",
    "color": "#0d9488",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "managed_identity": {
    "label": "Managed Identity",
    "color": "#0891b2",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "misconfiguration": {
    "label": "Misconfiguration",
    "color": "#f97316",
    "shape": "triangle",
    "layer": "finding",
    "icon": "triangle",
    "category_uid": 2,
    "class_uid": 2003,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "model": {
    "label": "Model",
    "color": "#8b5cf6",
    "shape": "square",
    "layer": "asset",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "org": {
    "label": "Organization",
    "color": "#115e59",
    "shape": "square",
    "layer": "identity",
    "icon": "square",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "package": {
    "label": "Package",
    "color": "#52525b",
    "shape": "square",
    "layer": "package",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "policy": {
    "label": "Policy",
    "color": "#d97706",
    "shape": "diamond",
    "layer": "identity",
    "icon": "diamond",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "provider": {
    "label": "Provider",
    "color": "#d1d5db",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 0,
    "class_uid": 0,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "resource": {
    "label": "Resource",
    "color": "#38bdf8",
    "shape": "square",
    "layer": "asset",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "runtime_proxy",
      "gateway_event_projection",
      "cnapp_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "role": {
    "label": "Role",
    "color": "#ea580c",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "server": {
    "label": "MCP Server",
    "color": "#3b82f6",
    "shape": "circle",
    "layer": "mcp_server",
    "icon": "circle",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "service_account": {
    "label": "Service Account",
    "color": "#0f766e",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "service_principal": {
    "label": "Service Principal",
    "color": "#0f766e",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "source_file": {
    "label": "Source File",
    "color": "#22d3ee",
    "shape": "square",
    "layer": "code",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "reserved",
    "emission_surfaces": [
      "code_graph"
    ],
    "emission_notes": "Reserved for source-code topology; static supply-chain scans do not emit file-level nodes yet."
  },
  "tool": {
    "label": "Tool",
    "color": "#a855f7",
    "shape": "diamond",
    "layer": "tool",
    "icon": "diamond",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "tool_call": {
    "label": "Tool Call",
    "color": "#c084fc",
    "shape": "diamond",
    "layer": "runtime_evidence",
    "icon": "diamond",
    "category_uid": 5,
    "class_uid": 4001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "runtime_proxy",
      "gateway_event_projection"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "user": {
    "label": "User",
    "color": "#14b8a6",
    "shape": "circle",
    "layer": "user",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "vulnerability": {
    "label": "Vulnerability",
    "color": "#ef4444",
    "shape": "triangle",
    "layer": "finding",
    "icon": "triangle",
    "category_uid": 2,
    "class_uid": 2001,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// Edge kinds (relationship types)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphEdgeKind {
  ACCESSED = "accessed",
  ACTED_AS = "acted_as",
  AFFECTS = "affects",
  ASSUMES = "assumes",
  ATTACHED = "attached",
  AUTHENTICATES_AS = "authenticates_as",
  CALLED = "called",
  CAN_ACCESS = "can_access",
  CONFIGURES = "configures",
  CONTAINS = "contains",
  CORRELATES_WITH = "correlates_with",
  CROSS_ACCOUNT_TRUST = "cross_account_trust",
  DEFINES = "defines",
  DELEGATED_TO = "delegated_to",
  DEPENDS_ON = "depends_on",
  EXHIBITS_DRIFT = "exhibits_drift",
  EXPLOITABLE_VIA = "exploitable_via",
  EXPOSED_TO = "exposed_to",
  EXPOSES_CRED = "exposes_cred",
  GOVERNS = "governs",
  HAS_PERMISSION = "has_permission",
  HOSTS = "hosts",
  IMPORTS = "imports",
  INHERITS = "inherits",
  INVOKED = "invoked",
  LATERAL_PATH = "lateral_path",
  MANAGES = "manages",
  MEMBER_OF = "member_of",
  OWNS = "owns",
  PART_OF = "part_of",
  POSSIBLY_CORRELATES_WITH = "possibly_correlates_with",
  PROVIDES_TOOL = "provides_tool",
  REACHES_TOOL = "reaches_tool",
  REMEDIATES = "remediates",
  RUNS = "runs",
  SCOPED_TO = "scoped_to",
  SERVES_MODEL = "serves_model",
  SHARES_CRED = "shares_cred",
  SHARES_SERVER = "shares_server",
  STORES = "stores",
  TRIGGERS = "triggers",
  TRUSTS = "trusts",
  USED_CREDENTIAL = "used_credential",
  USES = "uses",
  VULNERABLE_TO = "vulnerable_to",
}

export type GraphEdgeKindKey = "accessed" | "acted_as" | "affects" | "assumes" | "attached" | "authenticates_as" | "called" | "can_access" | "configures" | "contains" | "correlates_with" | "cross_account_trust" | "defines" | "delegated_to" | "depends_on" | "exhibits_drift" | "exploitable_via" | "exposed_to" | "exposes_cred" | "governs" | "has_permission" | "hosts" | "imports" | "inherits" | "invoked" | "lateral_path" | "manages" | "member_of" | "owns" | "part_of" | "possibly_correlates_with" | "provides_tool" | "reaches_tool" | "remediates" | "runs" | "scoped_to" | "serves_model" | "shares_cred" | "shares_server" | "stores" | "triggers" | "trusts" | "used_credential" | "uses" | "vulnerable_to";

export const GRAPH_EDGE_KINDS: readonly GraphEdgeKindKey[] = ["accessed", "acted_as", "affects", "assumes", "attached", "authenticates_as", "called", "can_access", "configures", "contains", "correlates_with", "cross_account_trust", "defines", "delegated_to", "depends_on", "exhibits_drift", "exploitable_via", "exposed_to", "exposes_cred", "governs", "has_permission", "hosts", "imports", "inherits", "invoked", "lateral_path", "manages", "member_of", "owns", "part_of", "possibly_correlates_with", "provides_tool", "reaches_tool", "remediates", "runs", "scoped_to", "serves_model", "shares_cred", "shares_server", "stores", "triggers", "trusts", "used_credential", "uses", "vulnerable_to"] as const;

export interface GraphEdgeKindMeta {
  label: string;
  color: string;
  category: string;
  direction: "directed" | "bidirectional";
  source_types: readonly GraphNodeKindKey[];
  target_types: readonly GraphNodeKindKey[];
  traversable: boolean;
  emission_status: "emitted" | "reserved";
  emission_surfaces: readonly string[];
  emission_notes: string;
}

export const GRAPH_EDGE_KIND_META: Record<GraphEdgeKindKey, GraphEdgeKindMeta> = {
  "accessed": {
    "label": "Accessed (runtime)",
    "color": "#3b82f6",
    "category": "runtime",
    "direction": "directed",
    "source_types": [
      "tool",
      "tool_call"
    ],
    "target_types": [
      "cloud_resource",
      "dataset",
      "credential",
      "credential_ref",
      "resource"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "acted_as": {
    "label": "Acted As (runtime)",
    "color": "#14b8a6",
    "category": "runtime",
    "direction": "directed",
    "source_types": [
      "user",
      "service_account",
      "service_principal",
      "federated_identity"
    ],
    "target_types": [
      "agent"
    ],
    "traversable": true,
    "emission_status": "reserved",
    "emission_surfaces": [
      "runtime_graph"
    ],
    "emission_notes": "Reserved for explicit user/service-principal runtime delegation once traces carry that identity link."
  },
  "affects": {
    "label": "Affects",
    "color": "#dc2626",
    "category": "vulnerability",
    "direction": "directed",
    "source_types": [
      "vulnerability",
      "misconfiguration"
    ],
    "target_types": [
      "package",
      "server",
      "container"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "assumes": {
    "label": "Assumes",
    "color": "#ea580c",
    "category": "identity",
    "direction": "directed",
    "source_types": [
      "user",
      "service_account",
      "service_principal",
      "federated_identity"
    ],
    "target_types": [
      "role"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "attached": {
    "label": "Attached",
    "color": "#d97706",
    "category": "identity",
    "direction": "directed",
    "source_types": [
      "user",
      "group",
      "role",
      "service_account",
      "service_principal",
      "managed_identity"
    ],
    "target_types": [
      "policy",
      "access_grant"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "authenticates_as": {
    "label": "Authenticates As",
    "color": "#0891b2",
    "category": "governance",
    "direction": "directed",
    "source_types": [
      "agent"
    ],
    "target_types": [
      "managed_identity"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "called": {
    "label": "Called (runtime)",
    "color": "#c084fc",
    "category": "runtime",
    "direction": "directed",
    "source_types": [
      "tool_call",
      "agent"
    ],
    "target_types": [
      "tool",
      "server"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "runtime_proxy",
      "gateway_event_projection"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "can_access": {
    "label": "Can Access",
    "color": "#dc2626",
    "category": "identity",
    "direction": "directed",
    "source_types": [
      "account",
      "user",
      "group",
      "role",
      "service_account",
      "service_principal",
      "federated_identity"
    ],
    "target_types": [
      "cloud_resource",
      "dataset",
      "credential",
      "resource"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "configures": {
    "label": "Configures",
    "color": "#f97316",
    "category": "code_topology",
    "direction": "directed",
    "source_types": [
      "config_file"
    ],
    "target_types": [
      "agent",
      "server",
      "ci_job",
      "tool"
    ],
    "traversable": true,
    "emission_status": "reserved",
    "emission_surfaces": [
      "code_graph"
    ],
    "emission_notes": "Reserved for configuration topology linking config files to agents, servers, CI jobs, and tools."
  },
  "contains": {
    "label": "Contains",
    "color": "#6366f1",
    "category": "inventory",
    "direction": "directed",
    "source_types": [
      "container",
      "cluster",
      "fleet"
    ],
    "target_types": [
      "package",
      "server",
      "container"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "correlates_with": {
    "label": "Correlates With (cross-env)",
    "color": "#0ea5e9",
    "category": "correlation",
    "direction": "bidirectional",
    "source_types": [
      "agent",
      "server"
    ],
    "target_types": [
      "agent",
      "server"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "cross_account_trust": {
    "label": "Cross-Account Trust",
    "color": "#be123c",
    "category": "identity",
    "direction": "directed",
    "source_types": [
      "account",
      "role",
      "service_principal",
      "federated_identity"
    ],
    "target_types": [
      "account",
      "role",
      "service_principal",
      "federated_identity"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "defines": {
    "label": "Defines",
    "color": "#06b6d4",
    "category": "code_topology",
    "direction": "directed",
    "source_types": [
      "source_file"
    ],
    "target_types": [
      "code_module",
      "tool",
      "ci_job"
    ],
    "traversable": true,
    "emission_status": "reserved",
    "emission_surfaces": [
      "code_graph"
    ],
    "emission_notes": "Reserved for source-code topology linking source files to modules, tools, and CI jobs."
  },
  "delegated_to": {
    "label": "Delegated To (runtime)",
    "color": "#a855f7",
    "category": "runtime",
    "direction": "directed",
    "source_types": [
      "agent"
    ],
    "target_types": [
      "agent"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "depends_on": {
    "label": "Depends On",
    "color": "#52525b",
    "category": "inventory",
    "direction": "directed",
    "source_types": [
      "server",
      "container"
    ],
    "target_types": [
      "package"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "exhibits_drift": {
    "label": "Exhibits Drift",
    "color": "#fb923c",
    "category": "governance",
    "direction": "bidirectional",
    "source_types": [
      "agent"
    ],
    "target_types": [
      "drift_incident"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "exploitable_via": {
    "label": "Exploitable Via",
    "color": "#b91c1c",
    "category": "vulnerability",
    "direction": "directed",
    "source_types": [
      "vulnerability",
      "misconfiguration"
    ],
    "target_types": [
      "tool",
      "credential"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "exposed_to": {
    "label": "Exposed To",
    "color": "#e11d48",
    "category": "exposure",
    "direction": "directed",
    "source_types": [
      "cloud_resource",
      "server",
      "agent",
      "data_store"
    ],
    "target_types": [
      "cloud_resource",
      "resource",
      "data_store"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "exposes_cred": {
    "label": "Exposes Credential",
    "color": "#f59e0b",
    "category": "inventory",
    "direction": "directed",
    "source_types": [
      "server",
      "agent"
    ],
    "target_types": [
      "credential"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "governs": {
    "label": "Governs",
    "color": "#a16207",
    "category": "governance",
    "direction": "directed",
    "source_types": [
      "access_policy"
    ],
    "target_types": [
      "agent",
      "managed_identity",
      "tool"
    ],
    "traversable": false,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "has_permission": {
    "label": "Has Permission",
    "color": "#dc2626",
    "category": "identity",
    "direction": "directed",
    "source_types": [
      "user",
      "role",
      "service_account",
      "service_principal",
      "managed_identity"
    ],
    "target_types": [
      "cloud_resource",
      "data_store",
      "resource",
      "tool"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "hosts": {
    "label": "Hosts",
    "color": "#6b7280",
    "category": "inventory",
    "direction": "directed",
    "source_types": [
      "provider",
      "environment",
      "fleet",
      "account",
      "cloud_resource"
    ],
    "target_types": [
      "account",
      "org",
      "agent",
      "server",
      "cloud_resource"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "imports": {
    "label": "Imports",
    "color": "#22d3ee",
    "category": "code_topology",
    "direction": "directed",
    "source_types": [
      "source_file",
      "code_module"
    ],
    "target_types": [
      "external_import",
      "code_module",
      "package"
    ],
    "traversable": true,
    "emission_status": "reserved",
    "emission_surfaces": [
      "code_graph"
    ],
    "emission_notes": "Reserved for source-code topology linking files, modules, packages, and imports."
  },
  "inherits": {
    "label": "Inherits",
    "color": "#a16207",
    "category": "identity",
    "direction": "directed",
    "source_types": [
      "user",
      "group",
      "role",
      "service_account",
      "service_principal"
    ],
    "target_types": [
      "policy",
      "role"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "invoked": {
    "label": "Invoked (runtime)",
    "color": "#10b981",
    "category": "runtime",
    "direction": "directed",
    "source_types": [
      "agent",
      "user"
    ],
    "target_types": [
      "tool",
      "tool_call"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "lateral_path": {
    "label": "Lateral Path",
    "color": "#ea580c",
    "category": "lateral_movement",
    "direction": "directed",
    "source_types": [
      "agent"
    ],
    "target_types": [
      "agent"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "manages": {
    "label": "Manages",
    "color": "#14b8a6",
    "category": "governance",
    "direction": "directed",
    "source_types": [
      "user",
      "group",
      "role",
      "service_account",
      "service_principal",
      "federated_identity"
    ],
    "target_types": [
      "agent",
      "fleet",
      "environment",
      "cloud_resource"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "member_of": {
    "label": "Member Of",
    "color": "#4b5563",
    "category": "governance",
    "direction": "directed",
    "source_types": [
      "user",
      "group",
      "role",
      "service_account",
      "service_principal",
      "federated_identity",
      "agent"
    ],
    "target_types": [
      "account",
      "group",
      "agent",
      "fleet"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "owns": {
    "label": "Owns",
    "color": "#0d9488",
    "category": "governance",
    "direction": "directed",
    "source_types": [
      "org",
      "account",
      "user",
      "group",
      "role",
      "service_account",
      "service_principal"
    ],
    "target_types": [
      "environment",
      "cloud_resource",
      "agent"
    ],
    "traversable": true,
    "emission_status": "reserved",
    "emission_surfaces": [
      "identity_graph"
    ],
    "emission_notes": "Reserved for ownership imports from enterprise identity and cloud inventory sources."
  },
  "part_of": {
    "label": "Part Of",
    "color": "#6b7280",
    "category": "governance",
    "direction": "directed",
    "source_types": [
      "account",
      "agent",
      "server",
      "container"
    ],
    "target_types": [
      "org",
      "fleet",
      "cluster",
      "environment"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "possibly_correlates_with": {
    "label": "Possibly Correlates With (low confidence)",
    "color": "#7dd3fc",
    "category": "correlation",
    "direction": "bidirectional",
    "source_types": [
      "agent",
      "server"
    ],
    "target_types": [
      "agent",
      "server"
    ],
    "traversable": false,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "provides_tool": {
    "label": "Provides Tool",
    "color": "#a855f7",
    "category": "inventory",
    "direction": "directed",
    "source_types": [
      "server"
    ],
    "target_types": [
      "tool"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "reaches_tool": {
    "label": "Credential Reaches Tool",
    "color": "#fbbf24",
    "category": "inventory",
    "direction": "directed",
    "source_types": [
      "credential",
      "agent"
    ],
    "target_types": [
      "tool"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "remediates": {
    "label": "Remediates",
    "color": "#22c55e",
    "category": "vulnerability",
    "direction": "directed",
    "source_types": [
      "package"
    ],
    "target_types": [
      "vulnerability",
      "misconfiguration"
    ],
    "traversable": false,
    "emission_status": "reserved",
    "emission_surfaces": [
      "remediation_graph"
    ],
    "emission_notes": "Reserved for fixed-version and remediation-plan graph edges."
  },
  "runs": {
    "label": "Runs",
    "color": "#a855f7",
    "category": "code_topology",
    "direction": "directed",
    "source_types": [
      "ci_job"
    ],
    "target_types": [
      "tool",
      "server",
      "agent"
    ],
    "traversable": true,
    "emission_status": "reserved",
    "emission_surfaces": [
      "ci_graph"
    ],
    "emission_notes": "Reserved for CI/CD topology linking workflow jobs to tools, servers, and agents."
  },
  "scoped_to": {
    "label": "Scoped To",
    "color": "#22d3ee",
    "category": "governance",
    "direction": "directed",
    "source_types": [
      "managed_identity",
      "access_grant",
      "drift_incident"
    ],
    "target_types": [
      "tool"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "serves_model": {
    "label": "Serves Model",
    "color": "#8b5cf6",
    "category": "inventory",
    "direction": "directed",
    "source_types": [
      "server"
    ],
    "target_types": [
      "model"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "shares_cred": {
    "label": "Shares Credential",
    "color": "#f97316",
    "category": "lateral_movement",
    "direction": "bidirectional",
    "source_types": [
      "agent"
    ],
    "target_types": [
      "agent"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "shares_server": {
    "label": "Shares Server",
    "color": "#22d3ee",
    "category": "lateral_movement",
    "direction": "bidirectional",
    "source_types": [
      "agent"
    ],
    "target_types": [
      "agent"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "stores": {
    "label": "Stores",
    "color": "#0284c7",
    "category": "exposure",
    "direction": "directed",
    "source_types": [
      "cloud_resource",
      "data_store",
      "server"
    ],
    "target_types": [
      "dataset",
      "data_store"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "triggers": {
    "label": "Triggers",
    "color": "#f97316",
    "category": "vulnerability",
    "direction": "directed",
    "source_types": [
      "vulnerability"
    ],
    "target_types": [
      "misconfiguration"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "trusts": {
    "label": "Trusts",
    "color": "#0891b2",
    "category": "identity",
    "direction": "directed",
    "source_types": [
      "role",
      "account"
    ],
    "target_types": [
      "account",
      "user",
      "group",
      "role",
      "service_account",
      "service_principal",
      "federated_identity"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "used_credential": {
    "label": "Used Credential (runtime)",
    "color": "#fbbf24",
    "category": "runtime",
    "direction": "directed",
    "source_types": [
      "tool_call",
      "agent",
      "tool"
    ],
    "target_types": [
      "credential_ref",
      "credential"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "runtime_proxy",
      "gateway_event_projection"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "uses": {
    "label": "Uses",
    "color": "#10b981",
    "category": "inventory",
    "direction": "directed",
    "source_types": [
      "agent"
    ],
    "target_types": [
      "server"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
  "vulnerable_to": {
    "label": "Vulnerable To",
    "color": "#ef4444",
    "category": "vulnerability",
    "direction": "directed",
    "source_types": [
      "package",
      "server",
      "container"
    ],
    "target_types": [
      "vulnerability"
    ],
    "traversable": true,
    "emission_status": "emitted",
    "emission_surfaces": [
      "static_scan",
      "graph_overlay",
      "computed_path"
    ],
    "emission_notes": "Emitted by at least one graph builder or runtime projection."
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// Type guards
// ═══════════════════════════════════════════════════════════════════════════

export function isGraphNodeKind(value: unknown): value is GraphNodeKindKey {
  return (
    typeof value === "string" &&
    (GRAPH_NODE_KINDS as readonly string[]).includes(value)
  );
}

export function isGraphEdgeKind(value: unknown): value is GraphEdgeKindKey {
  return (
    typeof value === "string" &&
    (GRAPH_EDGE_KINDS as readonly string[]).includes(value)
  );
}
