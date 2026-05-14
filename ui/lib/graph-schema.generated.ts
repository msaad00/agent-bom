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
}

export type GraphSemanticLayerKey = "user" | "identity" | "app" | "api_gateway" | "orchestration" | "mcp_server" | "tool" | "package" | "runtime_evidence" | "asset" | "infra" | "finding";

export const GRAPH_SEMANTIC_LAYERS: readonly GraphSemanticLayerKey[] = ["user", "identity", "app", "api_gateway", "orchestration", "mcp_server", "tool", "package", "runtime_evidence", "asset", "infra", "finding"] as const;

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
};

// ═══════════════════════════════════════════════════════════════════════════
// Node kinds (entity types)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphNodeKind {
  ACCOUNT = "account",
  AGENT = "agent",
  CLOUD_RESOURCE = "cloud_resource",
  CLUSTER = "cluster",
  CONTAINER = "container",
  CREDENTIAL = "credential",
  DATASET = "dataset",
  ENVIRONMENT = "environment",
  FEDERATED_IDENTITY = "federated_identity",
  FLEET = "fleet",
  GROUP = "group",
  MISCONFIGURATION = "misconfiguration",
  MODEL = "model",
  ORG = "org",
  PACKAGE = "package",
  POLICY = "policy",
  PROVIDER = "provider",
  ROLE = "role",
  SERVER = "server",
  SERVICE_ACCOUNT = "service_account",
  SERVICE_PRINCIPAL = "service_principal",
  TOOL = "tool",
  USER = "user",
  VULNERABILITY = "vulnerability",
}

export type GraphNodeKindKey = "account" | "agent" | "cloud_resource" | "cluster" | "container" | "credential" | "dataset" | "environment" | "federated_identity" | "fleet" | "group" | "misconfiguration" | "model" | "org" | "package" | "policy" | "provider" | "role" | "server" | "service_account" | "service_principal" | "tool" | "user" | "vulnerability";

export const GRAPH_NODE_KINDS: readonly GraphNodeKindKey[] = ["account", "agent", "cloud_resource", "cluster", "container", "credential", "dataset", "environment", "federated_identity", "fleet", "group", "misconfiguration", "model", "org", "package", "policy", "provider", "role", "server", "service_account", "service_principal", "tool", "user", "vulnerability"] as const;

export interface GraphNodeKindMeta {
  label: string;
  color: string;
  shape: string;
  layer: GraphSemanticLayerKey;
  icon: string;
  category_uid: number;
  class_uid: number;
}

export const GRAPH_NODE_KIND_META: Record<GraphNodeKindKey, GraphNodeKindMeta> = {
  "account": {
    "label": "Account",
    "color": "#0f766e",
    "shape": "square",
    "layer": "identity",
    "icon": "square",
    "category_uid": 3,
    "class_uid": 3001
  },
  "agent": {
    "label": "AI Agent",
    "color": "#10b981",
    "shape": "circle",
    "layer": "orchestration",
    "icon": "circle",
    "category_uid": 5,
    "class_uid": 4001
  },
  "cloud_resource": {
    "label": "Cloud Resource",
    "color": "#0ea5e9",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001
  },
  "cluster": {
    "label": "Cluster",
    "color": "#4b5563",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001
  },
  "container": {
    "label": "Container",
    "color": "#6366f1",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001
  },
  "credential": {
    "label": "Credential",
    "color": "#f59e0b",
    "shape": "diamond",
    "layer": "identity",
    "icon": "diamond",
    "category_uid": 5,
    "class_uid": 4001
  },
  "dataset": {
    "label": "Dataset",
    "color": "#06b6d4",
    "shape": "square",
    "layer": "asset",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001
  },
  "environment": {
    "label": "Environment",
    "color": "#9ca3af",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 0,
    "class_uid": 0
  },
  "federated_identity": {
    "label": "Federated Identity",
    "color": "#0e7490",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001
  },
  "fleet": {
    "label": "Fleet",
    "color": "#6b7280",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001
  },
  "group": {
    "label": "Group",
    "color": "#0d9488",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001
  },
  "misconfiguration": {
    "label": "Misconfiguration",
    "color": "#f97316",
    "shape": "triangle",
    "layer": "finding",
    "icon": "triangle",
    "category_uid": 2,
    "class_uid": 2003
  },
  "model": {
    "label": "Model",
    "color": "#8b5cf6",
    "shape": "square",
    "layer": "asset",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001
  },
  "org": {
    "label": "Organization",
    "color": "#115e59",
    "shape": "square",
    "layer": "identity",
    "icon": "square",
    "category_uid": 3,
    "class_uid": 3001
  },
  "package": {
    "label": "Package",
    "color": "#52525b",
    "shape": "square",
    "layer": "package",
    "icon": "square",
    "category_uid": 5,
    "class_uid": 4001
  },
  "policy": {
    "label": "Policy",
    "color": "#d97706",
    "shape": "diamond",
    "layer": "identity",
    "icon": "diamond",
    "category_uid": 3,
    "class_uid": 3001
  },
  "provider": {
    "label": "Provider",
    "color": "#d1d5db",
    "shape": "square",
    "layer": "infra",
    "icon": "square",
    "category_uid": 0,
    "class_uid": 0
  },
  "role": {
    "label": "Role",
    "color": "#ea580c",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001
  },
  "server": {
    "label": "MCP Server",
    "color": "#3b82f6",
    "shape": "circle",
    "layer": "mcp_server",
    "icon": "circle",
    "category_uid": 5,
    "class_uid": 4001
  },
  "service_account": {
    "label": "Service Account",
    "color": "#0f766e",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001
  },
  "service_principal": {
    "label": "Service Principal",
    "color": "#0f766e",
    "shape": "circle",
    "layer": "identity",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001
  },
  "tool": {
    "label": "Tool",
    "color": "#a855f7",
    "shape": "diamond",
    "layer": "tool",
    "icon": "diamond",
    "category_uid": 5,
    "class_uid": 4001
  },
  "user": {
    "label": "User",
    "color": "#14b8a6",
    "shape": "circle",
    "layer": "user",
    "icon": "circle",
    "category_uid": 3,
    "class_uid": 3001
  },
  "vulnerability": {
    "label": "Vulnerability",
    "color": "#ef4444",
    "shape": "triangle",
    "layer": "finding",
    "icon": "triangle",
    "category_uid": 2,
    "class_uid": 2001
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// Edge kinds (relationship types)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphEdgeKind {
  ACCESSED = "accessed",
  AFFECTS = "affects",
  ASSUMES = "assumes",
  ATTACHED = "attached",
  CAN_ACCESS = "can_access",
  CONTAINS = "contains",
  CORRELATES_WITH = "correlates_with",
  CROSS_ACCOUNT_TRUST = "cross_account_trust",
  DELEGATED_TO = "delegated_to",
  DEPENDS_ON = "depends_on",
  EXPLOITABLE_VIA = "exploitable_via",
  EXPOSES_CRED = "exposes_cred",
  HOSTS = "hosts",
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
  SERVES_MODEL = "serves_model",
  SHARES_CRED = "shares_cred",
  SHARES_SERVER = "shares_server",
  TRIGGERS = "triggers",
  TRUSTS = "trusts",
  USES = "uses",
  VULNERABLE_TO = "vulnerable_to",
}

export type GraphEdgeKindKey = "accessed" | "affects" | "assumes" | "attached" | "can_access" | "contains" | "correlates_with" | "cross_account_trust" | "delegated_to" | "depends_on" | "exploitable_via" | "exposes_cred" | "hosts" | "inherits" | "invoked" | "lateral_path" | "manages" | "member_of" | "owns" | "part_of" | "possibly_correlates_with" | "provides_tool" | "reaches_tool" | "remediates" | "serves_model" | "shares_cred" | "shares_server" | "triggers" | "trusts" | "uses" | "vulnerable_to";

export const GRAPH_EDGE_KINDS: readonly GraphEdgeKindKey[] = ["accessed", "affects", "assumes", "attached", "can_access", "contains", "correlates_with", "cross_account_trust", "delegated_to", "depends_on", "exploitable_via", "exposes_cred", "hosts", "inherits", "invoked", "lateral_path", "manages", "member_of", "owns", "part_of", "possibly_correlates_with", "provides_tool", "reaches_tool", "remediates", "serves_model", "shares_cred", "shares_server", "triggers", "trusts", "uses", "vulnerable_to"] as const;

export interface GraphEdgeKindMeta {
  label: string;
  color: string;
  category: string;
  direction: "directed" | "bidirectional";
  source_types: readonly GraphNodeKindKey[];
  target_types: readonly GraphNodeKindKey[];
  traversable: boolean;
}

export const GRAPH_EDGE_KIND_META: Record<GraphEdgeKindKey, GraphEdgeKindMeta> = {
  "accessed": {
    "label": "Accessed (runtime)",
    "color": "#3b82f6",
    "category": "runtime",
    "direction": "directed",
    "source_types": [
      "tool"
    ],
    "target_types": [
      "cloud_resource",
      "dataset",
      "credential"
    ],
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
      "service_principal"
    ],
    "target_types": [
      "policy"
    ],
    "traversable": true
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
      "credential"
    ],
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
  },
  "invoked": {
    "label": "Invoked (runtime)",
    "color": "#10b981",
    "category": "runtime",
    "direction": "directed",
    "source_types": [
      "agent"
    ],
    "target_types": [
      "tool"
    ],
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": false
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
    "traversable": true
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
    "traversable": true
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
    "traversable": false
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
    "traversable": true
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
