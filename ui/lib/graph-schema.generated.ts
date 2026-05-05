// AUTO-GENERATED — do not edit. Run `npm run codegen:graph-schema` to refresh.
//
// Source of truth: agent_bom.graph.types.EntityType + RelationshipType.
// The Python API at GET /v1/graph/schema is the canonical taxonomy; this
// file is materialised by ui/scripts/codegen-graph-schema.mjs and the CI
// "UI Validate" job fails when it drifts (see #2255).

export const GRAPH_SCHEMA_VERSION = 1 as const;

// ═══════════════════════════════════════════════════════════════════════════
// Node kinds (entity types)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphNodeKind {
  AGENT = "agent",
  CLOUD_RESOURCE = "cloud_resource",
  CLUSTER = "cluster",
  CONTAINER = "container",
  CREDENTIAL = "credential",
  DATASET = "dataset",
  ENVIRONMENT = "environment",
  FLEET = "fleet",
  GROUP = "group",
  MISCONFIGURATION = "misconfiguration",
  MODEL = "model",
  PACKAGE = "package",
  PROVIDER = "provider",
  SERVER = "server",
  SERVICE_ACCOUNT = "service_account",
  TOOL = "tool",
  USER = "user",
  VULNERABILITY = "vulnerability",
}

export type GraphNodeKindKey = "agent" | "cloud_resource" | "cluster" | "container" | "credential" | "dataset" | "environment" | "fleet" | "group" | "misconfiguration" | "model" | "package" | "provider" | "server" | "service_account" | "tool" | "user" | "vulnerability";

export const GRAPH_NODE_KINDS: readonly GraphNodeKindKey[] = ["agent", "cloud_resource", "cluster", "container", "credential", "dataset", "environment", "fleet", "group", "misconfiguration", "model", "package", "provider", "server", "service_account", "tool", "user", "vulnerability"] as const;

export interface GraphNodeKindMeta {
  label: string;
  color: string;
  shape: string;
  icon: string;
}

export const GRAPH_NODE_KIND_META: Record<GraphNodeKindKey, GraphNodeKindMeta> = {
  "agent": {
    "label": "AI Agent",
    "color": "#10b981",
    "shape": "circle",
    "icon": "circle"
  },
  "cloud_resource": {
    "label": "Cloud Resource",
    "color": "#0ea5e9",
    "shape": "square",
    "icon": "square"
  },
  "cluster": {
    "label": "Cluster",
    "color": "#4b5563",
    "shape": "square",
    "icon": "square"
  },
  "container": {
    "label": "Container",
    "color": "#6366f1",
    "shape": "square",
    "icon": "square"
  },
  "credential": {
    "label": "Credential",
    "color": "#f59e0b",
    "shape": "diamond",
    "icon": "diamond"
  },
  "dataset": {
    "label": "Dataset",
    "color": "#06b6d4",
    "shape": "square",
    "icon": "square"
  },
  "environment": {
    "label": "Environment",
    "color": "#9ca3af",
    "shape": "square",
    "icon": "square"
  },
  "fleet": {
    "label": "Fleet",
    "color": "#6b7280",
    "shape": "square",
    "icon": "square"
  },
  "group": {
    "label": "Group",
    "color": "#0d9488",
    "shape": "circle",
    "icon": "circle"
  },
  "misconfiguration": {
    "label": "Misconfiguration",
    "color": "#f97316",
    "shape": "triangle",
    "icon": "triangle"
  },
  "model": {
    "label": "Model",
    "color": "#8b5cf6",
    "shape": "square",
    "icon": "square"
  },
  "package": {
    "label": "Package",
    "color": "#52525b",
    "shape": "square",
    "icon": "square"
  },
  "provider": {
    "label": "Provider",
    "color": "#d1d5db",
    "shape": "square",
    "icon": "square"
  },
  "server": {
    "label": "MCP Server",
    "color": "#3b82f6",
    "shape": "circle",
    "icon": "circle"
  },
  "service_account": {
    "label": "Service Account",
    "color": "#0f766e",
    "shape": "circle",
    "icon": "circle"
  },
  "tool": {
    "label": "Tool",
    "color": "#a855f7",
    "shape": "diamond",
    "icon": "diamond"
  },
  "user": {
    "label": "User",
    "color": "#14b8a6",
    "shape": "circle",
    "icon": "circle"
  },
  "vulnerability": {
    "label": "Vulnerability",
    "color": "#ef4444",
    "shape": "triangle",
    "icon": "triangle"
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// Edge kinds (relationship types)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphEdgeKind {
  ACCESSED = "accessed",
  AFFECTS = "affects",
  CONTAINS = "contains",
  CORRELATES_WITH = "correlates_with",
  DELEGATED_TO = "delegated_to",
  DEPENDS_ON = "depends_on",
  EXPLOITABLE_VIA = "exploitable_via",
  EXPOSES_CRED = "exposes_cred",
  HOSTS = "hosts",
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
  USES = "uses",
  VULNERABLE_TO = "vulnerable_to",
}

export type GraphEdgeKindKey = "accessed" | "affects" | "contains" | "correlates_with" | "delegated_to" | "depends_on" | "exploitable_via" | "exposes_cred" | "hosts" | "invoked" | "lateral_path" | "manages" | "member_of" | "owns" | "part_of" | "possibly_correlates_with" | "provides_tool" | "reaches_tool" | "remediates" | "serves_model" | "shares_cred" | "shares_server" | "triggers" | "uses" | "vulnerable_to";

export const GRAPH_EDGE_KINDS: readonly GraphEdgeKindKey[] = ["accessed", "affects", "contains", "correlates_with", "delegated_to", "depends_on", "exploitable_via", "exposes_cred", "hosts", "invoked", "lateral_path", "manages", "member_of", "owns", "part_of", "possibly_correlates_with", "provides_tool", "reaches_tool", "remediates", "serves_model", "shares_cred", "shares_server", "triggers", "uses", "vulnerable_to"] as const;

export interface GraphEdgeKindMeta {
  label: string;
  color: string;
}

export const GRAPH_EDGE_KIND_META: Record<GraphEdgeKindKey, GraphEdgeKindMeta> = {
  "accessed": {
    "label": "Accessed (runtime)",
    "color": "#3b82f6"
  },
  "affects": {
    "label": "Affects",
    "color": "#dc2626"
  },
  "contains": {
    "label": "Contains",
    "color": "#6366f1"
  },
  "correlates_with": {
    "label": "Correlates With (cross-env)",
    "color": "#0ea5e9"
  },
  "delegated_to": {
    "label": "Delegated To (runtime)",
    "color": "#a855f7"
  },
  "depends_on": {
    "label": "Depends On",
    "color": "#52525b"
  },
  "exploitable_via": {
    "label": "Exploitable Via",
    "color": "#b91c1c"
  },
  "exposes_cred": {
    "label": "Exposes Credential",
    "color": "#f59e0b"
  },
  "hosts": {
    "label": "Hosts",
    "color": "#6b7280"
  },
  "invoked": {
    "label": "Invoked (runtime)",
    "color": "#10b981"
  },
  "lateral_path": {
    "label": "Lateral Path",
    "color": "#ea580c"
  },
  "manages": {
    "label": "Manages",
    "color": "#14b8a6"
  },
  "member_of": {
    "label": "Member Of",
    "color": "#4b5563"
  },
  "owns": {
    "label": "Owns",
    "color": "#0d9488"
  },
  "part_of": {
    "label": "Part Of",
    "color": "#6b7280"
  },
  "possibly_correlates_with": {
    "label": "Possibly Correlates With (low confidence)",
    "color": "#7dd3fc"
  },
  "provides_tool": {
    "label": "Provides Tool",
    "color": "#a855f7"
  },
  "reaches_tool": {
    "label": "Credential Reaches Tool",
    "color": "#fbbf24"
  },
  "remediates": {
    "label": "Remediates",
    "color": "#22c55e"
  },
  "serves_model": {
    "label": "Serves Model",
    "color": "#8b5cf6"
  },
  "shares_cred": {
    "label": "Shares Credential",
    "color": "#f97316"
  },
  "shares_server": {
    "label": "Shares Server",
    "color": "#22d3ee"
  },
  "triggers": {
    "label": "Triggers",
    "color": "#f97316"
  },
  "uses": {
    "label": "Uses",
    "color": "#10b981"
  },
  "vulnerable_to": {
    "label": "Vulnerable To",
    "color": "#ef4444"
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
