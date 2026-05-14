/**
 * Unified Graph Schema — TypeScript surface for the Python graph schema.
 *
 * As of #2255 the canonical taxonomy (entity types + relationship types)
 * is generated from the Python source via `npm run codegen:graph-schema`
 * into ./graph-schema.generated.ts. This file re-exports the generated
 * kind enums and continues to host the richer TypeScript-specific types
 * (UnifiedNode/UnifiedEdge interfaces, OCSF mappings, severity helpers,
 * legend data) that are not part of the cross-language contract.
 *
 * When adding a new entity / edge type:
 *   1. Add it to agent_bom.graph.types in Python.
 *   2. Run `cd ui && npm run codegen:graph-schema` to refresh
 *      graph-schema.generated.ts.
 *   3. Extend any UI-only maps in this file (ENTITY_OCSF_MAP, color
 *      maps, etc.) to cover the new key.
 */

// Re-export the codegen output so consumers can keep the
// `from "@/lib/graph-schema"` import path while still resolving the
// generated, drift-checked enum/union types.
export {
  GRAPH_SCHEMA_VERSION,
  GraphNodeKind,
  GraphEdgeKind,
  GRAPH_NODE_KINDS,
  GRAPH_EDGE_KINDS,
  GRAPH_NODE_KIND_META,
  GRAPH_EDGE_KIND_META,
  isGraphNodeKind,
  isGraphEdgeKind,
} from "./graph-schema.generated";
export type {
  GraphNodeKindKey,
  GraphEdgeKindKey,
  GraphNodeKindMeta,
  GraphEdgeKindMeta,
} from "./graph-schema.generated";

// ═══════════════════════════════════════════════════════════════════════════
// Enums
// ═══════════════════════════════════════════════════════════════════════════

export enum EntityType {
  // Inventory entities (OCSF Category 5)
  AGENT = "agent",
  SERVER = "server",
  PACKAGE = "package",
  TOOL = "tool",
  MODEL = "model",
  DATASET = "dataset",
  CONTAINER = "container",
  CLOUD_RESOURCE = "cloud_resource",
  // Finding entities (OCSF Category 2)
  VULNERABILITY = "vulnerability",
  MISCONFIGURATION = "misconfiguration",
  // Inventory but security-relevant (OCSF Category 5)
  CREDENTIAL = "credential",
  // Identity & governance (OCSF Category 3)
  ORG = "org",
  ACCOUNT = "account",
  USER = "user",
  GROUP = "group",
  ROLE = "role",
  POLICY = "policy",
  SERVICE_ACCOUNT = "service_account",
  SERVICE_PRINCIPAL = "service_principal",
  FEDERATED_IDENTITY = "federated_identity",
  // Organizational hierarchy
  PROVIDER = "provider",
  ENVIRONMENT = "environment",
  FLEET = "fleet",
  CLUSTER = "cluster",
}

export enum RelationshipType {
  // Static inventory
  HOSTS = "hosts",
  USES = "uses",
  DEPENDS_ON = "depends_on",
  PROVIDES_TOOL = "provides_tool",
  EXPOSES_CRED = "exposes_cred",
  REACHES_TOOL = "reaches_tool",
  SERVES_MODEL = "serves_model",
  CONTAINS = "contains",
  // Vulnerability
  AFFECTS = "affects",
  VULNERABLE_TO = "vulnerable_to",
  EXPLOITABLE_VIA = "exploitable_via",
  REMEDIATES = "remediates",
  TRIGGERS = "triggers",
  // Lateral movement
  SHARES_SERVER = "shares_server",
  SHARES_CRED = "shares_cred",
  LATERAL_PATH = "lateral_path",
  // Ownership & governance
  MANAGES = "manages",
  OWNS = "owns",
  PART_OF = "part_of",
  MEMBER_OF = "member_of",
  ASSUMES = "assumes",
  TRUSTS = "trusts",
  ATTACHED = "attached",
  INHERITS = "inherits",
  CAN_ACCESS = "can_access",
  CROSS_ACCOUNT_TRUST = "cross_account_trust",
  // Runtime
  INVOKED = "invoked",
  ACCESSED = "accessed",
  DELEGATED_TO = "delegated_to",
  // Cross-environment correlation (#1892)
  CORRELATES_WITH = "correlates_with",
  POSSIBLY_CORRELATES_WITH = "possibly_correlates_with",
}

export enum NodeStatus {
  ACTIVE = "active",
  INACTIVE = "inactive",
  VULNERABLE = "vulnerable",
  REMEDIATED = "remediated",
}

// Compile-time parity guard — fails the typecheck if the hand-rolled
// EntityType / RelationshipType enums above drift from the generated
// GraphNodeKind / GraphEdgeKind. The generated file is the source of
// truth (#2255); this guard turns drift into a tsc error rather than a
// silent runtime miss.
import type {
  GraphNodeKindKey as _GraphNodeKindKey,
  GraphEdgeKindKey as _GraphEdgeKindKey,
} from "./graph-schema.generated";
type _AssertExtends<T extends U, U> = T;
type _EntityTypeValue = `${EntityType}`;
type _RelationshipTypeValue = `${RelationshipType}`;
type _NodeParity = _AssertExtends<_EntityTypeValue, _GraphNodeKindKey>;
type _EdgeParity = _AssertExtends<_RelationshipTypeValue, _GraphEdgeKindKey>;
type _GeneratedNodeParity = _AssertExtends<_GraphNodeKindKey, _EntityTypeValue>;
type _GeneratedEdgeParity = _AssertExtends<
  _GraphEdgeKindKey,
  _RelationshipTypeValue
>;
// Surface the helper aliases so they aren't pruned as unused imports.
export type _GraphSchemaParity = [
  _NodeParity,
  _EdgeParity,
  _GeneratedNodeParity,
  _GeneratedEdgeParity,
];

export enum OCSFSeverity {
  UNKNOWN = 0,
  INFORMATIONAL = 1,
  LOW = 2,
  MEDIUM = 3,
  HIGH = 4,
  CRITICAL = 5,
}

// ═══════════════════════════════════════════════════════════════════════════
// Severity constants (single source of truth)
// ═══════════════════════════════════════════════════════════════════════════

/** String severity → OCSF severity_id */
export const SEVERITY_TO_OCSF: Record<string, number> = {
  critical: OCSFSeverity.CRITICAL,
  high: OCSFSeverity.HIGH,
  medium: OCSFSeverity.MEDIUM,
  low: OCSFSeverity.LOW,
  info: OCSFSeverity.INFORMATIONAL,
  informational: OCSFSeverity.INFORMATIONAL,
  none: OCSFSeverity.UNKNOWN,
  unknown: OCSFSeverity.UNKNOWN,
};

/** String severity → numeric rank for sorting (0-5, higher = worse) */
export const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  informational: 1,
  none: 0,
  unknown: 0,
};

/** Severity → compact badge for display */
export const SEVERITY_BADGE: Record<string, string> = {
  critical: "R2",
  high: "R1",
  medium: "M",
  low: "L",
  info: "I",
  unknown: "?",
};

/** Severity → risk score contribution */
export const SEVERITY_RISK_SCORE: Record<string, number> = {
  critical: 8.0,
  high: 6.0,
  medium: 4.0,
  low: 2.0,
  info: 0.5,
  informational: 0.5,
  none: 0.0,
  unknown: 0.0,
};

// ═══════════════════════════════════════════════════════════════════════════
// OCSF entity mapping
// ═══════════════════════════════════════════════════════════════════════════

export const ENTITY_OCSF_MAP: Record<
  string,
  { category_uid: number; class_uid: number }
> = {
  [EntityType.AGENT]: { category_uid: 5, class_uid: 4001 },
  [EntityType.SERVER]: { category_uid: 5, class_uid: 4001 },
  [EntityType.PACKAGE]: { category_uid: 5, class_uid: 4001 },
  [EntityType.TOOL]: { category_uid: 5, class_uid: 4001 },
  [EntityType.MODEL]: { category_uid: 5, class_uid: 4001 },
  [EntityType.DATASET]: { category_uid: 5, class_uid: 4001 },
  [EntityType.CONTAINER]: { category_uid: 5, class_uid: 4001 },
  [EntityType.CLOUD_RESOURCE]: { category_uid: 5, class_uid: 4001 },
  [EntityType.VULNERABILITY]: { category_uid: 2, class_uid: 2001 },
  // Credentials are INVENTORY — presence of env var is not a finding
  [EntityType.CREDENTIAL]: { category_uid: 5, class_uid: 4001 },
  [EntityType.MISCONFIGURATION]: { category_uid: 2, class_uid: 2003 },
  // Identity (Category 3)
  [EntityType.ORG]: { category_uid: 3, class_uid: 3001 },
  [EntityType.ACCOUNT]: { category_uid: 3, class_uid: 3001 },
  [EntityType.USER]: { category_uid: 3, class_uid: 3001 },
  [EntityType.GROUP]: { category_uid: 3, class_uid: 3001 },
  [EntityType.ROLE]: { category_uid: 3, class_uid: 3001 },
  [EntityType.POLICY]: { category_uid: 3, class_uid: 3001 },
  [EntityType.SERVICE_ACCOUNT]: { category_uid: 3, class_uid: 3001 },
  [EntityType.SERVICE_PRINCIPAL]: { category_uid: 3, class_uid: 3001 },
  [EntityType.FEDERATED_IDENTITY]: { category_uid: 3, class_uid: 3001 },
  // Organizational
  [EntityType.PROVIDER]: { category_uid: 0, class_uid: 0 },
  [EntityType.ENVIRONMENT]: { category_uid: 0, class_uid: 0 },
  [EntityType.FLEET]: { category_uid: 5, class_uid: 4001 },
  [EntityType.CLUSTER]: { category_uid: 5, class_uid: 4001 },
};

// ═══════════════════════════════════════════════════════════════════════════
// Core interfaces
// ═══════════════════════════════════════════════════════════════════════════

export interface NodeDimensions {
  ecosystem?: string;
  cloud_provider?: string;
  agent_type?: string;
  surface?: string;
  environment?: string;
}

export interface UnifiedNode {
  id: string;
  entity_type: EntityType | string;
  label: string;

  // OCSF classification
  category_uid: number;
  class_uid: number;
  type_uid: number;

  // State
  status: NodeStatus | string;
  risk_score: number;
  severity: string;
  severity_id: number;

  // Temporal
  first_seen: string;
  last_seen: string;

  // Entity-specific
  attributes: Record<string, unknown>;

  // Tags
  compliance_tags: string[];
  data_sources: string[];

  // Dimensions
  dimensions: NodeDimensions;
}

export interface UnifiedEdge {
  id: string;
  source: string;
  target: string;
  relationship: RelationshipType | string;

  // Traversal
  direction: "directed" | "bidirectional";
  weight: number;
  traversable: boolean;

  // Temporal
  first_seen: string;
  last_seen: string;

  // Evidence
  evidence: Record<string, unknown>;

  // OCSF
  activity_id: number;
}

export interface AttackPath {
  source: string;
  target: string;
  hops: string[];
  edges: string[];
  composite_risk: number;
  summary: string;
  credential_exposure: string[];
  tool_exposure: string[];
  vuln_ids: string[];
}

export interface InteractionRisk {
  pattern: string;
  agents: string[];
  risk_score: number;
  description: string;
  owasp_agentic_tag?: string;
}

export interface GraphStats {
  total_nodes: number;
  total_edges: number;
  node_types: Record<string, number>;
  severity_counts: Record<string, number>;
  relationship_types: Record<string, number>;
  attack_path_count: number;
  interaction_risk_count: number;
  max_attack_path_risk: number;
  highest_interaction_risk: number;
}

export interface UnifiedGraphData {
  scan_id: string;
  tenant_id: string;
  created_at: string;
  nodes: UnifiedNode[];
  edges: UnifiedEdge[];
  attack_paths: AttackPath[];
  interaction_risks: InteractionRisk[];
  stats: GraphStats;
}

// ═══════════════════════════════════════════════════════════════════════════
// Backward-compat aliases (map old kind→entity_type, old edge kind→relationship)
// ═══════════════════════════════════════════════════════════════════════════

/** Map legacy NodeKind values → EntityType */
export const NODE_KIND_TO_ENTITY: Record<string, EntityType> = {
  agent: EntityType.AGENT,
  server: EntityType.SERVER,
  credential: EntityType.CREDENTIAL,
  tool: EntityType.TOOL,
  vulnerability: EntityType.VULNERABILITY,
};

/** Map legacy EdgeKind values → RelationshipType */
export const EDGE_KIND_TO_RELATIONSHIP: Record<string, RelationshipType> = {
  uses: RelationshipType.USES,
  exposes: RelationshipType.EXPOSES_CRED,
  provides: RelationshipType.PROVIDES_TOOL,
  vulnerable_to: RelationshipType.VULNERABLE_TO,
  shares_server: RelationshipType.SHARES_SERVER,
  shares_credential: RelationshipType.SHARES_CRED,
};

// ═══════════════════════════════════════════════════════════════════════════
// Display constants
// ═══════════════════════════════════════════════════════════════════════════

/** Canonical node colors by entity type */
export const ENTITY_COLOR_MAP: Record<string, string> = {
  [EntityType.AGENT]: "#10b981",           // emerald
  [EntityType.SERVER]: "#3b82f6",          // blue
  [EntityType.PACKAGE]: "#52525b",         // zinc
  [EntityType.TOOL]: "#a855f7",            // purple
  [EntityType.MODEL]: "#8b5cf6",           // violet
  [EntityType.DATASET]: "#06b6d4",         // cyan
  [EntityType.CONTAINER]: "#6366f1",       // indigo
  [EntityType.CLOUD_RESOURCE]: "#0ea5e9",  // sky
  [EntityType.VULNERABILITY]: "#ef4444",   // red
  [EntityType.CREDENTIAL]: "#f59e0b",      // amber
  [EntityType.MISCONFIGURATION]: "#f97316", // orange
  [EntityType.ORG]: "#115e59",             // teal
  [EntityType.ACCOUNT]: "#0f766e",         // teal
  [EntityType.USER]: "#14b8a6",            // teal
  [EntityType.GROUP]: "#0d9488",           // teal
  [EntityType.ROLE]: "#ea580c",            // orange
  [EntityType.POLICY]: "#d97706",          // amber
  [EntityType.SERVICE_ACCOUNT]: "#0f766e", // teal
  [EntityType.SERVICE_PRINCIPAL]: "#0f766e", // teal
  [EntityType.FEDERATED_IDENTITY]: "#0e7490", // cyan
  [EntityType.PROVIDER]: "#6b7280",        // gray
  [EntityType.ENVIRONMENT]: "#6b7280",     // gray
};

/** Canonical edge colors by relationship type */
export const RELATIONSHIP_COLOR_MAP: Record<string, string> = {
  [RelationshipType.HOSTS]: "#6b7280",
  [RelationshipType.USES]: "#10b981",
  [RelationshipType.DEPENDS_ON]: "#52525b",
  [RelationshipType.PROVIDES_TOOL]: "#a855f7",
  [RelationshipType.EXPOSES_CRED]: "#f59e0b",
  [RelationshipType.REACHES_TOOL]: "#fbbf24",
  [RelationshipType.SERVES_MODEL]: "#8b5cf6",
  [RelationshipType.CONTAINS]: "#6366f1",
  [RelationshipType.AFFECTS]: "#ef4444",
  [RelationshipType.VULNERABLE_TO]: "#ef4444",
  [RelationshipType.EXPLOITABLE_VIA]: "#dc2626",
  [RelationshipType.SHARES_SERVER]: "#22d3ee",
  [RelationshipType.SHARES_CRED]: "#f97316",
  [RelationshipType.LATERAL_PATH]: "#ea580c",
  [RelationshipType.INVOKED]: "#10b981",
  [RelationshipType.ACCESSED]: "#3b82f6",
  [RelationshipType.DELEGATED_TO]: "#a855f7",
  [RelationshipType.CORRELATES_WITH]: "#0ea5e9",
  [RelationshipType.POSSIBLY_CORRELATES_WITH]: "#7dd3fc",
  // Vulnerability lifecycle relations (audit-4 P1: missing UI colors).
  [RelationshipType.REMEDIATES]: "#22c55e",
  [RelationshipType.TRIGGERS]: "#f97316",
  // Ownership / governance relations.
  [RelationshipType.MANAGES]: "#14b8a6",
  [RelationshipType.OWNS]: "#0d9488",
  [RelationshipType.PART_OF]: "#6b7280",
  [RelationshipType.MEMBER_OF]: "#4b5563",
  [RelationshipType.ASSUMES]: "#ea580c",
  [RelationshipType.TRUSTS]: "#0891b2",
  [RelationshipType.ATTACHED]: "#d97706",
  [RelationshipType.INHERITS]: "#a16207",
  [RelationshipType.CAN_ACCESS]: "#dc2626",
  [RelationshipType.CROSS_ACCOUNT_TRUST]: "#be123c",
};

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Get severity rank for sorting. Higher = worse. */
export function severityRank(sev: string): number {
  return SEVERITY_RANK[sev?.toLowerCase() ?? ""] ?? 0;
}

/** Compare two severity strings. Returns positive if a is worse than b. */
export function compareSeverity(a: string, b: string): number {
  return severityRank(a) - severityRank(b);
}

/** Filter nodes by entity type set and minimum severity rank. */
export function filterNodes(
  nodes: UnifiedNode[],
  opts: {
    entityTypes?: Set<EntityType | string>;
    minSeverity?: string;
    status?: NodeStatus | string;
    dataSource?: string;
  } = {},
): UnifiedNode[] {
  const minRank = opts.minSeverity ? severityRank(opts.minSeverity) : 0;
  return nodes.filter((n) => {
    if (opts.entityTypes && !opts.entityTypes.has(n.entity_type)) return false;
    if (minRank && severityRank(n.severity) < minRank) return false;
    if (opts.status && n.status !== opts.status) return false;
    if (opts.dataSource && !n.data_sources.includes(opts.dataSource)) return false;
    return true;
  });
}

/** Filter edges by relationship type set and traversability. */
export function filterEdges(
  edges: UnifiedEdge[],
  opts: {
    relationships?: Set<RelationshipType | string>;
    traversableOnly?: boolean;
    minWeight?: number;
  } = {},
): UnifiedEdge[] {
  return edges.filter((e) => {
    if (opts.relationships && !opts.relationships.has(e.relationship)) return false;
    if (opts.traversableOnly && !e.traversable) return false;
    if (opts.minWeight != null && e.weight < opts.minWeight) return false;
    return true;
  });
}

/** BFS from a source node, respecting edge direction. */
export function reachableFrom(
  sourceId: string,
  edges: UnifiedEdge[],
  maxDepth: number = 6,
): Set<string> {
  // Build direction-aware adjacency: directed edges are one-way,
  // bidirectional edges go both ways.
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    if (!adj.has(e.source)) adj.set(e.source, []);
    adj.get(e.source)!.push(e.target);
    if (e.direction === "bidirectional") {
      if (!adj.has(e.target)) adj.set(e.target, []);
      adj.get(e.target)!.push(e.source);
    }
  }

  const visited = new Set<string>([sourceId]);
  const queue: Array<[string, number]> = [[sourceId, 0]];

  while (queue.length > 0) {
    const [current, depth] = queue.shift()!;
    if (depth >= maxDepth) continue;
    for (const neighbor of adj.get(current) ?? []) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push([neighbor, depth + 1]);
      }
    }
  }

  return visited;
}

// ═══════════════════════════════════════════════════════════════════════════
// Filter options & legend (mirrors Python graph/container.py)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphLayout {
  DAGRE = "dagre",
  FORCE = "force",
  RADIAL = "radial",
  SANKEY = "sankey",
  HIERARCHICAL = "hierarchical",
  GRID = "grid",
}

export interface GraphFilterOptions {
  maxDepth: number;
  maxHops: number;
  minSeverity: string;
  entityTypes: Set<EntityType | string>;
  relationshipTypes: Set<RelationshipType | string>;
  staticOnly: boolean;
  dynamicOnly: boolean;
  includeIds: Set<string>;
  excludeIds: Set<string>;
  layout: GraphLayout | string;
}

export function defaultFilters(): GraphFilterOptions {
  return {
    maxDepth: 6,
    maxHops: 0,
    minSeverity: "",
    entityTypes: new Set(),
    relationshipTypes: new Set(),
    staticOnly: false,
    dynamicOnly: false,
    includeIds: new Set(),
    excludeIds: new Set(),
    layout: GraphLayout.DAGRE,
  };
}

export interface LegendEntry {
  key: string;
  label: string;
  color: string;
  shape: "circle" | "diamond" | "square" | "triangle";
}

export const ENTITY_LEGEND: LegendEntry[] = [
  { key: "agent", label: "AI Agent", color: "#10b981", shape: "circle" },
  { key: "server", label: "MCP Server", color: "#3b82f6", shape: "circle" },
  { key: "package", label: "Package", color: "#52525b", shape: "square" },
  { key: "tool", label: "Tool", color: "#a855f7", shape: "diamond" },
  { key: "vulnerability", label: "Vulnerability", color: "#ef4444", shape: "triangle" },
  { key: "credential", label: "Credential", color: "#f59e0b", shape: "diamond" },
  { key: "misconfiguration", label: "Misconfiguration", color: "#f97316", shape: "triangle" },
  { key: "model", label: "Model", color: "#8b5cf6", shape: "square" },
  { key: "container", label: "Container", color: "#6366f1", shape: "square" },
  { key: "cloud_resource", label: "Cloud Resource", color: "#0ea5e9", shape: "square" },
  { key: "org", label: "Organization", color: "#115e59", shape: "square" },
  { key: "account", label: "Account", color: "#0f766e", shape: "square" },
  { key: "user", label: "User", color: "#14b8a6", shape: "circle" },
  { key: "group", label: "Group", color: "#0d9488", shape: "circle" },
  { key: "role", label: "Role", color: "#ea580c", shape: "circle" },
  { key: "policy", label: "Policy", color: "#d97706", shape: "diamond" },
  { key: "service_account", label: "Service Account", color: "#0f766e", shape: "circle" },
  { key: "service_principal", label: "Service Principal", color: "#0f766e", shape: "circle" },
  { key: "federated_identity", label: "Federated Identity", color: "#0e7490", shape: "circle" },
];

export const RELATIONSHIP_LEGEND: LegendEntry[] = [
  { key: "uses", label: "Uses", color: "#10b981", shape: "circle" },
  { key: "depends_on", label: "Depends On", color: "#52525b", shape: "circle" },
  { key: "provides_tool", label: "Provides Tool", color: "#a855f7", shape: "circle" },
  { key: "exposes_cred", label: "Exposes Credential", color: "#f59e0b", shape: "circle" },
  { key: "reaches_tool", label: "Credential Reaches Tool", color: "#fbbf24", shape: "circle" },
  { key: "vulnerable_to", label: "Vulnerable To", color: "#ef4444", shape: "circle" },
  { key: "shares_server", label: "Shares Server", color: "#22d3ee", shape: "circle" },
  { key: "shares_cred", label: "Shares Credential", color: "#f97316", shape: "circle" },
  { key: "lateral_path", label: "Lateral Path", color: "#ea580c", shape: "circle" },
  { key: "invoked", label: "Invoked (runtime)", color: "#10b981", shape: "circle" },
  { key: "accessed", label: "Accessed (runtime)", color: "#3b82f6", shape: "circle" },
  { key: "assumes", label: "Assumes", color: "#ea580c", shape: "circle" },
  { key: "trusts", label: "Trusts", color: "#0891b2", shape: "circle" },
  { key: "attached", label: "Attached", color: "#d97706", shape: "circle" },
  { key: "inherits", label: "Inherits", color: "#a16207", shape: "circle" },
  { key: "can_access", label: "Can Access", color: "#dc2626", shape: "circle" },
  { key: "cross_account_trust", label: "Cross-Account Trust", color: "#be123c", shape: "circle" },
];

/** Entity types that represent actual security findings (for SIEM export) */
export const FINDING_ENTITY_TYPES: Set<EntityType> = new Set([
  EntityType.VULNERABILITY,
  EntityType.MISCONFIGURATION,
]);
