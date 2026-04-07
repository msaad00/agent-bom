/**
 * Unified Graph Schema — TypeScript mirror of Python graph_schema.py.
 *
 * Single source of truth for all graph types in the Next.js UI.
 * Every enum, interface, and constant here mirrors the Python module exactly.
 *
 * OCSF-aligned: every node carries category_uid / class_uid / type_uid.
 */

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
  CREDENTIAL = "credential",
  MISCONFIGURATION = "misconfiguration",
  // Grouping (virtual)
  PROVIDER = "provider",
  ENVIRONMENT = "environment",
}

export enum RelationshipType {
  // Static inventory
  HOSTS = "hosts",
  USES = "uses",
  DEPENDS_ON = "depends_on",
  PROVIDES_TOOL = "provides_tool",
  EXPOSES_CRED = "exposes_cred",
  SERVES_MODEL = "serves_model",
  CONTAINS = "contains",
  // Vulnerability
  AFFECTS = "affects",
  VULNERABLE_TO = "vulnerable_to",
  EXPLOITABLE_VIA = "exploitable_via",
  // Lateral movement
  SHARES_SERVER = "shares_server",
  SHARES_CRED = "shares_cred",
  LATERAL_PATH = "lateral_path",
  // Runtime
  INVOKED = "invoked",
  ACCESSED = "accessed",
  DELEGATED_TO = "delegated_to",
}

export enum NodeStatus {
  ACTIVE = "active",
  INACTIVE = "inactive",
  VULNERABLE = "vulnerable",
  REMEDIATED = "remediated",
}

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
  [EntityType.PROVIDER]: { category_uid: 0, class_uid: 0 },
  [EntityType.ENVIRONMENT]: { category_uid: 0, class_uid: 0 },
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
];

export const RELATIONSHIP_LEGEND: LegendEntry[] = [
  { key: "uses", label: "Uses", color: "#10b981", shape: "circle" },
  { key: "depends_on", label: "Depends On", color: "#52525b", shape: "circle" },
  { key: "provides_tool", label: "Provides Tool", color: "#a855f7", shape: "circle" },
  { key: "exposes_cred", label: "Exposes Credential", color: "#f59e0b", shape: "circle" },
  { key: "vulnerable_to", label: "Vulnerable To", color: "#ef4444", shape: "circle" },
  { key: "shares_server", label: "Shares Server", color: "#22d3ee", shape: "circle" },
  { key: "shares_cred", label: "Shares Credential", color: "#f97316", shape: "circle" },
  { key: "lateral_path", label: "Lateral Path", color: "#ea580c", shape: "circle" },
  { key: "invoked", label: "Invoked (runtime)", color: "#10b981", shape: "circle" },
  { key: "accessed", label: "Accessed (runtime)", color: "#3b82f6", shape: "circle" },
];

/** Entity types that represent actual security findings (for SIEM export) */
export const FINDING_ENTITY_TYPES: Set<EntityType> = new Set([
  EntityType.VULNERABILITY,
  EntityType.MISCONFIGURATION,
]);
