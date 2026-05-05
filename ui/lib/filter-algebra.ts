/**
 * Filter algebra — constraint propagation across the filter set.
 *
 * Today the graph filters (severity, layer, agent, runtime mode, depth,
 * relationships) are independent toggles. This module makes them
 * mutually-aware: when the operator picks a severity, the agent dropdown
 * shrinks to only agents that have at least one finding at that severity;
 * picking an agent narrows which severities and layers are reachable.
 *
 * Pure constraint propagation, deterministic, no I/O.
 *
 * Public surface:
 *   applyFilters(graph, filters)
 *     → { nodes, edges, validValues }
 *
 * Where `validValues` is the post-filter intersection of every OTHER
 * filter's possible options — i.e. the values that would still produce a
 * non-empty result if the user toggled them next.
 */

import type { LineageNodeType } from "@/components/lineage-nodes";
import type { FilterState } from "@/components/lineage-filter";
import {
  EntityType,
  RelationshipType,
  SEVERITY_RANK,
  type UnifiedEdge,
  type UnifiedNode,
} from "@/lib/graph-schema";
import type { UnifiedGraphResponse } from "@/lib/api-types";

// ───────────────────────────────────────────────────────────────────────
// Public types
// ───────────────────────────────────────────────────────────────────────

export interface FilterValidValues {
  /** Severities present in nodes that pass every OTHER filter. */
  severities: Set<string>;
  /** Agent names that survive every OTHER filter. */
  agents: Set<string>;
  /** Entity kinds (LineageNodeType) reachable given the OTHER filters. */
  layers: Set<LineageNodeType>;
  /** Edge kinds present given the OTHER filters. */
  relationships: Set<RelationshipType | string>;
}

export interface AppliedFilterResult {
  nodes: UnifiedNode[];
  edges: UnifiedEdge[];
  validValues: FilterValidValues;
}

// ───────────────────────────────────────────────────────────────────────
// Layer ↔ entity-type map (mirror of graph-page-client.tsx LAYER_ENTITY_TYPES)
// Kept local so the algebra has no React dependency.
// ───────────────────────────────────────────────────────────────────────

const LAYER_TO_ENTITY: Record<LineageNodeType, EntityType | string> = {
  provider: EntityType.PROVIDER,
  agent: EntityType.AGENT,
  user: EntityType.USER,
  group: EntityType.GROUP,
  serviceAccount: EntityType.SERVICE_ACCOUNT,
  environment: EntityType.ENVIRONMENT,
  fleet: EntityType.FLEET,
  cluster: EntityType.CLUSTER,
  server: EntityType.SERVER,
  // sharedServer is a UI-only refinement of SERVER — treat as server for
  // entity-type membership.
  sharedServer: EntityType.SERVER,
  package: EntityType.PACKAGE,
  model: EntityType.MODEL,
  dataset: EntityType.DATASET,
  container: EntityType.CONTAINER,
  cloudResource: EntityType.CLOUD_RESOURCE,
  vulnerability: EntityType.VULNERABILITY,
  misconfiguration: EntityType.MISCONFIGURATION,
  credential: EntityType.CREDENTIAL,
  tool: EntityType.TOOL,
};

const ENTITY_TO_LAYER: Map<string, LineageNodeType> = new Map();
for (const [layer, entity] of Object.entries(LAYER_TO_ENTITY)) {
  // First write wins — sharedServer collides with server, but server is
  // listed first in the iteration order above so this is safe.
  if (!ENTITY_TO_LAYER.has(String(entity))) {
    ENTITY_TO_LAYER.set(String(entity), layer as LineageNodeType);
  }
}

const RELATIONSHIP_SCOPE_MAP: Record<FilterState["relationshipScope"], Set<string> | null> = {
  all: null,
  inventory: new Set<string>([
    RelationshipType.HOSTS,
    RelationshipType.USES,
    RelationshipType.DEPENDS_ON,
    RelationshipType.PROVIDES_TOOL,
    RelationshipType.EXPOSES_CRED,
    RelationshipType.REACHES_TOOL,
    RelationshipType.SERVES_MODEL,
    RelationshipType.CONTAINS,
  ]),
  attack: new Set<string>([
    RelationshipType.AFFECTS,
    RelationshipType.VULNERABLE_TO,
    RelationshipType.EXPLOITABLE_VIA,
    RelationshipType.REMEDIATES,
    RelationshipType.TRIGGERS,
    RelationshipType.SHARES_SERVER,
    RelationshipType.SHARES_CRED,
    RelationshipType.LATERAL_PATH,
  ]),
  runtime: new Set<string>([
    RelationshipType.INVOKED,
    RelationshipType.ACCESSED,
    RelationshipType.DELEGATED_TO,
  ]),
  governance: new Set<string>([
    RelationshipType.MANAGES,
    RelationshipType.OWNS,
    RelationshipType.PART_OF,
    RelationshipType.MEMBER_OF,
  ]),
};

const RUNTIME_RELATIONSHIPS: Set<string> = new Set([
  RelationshipType.INVOKED,
  RelationshipType.ACCESSED,
  RelationshipType.DELEGATED_TO,
]);

// ───────────────────────────────────────────────────────────────────────
// Predicates — each represents one filter dimension
// ───────────────────────────────────────────────────────────────────────

function severityPasses(node: UnifiedNode, minSeverity: string | null): boolean {
  if (!minSeverity) return true;
  const minRank = SEVERITY_RANK[minSeverity.toLowerCase()] ?? 0;
  if (minRank === 0) return true;
  // Severity filter only constrains entities that *carry* a severity
  // (vulnerabilities, misconfigurations). Otherwise an agent with no
  // CVSS would always be filtered out by `severity:high` and the user
  // would see an empty graph. Match the server behaviour in
  // discovery.py /v1/graph.
  if (!node.severity) return true;
  const rank = SEVERITY_RANK[String(node.severity).toLowerCase()] ?? 0;
  if (rank === 0) return true;
  return rank >= minRank;
}

function layerPasses(node: UnifiedNode, layers: Record<LineageNodeType, boolean>): boolean {
  const layer = ENTITY_TO_LAYER.get(String(node.entity_type));
  if (!layer) return true; // unmapped entity types pass through
  return Boolean(layers[layer]);
}

function vulnOnlyPasses(node: UnifiedNode, vulnOnly: boolean): boolean {
  if (!vulnOnly) return true;
  return (
    node.entity_type === EntityType.VULNERABILITY ||
    node.entity_type === EntityType.MISCONFIGURATION
  );
}

function relationshipScopePasses(
  edge: UnifiedEdge,
  scope: FilterState["relationshipScope"],
): boolean {
  const allowed = RELATIONSHIP_SCOPE_MAP[scope];
  if (!allowed) return true;
  return allowed.has(String(edge.relationship));
}

function runtimeModePasses(edge: UnifiedEdge, mode: FilterState["runtimeMode"]): boolean {
  if (mode === "all") return true;
  const isRuntime = RUNTIME_RELATIONSHIPS.has(String(edge.relationship));
  if (mode === "static") return !isRuntime;
  if (mode === "dynamic") return isRuntime;
  return true;
}

// ───────────────────────────────────────────────────────────────────────
// Agent reachability — used by both severity-via-agent and the agent filter
// ───────────────────────────────────────────────────────────────────────

interface ReachIndex {
  /** node id → set of agent names that can reach it. */
  agentsReaching: Map<string, Set<string>>;
}

/**
 * Build a precomputed index: for each agent, BFS the *bidirectional*
 * adjacency over the supplied edges and stamp every reached node with
 * that agent's name. Result is symmetric — i.e. a vulnerability is "in
 * agent X's neighborhood" iff X reaches it via some path.
 *
 * The traversal is intentionally direction-agnostic because the operator
 * mental model is "show me everything connected to agent X", not
 * "follow only USES → PROVIDES_TOOL". Direction-aware traversal lives
 * in graph-schema.reachableFrom and is used elsewhere.
 */
function buildAgentReachIndex(
  nodes: UnifiedNode[],
  edges: UnifiedEdge[],
  maxDepth: number,
): ReachIndex {
  const agents = nodes.filter((n) => n.entity_type === EntityType.AGENT);
  const adj = new Map<string, Set<string>>();
  for (const e of edges) {
    if (!adj.has(e.source)) adj.set(e.source, new Set());
    if (!adj.has(e.target)) adj.set(e.target, new Set());
    adj.get(e.source)!.add(e.target);
    adj.get(e.target)!.add(e.source);
  }

  const agentsReaching = new Map<string, Set<string>>();
  for (const agent of agents) {
    const visited = new Set<string>([agent.id]);
    const queue: Array<[string, number]> = [[agent.id, 0]];
    while (queue.length > 0) {
      const [current, depth] = queue.shift()!;
      // Stamp this agent on the visited node.
      if (!agentsReaching.has(current)) agentsReaching.set(current, new Set());
      agentsReaching.get(current)!.add(agent.label || agent.id);
      if (depth >= maxDepth) continue;
      for (const neighbor of adj.get(current) ?? []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push([neighbor, depth + 1]);
        }
      }
    }
  }
  return { agentsReaching };
}

function nodeIsInAgentNeighborhood(
  node: UnifiedNode,
  agentName: string | null,
  index: ReachIndex,
): boolean {
  if (!agentName) return true;
  return index.agentsReaching.get(node.id)?.has(agentName) ?? false;
}

// ───────────────────────────────────────────────────────────────────────
// Core filter pass
// ───────────────────────────────────────────────────────────────────────

interface FilterPassOptions {
  /** Skip the severity predicate (used to compute valid severities). */
  skipSeverity?: boolean;
  /** Skip the agent predicate (used to compute valid agents). */
  skipAgent?: boolean;
  /** Skip the layer predicate (used to compute valid layers). */
  skipLayer?: boolean;
  /** Skip the relationship-scope predicate (used to compute valid relationships). */
  skipRelationship?: boolean;
}

function passEdges(
  edges: UnifiedEdge[],
  filters: FilterState,
  opts: FilterPassOptions,
): UnifiedEdge[] {
  return edges.filter((e) => {
    if (!opts.skipRelationship && !relationshipScopePasses(e, filters.relationshipScope)) {
      return false;
    }
    if (!runtimeModePasses(e, filters.runtimeMode)) return false;
    return true;
  });
}

function passNodes(
  nodes: UnifiedNode[],
  edgeSubset: UnifiedEdge[],
  filters: FilterState,
  opts: FilterPassOptions,
): { nodes: UnifiedNode[]; reachIndex: ReachIndex } {
  const reachIndex = buildAgentReachIndex(nodes, edgeSubset, filters.maxDepth);
  const filtered = nodes.filter((n) => {
    if (!opts.skipLayer && !layerPasses(n, filters.layers)) return false;
    if (!opts.skipSeverity && !severityPasses(n, filters.severity)) return false;
    if (!vulnOnlyPasses(n, filters.vulnOnly)) return false;
    if (!opts.skipAgent && !nodeIsInAgentNeighborhood(n, filters.agentName, reachIndex)) {
      return false;
    }
    return true;
  });
  return { nodes: filtered, reachIndex };
}

function pruneEdgesToNodes(edges: UnifiedEdge[], nodeIds: Set<string>): UnifiedEdge[] {
  return edges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
}

// ───────────────────────────────────────────────────────────────────────
// Public entry points
// ───────────────────────────────────────────────────────────────────────

/**
 * Apply all filters and compute the constraint-propagation valid-values
 * for the remaining filter dropdowns.
 */
export function applyFilters(
  graph: UnifiedGraphResponse | null | undefined,
  filters: FilterState,
): AppliedFilterResult {
  const nodes: UnifiedNode[] = graph?.nodes ?? [];
  const edges: UnifiedEdge[] = graph?.edges ?? [];

  if (nodes.length === 0) {
    return {
      nodes: [],
      edges: [],
      validValues: {
        severities: new Set(),
        agents: new Set(),
        layers: new Set(),
        relationships: new Set(),
      },
    };
  }

  // Fully-applied result (every filter active).
  const filteredEdges = passEdges(edges, filters, {});
  const { nodes: filteredNodes } = passNodes(nodes, filteredEdges, filters, {});
  const keepIds = new Set(filteredNodes.map((n) => n.id));
  const finalEdges = pruneEdgesToNodes(filteredEdges, keepIds);

  // Compute valid values by running 4 alternative passes — each one
  // skips ONE dimension so we can collect what would still appear.
  const validValues = computeValidValues(nodes, edges, filters);

  return {
    nodes: filteredNodes,
    edges: finalEdges,
    validValues,
  };
}

/**
 * Compute the set of values that would survive every OTHER filter, for
 * each filter dimension.
 */
export function computeValidValues(
  nodes: UnifiedNode[],
  edges: UnifiedEdge[],
  filters: FilterState,
): FilterValidValues {
  // Severity — drop severity, keep the rest.
  const sevPassEdges = passEdges(edges, filters, {});
  const { nodes: sevNodes } = passNodes(nodes, sevPassEdges, filters, { skipSeverity: true });
  const severities = new Set<string>();
  for (const n of sevNodes) {
    if (!n.severity) continue;
    const rank = SEVERITY_RANK[String(n.severity).toLowerCase()] ?? 0;
    if (rank === 0) continue;
    severities.add(String(n.severity).toLowerCase());
  }

  // Agents — drop agent, keep the rest. We collect *agent names* whose
  // neighborhood (with current other filters) is non-empty.
  const agentPassEdges = passEdges(edges, filters, {});
  const { nodes: agentSurvivors, reachIndex: agentReach } = passNodes(
    nodes,
    agentPassEdges,
    filters,
    { skipAgent: true },
  );
  const agents = new Set<string>();
  // For each agent name in the graph, check if at least one survivor is
  // in its neighborhood.
  const allAgentNames: string[] = [];
  for (const n of nodes) {
    if (n.entity_type === EntityType.AGENT) allAgentNames.push(n.label || n.id);
  }
  for (const name of allAgentNames) {
    const hasNeighbor = agentSurvivors.some((s) =>
      agentReach.agentsReaching.get(s.id)?.has(name),
    );
    if (hasNeighbor) agents.add(name);
  }

  // Layers — drop layer filter, see which entity-types survive.
  const layerPassEdges = passEdges(edges, filters, {});
  const { nodes: layerSurvivors } = passNodes(nodes, layerPassEdges, filters, {
    skipLayer: true,
  });
  const layers = new Set<LineageNodeType>();
  for (const n of layerSurvivors) {
    const layer = ENTITY_TO_LAYER.get(String(n.entity_type));
    if (layer) layers.add(layer);
  }

  // Relationships — drop relationship-scope, keep the rest. Collect
  // every distinct edge.relationship that connects two surviving nodes.
  const relPassEdges = passEdges(edges, filters, { skipRelationship: true });
  const { nodes: relNodes } = passNodes(nodes, relPassEdges, filters, {});
  const relIds = new Set(relNodes.map((n) => n.id));
  const relationships = new Set<string>();
  for (const e of relPassEdges) {
    if (relIds.has(e.source) && relIds.has(e.target)) {
      relationships.add(String(e.relationship));
    }
  }

  return { severities, agents, layers, relationships };
}

// ───────────────────────────────────────────────────────────────────────
// URL state codec
// ───────────────────────────────────────────────────────────────────────

const URL_LAYER_KEYS: LineageNodeType[] = [
  "provider",
  "agent",
  "user",
  "group",
  "serviceAccount",
  "environment",
  "fleet",
  "cluster",
  "server",
  "sharedServer",
  "package",
  "model",
  "dataset",
  "container",
  "cloudResource",
  "vulnerability",
  "misconfiguration",
  "credential",
  "tool",
];

/** Encode a FilterState into URLSearchParams (deterministic, no defaults). */
export function encodeFiltersToParams(filters: FilterState): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.agentName) params.set("agent", filters.agentName);
  if (filters.runtimeMode !== "all") params.set("runtime", filters.runtimeMode);
  if (filters.relationshipScope !== "all") {
    params.set("relationships", filters.relationshipScope);
  }
  if (filters.maxDepth !== 3) params.set("depth", String(filters.maxDepth));
  if (filters.pageSize !== 250) params.set("pageSize", String(filters.pageSize));
  if (filters.vulnOnly) params.set("vulnOnly", "1");

  // Encode layers as a compact CSV of enabled keys, but only when the
  // layer set diverges from the focused defaults — avoids polluting
  // the URL on first load.
  const enabled = URL_LAYER_KEYS.filter((k) => filters.layers[k]);
  params.set("layers", enabled.join(","));

  return params;
}

/**
 * Decode URLSearchParams (or anything iterable like Next's
 * `ReadonlyURLSearchParams`) into a partial FilterState patch. Caller
 * applies the patch on top of `createFocusedGraphFilters()` or another
 * baseline so values absent from the URL fall back to the baseline.
 */
export function decodeFiltersFromParams(
  params: URLSearchParams | { get(name: string): string | null },
): Partial<FilterState> {
  const patch: Partial<FilterState> = {};
  const get = (k: string): string | null => {
    if (typeof (params as URLSearchParams).get === "function") {
      return (params as URLSearchParams).get(k);
    }
    return null;
  };

  const severity = get("severity");
  if (severity) patch.severity = severity;
  else if (severity === "") patch.severity = null;

  const agent = get("agent");
  if (agent) patch.agentName = agent;

  const runtime = get("runtime");
  if (runtime === "static" || runtime === "dynamic" || runtime === "all") {
    patch.runtimeMode = runtime;
  }

  const relationships = get("relationships");
  if (
    relationships === "all" ||
    relationships === "inventory" ||
    relationships === "attack" ||
    relationships === "runtime" ||
    relationships === "governance"
  ) {
    patch.relationshipScope = relationships;
  }

  const depth = get("depth");
  if (depth) {
    const n = Number(depth);
    if (Number.isFinite(n) && n > 0 && n <= 20) patch.maxDepth = n;
  }

  const pageSize = get("pageSize");
  if (pageSize) {
    const n = Number(pageSize);
    if (Number.isFinite(n) && n > 0 && n <= 50000) patch.pageSize = n;
  }

  const vulnOnly = get("vulnOnly");
  if (vulnOnly === "1" || vulnOnly === "true") patch.vulnOnly = true;
  else if (vulnOnly === "0" || vulnOnly === "false") patch.vulnOnly = false;

  const layers = get("layers");
  if (layers !== null) {
    const enabled = new Set(layers.split(",").map((s) => s.trim()).filter(Boolean));
    const next = {} as Record<LineageNodeType, boolean>;
    for (const key of URL_LAYER_KEYS) {
      next[key] = enabled.has(key);
    }
    patch.layers = next;
  }

  return patch;
}

// Re-export for callers that want the layer→entity map without importing
// from graph-page-client (which is "use client").
export { LAYER_TO_ENTITY, ENTITY_TO_LAYER };
