import type { ContextGraphData, ContextGraphEdge, ContextGraphNode } from "@/lib/context-graph";

export type ContextNeighborhoodDirection = "in" | "out" | "both";
export interface HiddenContextGroup { kind: string; count: number; nodeIds: string[]; nodeIdsTruncated: boolean }
export interface ContextNeighborhood {
  nodes: ContextGraphNode[];
  edges: ContextGraphEdge[];
  seedFound: boolean;
  depthById: Record<string, number>;
  /** Hidden counts describe only the loaded graph, never the whole estate. */
  hiddenNodeCount: number;
  hiddenEdgeCount: number;
  truncated: boolean;
  sourceIncomplete: boolean;
  hiddenGroups: Record<string, HiddenContextGroup[]>;
}

const NODE_LIMIT = 40;
const EDGE_LIMIT = 80;

/** Bounded recorded topology. Expansion is not evidence of effective access. */
export function projectContextNeighborhood(
  data: ContextGraphData,
  seedId: string,
  expandedIds: string[] = [],
  direction: ContextNeighborhoodDirection = "both",
  depth = 2,
): ContextNeighborhood {
  const nodesById = new Map<string, ContextGraphNode>();
  for (const node of data.nodes) if (!nodesById.has(node.id)) nodesById.set(node.id, node);
  const validEdges = data.edges.filter(edge => nodesById.has(edge.source) && nodesById.has(edge.target));
  const adjacency = new Map<string, Array<{ id: string; edge: number }>>();
  const add = (from: string, to: string, edge: number) => {
    const neighbors = adjacency.get(from) ?? [];
    neighbors.push({ id: to, edge });
    adjacency.set(from, neighbors);
  };
  validEdges.forEach((edge, index) => {
    if (direction !== "in") add(edge.source, edge.target, index);
    if (direction !== "out" && edge.source !== edge.target) add(edge.target, edge.source, index);
  });
  // IDs provide stable selection even when provider ordering or labels change.
  for (const neighbors of adjacency.values()) neighbors.sort((a, b) => a.id.localeCompare(b.id) || a.edge - b.edge);
  const visible = new Set<string>();
  const discoveryEdges = new Set<number>();
  const expanded = new Set(expandedIds);
  const distance = new Map<string, number>();
  const queue: string[] = [];
  const maxDepth = Number.isFinite(depth) ? Math.max(1, Math.min(3, Math.floor(depth))) : 2;
  let truncated = false;
  if (nodesById.has(seedId)) {
    visible.add(seedId);
    distance.set(seedId, 0);
    queue.push(seedId);
  }
  for (let index = 0; index < queue.length; index++) {
    const current = queue[index]!;
    const currentDepth = distance.get(current)!;
    if (currentDepth >= maxDepth && !expanded.has(current)) continue;
    for (const neighbor of adjacency.get(current) ?? []) {
      if (visible.has(neighbor.id)) continue;
      if (visible.size >= NODE_LIMIT) { truncated = true; continue; }
      visible.add(neighbor.id);
      distance.set(neighbor.id, currentDepth + 1);
      discoveryEdges.add(neighbor.edge);
      queue.push(neighbor.id);
    }
  }
  // Keep each node's discovery edge before optional cross-links so edge limits
  // cannot turn discovered neighbors into disconnected canvas nodes.
  const eligibleEdges = validEdges.flatMap((edge, index) => visible.has(edge.source) && visible.has(edge.target) ? [index] : []);
  const selectedEdges = [...discoveryEdges, ...eligibleEdges.filter(index => !discoveryEdges.has(index))];
  if (selectedEdges.length > EDGE_LIMIT) truncated = true;
  const edges = selectedEdges.slice(0, EDGE_LIMIT).map(index => validEdges[index]!);
  const hiddenGroups: Record<string, HiddenContextGroup[]> = Object.create(null);
  for (const id of visible) {
    const groups = new Map<string, Set<string>>();
    for (const neighbor of adjacency.get(id) ?? []) {
      if (visible.has(neighbor.id)) continue;
      const node = nodesById.get(neighbor.id)!;
      const kind = node.entity_type ?? node.kind;
      const ids = groups.get(kind) ?? new Set<string>();
      ids.add(neighbor.id);
      groups.set(kind, ids);
    }
    hiddenGroups[id] = [...groups].sort(([a], [b]) => a.localeCompare(b)).map(([kind, ids]) => ({ kind, count: ids.size, nodeIds: [...ids].slice(0, NODE_LIMIT), nodeIdsTruncated: ids.size > NODE_LIMIT }));
  }
  return {
    nodes: [...visible].map(id => nodesById.get(id)!), edges,
    seedFound: nodesById.has(seedId),
    depthById: Object.fromEntries(distance),
    hiddenNodeCount: nodesById.size - visible.size,
    hiddenEdgeCount: validEdges.length - edges.length,
    truncated,
    sourceIncomplete: data.completeness?.complete === false || data.completeness?.truncated === true || data.completeness?.sampled === true,
    hiddenGroups,
  };
}
