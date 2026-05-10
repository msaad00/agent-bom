import type { UnifiedEdge, UnifiedNode } from "@/lib/graph-schema";

export type ReachabilityPathPreview = {
  targetId: string;
  targetLabel: string;
  targetType: string;
  depth: number;
  hops: string[];
  labels: string[];
};

export type ReachabilitySummary = {
  rootId: string;
  rootLabel: string;
  truncated: boolean;
  nodeIds: Set<string>;
  edgeKeys: Set<string>;
  countsByType: Record<string, number>;
  pathPreviews: ReachabilityPathPreview[];
};

type SummarizeReachabilityInput = {
  rootId: string;
  rootLabel?: string | undefined;
  nodes: UnifiedNode[];
  edges: UnifiedEdge[];
  depthByNode?: Record<string, number> | undefined;
  truncated?: boolean | undefined;
  maxPaths?: number | undefined;
};

export function summarizeReachability({
  rootId,
  rootLabel,
  nodes,
  edges,
  depthByNode = {},
  truncated = false,
  maxPaths = 8,
}: SummarizeReachabilityInput): ReachabilitySummary {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const adjacency = buildReachabilityAdjacency(edges);
  const { reached, previous, depth } = walkReachable(rootId, adjacency, depthByNode);
  const nodeIds = new Set([rootId, ...nodes.filter((node) => reached.has(node.id)).map((node) => node.id)]);
  const edgeKeys = new Set<string>();

  for (const edge of edges) {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) continue;
    edgeKeys.add(`${edge.source}=>${edge.target}`);
    if (edge.direction === "bidirectional") {
      edgeKeys.add(`${edge.target}=>${edge.source}`);
    }
  }

  const countsByType: Record<string, number> = {};
  for (const node of nodes) {
    if (node.id === rootId || !nodeIds.has(node.id)) continue;
    const type = String(node.entity_type || "unknown");
    countsByType[type] = (countsByType[type] ?? 0) + 1;
  }

  const pathPreviews = nodes
    .filter((node) => node.id !== rootId && nodeIds.has(node.id))
    .sort((left, right) => {
      const depthDelta = (depth.get(left.id) ?? Number.MAX_SAFE_INTEGER) - (depth.get(right.id) ?? Number.MAX_SAFE_INTEGER);
      if (depthDelta !== 0) return depthDelta;
      return right.risk_score - left.risk_score || left.label.localeCompare(right.label);
    })
    .slice(0, maxPaths)
    .map((node) => {
      const hops = reconstructPath(rootId, node.id, previous);
      return {
        targetId: node.id,
        targetLabel: node.label,
        targetType: String(node.entity_type || "unknown"),
        depth: Math.max(0, hops.length - 1),
        hops,
        labels: hops.map((id) => nodeById.get(id)?.label ?? id),
      };
    });

  return {
    rootId,
    rootLabel: rootLabel ?? nodeById.get(rootId)?.label ?? rootId,
    truncated,
    nodeIds,
    edgeKeys,
    countsByType,
    pathPreviews,
  };
}

function buildReachabilityAdjacency(edges: UnifiedEdge[]): Map<string, string[]> {
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    if (edge.traversable === false) continue;
    addDirectedNeighbor(adjacency, edge.source, edge.target);
    if (edge.direction === "bidirectional") {
      addDirectedNeighbor(adjacency, edge.target, edge.source);
    }
  }
  return adjacency;
}

function addDirectedNeighbor(adjacency: Map<string, string[]>, source: string, target: string): void {
  const neighbors = adjacency.get(source);
  if (neighbors) {
    neighbors.push(target);
  } else {
    adjacency.set(source, [target]);
  }
}

function walkReachable(
  rootId: string,
  adjacency: Map<string, string[]>,
  depthByNode: Record<string, number>,
): { reached: Set<string>; previous: Map<string, string>; depth: Map<string, number> } {
  const reached = new Set<string>([rootId]);
  const previous = new Map<string, string>();
  const depth = new Map<string, number>([[rootId, 0]]);
  const queue = [rootId];

  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const next of adjacency.get(current) ?? []) {
      if (reached.has(next)) continue;
      reached.add(next);
      previous.set(next, current);
      depth.set(next, (depth.get(current) ?? 0) + 1);
      queue.push(next);
    }
  }

  for (const [nodeId, value] of Object.entries(depthByNode)) {
    if (value >= 0) {
      reached.add(nodeId);
      depth.set(nodeId, value);
    }
  }

  return { reached, previous, depth };
}

function reconstructPath(rootId: string, targetId: string, previous: Map<string, string>): string[] {
  const reversed = [targetId];
  let current = targetId;
  while (current !== rootId) {
    const parent = previous.get(current);
    if (!parent) return [rootId, targetId];
    reversed.push(parent);
    current = parent;
  }
  return reversed.reverse();
}

export function prettifyReachabilityType(type: string): string {
  return type
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}
