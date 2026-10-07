import type { GraphNodeNeighborsResponse } from "@/lib/api-types";
import type { UnifiedGraphData } from "@/lib/graph-schema";

/** Merge bounded, server-authored one-hop evidence into the current projection. */
export function mergeGraphNeighborExpansions(
  graph: UnifiedGraphData,
  expansions: Iterable<GraphNodeNeighborsResponse>,
): UnifiedGraphData {
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const edges = new Map(graph.edges.map((edge) => [edge.id, edge]));
  for (const expansion of expansions) {
    for (const node of expansion.neighbors) nodes.set(node.id, node);
    for (const edge of expansion.edges) edges.set(edge.id, edge);
  }
  return { ...graph, nodes: [...nodes.values()], edges: [...edges.values()] };
}

export const INVESTIGATION_NODE_LIMIT = 100;

/** Page loaded context without dropping selected path nodes or fabricating edges.
 * Source stats remain estate/snapshot totals, never the count on this canvas.
 */
export function boundedInvestigationGraph(graph: UnifiedGraphData, pinnedIds: string[], page: number) {
  const pinned = new Set(pinnedIds);
  const anchors = graph.nodes.filter(node => pinned.has(node.id)).slice(0, INVESTIGATION_NODE_LIMIT);
  const context = graph.nodes.filter(node => !pinned.has(node.id));
  const pageSize = Math.max(1, INVESTIGATION_NODE_LIMIT - anchors.length);
  const pageCount = Math.max(1, Math.ceil(context.length / pageSize));
  const currentPage = Math.min(Math.max(0, page), pageCount - 1);
  const nodes = [...anchors, ...context.slice(currentPage * pageSize, (currentPage + 1) * pageSize)]
    .slice(0, INVESTIGATION_NODE_LIMIT);
  const ids = new Set(nodes.map(node => node.id));
  return {
    graph: { ...graph, nodes, edges: graph.edges.filter(edge => ids.has(edge.source) && ids.has(edge.target)) },
    omittedNodes: graph.nodes.length - nodes.length,
    pageCount,
    page: currentPage,
  };
}
