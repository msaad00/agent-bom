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
