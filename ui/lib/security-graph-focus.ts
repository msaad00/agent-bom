import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";

export function buildFocusedGraphData(
  graph: UnifiedGraphData,
  path: AttackPath,
): UnifiedGraphData | null {
  if (path.hops.length === 0) return null;

  const hopSet = new Set(path.hops);
  const pathEdgeSet = new Set(path.edges);

  const nodes = graph.nodes.filter((node) => hopSet.has(node.id));
  if (nodes.length === 0) return null;

  const edges = graph.edges.filter(
    (edge) =>
      pathEdgeSet.has(edge.id) ||
      (hopSet.has(edge.source) && hopSet.has(edge.target)),
  );

  return {
    ...graph,
    nodes,
    edges,
    attack_paths: [path],
    interaction_risks: [],
    stats: {
      ...graph.stats,
      total_nodes: nodes.length,
      total_edges: edges.length,
      attack_path_count: 1,
      interaction_risk_count: 0,
    },
  };
}
