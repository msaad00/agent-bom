import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";
import type { GraphCorrelationRun, GraphSnapshot } from "@/lib/api-types";

export function latestCompletedCorrelation(
  correlations: GraphCorrelationRun[],
): GraphCorrelationRun | null {
  return correlations.reduce<GraphCorrelationRun | null>((latest, candidate) => {
    if (candidate.status !== "complete" || !candidate.output_scan_id) return latest;
    return !latest || candidate.created_at > latest.created_at ? candidate : latest;
  }, null);
}

export function selectInitialGraphSnapshot(
  snapshots: GraphSnapshot[],
  requestedScanId: string,
  latestCorrelation: GraphCorrelationRun | null,
): string {
  if (requestedScanId) {
    return snapshots.some((snapshot) => snapshot.scan_id === requestedScanId)
      ? requestedScanId
      : "";
  }
  if (
    latestCorrelation?.output_scan_id &&
    snapshots.some((snapshot) => snapshot.scan_id === latestCorrelation.output_scan_id)
  ) {
    return latestCorrelation.output_scan_id;
  }
  return snapshots[0]?.scan_id ?? "";
}

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
