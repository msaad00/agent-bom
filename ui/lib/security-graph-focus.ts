import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";
import type { GraphCorrelationRun, GraphSnapshot } from "@/lib/api-types";

const CORRELATION_PATH_TARGET_ID = "selected-investigation-path";

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

export function correlationOutcomeMatchesOutput(
  outputScanId: string | undefined,
  graphScanId: string | undefined,
  fixFirstScanId: string | undefined,
): boolean {
  return Boolean(
    outputScanId &&
      graphScanId === outputScanId &&
      fixFirstScanId === outputScanId,
  );
}

export function buildCorrelationPathHref(
  pathname: string,
  _current: URLSearchParams,
  scanId: string,
): string {
  const params = new URLSearchParams();
  params.set("scan", scanId);
  params.set("path", "top");
  return `${pathname}?${params.toString()}#${CORRELATION_PATH_TARGET_ID}`;
}

export function focusCorrelationPathTarget(documentRef: Document): boolean {
  const target = documentRef.getElementById(CORRELATION_PATH_TARGET_ID);
  if (!target) return false;
  target.focus({ preventScroll: true });
  target.scrollIntoView({ behavior: "smooth", block: "start" });
  return true;
}

export function buildCorrelationRemediationHref(
  href: string,
  scanId: string,
  finding?: string,
  packageName?: string,
): string {
  const [splitPath, query = ""] = href.split("?", 2);
  const path = splitPath || href;
  const params = new URLSearchParams(query);
  params.set("scan", scanId);
  if (finding) params.set("cve", finding);
  if (packageName) params.set("package", packageName);
  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
}

export function completeDirectedHopCount(path: AttackPath): number | null {
  const expected = path.hops.length - 1;
  const receipts = path.hop_evidence;
  if (
    expected < 1 || path.analysis?.status !== "complete" ||
    path.source !== path.hops[0] || path.target !== path.hops.at(-1) ||
    path.edges.length !== expected || !Array.isArray(receipts) || receipts.length !== expected
  ) return null;
  const valid = receipts.every((receipt, index) =>
    receipt != null &&
    receipt.source_node_id === path.hops[index] &&
    receipt.target_node_id === path.hops[index + 1] &&
    typeof receipt.relationship === "string" && receipt.relationship.trim().length > 0 &&
    receipt.relationship === path.edges[index] &&
    receipt.direction === "directed" && receipt.traversable === true &&
    receipt.complete === true && receipt.truncated === false &&
    receipt.freshness === "fresh" && receipt.relationship_provenance === "recorded" &&
    receipt.correlation_identity_status === "current" &&
    Array.isArray(receipt.source_snapshot_ids) && receipt.source_snapshot_ids.length > 0 &&
    receipt.source_snapshot_ids.every((id) => typeof id === "string" && id.trim().length > 0)
  );
  return valid ? receipts.length : null;
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
