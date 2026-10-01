/** Compose the summary and small canvas only when both prove the same revision. */
import type { api } from "./api";
import type { GraphCompleteness } from "./api-types";

export type BlastRadiusState = {
  rootId: string;
  rootLabel: string;
  nodeIds: Set<string>;
  countsByType: Record<string, number>;
  affectedCount: number;
  maxDepthReached: number;
  completeness?: GraphCompleteness | undefined;
  visibleRelatedCount: number;
};

export async function loadBlastInvestigation(
  client: Pick<typeof api, "getGraphImpact" | "queryGraph">,
  nodeId: string,
  scanId: string | undefined,
  signal?: AbortSignal,
) {
  const options = signal ? { signal } : undefined;
  const impact = await client.getGraphImpact(nodeId, scanId, 4, options);
  if (!impact.snapshot_generation || !impact.scan_id) {
    throw new Error("This backend cannot pin blast-radius evidence. Refresh or use a backend with snapshot revisions.");
  }
  const context = await client.queryGraph({
    roots: [nodeId], scan_id: impact.scan_id, snapshot_generation: impact.snapshot_generation,
    direction: "reverse", max_depth: 4, max_nodes: 4, max_edges: 32,
    timeout_ms: 2500, traversable_only: false, include_roots: true, include_attack_paths: false,
  }, options);
  if (context.snapshot_generation !== impact.snapshot_generation || context.scan_id !== impact.scan_id || context.tenant_id !== impact.tenant_id) {
    throw new Error("Graph snapshot changed. Restart the blast-radius investigation.");
  }
  return { impact, context };
}
