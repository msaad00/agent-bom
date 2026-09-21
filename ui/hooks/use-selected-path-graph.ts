"use client";

import { useEffect, useMemo, useState } from "react";
import { api, type GraphQueryResponse } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";

const MAX_PATH_NODES = 64;
const MAX_CONTEXT_EDGES = 2048;

function counts(values: string[]): Record<string, number> {
  const totals = new Map<string, number>();
  for (const value of values) totals.set(value, (totals.get(value) ?? 0) + 1);
  return Object.fromEntries(totals);
}

function containsPath(graph: UnifiedGraphData, path: AttackPath): boolean {
  const nodes = new Set(graph.nodes.map((node) => node.id));
  return path.hops.length > 0 && path.hops.every((id) => nodes.has(id)) && path.hops.slice(1).every((target, index) =>
    graph.edges.some((edge) =>
      (edge.relationship === path.edges[index] || edge.id === path.edges[index]) && (
        (edge.source === path.hops[index] && edge.target === target) ||
        (edge.direction === "bidirectional" && edge.target === path.hops[index] && edge.source === target)
      ),
    ),
  );
}

type Result = { key: string; graph: UnifiedGraphData | null; message: string; failed: boolean };

/** Load recorded nodes/edges for a selected path outside the paginated queue. */
export function useSelectedPathGraph({ graph, path, scanId, enabled }: {
  graph: UnifiedGraphData | null;
  path: AttackPath | null;
  scanId: string;
  enabled: boolean;
}) {
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<Result | null>(null);
  const roots = useMemo(() => [...new Set(path?.hops ?? [])], [path]);
  const key = useMemo(() => JSON.stringify([graph?.tenant_id, scanId, path, attempt]), [graph?.tenant_id, scanId, path, attempt]);
  const inScope = Boolean(graph && scanId && graph.scan_id === scanId);
  const available = useMemo(() => Boolean(inScope && graph && path && containsPath(graph, path)), [graph, inScope, path]);
  const overBudget = roots.length > MAX_PATH_NODES;
  const needsLoad = enabled && inScope && path !== null && roots.length > 0 && !available && !overBudget;

  useEffect(() => {
    if (!needsLoad || !graph || !path) return;
    const controller = new AbortController();
    const tenantId = graph.tenant_id;
    setResult(null);
    void api.queryGraph({
      roots,
      scan_id: scanId,
      direction: "both",
      max_depth: 1,
      max_nodes: roots.length,
      max_edges: MAX_CONTEXT_EDGES,
      timeout_ms: 2500,
      traversable_only: false,
      include_roots: true,
      include_attack_paths: false,
    }, { signal: controller.signal }).then((response: GraphQueryResponse) => {
      if (controller.signal.aborted) return;
      if (response.scan_id !== scanId || response.tenant_id !== tenantId) {
        setResult({ key, graph: null, failed: true, message: "Selected path graph did not match this snapshot. Retry to load its recorded evidence." });
        return;
      }
      const hopIds = new Set(roots);
      const nodes = response.nodes.filter((node) => hopIds.has(node.id));
      const nodeIds = new Set(nodes.map((node) => node.id));
      const edges = response.edges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target));
      const selectedGraph: UnifiedGraphData = {
        scan_id: response.scan_id,
        tenant_id: response.tenant_id,
        created_at: response.created_at,
        nodes, edges, attack_paths: [path], interaction_risks: [],
        // Query totals/completeness describe broader traversal, not this slice.
        stats: {
          total_nodes: nodes.length,
          total_edges: edges.length,
          node_types: counts(nodes.map((node) => node.entity_type)),
          severity_counts: counts(nodes.map((node) => node.severity)),
          relationship_types: counts(edges.map((edge) => edge.relationship)),
          attack_path_count: 1,
          interaction_risk_count: 0,
          max_attack_path_risk: path.composite_risk,
          highest_interaction_risk: 0,
        },
      };
      const complete = containsPath(selectedGraph, path);
      setResult({
        key, graph: selectedGraph, failed: false,
        message: !complete
          ? "Selected path graph is incomplete: some recorded nodes or relationships were not returned. The ordered Path retains the available source receipts."
          : response.truncated || response.completeness?.complete === false
            ? "Selected path loaded. Broader context was limited by the graph query budget."
            : "",
      });
    }).catch((error: unknown) => {
      if (!controller.signal.aborted) {
        setResult({ key, graph: null, failed: true, message: userFacingApiErrorMessage(error, "Selected path graph could not be loaded. Retry or inspect the ordered Path.") });
      }
    });
    return () => controller.abort();
  }, [graph, key, needsLoad, path, roots, scanId]);

  const current = result?.key === key ? result : null;
  return {
    graph: available ? graph : inScope ? current?.graph ?? null : null,
    loading: needsLoad && current === null,
    message: path && roots.length === 0
      ? "This path has no recorded hops to display. Inspect the ordered Path evidence or open the full graph."
      : !available && overBudget
        ? "This path exceeds the 64-node graph inspection limit. Inspect its ordered Path or open the full graph."
        : current?.message ?? "",
    canRetry: Boolean(current?.failed),
    retry: () => setAttempt((value) => value + 1),
  };
}
