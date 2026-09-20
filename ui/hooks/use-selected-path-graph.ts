"use client";

import { useEffect, useMemo, useState } from "react";
import { api, type GraphQueryResponse } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";

const MAX_PATH_NODES = 64;
const MAX_CONTEXT_EDGES = 2048;

function containsPath(graph: UnifiedGraphData, path: AttackPath): boolean {
  const nodes = new Set(graph.nodes.map((node) => node.id));
  return path.hops.every((id) => nodes.has(id)) && path.hops.slice(1).every((target, index) =>
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
        ...response, nodes, edges, attack_paths: [path], interaction_risks: [],
        stats: { ...response.stats, total_nodes: nodes.length, total_edges: edges.length, attack_path_count: 1, interaction_risk_count: 0 },
      };
      const complete = containsPath(selectedGraph, path);
      setResult({
        key, graph: selectedGraph, failed: false,
        message: !complete
          ? "Selected path graph is incomplete: some recorded nodes or relationships were not returned. The ordered Path retains the available source receipts."
          : response.truncated
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
    message: !available && overBudget
      ? "This path exceeds the 64-node graph inspection limit. Inspect its ordered Path or open the full graph."
      : current?.message ?? "",
    canRetry: Boolean(current?.failed),
    retry: () => setAttempt((value) => value + 1),
  };
}
