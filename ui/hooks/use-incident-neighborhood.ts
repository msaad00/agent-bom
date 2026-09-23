"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { ApiError } from "@/lib/api-errors";
import type { GraphIncidentPage } from "@/lib/api-types";
import type { UnifiedEdge, UnifiedNode } from "@/lib/graph-schema";

export const INCIDENT_CACHE_EDGE_LIMIT = 240;
export const INCIDENT_CACHE_PAGE_LIMIT = 10;
export type IncidentDirection = "in" | "out" | "both";
interface State { scope: string; pages: GraphIncidentPage[]; busy: boolean; error: string | null; stale: boolean }
const empty = (scope: string): State => ({ scope, pages: [], busy: false, error: null, stale: false });

/** One snapshot generation per workspace, including first pages of other nodes. */
export function useIncidentNeighborhood(scanId: string, rootId: string, direction: IncidentDirection, owner: string) {
  const scope = JSON.stringify([owner, scanId, rootId, direction]);
  const current = useRef(empty(scope));
  const request = useRef<{ controller: AbortController; sequence: number } | null>(null);
  const sequence = useRef(0);
  const [state, setState] = useState(current.current);
  const cancel = useCallback(() => { ++sequence.current; request.current?.controller.abort(); }, []);
  const publish = useCallback((next: State) => { current.current = next; setState(next); }, []);
  const load = useCallback(async (nodeId: string, cursor?: string, restart = false) => {
    const previous = restart || current.current.scope !== scope ? empty(scope) : current.current;
    if (!scanId || !nodeId || previous.busy || previous.stale) return;
    if (previous.pages.length >= INCIDENT_CACHE_PAGE_LIMIT) return;
    request.current?.controller.abort();
    const controller = new AbortController();
    const token = ++sequence.current;
    request.current = { controller, sequence: token };
    publish({ ...previous, busy: true, error: null });
    const generation = previous.pages[0]?.snapshot_generation;
    try {
      const page = await api.getGraphIncidentEdges(nodeId, { scanId, direction, signal: controller.signal,
        ...(cursor ? { cursor } : {}), ...(generation ? { snapshotGeneration: generation } : {}) });
      if (controller.signal.aborted || token !== sequence.current) return;
      if (page.scan_id !== scanId || page.node_id !== nodeId || page.direction !== direction || (page.found && !page.snapshot_generation)
        || (generation && page.snapshot_generation !== generation)) throw new Error("Scope changed");
      if (!page.found) {
        publish({ ...previous, busy: false, error: "Recorded node or snapshot unavailable; relationship coverage is unknown." });
        return;
      }
      publish({ ...previous, pages: [...previous.pages, page], busy: false });
    } catch (error) {
      if (controller.signal.aborted || token !== sequence.current) return;
      // Discard every node's pages: never union generations after replacement.
      if ((error instanceof ApiError && error.status === 400) || (error instanceof Error && error.message === "Scope changed")) {
        publish({ ...empty(scope), stale: true, error: "Snapshot changed. Restart the neighborhood to load consistent evidence." });
      } else publish({ ...previous, busy: false, error: "Unable to load recorded relationships. Retry or choose another snapshot." });
    }
  }, [scope, scanId, direction, publish]);
  useEffect(() => {
    publish(empty(scope));
    void load(rootId, undefined, true);
    return cancel;
  }, [scope, rootId, load, publish, cancel]);
  const visible = state.scope === scope ? state : empty(scope);
  const graph = useMemo(() => {
    const nodes = new Map<string, UnifiedNode>();
    const edges = new Map<string, UnifiedEdge>();
    for (const page of visible.pages) {
      for (const node of [page.node, ...page.nodes]) if (node) nodes.set(node.id, node);
      for (const edge of page.edges) edges.set(JSON.stringify([edge.source, edge.target, edge.relationship]), edge);
    }
    return { nodes: [...nodes.values()], edges: [...edges.values()].filter(edge => nodes.has(edge.source) && nodes.has(edge.target)) };
  }, [visible.pages]);
  return { ...visible, ...graph, capped: visible.pages.length >= INCIDENT_CACHE_PAGE_LIMIT || graph.edges.length >= INCIDENT_CACHE_EDGE_LIMIT,
    load, restart: () => { publish(empty(scope)); void load(rootId, undefined, true); },
    collapse: (nodeId: string) => { request.current?.controller.abort(); ++sequence.current; publish({ ...current.current, busy: false, pages: current.current.pages.slice(0, current.current.pages.findIndex(page => page.node_id === nodeId)) }); },
  };
}
