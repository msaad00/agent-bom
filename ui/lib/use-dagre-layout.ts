"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { type Edge, type Node } from "@xyflow/react";

import { applyDagreLayout, type LayoutOptions } from "@/lib/dagre-layout";

type LayoutState = {
  nodes: Node[];
  edges: Edge[];
  pending: boolean;
  inputNodes?: Node[];
  inputEdges?: Edge[];
};

type WorkerResponse =
  | {
      id: number;
      ok: true;
      nodes: Node[];
      edges: Edge[];
    }
  | {
      id: number;
      ok: false;
      error: string;
    };

const WORKER_NODE_THRESHOLD = 150;

function optionsKey(options: LayoutOptions): string {
  return JSON.stringify({
    direction: options.direction ?? "LR",
    nodeWidth: options.nodeWidth ?? 180,
    nodeHeight: options.nodeHeight ?? 60,
    rankSep: options.rankSep ?? 80,
    nodeSep: options.nodeSep ?? 30,
    // Kept in the key so the min-separation guarantee survives the JSON
    // round-trip into both the sync layout and the web worker. The key IS the
    // options object both paths run on, so anything omitted here is silently
    // dropped before it ever reaches `applyDagreLayout`.
    minSeparation: options.minSeparation ?? null,
    fitAspect: options.fitAspect ?? null,
  });
}

export function useDagreLayout(nodes: Node[], edges: Edge[], options: LayoutOptions): LayoutState {
  const requestId = useRef(0);
  const [workerState, setWorkerState] = useState<LayoutState | null>(null);
  const key = optionsKey(options);
  const stableOptions = useMemo<LayoutOptions>(() => JSON.parse(key) as LayoutOptions, [key]);
  const shouldUseWorker = nodes.length > WORKER_NODE_THRESHOLD;

  const syncLayout = useMemo(() => {
    if (nodes.length === 0) return { nodes: [] as Node[], edges: [] as Edge[], pending: false };
    if (shouldUseWorker) return null;
    return { ...applyDagreLayout(nodes, edges, stableOptions), pending: false };
  }, [edges, nodes, shouldUseWorker, stableOptions]);

  // Worker failures must not return every card at its input origin (0, 0).
  // A deterministic grid is a readable fallback and keeps all real edges.
  const fallback = useMemo<LayoutState>(() => {
    const columns = Math.max(1, Math.ceil(Math.sqrt(nodes.length * 1.6)));
    const width = Math.max(stableOptions.nodeWidth ?? 300, 300) + 60;
    const height = Math.max(stableOptions.nodeHeight ?? 160, 160) + 60;
    return { nodes: nodes.map((node, index) => ({ ...node, position: {
      x: (index % columns) * width, y: Math.floor(index / columns) * height,
    } })), edges, pending: false, inputNodes: nodes, inputEdges: edges };
  }, [nodes, edges, stableOptions]);

  useEffect(() => {
    if (nodes.length === 0 || !shouldUseWorker || typeof Worker === "undefined") {
      setWorkerState(null);
      return;
    }

    const id = requestId.current + 1;
    requestId.current = id;
    setWorkerState({ ...fallback, pending: true });

    let cancelled = false;
    let worker: Worker;
    try {
      worker = new Worker(new URL("./dagre-layout.worker.ts", import.meta.url), { type: "module" });
    } catch {
      setWorkerState(fallback);
      return;
    }
    const timeout = window.setTimeout(() => {
      if (!cancelled) setWorkerState(fallback);
      worker.terminate();
    }, 15000);
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const response = event.data;
      if (cancelled || response.id !== requestId.current) return;
      window.clearTimeout(timeout);
      if (response.ok) {
        setWorkerState({ nodes: response.nodes, edges: response.edges, pending: false, inputNodes: nodes, inputEdges: edges });
      } else {
        setWorkerState(fallback);
      }
      worker.terminate();
    };
    worker.onerror = () => {
      window.clearTimeout(timeout);
      if (!cancelled && id === requestId.current) {
        setWorkerState(fallback);
      }
      worker.terminate();
    };
    try {
      worker.postMessage({ id, nodes, edges, options: stableOptions });
    } catch {
      window.clearTimeout(timeout);
      setWorkerState(fallback);
      worker.terminate();
    }

    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
      worker.terminate();
    };
  }, [edges, nodes, shouldUseWorker, stableOptions, fallback]);

  if (syncLayout) return syncLayout;
  return workerState?.inputNodes === nodes && workerState.inputEdges === edges
    ? workerState
    : { ...fallback, pending: shouldUseWorker && typeof Worker !== "undefined" };
}
