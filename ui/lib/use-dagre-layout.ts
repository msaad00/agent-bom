"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { type Edge, type Node } from "@xyflow/react";

import { applyDagreLayout, type LayoutOptions } from "@/lib/dagre-layout";

type LayoutState = {
  nodes: Node[];
  edges: Edge[];
  pending: boolean;
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

  useEffect(() => {
    if (nodes.length === 0 || !shouldUseWorker || typeof Worker === "undefined") {
      setWorkerState(null);
      return;
    }

    const id = requestId.current + 1;
    requestId.current = id;
    setWorkerState({ nodes, edges, pending: true });

    const worker = new Worker(new URL("./dagre-layout.worker.ts", import.meta.url), { type: "module" });
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const response = event.data;
      if (response.id !== requestId.current) return;
      if (response.ok) {
        setWorkerState({ nodes: response.nodes, edges: response.edges, pending: false });
      } else {
        setWorkerState({ nodes, edges, pending: false });
      }
      worker.terminate();
    };
    worker.onerror = () => {
      if (id === requestId.current) {
        setWorkerState({ nodes, edges, pending: false });
      }
      worker.terminate();
    };
    worker.postMessage({ id, nodes, edges, options: stableOptions });

    return () => {
      worker.terminate();
    };
  }, [edges, nodes, shouldUseWorker, stableOptions]);

  if (syncLayout) return syncLayout;
  return workerState ?? { nodes, edges, pending: shouldUseWorker };
}
