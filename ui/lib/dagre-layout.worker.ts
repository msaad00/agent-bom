import { applyDagreLayout, type LayoutOptions } from "./dagre-layout";

import type { Edge, Node } from "@xyflow/react";

type LayoutRequest = {
  id: number;
  nodes: Node[];
  edges: Edge[];
  options: LayoutOptions;
};

type LayoutResponse =
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

self.onmessage = (event: MessageEvent<LayoutRequest>) => {
  const { id, nodes, edges, options } = event.data;
  try {
    const result = applyDagreLayout(nodes, edges, options);
    self.postMessage({ id, ok: true, ...result } satisfies LayoutResponse);
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      error: error instanceof Error ? error.message : "layout failed",
    } satisfies LayoutResponse);
  }
};
