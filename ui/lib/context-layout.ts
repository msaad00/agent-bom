import { type Edge, type Node } from "@xyflow/react";
import { applyDagreLayout, type LayoutOptions } from "@/lib/dagre-layout";

export type ContextLayoutMode = "auto" | "horizontal" | "vertical";
export type ContextDirection = "LR" | "TB";
export interface CanvasSize { width: number; height: number }

export function contextLayoutOptions(focused: boolean, direction: ContextDirection): LayoutOptions {
  const width = focused ? 260 : 208;
  const height = focused ? 130 : 80;
  const gap = !focused && direction === "LR" ? 8 : 16;
  return { direction, nodeWidth: width, nodeHeight: height, rankSep: 40, nodeSep: gap,
    minSeparation: { width, height, gap } };
}

/** Score actual layout bounds at readable card scale, on the usable canvas. */
export function contextFitScore(nodes: Node[], canvas: CanvasSize, focused: boolean): number {
  if (!nodes.length || canvas.width <= 0 || canvas.height <= 0) return 0;
  const width = focused ? 260 : 208, height = focused ? 130 : 80;
  const xs = nodes.map(node => node.position.x), ys = nodes.map(node => node.position.y);
  const boundsWidth = Math.max(...xs) - Math.min(...xs) + width;
  const boundsHeight = Math.max(...ys) - Math.min(...ys) + height;
  // Match the fitView breathing room. Enlarging already readable cards buys
  // no readability. Below 0.75, the canvas permits panning at readable scale.
  return Math.min(1, canvas.width * 0.88 / boundsWidth, canvas.height * 0.88 / boundsHeight);
}

export function chooseContextDirection(horizontalScore: number, verticalScore: number, previous?: ContextDirection): ContextDirection {
  if (previous === "LR" && verticalScore < horizontalScore * 1.15) return previous;
  if (previous === "TB" && horizontalScore < verticalScore * 1.15) return previous;
  return horizontalScore > verticalScore ? "LR" : "TB";
}

/** Called only for the bounded neighborhood (at most 24 nodes / 36 edges). */
export function contextLayoutCandidates(nodes: Node[], edges: Edge[], focused: boolean) {
  return {
    LR: applyDagreLayout(nodes, edges, contextLayoutOptions(focused, "LR")),
    TB: applyDagreLayout(nodes, edges, contextLayoutOptions(focused, "TB")),
  };
}
