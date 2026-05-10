export type GraphViewportMode = "lineage" | "mesh" | "context";

export type GraphViewportInput = {
  nodeCount: number;
  edgeCount?: number;
  selectedNode?: boolean;
  mode?: GraphViewportMode;
  captureMode?: boolean;
};

export type GraphFitViewOptions = {
  padding: number;
  maxZoom: number;
  duration: number;
};

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function normalizedCount(value: number | undefined): number {
  return Math.max(0, Math.floor(Number.isFinite(value) ? value ?? 0 : 0));
}

export function graphFitViewOptions(input: GraphViewportInput): GraphFitViewOptions {
  const nodeCount = normalizedCount(input.nodeCount);
  const edgeCount = normalizedCount(input.edgeCount);
  const selectedBoost = input.selectedNode ? 0.1 : 0;

  let padding = 0.16;
  let maxZoom = 1.05;

  if (nodeCount <= 0) {
    padding = 0.18;
    maxZoom = 1;
  } else if (nodeCount <= 6) {
    padding = 0.08;
    maxZoom = 1.72;
  } else if (nodeCount <= 16) {
    padding = 0.1;
    maxZoom = 1.48;
  } else if (nodeCount <= 32) {
    padding = 0.12;
    maxZoom = 1.28;
  } else if (nodeCount <= 80) {
    padding = 0.16;
    maxZoom = 1.08;
  } else {
    padding = 0.2;
    maxZoom = 0.92;
  }

  const density = nodeCount > 0 ? edgeCount / nodeCount : 0;
  if (density > 3.5) {
    maxZoom -= 0.12;
    padding += 0.02;
  }

  if (input.mode === "mesh") {
    maxZoom -= 0.06;
  } else if (input.mode === "context") {
    maxZoom -= 0.04;
  }

  if (input.captureMode) {
    padding -= input.mode === "mesh" ? 0.04 : 0.02;
    maxZoom += input.mode === "mesh" ? 0.18 : 0.1;
  }

  return {
    padding: clamp(padding, 0.08, 0.24),
    maxZoom: clamp(maxZoom + selectedBoost, 0.82, 1.82),
    duration: input.captureMode ? 0 : 240,
  };
}

export function shouldShowGraphMiniMap(input: GraphViewportInput): boolean {
  const nodeCount = normalizedCount(input.nodeCount);
  const edgeCount = normalizedCount(input.edgeCount);
  if (nodeCount <= 0) return false;
  if (input.selectedNode && nodeCount <= 28) return false;
  if (nodeCount <= 18 && edgeCount <= 36) return false;
  return true;
}
