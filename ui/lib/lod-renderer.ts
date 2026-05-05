/**
 * Levels-of-detail rendering for the unified graph (#2257).
 *
 * The 244-node self-scan graph collapses to a wall of unreadable rows when
 * fit-to-viewport. Three deterministic, zoom-driven bands swap node renderers
 * so the canvas always shows information at the resolution the operator can
 * actually parse:
 *
 *   - cluster  (zoom < 0.4):     one bubble per agent / cluster pill only.
 *   - summary  (0.4 <= zoom < 1): individual nodes with badges (CVE count,
 *                                  severity max).
 *   - detail   (zoom >= 1):       full node detail (icons, labels, scope chips).
 *
 * Wiring: every consumer pulls the band via `useLodBand()`; the /graph page
 * swaps its `nodeTypes` map against the value returned here. Threshold
 * constants are exported so tests can pin behaviour to specific zoom values.
 */

import { useStore } from "@xyflow/react";

export type LodBand = "cluster" | "summary" | "detail";

/** Zoom thresholds — swap to a finer-grained renderer as the operator zooms in. */
export const LOD_CLUSTER_MAX_ZOOM = 0.4;
export const LOD_SUMMARY_MAX_ZOOM = 1.0;
export const LOD_CLUSTER_MIN_COLLAPSED_SHARE = 0.25;

/**
 * Pure resolver: zoom -> band. Exported separately from the hook so logic
 * tests can call it without standing up an xyflow provider.
 */
export function lodBandForZoom(zoom: number): LodBand {
  if (!Number.isFinite(zoom) || zoom < LOD_CLUSTER_MAX_ZOOM) return "cluster";
  if (zoom < LOD_SUMMARY_MAX_ZOOM) return "summary";
  return "detail";
}

export interface LodGraphShape {
  sourceNodeCount: number;
  renderedNodeCount: number;
  clusterCount: number;
}

/**
 * Low-zoom bubbles are only useful when sibling aggregation has materially
 * compressed the graph. Otherwise the canvas becomes a field of unlabeled
 * dots, so keep the labeled summary renderer even below the cluster zoom.
 */
export function effectiveLodBandForGraph(band: LodBand, shape: LodGraphShape): LodBand {
  if (band !== "cluster") return band;

  const sourceNodeCount = Math.max(0, shape.sourceNodeCount);
  const renderedNodeCount = Math.max(0, shape.renderedNodeCount);
  if (shape.clusterCount <= 0 || sourceNodeCount <= 0 || renderedNodeCount >= sourceNodeCount) {
    return "summary";
  }

  const collapsedShare = (sourceNodeCount - renderedNodeCount) / sourceNodeCount;
  return collapsedShare >= LOD_CLUSTER_MIN_COLLAPSED_SHARE ? "cluster" : "summary";
}

/**
 * React hook — reads `viewport.zoom` from the xyflow store on every change
 * and returns the corresponding band. Must be called inside a
 * `<ReactFlowProvider>` / `<ReactFlow>` subtree.
 */
export function useLodBand(): LodBand {
  // xyflow internal store shape: `transform: [tx, ty, zoom]`.
  const zoom = useStore((s: { transform: [number, number, number] }) => s.transform[2]);
  return lodBandForZoom(zoom);
}
