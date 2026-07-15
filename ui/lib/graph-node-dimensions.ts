/**
 * Shared footprint for the lineage node cards rendered across every React Flow
 * graph surface (unified graph, Agent Mesh, context lineage).
 *
 * The cards are `min-w-[208px] max-w-[300px]` with `border-2 px-4 py-3` and a
 * variable-height body (header + optional subtitle + optional footer rows). To
 * guarantee the auto-layout never lets two cards touch — the top dogfooding
 * complaint, visible even on a 4-node chain — dagre must be told a box that is
 * at least as large as the *widest / tallest* card it will ever draw. Declaring
 * the worst-case footprint means every real card, being equal or smaller, keeps
 * at least the configured rank/node separation of clear space around it.
 */

import type { DagreLrOptions } from "@/lib/use-dagre-lr";
import type { MinSeparationOptions } from "@/lib/dagre-layout";

/** Worst-case rendered width of a lineage card (max-w-[300px] + border). */
export const LINEAGE_NODE_WIDTH = 300;
/** Worst-case rendered height of a lineage card (tall CVE card + border). */
export const LINEAGE_NODE_HEIGHT = 140;
/** Minimum clear gap enforced between any two lineage cards, at any scale. */
export const GRAPH_NODE_MIN_GAP = 48;

/** Collision footprint shared by the layout and the separation guarantee. */
export const LINEAGE_MIN_SEPARATION: MinSeparationOptions = {
  width: LINEAGE_NODE_WIDTH,
  height: LINEAGE_NODE_HEIGHT,
  gap: GRAPH_NODE_MIN_GAP,
};

/**
 * Canonical left-to-right dagre options for lineage graphs: a box that matches
 * the real card footprint, generous rank/node separation for breathing room,
 * and the min-separation guarantee wired in. Rank separation reads as the
 * blast-radius flow direction (agent → server → package → finding); node
 * separation keeps stacked siblings clearly apart.
 */
export const READABLE_LINEAGE_DAGRE_LR: DagreLrOptions = {
  nodeWidth: LINEAGE_NODE_WIDTH,
  nodeHeight: LINEAGE_NODE_HEIGHT,
  rankSep: 176,
  nodeSep: 56,
  minSeparation: LINEAGE_MIN_SEPARATION,
};

/**
 * Merge caller overrides onto the readable defaults while always preserving the
 * separation guarantee. Callers can tighten/loosen rank + node separation (e.g.
 * a focused single-agent view) without ever reintroducing overlapping cards.
 */
export function readableLineageDagreLr(
  overrides: Partial<DagreLrOptions> = {},
): DagreLrOptions {
  return {
    ...READABLE_LINEAGE_DAGRE_LR,
    ...overrides,
    minSeparation: overrides.minSeparation ?? LINEAGE_MIN_SEPARATION,
  };
}
