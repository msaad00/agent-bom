/**
 * The roll-up grid must not build a tower that no canvas can fit.
 *
 * Measured on the demo estate: `/graph` opens on 106 sibling containers, and
 * `buildRollupFlowGraph` laid every one of them out at a fixed 3 columns. That
 * is a 996 x 3994 portrait tower dropped into a ~1322 x 610 landscape canvas,
 * so React Flow's `fitView` — working exactly as designed — resolved to scale
 * **0.16**. At that scale the node labels render around 2.6px and half the
 * nodes still sit below the fold.
 *
 * The controls looked broken too: Fit, Reset and Auto-layout all appeared to be
 * no-ops because each of them re-fits the *same* tower and lands back on 0.16.
 * There was never a bug in the fit handlers; the shape they were fitting was
 * the bug.
 *
 * The column count is now derived from the container count so the grid's own
 * aspect ratio lands near a landscape canvas, which is what a graph canvas
 * actually is. Small graphs are unaffected — they keep at least the original
 * three columns, and they are small enough to hit the zoom ceiling anyway.
 */
import { describe, expect, it } from "vitest";

import type { GraphRollupContainer } from "@/lib/api-types";
import { buildRollupFlowGraph } from "@/lib/graph-rollup-view";

/** The `/graph` canvas measured in the browser at a 1440px-wide viewport. */
const CANVAS_WIDTH = 1322;
const CANVAS_HEIGHT = 610;
/** React Flow's default `fitView` padding, as configured on the page. */
const FIT_PADDING = 0.1;

const NODE_CARD_WIDTH = 300;
const NODE_CARD_HEIGHT = 80;

function containers(count: number): GraphRollupContainer[] {
  return Array.from({ length: count }, (_, index) => ({
    id: `account:acct-${index}`,
    label: `acct-${index}`,
    entity_type: "account",
    severity: "",
    is_container: true,
    has_children: true,
    direct_child_count: 4,
    aggregate: {
      descendant_count: 40,
      by_type: { resource: 40 },
      severity_counts: { high: 7 },
      worst_severity: "high",
      worst_severity_rank: 3,
      internet_exposed: false,
      toxic_combo: false,
      exposed_count: 0,
      toxic_count: 0,
    },
  }));
}

/** The scale `fitView` resolves to for a laid-out graph on the real canvas. */
function fitScale(nodes: { position: { x: number; y: number } }[]): number {
  const xs = nodes.map((n) => n.position.x);
  const ys = nodes.map((n) => n.position.y);
  const width = Math.max(...xs) - Math.min(...xs) + NODE_CARD_WIDTH;
  const height = Math.max(...ys) - Math.min(...ys) + NODE_CARD_HEIGHT;
  return Math.min(
    (CANVAS_WIDTH * (1 - FIT_PADDING)) / width,
    (CANVAS_HEIGHT * (1 - FIT_PADDING)) / height,
  );
}

describe("the roll-up grid is shaped like the canvas it lands on", () => {
  it("opens the demo estate's 106 containers at a legible zoom", () => {
    const { nodes } = buildRollupFlowGraph(containers(106));
    const scale = fitScale(nodes);

    // 0.16 was the measured defect, at ~2.6px labels. A 300x80 card at 0.35 is
    // 105x28 — small, but its label is readable and its severity colour is
    // unmistakable.
    expect(scale).toBeGreaterThan(0.35);
  });

  it("picks the column count that fits best, rather than a fixed one", () => {
    // The real invariant. 106 cards of 300x80 occupy 2.5M px in an 806k px
    // canvas, so ~0.4 is close to the geometric ceiling however they are
    // arranged — the layout's job is to land on that ceiling at every size,
    // which is a property worth asserting where a magic constant is not.
    for (const count of [12, 40, 106, 250]) {
      const chosen = fitScale(buildRollupFlowGraph(containers(count)).nodes);
      const best = Math.max(
        ...Array.from({ length: count }, (_, i) =>
          fitScale(
            buildRollupFlowGraph(containers(count), { columns: i + 1 }).nodes,
          ),
        ),
      );
      expect(chosen).toBeGreaterThan(best * 0.9);
    }
  });

  it("never builds a portrait tower, at any estate size", () => {
    for (const count of [12, 40, 106, 250, 600]) {
      const { nodes } = buildRollupFlowGraph(containers(count));
      const xs = nodes.map((n) => n.position.x);
      const ys = nodes.map((n) => n.position.y);
      const width = Math.max(...xs) - Math.min(...xs) + NODE_CARD_WIDTH;
      const height = Math.max(...ys) - Math.min(...ys) + NODE_CARD_HEIGHT;
      // Wider than tall: the canvas is landscape, so a taller-than-wide layout
      // wastes horizontal room and pays for it in zoom.
      expect(width, `${count} containers`).toBeGreaterThan(height);
    }
  });

  it("leaves a handful of containers laid out across, not stacked down", () => {
    const { nodes } = buildRollupFlowGraph(containers(3));
    expect(new Set(nodes.map((n) => n.position.y)).size).toBe(1);
  });

  it("still honours an explicit column count", () => {
    const { nodes } = buildRollupFlowGraph(containers(9), { columns: 3 });
    expect(new Set(nodes.map((n) => n.position.x)).size).toBe(3);
    expect(new Set(nodes.map((n) => n.position.y)).size).toBe(3);
  });

  it("fills every row it opens", () => {
    // A column count above the container count would leave a single sparse row
    // and reintroduce the wasted-width problem from the other direction.
    const { nodes } = buildRollupFlowGraph(containers(2));
    expect(new Set(nodes.map((n) => n.position.x)).size).toBe(2);
  });
});
