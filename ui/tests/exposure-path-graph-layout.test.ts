import { describe, expect, it } from "vitest";

import type { ExposureEntityRef, ExposurePath } from "@/lib/exposure-path";
import {
  MAX_NODE_HEIGHT,
  MAX_NODE_WIDTH,
  MIN_NODE_HEIGHT,
  MIN_NODE_WIDTH,
  buildPathGraphLayout,
  labelCharsForWidth,
  nodeSizeForCount,
} from "@/lib/exposure-path-graph-layout";

function makePath(nodeCount: number): ExposurePath {
  const hops: ExposureEntityRef[] = Array.from({ length: nodeCount }, (_, index) => ({
    id: `node:${index}`,
    label: `entity-with-a-fairly-long-name-${index}`,
    role: index === 0 ? "agent" : "package",
  }));
  return {
    id: "path-test",
    label: hops.map((hop) => hop.label).join(" -> "),
    summary: "",
    riskScore: 5,
    severity: "high",
    source: hops[0]!,
    target: hops[hops.length - 1]!,
    hops,
    relationships: [],
    nodeIds: hops.map((hop) => hop.id),
    edgeIds: [],
    findings: [],
    affectedAgents: [],
    affectedServers: [],
    reachableTools: [],
    exposedCredentials: [],
  };
}

describe("nodeSizeForCount", () => {
  it("renders few-node paths at full design size and never larger", () => {
    for (const count of [1, 2, 3]) {
      const size = nodeSizeForCount(count);
      expect(size.width).toBe(MAX_NODE_WIDTH);
      expect(size.height).toBe(MAX_NODE_HEIGHT);
    }
  });

  it("shrinks node size monotonically as the path grows, down to a readable floor", () => {
    const sizes = [2, 4, 6, 8, 10, 20].map((count) => nodeSizeForCount(count).width);
    for (let i = 1; i < sizes.length; i += 1) {
      expect(sizes[i]!).toBeLessThanOrEqual(sizes[i - 1]!);
    }
    const dense = nodeSizeForCount(20);
    expect(dense.width).toBeGreaterThanOrEqual(MIN_NODE_WIDTH);
    expect(dense.height).toBeGreaterThanOrEqual(MIN_NODE_HEIGHT);
    // A large path must be strictly smaller than a tiny one.
    expect(dense.width).toBeLessThan(MAX_NODE_WIDTH);
  });
});

describe("labelCharsForWidth", () => {
  it("keeps a readable minimum of characters even at the smallest node", () => {
    expect(labelCharsForWidth(MIN_NODE_WIDTH)).toBeGreaterThanOrEqual(12);
    expect(labelCharsForWidth(MAX_NODE_WIDTH)).toBeGreaterThan(labelCharsForWidth(MIN_NODE_WIDTH) - 1);
  });
});

describe("buildPathGraphLayout auto-fit", () => {
  it("frames a 2-node path compactly so nodes cannot fill the whole canvas", () => {
    const layout = buildPathGraphLayout(makePath(2));
    // Single row: viewBox height is just one node band plus margins.
    expect(layout.height).toBeLessThan(layout.nodeHeight * 2);
    // The board is capped at its natural width so it renders 1:1, not stretched.
    expect(layout.fitWidth).toBe(layout.width);
    // Each node is a minority of the board width — never half-a-canvas boxes.
    expect(layout.nodeWidth / layout.width).toBeLessThan(0.4);
  });

  it("tightly bounds every node inside the viewBox with no overflow", () => {
    for (const count of [1, 2, 3, 6, 10]) {
      const layout = buildPathGraphLayout(makePath(count));
      for (const node of layout.nodes) {
        expect(node.x).toBeGreaterThanOrEqual(0);
        expect(node.y).toBeGreaterThanOrEqual(0);
        expect(node.x + layout.nodeWidth).toBeLessThanOrEqual(layout.width);
        expect(node.y + layout.nodeHeight).toBeLessThanOrEqual(layout.height);
      }
      expect(layout.nodes).toHaveLength(count);
    }
  });

  it("wraps a 10-node path into rows that fit instead of one giant row", () => {
    const layout = buildPathGraphLayout(makePath(10));
    // At most 4 columns, so the board never grows unbounded horizontally.
    const distinctX = new Set(layout.nodes.map((node) => Math.round(node.x)));
    expect(distinctX.size).toBeLessThanOrEqual(4);
    // Multiple rows means it grew vertically to fit, not off the right edge.
    const distinctY = new Set(layout.nodes.map((node) => Math.round(node.y)));
    expect(distinctY.size).toBeGreaterThan(1);
    // Dense path uses smaller nodes than a 2-node path.
    expect(layout.nodeWidth).toBeLessThan(buildPathGraphLayout(makePath(2)).nodeWidth);
  });

  it("produces one edge per hop transition", () => {
    const layout = buildPathGraphLayout(makePath(5));
    expect(layout.edges).toHaveLength(4);
    expect(layout.relationshipLabels).toHaveLength(4);
  });
});
