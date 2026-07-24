import { describe, expect, it } from "vitest";

import type { ExposureEntityRef, ExposurePath } from "@/lib/exposure-path";
import {
  COLLAPSED_HOPS_NODE_ID,
  FIT_REFERENCE_WIDTH,
  MAX_NODE_HEIGHT,
  MAX_NODE_WIDTH,
  MAX_READABLE_BOARD_WIDTH,
  MIN_NODE_HEIGHT,
  MIN_NODE_WIDTH,
  MIN_READABLE_SCALE,
  buildPathGraphLayout,
  labelCharsForWidth,
  naturalBoardWidth,
  nodeSizeForCount,
  shouldCollapsePath,
  summarizeHiddenHops,
  wrapGraphText,
} from "@/lib/exposure-path-graph-layout";

function makePath(nodeCount: number): ExposurePath {
  const hops: ExposureEntityRef[] = Array.from({ length: nodeCount }, (_, index) => ({
    id: `node:${index}`,
    label: `entity-with-a-fairly-long-name-${index}`,
    role: index === 0 ? "agent" : "package",
  }));
  return makePathFromHops(hops);
}

/**
 * Shape of the highest-ranked demo exposure path once the graph carries tool and
 * credential hops: agent -> server -> package -> finding -> 3 tools -> 3
 * credentials. 11 hops is the widest board the product has to frame.
 */
function makeElevenHopPath(): ExposurePath {
  return makePathFromHops([
    { id: "agent:cursor", label: "Cursor IDE Agent", role: "agent" },
    { id: "server:shell-runner", label: "shell-runner-server", role: "server" },
    { id: "pkg:pyyaml", label: "pyyaml@5.3", role: "package" },
    { id: "vuln:CVE-2020-14343", label: "CVE-2020-14343", role: "finding" },
    { id: "tool:run_shell", label: "run_shell", role: "tool" },
    { id: "tool:exec_command", label: "exec_command", role: "tool" },
    { id: "tool:read_file", label: "read_file", role: "tool" },
    { id: "cred:SNOWFLAKE_PASSWORD", label: "SNOWFLAKE_PASSWORD", role: "credential" },
    { id: "cred:DATABASE_URL", label: "DATABASE_URL", role: "credential" },
    { id: "cred:AWS_SECRET_ACCESS_KEY", label: "AWS_SECRET_ACCESS_KEY", role: "credential" },
    { id: "store:warehouse", label: "prod-warehouse", role: "environment" },
  ]);
}

function makePathFromHops(hops: ExposureEntityRef[]): ExposurePath {
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

describe("wrapGraphText", () => {
  it("does not split a readable entity name when a word boundary is available", () => {
    expect(wrapGraphText("Github Enterprise MCP service", 16, 2)).toEqual([
      "Github",
      "Enterprise MCP…",
    ]);
  });

  it("does not create a one-character line from an early identifier separator", () => {
    const lines = wrapGraphText("a/very-long-identifier", 16, 2);
    expect(lines[0]!.length).toBeGreaterThanOrEqual(5);
    expect(lines.join("")).toContain("a/very-long");
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
      const layout = buildPathGraphLayout(makePath(count), { expanded: true });
      for (const node of layout.nodes) {
        expect(node.x).toBeGreaterThanOrEqual(0);
        expect(node.y).toBeGreaterThanOrEqual(0);
        expect(node.x + layout.nodeWidth).toBeLessThanOrEqual(layout.width);
        expect(node.y + layout.nodeHeight).toBeLessThanOrEqual(layout.height);
      }
      expect(layout.nodes).toHaveLength(count);
    }
  });

  it("keeps a long path on one left-to-right row so edges never orphan", () => {
    // 7 hops is the demo critical-path shape. A prior 4-column wrap put the
    // finding on a second row with a vertical connector that read as broken.
    const layout = buildPathGraphLayout(makePath(7), { expanded: true });
    expect(layout.nodes).toHaveLength(7);
    const distinctY = new Set(layout.nodes.map((node) => Math.round(node.y)));
    expect(distinctY.size).toBe(1);
    for (let i = 1; i < layout.nodes.length; i += 1) {
      expect(layout.nodes[i]!.x).toBeGreaterThan(layout.nodes[i - 1]!.x);
    }
    // Finding (last hop) is the rightmost node on the single row.
    expect(layout.nodes[6]!.x).toBeGreaterThan(layout.nodes[0]!.x);
    expect(layout.edges).toHaveLength(6);
    // Same-row cubics only — no vertical wrap connector between hops.
    for (const edge of layout.edges) {
      expect(edge.path.split(" ").length).toBeGreaterThan(8);
      expect(edge.path).toContain(" C ");
    }
  });

  it("grows horizontally for dense paths instead of wrapping into rows", () => {
    const layout = buildPathGraphLayout(makePath(10), { expanded: true });
    const distinctY = new Set(layout.nodes.map((node) => Math.round(node.y)));
    expect(distinctY.size).toBe(1);
    expect(layout.width).toBeGreaterThan(buildPathGraphLayout(makePath(2)).width);
    // Dense path uses smaller nodes than a 2-node path.
    expect(layout.nodeWidth).toBeLessThan(buildPathGraphLayout(makePath(2)).nodeWidth);
  });

  it("produces one edge per hop transition", () => {
    const layout = buildPathGraphLayout(makePath(5), { expanded: true });
    expect(layout.edges).toHaveLength(4);
    expect(layout.relationshipLabels).toHaveLength(4);
  });
});

describe("board fit budget", () => {
  it("derives the readable board budget from the shell width and the text floor", () => {
    // 1400px shell cap - lg:px-8 (64) - card padding (44) - board insets (24).
    expect(FIT_REFERENCE_WIDTH).toBe(1268);
    // 11px relationship label must not scale below the 10px design-system floor.
    expect(MIN_READABLE_SCALE).toBeCloseTo(0.9, 5);
    expect(MAX_READABLE_BOARD_WIDTH).toBe(Math.floor(FIT_REFERENCE_WIDTH / MIN_READABLE_SCALE));
  });

  it("reports the natural board width the current node metrics produce", () => {
    // Regression anchors measured from MAX/MIN_NODE_WIDTH + COLUMN_GAP + MARGIN_X.
    expect(naturalBoardWidth(2)).toBe(564);
    expect(naturalBoardWidth(3)).toBe(884);
    expect(naturalBoardWidth(4)).toBe(1176);
    expect(naturalBoardWidth(5)).toBe(1459);
    expect(naturalBoardWidth(9)).toBe(2444);
    expect(naturalBoardWidth(11)).toBe(3004);
  });

  it("collapses only the chains that cannot fit at a readable scale", () => {
    // 4 hops (1176px) still fits 1268px at 1x — the demo hero keeps every hop.
    expect(shouldCollapsePath(4)).toBe(false);
    for (const count of [1, 2, 3, 4]) {
      expect(naturalBoardWidth(count)).toBeLessThanOrEqual(MAX_READABLE_BOARD_WIDTH);
      expect(shouldCollapsePath(count)).toBe(false);
    }
    // 5+ hops would need a sub-0.9 scale, so the middle collapses instead.
    for (const count of [5, 7, 9, 11, 20]) {
      expect(naturalBoardWidth(count)).toBeGreaterThan(MAX_READABLE_BOARD_WIDTH);
      expect(shouldCollapsePath(count)).toBe(true);
    }
  });
});

describe("summarizeHiddenHops", () => {
  it("names the security-significant kinds first", () => {
    const summary = summarizeHiddenHops([
      { id: "pkg:a", label: "a", role: "package" },
      { id: "tool:a", label: "a", role: "tool" },
      { id: "tool:b", label: "b", role: "tool" },
      { id: "cred:a", label: "a", role: "credential" },
    ]);
    expect(summary).toBe("1 credential · 2 tools");
  });

  it("returns an empty summary when nothing is hidden", () => {
    expect(summarizeHiddenHops([])).toBe("");
  });
});

describe("collapsed exposure-path board", () => {
  it("fits the 11-hop demo shape in the first frame without horizontal scroll", () => {
    const layout = buildPathGraphLayout(makeElevenHopPath());

    expect(layout.collapsed).toBe(true);
    expect(layout.totalHopCount).toBe(11);
    // Pinned entry hop, one summary node, pinned crown-jewel hop.
    expect(layout.nodes).toHaveLength(3);
    expect(layout.nodes[0]!.id).toBe("agent:cursor");
    expect(layout.nodes[2]!.id).toBe("store:warehouse");
    // Fits the reference board at 1x — no scaling, no clipping, no scroll.
    expect(layout.width).toBe(884);
    expect(layout.fitWidth).toBe(layout.width);
    expect(layout.width).toBeLessThanOrEqual(FIT_REFERENCE_WIDTH);
  });

  it("names the hidden tool and credential hops on the summary node", () => {
    const layout = buildPathGraphLayout(makeElevenHopPath());
    const summaryNode = layout.nodes[1]!;

    expect(summaryNode.id).toBe(COLLAPSED_HOPS_NODE_ID);
    expect(layout.hiddenHopCount).toBe(9);
    expect(summaryNode.label).toBe("+9 hops hidden");
    // The security payoff must be named, not silently scrolled off-screen.
    expect(layout.hiddenHopSummary).toBe("3 credentials · 3 tools");
    expect(summaryNode.subtitle).toBe(layout.hiddenHopSummary);
  });

  it("restores every hop when expanded", () => {
    const layout = buildPathGraphLayout(makeElevenHopPath(), { expanded: true });

    expect(layout.collapsed).toBe(false);
    expect(layout.hiddenHopCount).toBe(0);
    expect(layout.hiddenHopSummary).toBe("");
    expect(layout.nodes).toHaveLength(11);
    expect(layout.nodes.map((node) => node.id)).toContain("tool:run_shell");
    expect(layout.nodes.map((node) => node.id)).toContain("cred:AWS_SECRET_ACCESS_KEY");
    expect(layout.width).toBe(3004);
  });

  it("keeps every hop for a path that already fits", () => {
    const layout = buildPathGraphLayout(makePath(4));

    expect(layout.collapsed).toBe(false);
    expect(layout.nodes).toHaveLength(4);
    expect(layout.nodes.every((node) => node.id !== COLLAPSED_HOPS_NODE_ID)).toBe(true);
    expect(layout.width).toBe(1176);
  });
});
