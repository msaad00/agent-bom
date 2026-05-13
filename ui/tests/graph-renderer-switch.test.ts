import { describe, expect, it } from "vitest";

import { decideGraphRenderer } from "@/lib/graph-renderer-switch";
import {
  LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD,
  LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD,
} from "@/lib/large-graph-overview";

describe("graph renderer switch", () => {
  it("keeps focused investigation modes on React Flow", () => {
    const broadGraph = {
      nodeCount: LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD + 10,
      edgeCount: LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD + 10,
    };

    expect(decideGraphRenderer({ ...broadGraph, captureMode: true })).toMatchObject({
      kind: "react-flow",
      reason: "capture-mode",
      supportsInvestigation: true,
    });
    expect(decideGraphRenderer({ ...broadGraph, selectedAttackPath: true })).toMatchObject({
      kind: "react-flow",
      reason: "attack-path-focus",
      supportsInvestigation: true,
    });
    expect(decideGraphRenderer({ ...broadGraph, reachabilityActive: true })).toMatchObject({
      kind: "react-flow",
      reason: "reachability-drill-in",
      supportsInvestigation: true,
    });
    expect(decideGraphRenderer({ ...broadGraph, graphOnlyFindings: true })).toMatchObject({
      kind: "react-flow",
      reason: "findings-only-fallback",
      supportsInvestigation: true,
    });
  });

  it("preserves the existing large graph overview thresholds", () => {
    expect(
      decideGraphRenderer({
        nodeCount: LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD,
        edgeCount: 20,
      }),
    ).toMatchObject({
      kind: "large-overview",
      reason: "large-graph-overview-threshold",
      supportsInvestigation: false,
    });

    expect(
      decideGraphRenderer({
        nodeCount: 20,
        edgeCount: LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD,
      }),
    ).toMatchObject({
      kind: "large-overview",
      reason: "large-graph-overview-threshold",
      supportsInvestigation: false,
    });
  });

  it("keeps WebGL behind an explicit future switch", () => {
    expect(
      decideGraphRenderer({
        nodeCount: LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD + 1,
        edgeCount: LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD + 1,
      }),
    ).toMatchObject({ kind: "large-overview" });

    expect(
      decideGraphRenderer({
        nodeCount: LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD + 1,
        edgeCount: LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD + 1,
        webglEnabled: true,
      }),
    ).toMatchObject({
      kind: "webgl",
      reason: "large-graph-webgl-enabled",
      supportsInvestigation: false,
    });
  });

  it("uses React Flow for normal-sized interactive graphs", () => {
    expect(decideGraphRenderer({ nodeCount: 42, edgeCount: 84 })).toMatchObject({
      kind: "react-flow",
      reason: "focused-interactive-graph",
      interactive: true,
      supportsInvestigation: true,
    });
  });
});
