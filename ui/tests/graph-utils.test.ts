import { describe, expect, it } from "vitest";

import { GraphNodeKind, GRAPH_NODE_KIND_META } from "@/lib/graph-schema";
import {
  legendItemForNodeType,
  legendItemsForVisibleNodes,
  minimapNodeColor,
  NODE_COLOR_MAP,
  readableGraphEdges,
} from "@/lib/graph-utils";

describe("graph utility metadata", () => {
  it("uses generated schema metadata for production node legends", () => {
    expect(legendItemForNodeType("vulnerability")).toMatchObject({
      label: GRAPH_NODE_KIND_META[GraphNodeKind.VULNERABILITY].label,
      color: GRAPH_NODE_KIND_META[GraphNodeKind.VULNERABILITY].color,
      layer: GRAPH_NODE_KIND_META[GraphNodeKind.VULNERABILITY].layer,
      kind: "node",
      shape: "diamond",
    });
    expect(legendItemForNodeType("cloudResource")).toMatchObject({
      label: GRAPH_NODE_KIND_META[GraphNodeKind.CLOUD_RESOURCE].label,
      color: GRAPH_NODE_KIND_META[GraphNodeKind.CLOUD_RESOURCE].color,
      layer: GRAPH_NODE_KIND_META[GraphNodeKind.CLOUD_RESOURCE].layer,
      shape: "square",
    });
  });

  it("keeps minimap colors tied to generated node kind colors", () => {
    expect(NODE_COLOR_MAP.agent).toBe(GRAPH_NODE_KIND_META[GraphNodeKind.AGENT].color);
    expect(NODE_COLOR_MAP.serviceAccount).toBe(
      GRAPH_NODE_KIND_META[GraphNodeKind.SERVICE_ACCOUNT].color,
    );
    expect(minimapNodeColor({ data: { nodeType: "package" } })).toBe(
      GRAPH_NODE_KIND_META[GraphNodeKind.PACKAGE].color,
    );
  });

  it("keeps the computed shared-server node as the only non-schema legend item", () => {
    expect(legendItemsForVisibleNodes([{ data: { nodeType: "sharedServer" } }])).toEqual([
      {
        label: "Shared Server",
        color: "#22d3ee",
        layer: GRAPH_NODE_KIND_META[GraphNodeKind.SERVER].layer,
        kind: "node",
        shape: "square",
      },
    ]);
  });

  it("de-emphasizes dense default edges and restores contrast for focused paths", () => {
    const edges = readableGraphEdges([
      {
        id: "a-b",
        source: "a",
        target: "b",
        data: { relationship: "uses" },
        style: { strokeWidth: 3 },
        animated: true,
      },
      {
        id: "b-c",
        source: "b",
        target: "c",
        data: { relationship: "vulnerable_to" },
        style: { strokeWidth: 2 },
      },
    ]);

    expect(edges[0]!.animated).toBe(false);
    expect(edges[0]!.style?.opacity).toBeLessThan(edges[1]!.style?.opacity as number);
    expect(edges[0]!.style?.strokeWidth).toBeLessThanOrEqual(1.5);

    const focused = readableGraphEdges(edges, new Set(["b", "c"]));
    expect(focused[0]!.style?.opacity).toBeLessThan(0.1);
    expect(focused[1]!.style?.opacity).toBeGreaterThan(0.9);
    expect(focused[1]!.style?.strokeWidth).toBeGreaterThanOrEqual(2.6);
  });
});
