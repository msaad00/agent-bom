import { describe, expect, it } from "vitest";

import { GraphNodeKind, GRAPH_NODE_KIND_META } from "@/lib/graph-schema";
import {
  legendItemForNodeType,
  legendItemsForVisibleNodes,
  minimapNodeColor,
  NODE_COLOR_MAP,
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
});
