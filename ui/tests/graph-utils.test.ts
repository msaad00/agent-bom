import { describe, expect, it } from "vitest";

import { GraphNodeKind, GRAPH_NODE_KIND_META } from "@/lib/graph-schema";
import {
  countVisiblePathHops,
  legendItemForNodeType,
  legendItemsForVisibleNodes,
  legendItemsForVisibleGraph,
  minimapNodeColor,
  NODE_COLOR_MAP,
  relationshipEdgeLabelPresentation,
  relationshipLegendItem,
  readableGraphEdges,
} from "@/lib/graph-utils";

it("distinguishes evidence hops from hops visible in the active graph scope", () => {
  const hops = ["identity", "role", "agent", "server", "package", "finding"];
  expect(countVisiblePathHops(hops, hops)).toBe(5);
  expect(countVisiblePathHops(hops, ["agent", "server", "package", "finding"])).toBe(3);
  expect(countVisiblePathHops(hops, ["identity", "agent", "finding"])).toBe(0);
});

it("keeps relationship labels screen-readable across zoom levels", () => {
  const distant = relationshipEdgeLabelPresentation({ zoom: 0.4 });
  const close = relationshipEdgeLabelPresentation({ zoom: 1.6 });
  expect(Number(distant.labelStyle?.fontSize)).toBeGreaterThan(Number(close.labelStyle?.fontSize));
});

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
        nodeType: "sharedServer",
      },
    ]);
  });

  it("surfaces identity, data-store, and governance relationship legend metadata", () => {
    expect(legendItemForNodeType("managedIdentity")).toMatchObject({
      label: "Managed Identity",
      kind: "node",
    });
    expect(legendItemForNodeType("dataStore")).toMatchObject({
      label: "Data Store",
      kind: "node",
    });
    expect(relationshipLegendItem("has_permission")).toMatchObject({
      label: "Has Permission",
      kind: "edge",
      lineStyle: "dashed",
      layer: "identity",
    });
    expect(
      legendItemsForVisibleGraph(
        [{ data: { nodeType: "managedIdentity" } }, { data: { nodeType: "dataStore" } }],
        [{ data: { relationship: "has_permission" } }],
      ).map((item) => item.label),
    ).toEqual(["Data Store", "Managed Identity", "Has Permission"]);
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

    const focused = readableGraphEdges(edges, new Set(["b", "c"]), {
      nodeLabels: new Map([["b", "Package"], ["c", "CVE-2026-0001"]]),
    });
    expect(focused[0]!.style?.opacity).toBeLessThan(0.1);
    expect(focused[1]!.style?.opacity).toBeGreaterThan(0.9);
    expect(focused[1]!.style?.strokeWidth).toBeGreaterThanOrEqual(2.6);
    expect(focused[1]!.label).toBe("Has CVE");
    expect(focused[1]!.labelStyle).toMatchObject({ fontSize: 12 });
    expect(focused[1]!.ariaLabel).toMatch(/relationship from Package to CVE-2026-0001/i);
    expect(focused[1]!.ariaLabel).not.toMatch(/\bb\b|\bc\b/);
  });

  it("never exposes shared resource identifiers in labels or edge accessibility text", () => {
    const [edge] = readableGraphEdges(
      [{
        id: "private-source/private-target",
        source: "private-source",
        target: "private-target",
        data: { relationship: "shares_server", server: "arn:aws:private:server" },
      }],
      new Set(["private-source", "private-target"]),
      { nodeLabels: new Map([["private-source", "Agent"], ["private-target", "Server"]]) },
    );

    expect(edge?.label).toBe("Shares Server");
    expect(edge?.ariaLabel).toBe("Shares Server relationship from Agent to Server");
    expect(String(edge?.label)).not.toContain("arn:aws:private:server");
    expect(edge?.ariaLabel).not.toContain("arn:aws:private:server");
    expect(edge?.ariaLabel).not.toContain("private-");
  });

  it("uses generic ARIA endpoints when display labels are unavailable", () => {
    const [edge] = readableGraphEdges([{
      id: "edge-private",
      source: "arn:aws:private:source",
      target: "arn:aws:private:target",
      data: { relationship: "uses" },
    }]);
    expect(edge?.ariaLabel).toBe("Uses relationship from source node to target node");
    expect(edge?.ariaLabel).not.toContain("arn:aws");
  });

  it("uses a stable non-animated edge profile for capture mode", () => {
    const captured = readableGraphEdges(
      [
        {
          id: "a-b",
          source: "a",
          target: "b",
          data: { relationship: "uses" },
          animated: true,
          style: { strokeWidth: 1 },
        },
        {
          id: "b-c",
          source: "b",
          target: "c",
          data: { relationship: "vulnerable_to" },
          animated: true,
          style: { strokeWidth: 1 },
        },
      ],
      new Set(["b"]),
      { inactiveOpacity: 0.04, captureMode: true },
    );

    expect(captured.every((edge) => edge.animated === false)).toBe(true);
    expect(captured[0]!.style?.opacity).toBeGreaterThanOrEqual(0.18);
    expect(captured[1]!.style?.opacity).toBeGreaterThanOrEqual(0.18);
    expect(captured[1]!.style?.strokeWidth).toBeGreaterThanOrEqual(1.25);
  });
});

describe("readableGraphEdges label density", () => {
  const denseEdges = Array.from({ length: 200 }, (_, index) => ({
    id: `e${index}`,
    source: `n${index}`,
    target: `n${index + 1}`,
    data: { relationship: "exposes_cred" },
  }));

  it("labels high-signal edges when the graph is small enough to read", () => {
    const labelled = readableGraphEdges(denseEdges.slice(0, 3), null, {
      maxLabeledEdges: 60,
    });
    expect(labelled.every((edge) => Boolean(edge.label))).toBe(true);
  });

  it("drops labels past the density budget but keeps them on the focused path", () => {
    // At estate scale every high-signal edge carrying a label turns the canvas
    // into overlapping text. Past the budget only the selection stays labelled.
    const focus = new Set(["n0", "n1"]);
    const labelled = readableGraphEdges(denseEdges, focus, {
      maxLabeledEdges: 60,
    });

    const focused = labelled.find((edge) => edge.id === "e0");
    expect(focused?.label).toBeTruthy();

    const offPath = labelled.filter((edge) => edge.id !== "e0");
    expect(offPath.every((edge) => edge.label === undefined)).toBe(true);
  });
});
