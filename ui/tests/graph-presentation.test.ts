import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import {
  applyGraphPresentation,
  graphPresentationStorageKey,
  readGraphPresentation,
  selectGraphSubgraph,
  writeGraphPresentation,
  type GraphPresentationState,
} from "@/lib/graph-presentation";

const nodes: Node[] = [
  { id: "a", position: { x: 0, y: 0 }, data: {} },
  { id: "b", position: { x: 100, y: 0 }, data: {} },
  { id: "c", position: { x: 900, y: 500 }, data: {} },
];
const edges: Edge[] = [
  { id: "a-b", source: "a", target: "b" },
  { id: "b-c", source: "b", target: "c" },
];

describe("graph presentation state", () => {
  it("scopes browser-local state without exposing tenant, subject, or snapshot identifiers", () => {
    const key = graphPresentationStorageKey({
      tenantId: "tenant-private",
      subject: "person@example.test",
      snapshotId: "scan-private",
      lens: "mesh",
      scope: "account",
    });

    expect(key).toMatch(/^agent-bom:graph-presentation:v1:[a-f0-9]{16}$/);
    expect(key).not.toContain("tenant-private");
    expect(key).not.toContain("person@example.test");
    expect(key).not.toContain("scan-private");
  });

  it("round-trips only finite node positions, viewport, layout, and lock state", () => {
    const storage = new Map<string, string>();
    const adapter = {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
      removeItem: (key: string) => storage.delete(key),
    };
    const state: GraphPresentationState = {
      version: 1,
      positions: { a: { x: 42, y: 84 } },
      viewport: { x: 1, y: 2, zoom: 1.4 },
      layout: "topology",
      locked: true,
    };

    writeGraphPresentation(adapter, "key", state);

    expect(readGraphPresentation(adapter, "key")).toEqual(state);
    expect(storage.get("key")).not.toContain("data");
  });

  it("applies saved positions without changing node data or graph relationships", () => {
    const presented = applyGraphPresentation(nodes, {
      version: 1,
      positions: { a: { x: 44, y: 55 }, missing: { x: 1, y: 2 } },
      viewport: { x: 0, y: 0, zoom: 1 },
      layout: "topology",
      locked: false,
    });

    expect(presented.find((node) => node.id === "a")?.position).toEqual({ x: 44, y: 55 });
    expect(presented.find((node) => node.id === "b")?.position).toEqual({ x: 100, y: 0 });
    expect(edges).toEqual([
      { id: "a-b", source: "a", target: "b" },
      { id: "b-c", source: "b", target: "c" },
    ]);
  });

  it("selects a focused subgraph before layout and removes unrelated whitespace", () => {
    const focused = selectGraphSubgraph(nodes, edges, new Set(["a", "b"]));

    expect(focused.nodes.map((node) => node.id)).toEqual(["a", "b"]);
    expect(focused.edges.map((edge) => edge.id)).toEqual(["a-b"]);
  });
});
