import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import {
  applyGraphPresentation,
  graphNodeSetKey,
  graphNodeStorageKey,
  graphPositions,
  graphPresentationStorageKey,
  graphTopologyKey,
  purgeGraphPresentationsForOwner,
  readGraphPresentation,
  registerGraphPresentationKey,
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
      positions: { [graphNodeStorageKey("resource-private")]: { x: 42, y: 84 } },
      viewport: { x: 1, y: 2, zoom: 1.4 },
      layout: "topology",
      locked: true,
    };

    writeGraphPresentation(adapter, "key", state);

    expect(readGraphPresentation(adapter, "key")).toEqual(state);
    expect(storage.get("key")).not.toContain("resource-private");
    expect(storage.get("key")).not.toContain("data");
  });

  it("applies saved positions without changing node data or graph relationships", () => {
    const presented = applyGraphPresentation(nodes, {
      version: 1,
      positions: {
        [graphNodeStorageKey("a")]: { x: 44, y: 55 },
        [graphNodeStorageKey("missing")]: { x: 1, y: 2 },
      },
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

  it("stores only opaque node keys and invalidates the scope when the node set changes", () => {
    const positions = graphPositions([
      { id: "arn:private:resource", position: { x: 4, y: 8 }, data: { label: "Private resource" } },
    ]);
    expect(JSON.stringify(positions)).not.toContain("arn:private:resource");
    expect(JSON.stringify(positions)).not.toContain("Private resource");
    expect(Object.keys(positions)[0]).toMatch(/^n:[a-f0-9]{16}$/);
    expect(graphNodeSetKey(nodes)).not.toBe(graphNodeSetKey(nodes.slice(0, 2)));
    expect(graphTopologyKey(nodes, edges)).not.toBe(
      graphTopologyKey(nodes, [{ ...edges[0]!, data: { relationship: "changed" } }, edges[1]!]),
    );
  });

  it("tracks and purges every opaque layout key for an owner without storing owner identifiers", () => {
    const storage = new Map<string, string>();
    const adapter = {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => { storage.set(key, value); },
      removeItem: (key: string) => { storage.delete(key); },
    };
    const owner = { tenantId: "tenant-private", subject: "person@example.test" };
    const first = graphPresentationStorageKey({ ...owner, snapshotId: "one", lens: "mesh", scope: "full" });
    const second = graphPresentationStorageKey({ ...owner, snapshotId: "two", lens: "mesh", scope: "full" });
    registerGraphPresentationKey(adapter, owner, first);
    registerGraphPresentationKey(adapter, owner, second);
    adapter.setItem(first, "layout-one");
    adapter.setItem(second, "layout-two");

    expect(JSON.stringify([...storage])).not.toContain(owner.tenantId);
    expect(JSON.stringify([...storage])).not.toContain(owner.subject);
    purgeGraphPresentationsForOwner(adapter, owner.tenantId, owner.subject);
    expect(storage.has(first)).toBe(false);
    expect(storage.has(second)).toBe(false);
    expect(storage.size).toBe(0);
  });

  it("selects a focused subgraph before layout and removes unrelated whitespace", () => {
    const focused = selectGraphSubgraph(nodes, edges, new Set(["a", "b"]));

    expect(focused.nodes.map((node) => node.id)).toEqual(["a", "b"]);
    expect(focused.edges.map((edge) => edge.id)).toEqual(["a-b"]);
  });
});
