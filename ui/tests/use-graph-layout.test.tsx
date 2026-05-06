import { renderHook } from "@testing-library/react";
import { Position, type Edge, type Node } from "@xyflow/react";
import { describe, expect, it } from "vitest";

import { GraphLayout } from "@/lib/graph-schema";
import { resolveGraphLayoutKind, useGraphLayout } from "@/lib/use-graph-layout";

const nodes: Node[] = [
  {
    id: "agent:a",
    position: { x: 0, y: 0 },
    data: { entityType: "agent" },
  },
  {
    id: "server:b",
    position: { x: 0, y: 0 },
    data: { entityType: "server" },
  },
  {
    id: "package:c",
    position: { x: 0, y: 0 },
    data: { entityType: "package" },
  },
];

const edges: Edge[] = [
  { id: "a-b", source: "agent:a", target: "server:b" },
  { id: "b-c", source: "server:b", target: "package:c" },
];

describe("graph layout dispatcher", () => {
  it("resolves GraphLayout values and UI aliases to concrete layout hooks", () => {
    expect(resolveGraphLayoutKind(GraphLayout.FORCE)).toBe("force");
    expect(resolveGraphLayoutKind(GraphLayout.RADIAL)).toBe("radial");
    expect(resolveGraphLayoutKind(GraphLayout.DAGRE)).toBe("dagre");
    expect(resolveGraphLayoutKind(GraphLayout.HIERARCHICAL)).toBe("dagre");
    expect(resolveGraphLayoutKind("dagre-lr")).toBe("dagre-lr");
    expect(resolveGraphLayoutKind("topology")).toBe("dagre");
    expect(resolveGraphLayoutKind("spawn-tree")).toBe("dagre");
    expect(resolveGraphLayoutKind(GraphLayout.SANKEY)).toBe("sankey");
  });

  it("selects radial layout and forwards radial options", () => {
    const { result } = renderHook(() =>
      useGraphLayout("radial", nodes, edges, {
        radial: {
          baseRadius: 111,
          ringSpacing: 222,
        },
      }),
    );

    expect(result.current.kind).toBe("radial");
    expect(result.current.pending).toBe(false);
    expect(result.current.nodes.find((node) => node.id === "agent:a")?.position).toEqual({
      x: 0,
      y: 0,
    });
    const serverPosition = result.current.nodes.find((node) => node.id === "server:b")!.position;
    expect(Math.round(Math.hypot(serverPosition.x, serverPosition.y))).toBe(111);
    expect(result.current.edges).toBe(edges);
  });

  it("maps mesh topology aliases to the existing Dagre directions", () => {
    const { result: topology } = renderHook(() =>
      useGraphLayout("topology", nodes, edges, {
        dagre: {
          nodeWidth: 100,
          nodeHeight: 50,
          rankSep: 100,
          nodeSep: 20,
        },
      }),
    );
    const { result: spawnTree } = renderHook(() =>
      useGraphLayout("spawn-tree", nodes, edges, {
        dagre: {
          nodeWidth: 100,
          nodeHeight: 50,
          rankSep: 100,
          nodeSep: 20,
        },
      }),
    );

    expect(topology.current.kind).toBe("dagre");
    expect(topology.current.nodes[0]!.sourcePosition).toBe(Position.Right);
    expect(topology.current.nodes[0]!.targetPosition).toBe(Position.Left);
    expect(spawnTree.current.kind).toBe("dagre");
    expect(spawnTree.current.nodes[0]!.sourcePosition).toBe(Position.Bottom);
    expect(spawnTree.current.nodes[0]!.targetPosition).toBe(Position.Top);
  });

  it("selects sankey layout and forwards sankey spacing options", () => {
    const { result } = renderHook(() =>
      useGraphLayout("sankey", nodes, edges, {
        sankey: {
          nodeWidth: 80,
          columnGap: 20,
          nodeHeight: 40,
          rowGap: 10,
        },
      }),
    );

    expect(result.current.kind).toBe("sankey");
    expect(result.current.nodes.map((node) => node.position.x)).toEqual([0, 100, 200]);
  });
});
