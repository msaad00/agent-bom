import { act, renderHook } from "@testing-library/react";
import type { Node } from "@xyflow/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useGraphPresentation } from "@/hooks/use-graph-presentation";
import {
  graphPresentationStorageKey,
  readGraphPresentation,
  writeGraphPresentation,
  type GraphPresentationScope,
} from "@/lib/graph-presentation";

const scope: GraphPresentationScope = {
  tenantId: "tenant-test",
  subject: "viewer-test",
  snapshotId: "snapshot-test",
  lens: "lineage",
  scope: "repository",
};

const nodes: Node[] = [
  { id: "package:a", position: { x: 0, y: 0 }, data: { label: "Package A" } },
];

describe("useGraphPresentation", () => {
  beforeEach(() => window.localStorage.clear());

  it("restores a compatible personal viewport and node layout", () => {
    writeGraphPresentation(
      window.localStorage,
      graphPresentationStorageKey(scope),
      {
        version: 1,
        positions: { "package:a": { x: 120, y: 240 } },
        viewport: { x: -20, y: 15, zoom: 1.4 },
        layout: "dagre-lr",
        locked: true,
      },
    );

    const { result } = renderHook(() =>
      useGraphPresentation({ nodes, scope, layout: "dagre-lr" }),
    );

    expect(result.current.hasSavedState).toBe(true);
    expect(result.current.viewport).toEqual({ x: -20, y: 15, zoom: 1.4 });
    expect(result.current.nodes[0]?.position).toEqual({ x: 120, y: 240 });
    expect(result.current.nodes[0]?.ariaLabel).toBe("Package A");
  });

  it("blocks position changes while locked and persists them in edit mode", () => {
    const { result } = renderHook(() =>
      useGraphPresentation({ nodes, scope, layout: "dagre-lr" }),
    );

    act(() => {
      result.current.onNodesChange([
        { id: "package:a", type: "position", position: { x: 50, y: 80 } },
      ]);
    });
    expect(result.current.nodes[0]?.position).toEqual({ x: 0, y: 0 });

    act(() => result.current.toggleEditing());
    act(() => {
      result.current.onNodesChange([
        { id: "package:a", type: "position", position: { x: 50, y: 80 } },
      ]);
      result.current.onNodeDragStop(
        {} as never,
        { ...result.current.nodes[0]!, position: { x: 50, y: 80 } },
        [],
      );
    });

    expect(result.current.nodes[0]?.position).toEqual({ x: 50, y: 80 });
    expect(
      readGraphPresentation(window.localStorage, graphPresentationStorageKey(scope)),
    ).toMatchObject({
      positions: { "package:a": { x: 50, y: 80 } },
      locked: false,
    });
  });
});
