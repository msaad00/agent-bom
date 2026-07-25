import { act, renderHook } from "@testing-library/react";
import type { Node } from "@xyflow/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useGraphPresentation } from "@/hooks/use-graph-presentation";
import {
  graphPresentationStorageKey,
  graphNodeStorageKey,
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
  beforeEach(() => {
    const values = new Map<string, string>();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        get length() { return values.size; },
        clear: () => values.clear(),
        getItem: (key: string) => values.get(key) ?? null,
        key: (index: number) => [...values.keys()][index] ?? null,
        removeItem: (key: string) => { values.delete(key); },
        setItem: (key: string, value: string) => { values.set(key, value); },
      } satisfies Storage,
    });
  });

  it("restores a compatible personal viewport and node layout", () => {
    writeGraphPresentation(
      window.localStorage,
      graphPresentationStorageKey(scope),
      {
        version: 1,
        positions: { [graphNodeStorageKey("package:a")]: { x: 120, y: 240 } },
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

  it("uses a generic accessibility fallback instead of a raw node identifier", () => {
    const privateNodes: Node[] = [{ id: "arn:aws:private:resource", position: { x: 0, y: 0 }, data: {} }];
    const { result } = renderHook(() =>
      useGraphPresentation({ nodes: privateNodes, scope, layout: "dagre-lr" }),
    );
    expect(result.current.nodes[0]?.ariaLabel).toBe("Graph node");
    expect(result.current.nodes[0]?.ariaLabel).not.toContain("arn:aws");
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
      positions: { [graphNodeStorageKey("package:a")]: { x: 50, y: 80 } },
      locked: false,
    });
  });

  it("never removes evidence nodes from presentation state", () => {
    const { result } = renderHook(() =>
      useGraphPresentation({ nodes, scope, layout: "dagre-lr" }),
    );
    act(() => result.current.onNodesChange([{ id: "package:a", type: "remove" }]));
    expect(result.current.nodes.map((node) => node.id)).toEqual(["package:a"]);
  });

  it("performs no storage mutations while persistence starts disabled", () => {
    const setItem = vi.spyOn(window.localStorage, "setItem");
    const removeItem = vi.spyOn(window.localStorage, "removeItem");
    const { result } = renderHook(() =>
      useGraphPresentation({ nodes, scope, layout: "dagre-lr", enabled: false }),
    );
    act(() => {
      result.current.toggleEditing();
      result.current.autoLayout();
      result.current.reset();
      result.current.onMoveEnd(null, { x: 1, y: 2, zoom: 1.2 });
    });
    expect(setItem).not.toHaveBeenCalled();
    expect(removeItem).not.toHaveBeenCalled();
    setItem.mockRestore();
    removeItem.mockRestore();
  });

  it("does not persist unresolved auth placeholders unless the caller declares local mode", () => {
    const localScope = { ...scope, tenantId: "local", subject: "local-viewer" };
    const setItem = vi.spyOn(window.localStorage, "setItem");
    const { result, rerender } = renderHook(
      ({ localMode }) => useGraphPresentation({
        nodes,
        scope: localScope,
        layout: "dagre-lr",
        localMode,
      }),
      { initialProps: { localMode: false } },
    );

    act(() => result.current.toggleEditing());
    expect(result.current.enabled).toBe(false);
    expect(setItem).not.toHaveBeenCalled();

    rerender({ localMode: true });
    act(() => result.current.toggleEditing());
    expect(result.current.enabled).toBe(true);
    expect(setItem).toHaveBeenCalledTimes(2);
    setItem.mockRestore();
  });

  it("preserves layouts during auth refresh, then purges them on logout and identity change", () => {
    const { result, rerender } = renderHook(
      ({ activeScope, enabled, ownerActive }) => useGraphPresentation({ nodes, scope: activeScope, layout: "dagre-lr", enabled, ownerActive }),
      { initialProps: { activeScope: scope, enabled: true, ownerActive: true } },
    );
    act(() => result.current.toggleEditing());
    const secondScope = { ...scope, snapshotId: "snapshot-two" };
    rerender({ activeScope: secondScope, enabled: true, ownerActive: true });
    act(() => result.current.toggleEditing());
    expect(window.localStorage.getItem(graphPresentationStorageKey(scope))).not.toBeNull();
    expect(window.localStorage.getItem(graphPresentationStorageKey(secondScope))).not.toBeNull();

    // Auth refresh temporarily disables persistence while the same session is
    // still present. This must not be interpreted as logout.
    rerender({ activeScope: secondScope, enabled: false, ownerActive: true });
    expect(window.localStorage.getItem(graphPresentationStorageKey(scope))).not.toBeNull();
    expect(window.localStorage.getItem(graphPresentationStorageKey(secondScope))).not.toBeNull();

    rerender({ activeScope: secondScope, enabled: true, ownerActive: true });
    expect(window.localStorage.getItem(graphPresentationStorageKey(scope))).not.toBeNull();
    expect(window.localStorage.getItem(graphPresentationStorageKey(secondScope))).not.toBeNull();

    // The stable session signal becoming false is the actual logout boundary.
    rerender({ activeScope: secondScope, enabled: false, ownerActive: false });
    expect(window.localStorage.getItem(graphPresentationStorageKey(scope))).toBeNull();
    expect(window.localStorage.getItem(graphPresentationStorageKey(secondScope))).toBeNull();

    const nextScope = { ...scope, subject: "different-viewer" };
    rerender({ activeScope: nextScope, enabled: true, ownerActive: true });
    act(() => result.current.toggleEditing());
    expect(window.localStorage.getItem(graphPresentationStorageKey(nextScope))).not.toBeNull();
    rerender({ activeScope: scope, enabled: true, ownerActive: true });
    expect(window.localStorage.getItem(graphPresentationStorageKey(nextScope))).toBeNull();
  });
});
