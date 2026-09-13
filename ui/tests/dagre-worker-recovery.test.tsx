import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Node } from "@xyflow/react";
import { useDagreLayout } from "@/lib/use-dagre-layout";

const nodes: Node[] = Array.from({ length: 984 }, (_, i) => ({ id: `node-${i}`, data: {}, position: { x: 0, y: 0 } }));
const edges = [{ id: "e", source: "node-0", target: "node-1" }];
const options = { nodeWidth: 300, nodeHeight: 160 };
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("layout worker recovery", () => {
  it.each(["unavailable", "construction", "serialization"])("keeps nodes separated when the worker fails at %s", (failure) => {
    vi.stubGlobal("Worker", failure === "unavailable" ? undefined : class {
      constructor() { if (failure === "construction") throw new Error("worker unavailable"); }
      postMessage() { throw new Error("cannot clone payload"); }
      terminate() {}
    });
    const { result } = renderHook(() => useDagreLayout(nodes, edges, options));
    expect(result.current.pending).toBe(false);
    expect(result.current.nodes).toHaveLength(984);
    expect(new Set(result.current.nodes.map((node) => `${node.position.x},${node.position.y}`)).size).toBe(984);
    expect(result.current.edges).toEqual(edges);
  });

  it("recovers a worker that never replies without leaving a permanent loading state", () => {
    vi.useFakeTimers();
    const terminate = vi.fn();
    vi.stubGlobal("Worker", class { postMessage() {} terminate = terminate; });
    const { result } = renderHook(() => useDagreLayout(nodes, edges, options));
    expect(result.current.pending).toBe(true);
    act(() => { vi.advanceTimersByTime(15000); });
    expect(result.current.pending).toBe(false);
    expect(terminate).toHaveBeenCalled();
    expect(new Set(result.current.nodes.map((node) => `${node.position.x},${node.position.y}`)).size).toBe(984);
  });
});
