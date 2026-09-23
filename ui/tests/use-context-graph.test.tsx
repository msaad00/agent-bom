import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { useContextGraph } from "@/hooks/use-context-graph";

vi.mock("@/lib/api", () => ({ api: { getContextGraph: vi.fn() } }));
const fetchGraph = vi.mocked(api.getContextGraph);
function deferred() {
  let resolve!: (value: Awaited<ReturnType<typeof api.getContextGraph>>) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<Awaited<ReturnType<typeof api.getContextGraph>>>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const graph = (name: string) => ({ nodes: [{ id: name }] }) as unknown as Awaited<ReturnType<typeof api.getContextGraph>>;

beforeEach(() => vi.clearAllMocks());
describe("context evidence scope", () => {
  it.each(["resolve", "reject"] as const)("ignores a stale %s after switching agents", async (completion) => {
    const old = deferred();
    fetchGraph.mockReturnValueOnce(old.promise).mockResolvedValueOnce(graph("new"));
    const { result, rerender } = renderHook(({ agent }) => useContextGraph("scan", agent), { initialProps: { agent: "old" } });
    rerender({ agent: "new" });
    await waitFor(() => expect(result.current.data?.nodes[0]?.id).toBe("new"));
    await act(async () => {
      if (completion === "resolve") old.resolve(graph("old"));
      else old.reject(new Error("old failure"));
    });
    expect(result.current.data?.nodes[0]?.id).toBe("new");
    expect(result.current.error).toBeNull();
  });
  it("hides the previous scan immediately and clears errors on recovery", async () => {
    const next = deferred();
    fetchGraph.mockResolvedValueOnce(graph("old")).mockReturnValueOnce(next.promise).mockResolvedValueOnce(graph("recovered"));
    const { result, rerender } = renderHook(({ scan }) => useContextGraph(scan, "agent"), { initialProps: { scan: "old" } });
    await waitFor(() => expect(result.current.data).not.toBeNull());
    rerender({ scan: "new" });
    expect(result.current.data).toBeNull();
    await act(async () => next.reject(new Error("secret URL")));
    expect(result.current.error).toContain("Unable to load");
    expect(result.current.error).not.toContain("secret");
    rerender({ scan: "recovered" });
    expect(result.current.error).toBeNull();
    await waitFor(() => expect(result.current.data?.nodes[0]?.id).toBe("recovered"));
  });
  it("does not fetch without a selected scan", () => {
    renderHook(() => useContextGraph("", null));
    expect(fetchGraph).not.toHaveBeenCalled();
  });
});
