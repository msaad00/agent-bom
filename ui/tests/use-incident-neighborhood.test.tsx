import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { ApiError } from "@/lib/api-errors";
import type { GraphIncidentPage } from "@/lib/api-types";
import { useIncidentNeighborhood } from "@/hooks/use-incident-neighborhood";
vi.mock("@/lib/api", () => ({ api: { getGraphIncidentEdges: vi.fn() } }));
const fetchPage = vi.mocked(api.getGraphIncidentEdges);
const generation = "a".repeat(32);
function page(id = "agent:endpoint-a:desktop", next: string | null = null): GraphIncidentPage {
  return { scan_id: "persisted-scan", snapshot_generation: generation, node_id: id, found: true, direction: "both", limit: 24,
    node: { id, entity_type: "agent", label: "desktop", attributes: {} }, nodes: [{ id: "server:exact", entity_type: "server", label: "server", attributes: {} }],
    edges: [{ source: id, target: "server:exact", relationship: "uses", evidence: {}, id: "edge" }], next_cursor: next,
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 1, total: null, scope: "incident_edge_page", missing_endpoint_count: 0 },
  } as GraphIncidentPage;
}
beforeEach(() => fetchPage.mockReset());
it("pins snapshot generation on different-node first pages and cursor continuations", async () => {
  fetchPage.mockImplementation(async id => page(id, "next"));
  const { result } = renderHook(() => useIncidentNeighborhood("persisted-scan", "agent:endpoint-a:desktop", "both", "tenant-a"));
  await waitFor(() => expect(result.current.pages).toHaveLength(1));
  await act(() => result.current.load("server:exact"));
  expect(fetchPage).toHaveBeenLastCalledWith("server:exact", expect.objectContaining({ scanId: "persisted-scan", snapshotGeneration: generation, direction: "both" }));
  await act(() => result.current.load("server:exact", "next"));
  expect(fetchPage).toHaveBeenLastCalledWith("server:exact", expect.objectContaining({ snapshotGeneration: generation, cursor: "next" }));
  expect(result.current.edges).toHaveLength(2);
});
it("clears all nodes on stale cursor and restarts without the old generation", async () => {
  fetchPage.mockResolvedValueOnce(page()).mockRejectedValueOnce(new ApiError("stale", { status: 400, statusText: "Bad Request", url: "/incident", method: "GET" })).mockResolvedValueOnce({ ...page(), snapshot_generation: "b".repeat(32) });
  const { result } = renderHook(() => useIncidentNeighborhood("persisted-scan", "agent:endpoint-a:desktop", "both", "tenant-a"));
  await waitFor(() => expect(result.current.pages).toHaveLength(1));
  await act(() => result.current.load("server:exact"));
  expect(result.current.stale).toBe(true); expect(result.current.nodes).toHaveLength(0); expect(result.current.edges).toHaveLength(0);
  act(() => result.current.restart());
  await waitFor(() => expect(result.current.pages).toHaveLength(1));
  expect(fetchPage.mock.calls.at(-1)?.[1].snapshotGeneration).toBeUndefined();
  expect(result.current.pages[0]?.snapshot_generation).toBe("b".repeat(32));
});
it("aborts and ignores stale responses after direction or tenant changes", async () => {
  let resolve!: (value: GraphIncidentPage) => void;
  fetchPage.mockReturnValueOnce(new Promise(yes => { resolve = yes; })).mockResolvedValueOnce({ ...page(), direction: "in" });
  const { result, rerender } = renderHook(({ direction, owner }: { direction: "both" | "in"; owner: string }) => useIncidentNeighborhood("persisted-scan", "agent:endpoint-a:desktop", direction, owner), { initialProps: { direction: "both", owner: "tenant-a" } });
  const oldSignal = fetchPage.mock.calls[0]![1].signal;
  rerender({ direction: "in", owner: "tenant-b" });
  await waitFor(() => expect(result.current.pages).toHaveLength(1));
  expect(oldSignal.aborted).toBe(true);
  await act(async () => resolve(page("old")));
  expect(result.current.pages[0]?.direction).toBe("in");
});
it("marks missing snapshots unavailable and never invents a zero-degree verdict", async () => {
  fetchPage.mockResolvedValue({ ...page(), found: false, snapshot_generation: null, node: null, nodes: [], edges: [] });
  const { result } = renderHook(() => useIncidentNeighborhood("persisted-scan", "agent:endpoint-a:desktop", "both", "tenant-a"));
  await waitFor(() => expect(result.current.error).toContain("coverage is unknown"));
  expect(result.current.pages).toHaveLength(0);
});
it("bounds the cache to ten pages and collapses added-node evidence", async () => {
  fetchPage.mockImplementation(async id => page(id));
  const { result } = renderHook(() => useIncidentNeighborhood("persisted-scan", "root", "both", "tenant-a"));
  await waitFor(() => expect(result.current.pages).toHaveLength(1));
  for (let i = 0; i < 12; i++) await act(() => result.current.load(`node:${i}`));
  expect(result.current.pages).toHaveLength(10); expect(fetchPage).toHaveBeenCalledTimes(10); expect(result.current.capped).toBe(true);
  act(() => result.current.collapse("node:0"));
  expect(result.current.pages).toHaveLength(1); expect(result.current.nodes.some(node => node.id === "node:0")).toBe(false);
});
