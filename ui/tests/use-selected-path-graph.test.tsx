import { act, renderHook, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useSelectedPathGraph } from "@/hooks/use-selected-path-graph";
import { api, type GraphQueryResponse } from "@/lib/api";
import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";

vi.mock("@/lib/api", () => ({ api: { queryGraph: vi.fn() } }));
const fixture = JSON.parse(readFileSync(join(process.cwd(), "../examples/reference-evidence-lab/generated/correlation-proof.json"), "utf8")).capture_fixture.graph as UnifiedGraphData;
const path = fixture.attack_paths[0]!;
const graph: UnifiedGraphData = { ...fixture, nodes: [], edges: [], attack_paths: [] };
const response = { ...fixture, truncated: false, missing_roots: [] } as unknown as GraphQueryResponse;
const props = { graph, path, scanId: graph.scan_id, enabled: true };
const query = vi.mocked(api.queryGraph);

beforeEach(() => { query.mockReset(); });

describe("selected path graph hydration", () => {
  it("reuses a complete page without fetching or changing its recorded evidence", () => {
    const { result } = renderHook(() => useSelectedPathGraph({ ...props, graph: fixture }));
    expect(query).not.toHaveBeenCalled();
    expect(result.current.graph).toBe(fixture);
    expect(result.current.loading).toBe(false);
  });

  it("loads exact hop roots once with finite budgets and retains canonical receipts and edge truth", async () => {
    const edge = { ...fixture.edges[0]!, traversable: false, evidence: { blocked: true, receipt_id: "deny:1" } };
    query.mockResolvedValue({ ...response, nodes: [...response.nodes, { ...response.nodes[0]!, id: "unrelated" }], edges: [edge, ...response.edges.slice(1), { ...edge, id: "unrelated", target: "unrelated" }] });
    const { result } = renderHook(() => useSelectedPathGraph(props));
    expect(result.current.graph).toBeNull();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(query).toHaveBeenCalledTimes(1);
    expect(query.mock.calls[0]![0]).toEqual({ roots: [...new Set(path.hops)], scan_id: graph.scan_id, direction: "both", max_depth: 1, max_nodes: new Set(path.hops).size, max_edges: 2048, timeout_ms: 2500, traversable_only: false, include_roots: true, include_attack_paths: false });
    expect(result.current.graph!.nodes.map((node) => node.id).sort()).toEqual([...path.hops].sort());
    expect(result.current.graph!.edges).toContainEqual(edge);
    expect(result.current.graph!.edges.some((item) => item.id === "unrelated")).toBe(false);
    expect(result.current.graph!.attack_paths[0]).toBe(path);
    expect(result.current.graph!.attack_paths[0]!.hop_evidence).toBe(path.hop_evidence);
  });

  for (const field of ["scan_id", "tenant_id"] as const) {
    it(`rejects a response from another ${field}`, async () => {
      query.mockResolvedValue({ ...response, [field]: "other" });
      const { result } = renderHook(() => useSelectedPathGraph(props));
      await waitFor(() => expect(result.current.canRetry).toBe(true));
      expect(result.current.graph).toBeNull();
      expect(result.current.message).toContain("did not match this snapshot");
    });
  }

  it("does not hydrate old page data after the selected snapshot changes", () => {
    const { result } = renderHook(() => useSelectedPathGraph({ ...props, scanId: "other" }));
    expect(query).not.toHaveBeenCalled();
    expect(result.current.graph).toBeNull();
  });

  it("does not manufacture missing nodes or relationships and reports incomplete context", async () => {
    query.mockResolvedValue({ ...response, nodes: [response.nodes[0]!], edges: [] });
    const { result } = renderHook(() => useSelectedPathGraph(props));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.graph!.nodes).toHaveLength(1);
    expect(result.current.graph!.edges).toHaveLength(0);
    expect(result.current.message).toContain("incomplete");
    expect(result.current.graph!.attack_paths[0]).toBe(path);
  });

  it("retains the recorded edge direction instead of treating a reversed edge as path evidence", async () => {
    query.mockResolvedValue({ ...response, edges: response.edges.map((edge) => ({ ...edge, source: edge.target, target: edge.source })) });
    const { result } = renderHook(() => useSelectedPathGraph(props));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.message).toContain("incomplete");
    expect(result.current.graph!.edges[0]!.source).toBe(response.edges[0]!.target);
  });

  it("reports bounded broader context even when the selected path is fully returned", async () => {
    query.mockResolvedValue({ ...response, truncated: true });
    const { result } = renderHook(() => useSelectedPathGraph(props));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.message).toContain("Broader context was limited");
    expect(result.current.graph!.attack_paths[0]).toBe(path);
  });

  it("cancels selection changes and ignores late responses without stale path receipts", async () => {
    let finishFirst!: (value: GraphQueryResponse) => void;
    let finishSecond!: (value: GraphQueryResponse) => void;
    query.mockImplementationOnce(() => new Promise((resolve) => { finishFirst = resolve; }));
    query.mockImplementationOnce(() => new Promise((resolve) => { finishSecond = resolve; }));
    const second: AttackPath = { ...path, hops: path.hops.slice(-2), edges: path.edges.slice(-1), source: path.hops.at(-2)! };
    const { result, rerender, unmount } = renderHook((current) => useSelectedPathGraph(current), { initialProps: props });
    const firstSignal = query.mock.calls[0]![1]!.signal!;
    rerender({ ...props, path: second });
    expect(firstSignal.aborted).toBe(true);
    expect(result.current.graph).toBeNull();
    await act(async () => finishFirst(response));
    expect(result.current.graph).toBeNull();
    await act(async () => finishSecond(response));
    expect(result.current.graph!.attack_paths).toEqual([second]);
    expect(result.current.graph!.nodes).toHaveLength(2);
    const secondSignal = query.mock.calls[1]![1]!.signal!;
    unmount();
    expect(secondSignal.aborted).toBe(true);
  });

  it("aborts a snapshot change and cannot display a late response with matching hop IDs", async () => {
    let finishOld!: (value: GraphQueryResponse) => void;
    query.mockImplementationOnce(() => new Promise((resolve) => { finishOld = resolve; }));
    query.mockResolvedValueOnce({ ...response, scan_id: "new-snapshot" });
    const { result, rerender } = renderHook((current) => useSelectedPathGraph(current), { initialProps: props });
    const signal = query.mock.calls[0]![1]!.signal!;
    rerender({ ...props, scanId: "new-snapshot", graph: { ...graph, scan_id: "new-snapshot" } });
    expect(signal.aborted).toBe(true);
    await waitFor(() => expect(result.current.graph?.scan_id).toBe("new-snapshot"));
    await act(async () => finishOld(response));
    expect(result.current.graph?.scan_id).toBe("new-snapshot");
  });

  it("does not fetch in Path mode and aborts when Graph mode closes", () => {
    query.mockImplementation(() => new Promise(() => {}));
    const { rerender } = renderHook((current) => useSelectedPathGraph(current), { initialProps: { ...props, enabled: false } });
    expect(query).not.toHaveBeenCalled();
    rerender(props);
    const signal = query.mock.calls[0]![1]!.signal!;
    rerender({ ...props, enabled: false });
    expect(signal.aborted).toBe(true);
  });

  it("reconciles selected graph counts and omits metadata about the broader response", async () => {
    const selected = response.nodes.find((node) => node.id === path.hops[0])!;
    const wider = {
      ...response,
      nodes: [selected, { ...selected, id: "unrelated", entity_type: "package", severity: "critical" }],
      edges: [],
      stats: { ...response.stats, total_nodes_source: 999, total_nodes: 999, node_types: { package: 999 }, severity_counts: { critical: 999 }, relationship_types: { uses: 999 }, max_attack_path_risk: 999, highest_interaction_risk: 999, analysis_status: { broader: { status: "complete" } } },
      pagination: { total: 999, has_more: true },
      completeness: { complete: true, total: 999, returned: 999 },
      count_metadata: { total: 999 },
    } as unknown as GraphQueryResponse;
    query.mockResolvedValue(wider);
    const { result } = renderHook(() => useSelectedPathGraph(props));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.graph!.stats).toEqual({
      total_nodes: 1, total_edges: 0, node_types: { [selected.entity_type]: 1 }, severity_counts: { [selected.severity]: 1 }, relationship_types: {},
      attack_path_count: 1, interaction_risk_count: 0, max_attack_path_risk: path.composite_risk, highest_interaction_risk: 0,
    });
    for (const field of ["pagination", "completeness", "count_metadata", "missing_roots", "depth_by_node"]) {
      expect(result.current.graph).not.toHaveProperty(field);
    }
    expect(result.current.message).toContain("incomplete");
  });

  it("shows an explicit status for a path without recorded hops", () => {
    const { result } = renderHook(() => useSelectedPathGraph({ ...props, path: { ...path, hops: [], edges: [] } }));
    expect(query).not.toHaveBeenCalled();
    expect(result.current.graph).toBeNull();
    expect(result.current.loading).toBe(false);
    expect(result.current.message).toContain("no recorded hops");
  });

  it("does not issue unbounded requests for oversized paths", () => {
    const { result } = renderHook(() => useSelectedPathGraph({ ...props, path: { ...path, hops: Array.from({ length: 65 }, (_, index) => `node:${index}`) } }));
    expect(query).not.toHaveBeenCalled();
    expect(result.current.message).toContain("64-node");
  });

  it("keeps failures explicit and supports a bounded retry", async () => {
    query.mockRejectedValueOnce(new Error("backend unavailable"));
    query.mockResolvedValueOnce(response);
    const { result } = renderHook(() => useSelectedPathGraph(props));
    await waitFor(() => expect(result.current.canRetry).toBe(true));
    expect(result.current.graph).toBeNull();
    act(() => result.current.retry());
    await waitFor(() => expect(result.current.graph).not.toBeNull());
    expect(query).toHaveBeenCalledTimes(2);
  });
});
