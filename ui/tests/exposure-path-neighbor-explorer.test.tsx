import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ExposurePathNeighborExplorer } from "@/components/exposure-path-neighbor-explorer";
import type { GraphNodeNeighborsResponse } from "@/lib/api";
import type { ExposurePath } from "@/lib/exposure-path";
import type { UnifiedEdge, UnifiedNode } from "@/lib/graph-schema";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getGraphNodeNeighbors: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({
  api: apiMock,
}));

afterEach(() => {
  vi.resetAllMocks();
});

function node(id: string, entityType: string, label: string): UnifiedNode {
  return { id, entity_type: entityType, label, attributes: {} } as unknown as UnifiedNode;
}

function edge(source: string, target: string, relationship: string): UnifiedEdge {
  return { id: `${source}->${target}`, source, target, relationship } as unknown as UnifiedEdge;
}

const path: ExposurePath = {
  id: "path-1",
  label: "analyst-agent -> database -> werkzeug",
  riskScore: 9.1,
  severity: "critical",
  source: { id: "agent:analyst", label: "analyst-agent", role: "agent" },
  target: { id: "vuln:werkzeug:CVE", label: "CVE", role: "finding" },
  hops: [
    { id: "agent:analyst", label: "analyst-agent", role: "agent" },
    { id: "server:database", label: "database", role: "server" },
    { id: "pkg:werkzeug", label: "werkzeug@2.2.2", role: "package" },
    { id: "vuln:werkzeug:CVE", label: "CVE", role: "finding" },
  ],
  relationships: [],
  nodeIds: ["agent:analyst", "server:database", "pkg:werkzeug", "vuln:werkzeug:CVE"],
  edgeIds: [],
  findings: ["CVE"],
  affectedAgents: ["analyst-agent"],
  affectedServers: ["database"],
  reachableTools: [],
  exposedCredentials: [],
};

describe("ExposurePathNeighborExplorer", () => {
  it("lazy-loads and reveals a hop's neighbors on expand, then hides them on collapse", async () => {
    const response: GraphNodeNeighborsResponse = {
      node_id: "server:database",
      scan_id: "scan-1",
      found: true,
      direction: "both",
      limit: 12,
      total_neighbors: 2,
      truncated: false,
      neighbors: [
        node("pkg:werkzeug", "package", "werkzeug@2.2.2"),
        node("agent:analyst", "agent", "analyst-agent"),
      ],
      edges: [
        edge("server:database", "pkg:werkzeug", "depends_on"),
        edge("agent:analyst", "server:database", "uses"),
      ],
    };
    apiMock.getGraphNodeNeighbors.mockResolvedValue(response);

    render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);

    // Nothing is fetched until the analyst expands a hop.
    expect(apiMock.getGraphNodeNeighbors).not.toHaveBeenCalled();

    const expandButton = screen.getByRole("button", { name: /Expand neighbors of database/i });
    fireEvent.click(expandButton);

    await waitFor(() => expect(screen.getByText("Outgoing relationships")).toBeInTheDocument());
    expect(apiMock.getGraphNodeNeighbors).toHaveBeenCalledWith("server:database", {
      scanId: "scan-1",
      limit: 12,
      direction: "both",
    });
    expect(screen.getByText("Incoming relationships")).toBeInTheDocument();
    expect(screen.getByText("werkzeug")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Collapse neighbors of database/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Traverse from database/i })).toHaveAttribute(
      "href",
      "/security-graph?scan=scan-1&investigate=1&root=server%3Adatabase&q=database&lens=lineage",
    );

    // Collapsing hides the revealed neighbors without refetching.
    fireEvent.click(screen.getByRole("button", { name: /Collapse neighbors of database/i }));
    await waitFor(() => expect(screen.queryByText("Outgoing relationships")).not.toBeInTheDocument());

    // Re-expanding is served from cache (no second network call).
    fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of database/i }));
    await waitFor(() => expect(screen.getByText("Outgoing relationships")).toBeInTheDocument());
    expect(apiMock.getGraphNodeNeighbors).toHaveBeenCalledTimes(1);
  });

  it("honestly reports a bounded fan-out with a +N more affordance", async () => {
    apiMock.getGraphNodeNeighbors.mockResolvedValue({
      node_id: "pkg:werkzeug",
      scan_id: "scan-1",
      found: true,
      direction: "both",
      limit: 12,
      total_neighbors: 40,
      truncated: true,
      neighbors: [node("pkg:dep0", "package", "dep-0")],
      edges: [edge("pkg:werkzeug", "pkg:dep0", "depends_on")],
    } satisfies GraphNodeNeighborsResponse);

    render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
    fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of werkzeug/i }));

    await waitFor(() => expect(screen.getByText(/\+39 more neighbors not shown/i)).toBeInTheDocument());
  });

  it("offers neighbor inspection for finding hops without assuming they are leaves", () => {
    render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
    expect(screen.getByRole("button", { name: /Expand neighbors of CVE/i })).toBeInTheDocument();
  });
});

it("expands typed nonstandard hops and retries a failed lookup", async () => {
  const hop = { id: "repo:billing", label: "Billing repository", role: "unknown" as const, kindLabel: "Repository" };
  apiMock.getGraphNodeNeighbors.mockRejectedValueOnce(new Error("unavailable")).mockResolvedValueOnce({
    node_id: hop.id, scan_id: "scan-1", found: true, direction: "both", limit: 12,
    total_neighbors: 0, truncated: false, neighbors: [], edges: [],
  });
  render(<ExposurePathNeighborExplorer path={{ ...path, hops: [hop] }} scanId="scan-1" />);
  expect(screen.getByText("Repository")).toBeInTheDocument();
  expect(screen.queryByText("leaf")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of Billing repository/ }));
  fireEvent.click(await screen.findByRole("button", { name: "Retry neighbor lookup" }));
  expect(await screen.findByText("No direct graph neighbors recorded for this node.")).toBeInTheDocument();
  expect(apiMock.getGraphNodeNeighbors).toHaveBeenCalledTimes(2);
});

it("does not describe a truncated empty response as an isolated node", async () => {
  apiMock.getGraphNodeNeighbors.mockResolvedValue({ node_id: "pkg:werkzeug", scan_id: "scan-1", found: true,
    total_neighbors: 4, truncated: true, neighbors: [], edges: [] });
  render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
  fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of werkzeug/ }));
  expect(await screen.findByText(/No neighbors returned in this partial context/)).toBeInTheDocument();
  expect(screen.queryByText("No direct graph neighbors recorded for this node.")).not.toBeInTheDocument();
});

it("retains both directions and multiple relationship types for the same neighbor", async () => {
  apiMock.getGraphNodeNeighbors.mockResolvedValue({ node_id: "pkg:werkzeug", scan_id: "scan-1", found: true,
    total_neighbors: 1, truncated: false, neighbors: [node("cve:one", "vulnerability", "CVE-2023-25577")],
    edges: [edge("pkg:werkzeug", "cve:one", "vulnerable_to"), edge("cve:one", "pkg:werkzeug", "affects")] });
  render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
  fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of werkzeug/ }));
  expect(await screen.findByText("Vulnerable To")).toBeInTheDocument();
  expect(screen.getByText("Affects")).toBeInTheDocument();
  expect(screen.getByText("Incoming relationships")).toBeInTheDocument();
});


it("requests selected direction with the exact node and snapshot and reports evidence basis", async () => {
  apiMock.getGraphNodeNeighbors.mockResolvedValue({ node_id: "server:database", scan_id: "scan-1", found: true,
    total_neighbors: 1, truncated: false, neighbors: [node("tool:one", "tool", "query")],
    edges: [{ ...edge("server:database", "tool:one", "provides"), evidence: { evidence_tier: "static_evidence" } }] });
  render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
  fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of database/ }));
  expect(await screen.findByText("Configured / static evidence")).toBeVisible();
  fireEvent.change(screen.getByRole("combobox", { name: "Relationship direction for database" }), { target: { value: "in" } });
  await waitFor(() => expect(apiMock.getGraphNodeNeighbors).toHaveBeenLastCalledWith("server:database", { scanId: "scan-1", limit: 12, direction: "in" }));
});

it("rejects a response from another snapshot instead of showing unrelated evidence", async () => {
  apiMock.getGraphNodeNeighbors.mockResolvedValue({ node_id: "server:database", scan_id: "other-scan", found: true,
    total_neighbors: 1, truncated: false, neighbors: [node("tool:wrong", "tool", "wrong-scope-tool")], edges: [] });
  render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
  fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of database/ }));
  expect(await screen.findByRole("button", { name: "Retry neighbor lookup" })).toBeVisible();
  expect(screen.queryByText("wrong-scope-tool")).not.toBeInTheDocument();
});

it("keeps blocked attempts distinct from observed execution", async () => {
  apiMock.getGraphNodeNeighbors.mockResolvedValue({ node_id: "server:database", scan_id: "scan-1", found: true,
    total_neighbors: 1, truncated: false, neighbors: [node("tool:one", "tool", "query")],
    edges: [{ ...edge("tool:one", "server:database", "calls"), evidence: { runtime_observed_state: "blocked", evidence_tier: "runtime_observed" } }] });
  render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
  fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of database/ }));
  expect(await screen.findByText("Blocked attempt")).toBeVisible();
  expect(screen.getByText("Incoming relationships")).toBeVisible();
  expect(screen.queryByText("Runtime observed")).not.toBeInTheDocument();
});


it("ignores a slower response for the previous relationship direction", async () => {
  let resolveOld!: (response: GraphNodeNeighborsResponse) => void;
  const base: GraphNodeNeighborsResponse = { node_id: "server:database", scan_id: "scan-1", direction: "both", limit: 12, found: true, total_neighbors: 1, truncated: false, neighbors: [], edges: [] };
  apiMock.getGraphNodeNeighbors.mockReturnValueOnce(new Promise<GraphNodeNeighborsResponse>((resolve) => { resolveOld = resolve; }))
    .mockResolvedValueOnce({ ...base, direction: "in", neighbors: [node("tool:new", "tool", "current-direction")] });
  render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
  fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of database/ }));
  fireEvent.change(screen.getByRole("combobox", { name: "Relationship direction for database" }), { target: { value: "in" } });
  await act(async () => {});
  expect(screen.getByText("Current Direction")).toBeVisible();
  await act(async () => { resolveOld({ ...base, neighbors: [node("tool:old", "tool", "stale-direction")] }); });
  expect(screen.getByText("Current Direction")).toBeVisible();
  expect(screen.queryByText("Stale Direction")).not.toBeInTheDocument();
});

it("reports unknown totals without inventing an omitted-neighbor count", async () => {
  apiMock.getGraphNodeNeighbors.mockResolvedValue({ node_id: "server:database", scan_id: "scan-1", found: true,
    total_neighbors: null, truncated: true, neighbors: [node("tool:one", "tool", "query")],
    edges: [edge("server:database", "tool:one", "provides_tool")],
    completeness: { complete: false, truncated: true, status: "truncated", reason: "edge_budget" } });
  render(<ExposurePathNeighborExplorer path={path} scanId="scan-1" />);
  fireEvent.click(screen.getByRole("button", { name: /Expand neighbors of database/ }));
  expect(await screen.findByText("Neighbor coverage is incomplete; total unknown.")).toBeVisible();
  expect(screen.queryByText(/more neighbors? not shown/)).not.toBeInTheDocument();
});
