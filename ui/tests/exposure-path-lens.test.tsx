import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ExposurePathLens, toUiExposurePath } from "@/components/exposure-path-lens";
import type { GraphExposurePathsResponse } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getGraphExposurePaths: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

function response(paths: GraphExposurePathsResponse["paths"]): GraphExposurePathsResponse {
  return {
    schema_version: "v1",
    tool: "exposure_paths",
    tenant_id: "default",
    scan_id: "scan-1",
    count: paths.length,
    total: paths.length,
    filters: { limit: 25, min_risk: 0 },
    paths,
  };
}

beforeEach(() => {
  apiMock.getGraphExposurePaths.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ExposurePathLens", () => {
  it("loads and renders exposure paths for the snapshot", async () => {
    apiMock.getGraphExposurePaths.mockResolvedValue(
      response([
        {
          id: "p1",
          rank: 1,
          label: "claude-desktop → left-pad → CVE-2024-1",
          summary: "Reachable package inherits agent exposure.",
          riskScore: 88.5,
          severity: "critical",
          source: { id: "agent:claude-desktop", label: "claude-desktop", role: "agent" },
          target: { id: "finding:cve", label: "CVE-2024-1", role: "finding" },
          hops: [
            { id: "agent:claude-desktop", label: "claude-desktop", role: "agent" },
            { id: "pkg:left-pad", label: "left-pad", role: "package" },
            { id: "finding:cve", label: "CVE-2024-1", role: "finding" },
          ],
          relationships: [
            { id: "e1", source: "agent:claude-desktop", target: "pkg:left-pad", relationship: "depends_on" },
          ],
          nodeIds: ["agent:claude-desktop", "pkg:left-pad", "finding:cve"],
          edgeIds: ["e1"],
          findings: ["CVE-2024-1"],
          reachableTools: [],
          exposedCredentials: [],
        },
      ]),
    );

    render(<ExposurePathLens scanId="scan-1" />);

    await waitFor(() =>
      expect(apiMock.getGraphExposurePaths).toHaveBeenCalledWith({ scanId: "scan-1", limit: 25 }),
    );
    expect(await screen.findByTestId("exposure-path-lens")).toBeInTheDocument();
    expect(screen.getByText("Total in snapshot")).toBeInTheDocument();
    expect(screen.getAllByText(/88\.5/).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /left-pad/ })).toBeInTheDocument();
  });

  it("renders the empty state when no exposure paths exist", async () => {
    apiMock.getGraphExposurePaths.mockResolvedValue({
      ...response([]),
      message: "0 paths means no agent-to-vulnerability ExposurePath reaches a credential exposure.",
    });

    render(<ExposurePathLens scanId="scan-1" />);

    expect(await screen.findByTestId("exposure-path-lens-empty")).toBeInTheDocument();
    expect(screen.getByText(/No exposure paths recorded/)).toBeInTheDocument();
  });

  it("renders an error state when the endpoint fails", async () => {
    apiMock.getGraphExposurePaths.mockRejectedValue(new Error("boom"));

    render(<ExposurePathLens scanId="scan-1" />);

    expect(await screen.findByTestId("exposure-path-lens-error")).toBeInTheDocument();
  });
});


function qualifiedPath(id: string): GraphExposurePathsResponse["paths"][number] {
  return {
    id, label: id, summary: "Static dependency context; execution is unverified.", riskScore: 30, severity: "high",
    source: { id: "agent:a", label: "Assistant", role: "agent" },
    target: { id, label: id, role: "vulnerability" },
    hops: [{ id: "agent:a", label: "Assistant", role: "agent" }, { id, label: id, role: "vulnerability" }],
    relationships: [{ id: "edge", source: "agent:a", target: id, relationship: "vulnerable_to", direction: "directed", traversable: false }],
    nodeIds: ["agent:a", id], edgeIds: ["edge"], findings: [id], reachableTools: [], exposedCredentials: [],
    reachability: "unknown", reachabilityBasis: ["structural_topology_only"],
    evidenceDimensions: {
      reachability: { status: "unavailable", verdict: null, reasonCodes: ["reachability_not_assessed"] },
      exploitability: { status: "unavailable", verdict: null },
      impact: { status: "unavailable" }, actionability: { status: "unavailable" },
      completeness: { status: "partial", expectedHops: 1, evidencedHops: 0, reasonCodes: ["incomplete_hop_evidence"] },
    },
    provenance: { source: "mcp_exposure_paths", scanId: "scan-1" },
  };
}

it("preserves server evidence, direction, traversability and finding roles", () => {
  const input = qualifiedPath("CVE-2026-1");
  const path = toUiExposurePath(input);
  expect(path.target.role).toBe("finding");
  expect(path.relationships[0]).toMatchObject({ direction: "directed", traversable: false });
  expect(path.evidenceDimensions).toEqual(input.evidenceDimensions);
  expect(path.reachabilityBasis).toEqual(["structural_topology_only"]);
});

it("shows uncertainty and pages without accumulating an unbounded canvas", async () => {
  apiMock.getGraphExposurePaths.mockResolvedValueOnce({
    ...response([qualifiedPath("CVE-first")]), total: 2,
    pagination: { offset: 0, returned: 1, limit: 25, has_more: true, next_cursor: "page-two" },
  }).mockResolvedValueOnce({
    ...response([qualifiedPath("CVE-second")]), total: 2,
    pagination: { offset: 1, returned: 1, limit: 25, has_more: false, next_cursor: null },
  }).mockResolvedValueOnce({ ...response([qualifiedPath("CVE-first")]), total: 2 });
  render(<ExposurePathLens />);
  expect(await screen.findByRole("region", { name: "Path evidence assessment" })).toHaveTextContent("Unknown");
  fireEvent.click(screen.getByText("Evidence & relationships"));
  expect(screen.getByText(/Context only; not traversable/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next paths" }));
  expect(await screen.findByRole("button", { name: /CVE-second/ })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /CVE-first/ })).not.toBeInTheDocument();
  expect(apiMock.getGraphExposurePaths).toHaveBeenLastCalledWith({ scanId: "scan-1", limit: 25, cursor: "page-two" });
  expect(screen.getByRole("button", { name: "Next paths" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Previous paths" }));
  expect(await screen.findByRole("button", { name: /CVE-first/ })).toBeInTheDocument();
  expect(apiMock.getGraphExposurePaths).toHaveBeenLastCalledWith({ scanId: "scan-1", limit: 25 });
});

it("discloses lower-bound totals rather than claiming complete snapshot coverage", async () => {
  apiMock.getGraphExposurePaths.mockResolvedValue({
    ...response([qualifiedPath("CVE-1")]), total: 200,
    count_metadata: { source: "derived_graph_paths", total_is_lower_bound: true },
    completeness: { complete: false, truncated: true, reason: "node_budget" },
  });
  render(<ExposurePathLens scanId="scan-1" />);
  expect(await screen.findByText("At least in snapshot")).toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("node budget");
});
