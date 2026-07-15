import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ExposurePathLens } from "@/components/exposure-path-lens";
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
    expect(screen.getByText(/No exposure paths for this snapshot/)).toBeInTheDocument();
  });

  it("renders an error state when the endpoint fails", async () => {
    apiMock.getGraphExposurePaths.mockRejectedValue(new Error("boom"));

    render(<ExposurePathLens scanId="scan-1" />);

    expect(await screen.findByTestId("exposure-path-lens-error")).toBeInTheDocument();
  });
});
