import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CoverageCockpit } from "@/components/coverage-cockpit";
import { api } from "@/lib/api";

describe("CoverageCockpit", () => {
  it("renders deployment, accounts, and scans pillars with Wiz-style coverage copy", async () => {
    vi.spyOn(api, "listCloudConnections").mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "default",
      count: 1,
      connections: [
        {
          id: "conn-1",
          tenant_id: "default",
          provider: "aws",
          display_name: "Prod AWS",
          role_ref: "arn:aws:iam::123:role/read",
          has_external_id: true,
          regions: ["us-east-1"],
          status: "active",
          status_detail: "",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
          last_scan_at: "2026-01-02T00:00:00Z",
          last_event_at: null,
          last_scan_id: "scan-1",
          scan_interval_minutes: 1440,
        },
      ],
    });

    render(
      <CoverageCockpit
        counts={{
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          total: 0,
          kev: 0,
          compound_issues: 0,
          deployment_mode: "hybrid",
          has_local_scan: true,
          has_fleet_ingest: true,
          scan_count: 4,
          scan_sources: ["local", "aws"],
        }}
        scanCount={4}
        latestScanLabel="Jan 2"
      />,
    );

    expect(screen.getByRole("heading", { name: "Onboard & coverage" })).toBeInTheDocument();
    expect(screen.getByText(/Deployment is your control plane/i)).toBeInTheDocument();
    expect(screen.getByText("Deployment")).toBeInTheDocument();
    expect(screen.getByText("Cloud accounts")).toBeInTheDocument();
    expect(screen.getByText("Scans")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/1 connected · 1 active/i)).toBeInTheDocument();
    });
    expect(screen.getByRole("link", { name: /Scan account/i })).toHaveAttribute("href", "/scan?connection=conn-1");
  });
});
