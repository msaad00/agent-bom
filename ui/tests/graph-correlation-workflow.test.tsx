import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { GraphCorrelationWorkflow } from "@/components/graph-correlation-workflow";
import type { GraphCorrelationRun, GraphSnapshot } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    createGraphCorrelation: vi.fn(),
    getGraphCorrelation: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({ api: apiMock, formatDate: (value: string) => value }));

const snapshots: GraphSnapshot[] = [
  { scan_id: "repo", created_at: "2026-08-30T00:00:00Z", node_count: 4, edge_count: 3, risk_summary: {}, snapshot_kind: "scan" },
  { scan_id: "image", created_at: "2026-08-30T00:01:00Z", node_count: 8, edge_count: 7, risk_summary: {}, snapshot_kind: "scan" },
  { scan_id: "old-correlation", created_at: "2026-08-30T00:02:00Z", node_count: 9, edge_count: 8, risk_summary: {}, snapshot_kind: "correlation", correlation_id: "old-correlation" },
];

function run(status: "pending" | "complete"): GraphCorrelationRun {
  return {
    correlation_id: "corr-1",
    tenant_id: "default",
    name: "Investigation correlation",
    status,
    max_age_hours: 168,
    allow_stale: false,
    input_manifest: [
      { scan_id: "image", freshness: "fresh", node_count: 8, edge_count: 7 },
      { scan_id: "repo", freshness: "fresh", node_count: 4, edge_count: 3 },
    ],
    result_manifest: status === "complete" ? {
      correlation_merge: { conflict_count: 1 },
      output: { scan_id: "corr-1", node_count: 11, edge_count: 12, attack_path_count: 2 },
      analysis_bounds: { correlation_merge: { status: "complete", truncated: false } },
    } : {},
    manifest_sha256: status === "complete" ? `sha256:${"a".repeat(64)}` : "",
    output_scan_id: status === "complete" ? "corr-1" : "",
    failure_code: "",
    created_at: "2026-08-30T00:03:00Z",
    started_at: "",
    completed_at: status === "complete" ? "2026-08-30T00:04:00Z" : "",
  };
}

describe("GraphCorrelationWorkflow", () => {
  beforeEach(() => {
    apiMock.createGraphCorrelation.mockReset();
    apiMock.getGraphCorrelation.mockReset();
    apiMock.createGraphCorrelation.mockResolvedValue(run("complete"));
  });

  it("requires two scan snapshots and explicit confirmation of the visible seven-day bound", async () => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} onOpenSnapshot={vi.fn()} />);

    expect(screen.getByLabelText("Maximum evidence age (hours)")).toHaveValue(168);
    expect(screen.getByLabelText("old-correlation")).toBeDisabled();
    const create = screen.getByRole("button", { name: "Correlate selected evidence" });
    expect(create).toBeDisabled();

    fireEvent.click(screen.getByLabelText("repo"));
    fireEvent.click(screen.getByLabelText("image"));
    expect(create).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I confirm the 7-day freshness bound/i));
    expect(create).toBeEnabled();

    fireEvent.click(create);
    await waitFor(() => expect(apiMock.createGraphCorrelation).toHaveBeenCalledWith({
      name: "Investigation correlation",
      scan_ids: ["image", "repo"],
      max_age_hours: 168,
      allow_stale: false,
    }));
    expect(await screen.findByText("1 conflicting field set retained")).toBeInTheDocument();
    expect(screen.getByText("2 confirmed attack paths")).toBeInTheDocument();
  });

  it("opens the completed correlated snapshot", async () => {
    const onOpenSnapshot = vi.fn();
    render(<GraphCorrelationWorkflow snapshots={snapshots} onOpenSnapshot={onOpenSnapshot} />);
    fireEvent.click(screen.getByLabelText("repo"));
    fireEvent.click(screen.getByLabelText("image"));
    fireEvent.click(screen.getByLabelText(/I confirm the 7-day freshness bound/i));
    fireEvent.click(screen.getByRole("button", { name: "Correlate selected evidence" }));

    fireEvent.click(await screen.findByRole("button", { name: "Open correlated snapshot" }));
    expect(onOpenSnapshot).toHaveBeenCalledWith("corr-1");
  });
});
