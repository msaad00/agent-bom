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

function run(status: GraphCorrelationRun["status"]): GraphCorrelationRun {
  return {
    correlation_id: "corr-1",
    tenant_id: "default",
    name: "Investigation correlation",
    status,
    max_age_hours: 168,
    allow_stale: false,
    input_manifest: [
      { scan_id: "image", freshness: "fresh", node_count: 8, edge_count: 7, source_kinds: ["cyclonedx_sbom"], digest: `sha256:${"b".repeat(64)}` },
      { scan_id: "repo", freshness: "fresh", node_count: 4, edge_count: 3, source_kinds: ["repository_parser"], digest: `sha256:${"c".repeat(64)}` },
    ],
    result_manifest: status === "complete" ? {
      correlation_merge: { conflict_count: 1 },
      output: { scan_id: "corr-1", node_count: 11, edge_count: 12, attack_path_count: 2 },
      analysis_bounds: { correlation_merge: { status: "complete", truncated: false } },
    } : {},
    manifest_sha256: status === "complete" ? `sha256:${"a".repeat(64)}` : "",
    output_scan_id: status === "complete" ? "corr-1" : "",
    failure_code: status === "failed" ? "analysis_budget_exceeded" : "",
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

  it("loads the latest completed correlation as the primary automated evidence view", async () => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={run("complete")} onOpenSnapshot={vi.fn()} />);

    expect(await screen.findByText("Evidence correlation complete")).toBeInTheDocument();
    expect(screen.getByText("Connect")).toBeInTheDocument();
    expect(screen.getByText("Discover")).toBeInTheDocument();
    expect(screen.getByText("Scan")).toBeInTheDocument();
    expect(screen.getByText("Correlate")).toBeInTheDocument();
    expect(screen.getByText("Prioritize")).toBeInTheDocument();
    expect(screen.getByText("Enforce & verify")).toBeInTheDocument();
    expect(screen.getByText("Image + SBOM")).toBeInTheDocument();
    expect(screen.getByText("Repository")).toBeInTheDocument();
    expect(screen.getByText("2 confirmed attack paths")).toBeInTheDocument();
    expect(screen.queryByLabelText("Correlation name")).not.toBeVisible();
    expect(apiMock.createGraphCorrelation).not.toHaveBeenCalled();
    expect(screen.getByText("Opt-in runtime")).toBeInTheDocument();
  });

  it("keeps custom correlation behind progressive disclosure with safe defaults", async () => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} onOpenSnapshot={vi.fn()} />);

    fireEvent.click(screen.getByText("Run custom correlation"));
    expect(screen.getByLabelText("Maximum evidence age (hours)")).toHaveValue(168);
    expect(screen.getByLabelText("old-correlation")).toBeDisabled();
    expect(screen.getByLabelText("repo")).toBeChecked();
    expect(screen.getByLabelText("image")).toBeChecked();
    const create = screen.getByRole("button", { name: "Correlate selected evidence" });
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
    expect(await screen.findByText("1 conflict retained · bounded analysis")).toBeInTheDocument();
    expect(screen.getByText("2 confirmed attack paths")).toBeInTheDocument();
    expect(screen.getByLabelText("Correlation source receipt graph")).toBeInTheDocument();
    expect(screen.getByText("Evidence correlation complete")).toBeInTheDocument();
    expect(screen.getByText("Image + SBOM")).toBeInTheDocument();
  });

  it("keeps an edited freshness bound truthful", () => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} onOpenSnapshot={vi.fn()} />);
    fireEvent.click(screen.getByText("Run custom correlation"));
    fireEvent.change(screen.getByLabelText("Maximum evidence age (hours)"), { target: { value: "24" } });

    expect(screen.getByText("1-day freshness bound")).toBeInTheDocument();
    expect(screen.getByLabelText(/I confirm the 1-day freshness bound \(24 hours\)/i)).toBeInTheDocument();
    expect(screen.queryByText(/7-day freshness/i)).not.toBeInTheDocument();
  });

  it("shows a terminal failure without a running spinner", () => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={run("failed")} onOpenSnapshot={vi.fn()} />);

    expect(screen.getByText("Evidence correlation failed")).toBeInTheDocument();
    expect(screen.getByText("Failure code: analysis_budget_exceeded")).toBeInTheDocument();
    expect(screen.queryByText("Correlated snapshot")).not.toBeInTheDocument();
  });

  it("opens the completed correlated snapshot", async () => {
    const onOpenSnapshot = vi.fn();
    render(<GraphCorrelationWorkflow snapshots={snapshots} onOpenSnapshot={onOpenSnapshot} />);
    fireEvent.click(screen.getByText("Run custom correlation"));
    fireEvent.click(screen.getByLabelText(/I confirm the 7-day freshness bound/i));
    fireEvent.click(screen.getByRole("button", { name: "Correlate selected evidence" }));

    fireEvent.click(await screen.findByRole("button", { name: "Open correlated snapshot" }));
    expect(onOpenSnapshot).toHaveBeenCalledWith("corr-1");
  });
});
