import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  GraphCorrelationWorkflow,
  type GraphCorrelationOutcome,
} from "@/components/graph-correlation-workflow";
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

const outcome: GraphCorrelationOutcome = {
  scanId: "corr-1",
  title: "Public API reaches customer records through CVE-2023-4863",
  summary: "The confirmed path crosses the public service, workload, vulnerable package, MCP tool, and data asset.",
  source: "Public API service",
  target: "Modeled customer records",
  finding: "CVE-2023-4863",
  packageName: "pillow@9.0.0",
  risk: 9.8,
  hops: 7,
  runtimeObserved: true,
  runtimeBlocked: true,
  action: { title: "Open pillow@9.0.0 remediation", href: "/remediation?scan=corr-1&cve=CVE-2023-4863&package=pillow%409.0.0" },
};

function run(
  status: GraphCorrelationRun["status"],
  overrides: Partial<GraphCorrelationRun> = {},
): GraphCorrelationRun {
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
      analysis_bounds: {
        correlation_merge: { status: "complete", truncated: false },
        attack_path_fusion: { status: "complete", truncated: false },
      },
    } : {},
    manifest_sha256: status === "complete" ? `sha256:${"a".repeat(64)}` : "",
    output_scan_id: status === "complete" ? "corr-1" : "",
    failure_code: status === "failed" ? "analysis_budget_exceeded" : "",
    created_at: "2026-08-30T00:03:00Z",
    started_at: "",
    completed_at: status === "complete" ? "2026-08-30T00:04:00Z" : "",
    ...overrides,
  };
}

describe("GraphCorrelationWorkflow", () => {
  beforeEach(() => {
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-08-31T00:00:00Z"));
    apiMock.createGraphCorrelation.mockReset();
    apiMock.getGraphCorrelation.mockReset();
    apiMock.createGraphCorrelation.mockResolvedValue(run("complete"));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("loads the latest completed correlation as the primary automated evidence view", async () => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={run("complete")} outcome={outcome} onOpenSnapshot={vi.fn()} />);

    expect(await screen.findByTestId("graph-correlation-decision")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Review prioritized path preview"));
    expect(screen.getByText(outcome.title)).toBeInTheDocument();
    expect(screen.getByText("Risk 9.8")).toBeInTheDocument();
    expect(screen.getByText("7 directed hops")).toBeInTheDocument();
    expect(screen.getByText("Runtime observed")).toBeInTheDocument();
    expect(screen.getByText("Runtime block verified")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open pillow@9.0.0 remediation" })).toHaveAttribute(
      "href",
      "/remediation?scan=corr-1&cve=CVE-2023-4863&package=pillow%409.0.0",
    );
    expect(screen.queryByText("Connect")).not.toBeVisible();
    expect(screen.getByText("2 confirmed paths across 2 sources")).toBeInTheDocument();
    expect(screen.queryByLabelText("Correlation name")).not.toBeVisible();
    expect(apiMock.createGraphCorrelation).not.toHaveBeenCalled();
    expect(screen.getByText("Fresh evidence")).toBeInTheDocument();
  });

  it("keeps the duplicated path preview behind progressive disclosure", async () => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={run("complete")} outcome={outcome} onOpenSnapshot={vi.fn()} />);

    expect(await screen.findByTestId("graph-correlation-decision")).toBeInTheDocument();
    expect(screen.getByText("Review prioritized path preview")).toBeInTheDocument();
    expect(screen.getByText(outcome.title)).not.toBeVisible();
    expect(screen.getByRole("button", { name: "Open top path" })).toBeVisible();
  });

  it("does not preselect evidence outside the confirmed freshness bound", () => {
    const stale = { ...snapshots[0]!, scan_id: "stale-repo", created_at: "2026-08-01T00:00:00Z" };
    render(<GraphCorrelationWorkflow snapshots={[stale, snapshots[1]!]} onOpenSnapshot={vi.fn()} />);

    fireEvent.click(screen.getByText("Run custom correlation"));
    expect(screen.getByLabelText("stale-repo")).toBeDisabled();
    expect(screen.getByLabelText("stale-repo")).not.toBeChecked();
    expect(screen.getByText("Outside freshness bound")).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText("Allow stale inputs and label them stale"));
    expect(screen.getByLabelText("stale-repo")).toBeEnabled();
    expect(screen.getByLabelText("stale-repo")).not.toBeChecked();
    fireEvent.click(screen.getByLabelText("stale-repo"));
    expect(screen.getByLabelText("stale-repo")).toBeChecked();
  });

  it("keeps custom correlation behind progressive disclosure with safe defaults", async () => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} onOpenSnapshot={vi.fn()} />);

    fireEvent.click(screen.getByText("Run custom correlation"));
    expect(screen.getAllByText("Run name")).toHaveLength(1);
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
    expect(await screen.findByText("2 confirmed paths across 2 sources")).toBeInTheDocument();
    expect(screen.getByText("1 conflict")).toBeInTheDocument();
    expect(screen.getByText("Inspect source receipts · 2 sources · 1 conflict")).toBeInTheDocument();
    expect(screen.queryByText("Image + SBOM")).not.toBeVisible();
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

    expect(screen.getByText("Correlation failed")).toBeInTheDocument();
    expect(screen.getByText("Failure code: analysis_budget_exceeded")).toBeInTheDocument();
    expect(screen.queryByText("Correlated snapshot")).not.toBeInTheDocument();
    expect(screen.getByText("Analysis failed")).toBeInTheDocument();
    expect(screen.queryByText("Analysis complete")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Open top path/i })).not.toBeInTheDocument();
  });

  it("opens the top path in the completed correlated snapshot", async () => {
    const onOpenSnapshot = vi.fn();
    render(<GraphCorrelationWorkflow snapshots={snapshots} onOpenSnapshot={onOpenSnapshot} />);
    fireEvent.click(screen.getByText("Run custom correlation"));
    fireEvent.click(screen.getByLabelText(/I confirm the 7-day freshness bound/i));
    fireEvent.click(screen.getByRole("button", { name: "Correlate selected evidence" }));

    fireEvent.click(await screen.findByRole("button", { name: "Open top path" }));
    expect(onOpenSnapshot).toHaveBeenCalledWith("corr-1");
  });

  it("suppresses an outcome loaded from a different snapshot", () => {
    render(
      <GraphCorrelationWorkflow
        snapshots={snapshots}
        initialRun={run("complete")}
        outcome={{ ...outcome, scanId: "other-correlation" }}
        onOpenSnapshot={vi.fn()}
      />,
    );

    expect(screen.queryByText(outcome.title)).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Open pillow@9.0.0 remediation" })).not.toBeInTheDocument();
    expect(screen.getByText(/Load this correlation's output to review its prioritized paths/i)).toBeInTheDocument();
  });

  it("offers exposure candidates when a complete correlation has zero paths", () => {
    const zeroPathRun = run("complete", {
      result_manifest: {
        correlation_merge: { conflict_count: 0 },
        output: { scan_id: "corr-1", node_count: 11, edge_count: 12, attack_path_count: 0 },
        analysis_bounds: {
          correlation_merge: { status: "complete", truncated: false },
          attack_path_fusion: { status: "complete", truncated: false },
        },
      },
    });
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={zeroPathRun} outcome={null} onOpenSnapshot={vi.fn()} />);

    expect(screen.getByText("No confirmed attack path in this correlation")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review exposure candidates" })).toHaveAttribute(
      "href",
      "/security-graph?lens=attack-path&scan=corr-1",
    );
  });

  it("does not claim no confirmed path when a zero-path result is incomplete", () => {
    const limitedZeroPathRun = run("complete", {
      result_manifest: {
        correlation_merge: { conflict_count: 0 },
        output: { scan_id: "corr-1", node_count: 11, edge_count: 12, attack_path_count: 0 },
        analysis_bounds: {
          correlation_merge: { status: "complete", truncated: false },
          attack_path_fusion: { status: "limited", truncated: true },
        },
      },
    });
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={limitedZeroPathRun} outcome={null} onOpenSnapshot={vi.fn()} />);

    expect(screen.getByText(/0 retained paths; analysis is limited/i)).toBeInTheDocument();
    expect(screen.queryByText("No confirmed attack path in this correlation")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review exposure candidates" })).toBeInTheDocument();
  });

  it("does not present stale allowed evidence as fresh verification", () => {
    const staleRun = run("complete", {
      allow_stale: true,
      input_manifest: [
        { scan_id: "image", freshness: "stale_allowed", node_count: 8, edge_count: 7, source_kinds: ["cyclonedx_sbom"] },
        { scan_id: "repo", freshness: "fresh", node_count: 4, edge_count: 3, source_kinds: ["repository_parser"] },
      ],
    });
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={staleRun} outcome={outcome} onOpenSnapshot={vi.fn()} />);

    expect(screen.getByText(/stale source allowed/i)).toBeInTheDocument();
    expect(screen.queryByText(/confirmed paths across/i)).not.toBeInTheDocument();
    expect(screen.queryByText("Fresh evidence")).not.toBeInTheDocument();
  });

  it.each([
    ["limited", { attack_path_fusion: { status: "limited", truncated: false } }, "Analysis limited — inspect bounds"],
    ["truncated", { attack_path_fusion: { status: "complete", truncated: true } }, "Analysis limited — inspect bounds"],
    ["skipped", { attack_path_fusion: { status: "skipped", truncated: false } }, "Analysis skipped — inspect bounds"],
    ["failed", { attack_path_fusion: { status: "failed", truncated: false } }, "Analysis failed"],
  ])("reports %s analysis bounds without claiming completion", (_label, analysisBounds, expected) => {
    const boundedRun = run("complete", {
      result_manifest: {
        correlation_merge: { conflict_count: 0 },
        output: { scan_id: "corr-1", node_count: 11, edge_count: 12, attack_path_count: 2 },
        analysis_bounds: {
          correlation_merge: { status: "complete", truncated: false },
          ...analysisBounds,
        },
      },
    });
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={boundedRun} outcome={outcome} onOpenSnapshot={vi.fn()} />);

    expect(screen.getByText(expected)).toBeInTheDocument();
    expect(screen.queryByText("Analysis complete")).not.toBeInTheDocument();
  });

  it.each(["pending", "running"] as const)("reports %s run analysis as in progress", (status) => {
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={run(status)} onOpenSnapshot={vi.fn()} />);

    expect(screen.getByText("Analysis in progress")).toBeInTheDocument();
    expect(screen.queryByText("Analysis complete")).not.toBeInTheDocument();
  });

  it("does not infer analysis completion when bounds are missing", () => {
    const missingBounds = run("complete", {
      result_manifest: {
        correlation_merge: { conflict_count: 0 },
        output: { scan_id: "corr-1", node_count: 11, edge_count: 12, attack_path_count: 2 },
      },
    });
    render(<GraphCorrelationWorkflow snapshots={snapshots} initialRun={missingBounds} outcome={outcome} onOpenSnapshot={vi.fn()} />);

    expect(screen.getByText("Analysis status unavailable")).toBeInTheDocument();
    expect(screen.queryByText("Analysis complete")).not.toBeInTheDocument();
  });
});
