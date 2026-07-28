import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphEvidenceSummary } from "@/components/graph-evidence-summary";

describe("GraphEvidenceSummary", () => {
  it("shows factual snapshot completeness, freshness, and provenance without a quality score", () => {
    render(
      <GraphEvidenceSummary
        capturedAt="2026-07-24T20:00:00Z"
        returnedNodes={34}
        totalNodes={34}
        snapshotTotalNodes={36}
        evidencedEdges={7}
        totalEdges={142}
        completeness="complete"
      />,
    );

    expect(screen.getByText(/34 of 36 nodes in current scope/i)).toBeInTheDocument();
    expect(screen.getByText(/Complete for current scope/i)).toBeInTheDocument();
    expect(screen.getByText(/7 of 142 relationships/i)).toBeInTheDocument();
    expect(screen.getByText(/Captured/i)).toBeInTheDocument();
    expect(screen.queryByText(/quality|score|usable/i)).not.toBeInTheDocument();
  });

  it("renders unavailable instead of fabricating zero when provenance is not reported", () => {
    render(
      <GraphEvidenceSummary
        capturedAt={null}
        returnedNodes={3}
        totalNodes={3}
        snapshotTotalNodes={null}
        evidencedEdges={null}
        totalEdges={null}
        completeness="complete"
      />,
    );

    expect(screen.getAllByText("Unavailable").length).toBeGreaterThanOrEqual(2);
  });

  it("does not present a truncated traversal as an exhaustive N of N total", () => {
    render(
      <GraphEvidenceSummary
        capturedAt="2026-07-24T20:00:00Z"
        returnedNodes={2}
        totalNodes={null}
        snapshotTotalNodes={36}
        evidencedEdges={1}
        totalEdges={1}
        completeness="truncated"
        completenessReason="traversal_budget"
      />,
    );

    expect(screen.getByText(/2 nodes returned.*36 nodes in snapshot/i)).toBeInTheDocument();
    expect(screen.getByText(/Traversal budget/i)).toBeInTheDocument();
    expect(screen.queryByText(/2 of 2 nodes/i)).not.toBeInTheDocument();
  });

  it("hides topology counts when the canvas is roll-up navigation", () => {
    render(
      <GraphEvidenceSummary
        capturedAt="2026-07-24T20:00:00Z"
        returnedNodes={36}
        totalNodes={36}
        snapshotTotalNodes={36}
        evidencedEdges={4}
        totalEdges={4}
        completeness="complete"
        showCompleteness={false}
        showRelationships={false}
      />,
    );

    expect(screen.getByText(/Captured/i)).toBeInTheDocument();
    expect(screen.queryByText(/nodes in current scope/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/relationships/i)).not.toBeInTheDocument();
  });
});
