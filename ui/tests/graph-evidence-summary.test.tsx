import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphEvidenceSummary } from "@/components/graph-evidence-summary";

describe("GraphEvidenceSummary", () => {
  it("shows factual snapshot completeness, freshness, and provenance without a quality score", () => {
    render(
      <GraphEvidenceSummary
        capturedAt="2026-07-24T20:00:00Z"
        returnedNodes={93}
        totalNodes={112}
        evidencedEdges={7}
        totalEdges={142}
        completeness="truncated"
      />,
    );

    expect(screen.getByText(/93 of 112 nodes/i)).toBeInTheDocument();
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
        evidencedEdges={null}
        totalEdges={null}
        completeness="complete"
      />,
    );

    expect(screen.getAllByText("Unavailable").length).toBeGreaterThanOrEqual(2);
  });
});
