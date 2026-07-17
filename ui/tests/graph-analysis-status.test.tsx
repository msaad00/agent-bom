import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphAnalysisStatusBanner, graphAnalysisStatusCopy } from "@/components/graph-analysis-status";

describe("GraphAnalysisStatusBanner", () => {
  it("does not present a skipped large-estate analysis as no paths", () => {
    const status = {
      status: "skipped" as const,
      reason_codes: ["node_cap_exceeded"],
      limits: { max_nodes: 5000 },
      observed: { node_count: 5001 },
    };

    const { container } = render(<GraphAnalysisStatusBanner status={status} />);

    expect(screen.getByRole("alert")).toHaveTextContent("Attack-path analysis skipped");
    expect(screen.getByText(/estate exceeded the analysis node cap/)).toBeInTheDocument();
    expect(graphAnalysisStatusCopy(status).detail).not.toMatch(/no attack paths/i);
    expect(container.firstElementChild).toHaveClass("text-red-700", "dark:text-red-200");
  });

  it("marks capped results as partial", () => {
    render(
      <GraphAnalysisStatusBanner
        status={{
          status: "limited",
          reason_codes: ["path_cap_reached"],
          limits: { max_paths: 50 },
          observed: { candidate_path_count: 80, result_count: 50 },
        }}
      />,
    );

    expect(screen.getByRole("status")).toHaveTextContent("Results are partial");
  });

  it("labels legacy snapshots as unverified", () => {
    render(<GraphAnalysisStatusBanner />);
    expect(screen.getByText("Analysis status unavailable")).toBeInTheDocument();
  });
});
