import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphEvaluationSummary } from "@/components/graph-evaluation-summary";
import type { GraphUxEvaluation } from "@/lib/graph-ux-evaluation";

describe("GraphEvaluationSummary", () => {
  it("renders score dimensions and bounded warnings", () => {
    const evaluation: GraphUxEvaluation = {
      score: 84,
      grade: "strong",
      dimensions: [
        { id: "entities", label: "Entities", score: 88, detail: "7 types" },
        { id: "relationships", label: "Relationships", score: 76, detail: "6 types" },
        { id: "paths", label: "Paths", score: 95, detail: "3 ranked" },
        { id: "evidence", label: "Evidence", score: 80, detail: "71% edge evidence" },
        { id: "readability", label: "Readability", score: 82, detail: "42/90 nodes visible" },
      ],
      warnings: ["Few relationships carry evidence metadata.", "The visible canvas is dense; use filters or search for review."],
      stats: {
        sourceNodes: 90,
        sourceEdges: 140,
        renderedNodes: 42,
        renderedEdges: 80,
        entityTypes: 7,
        relationshipTypes: 6,
        attackPaths: 3,
        edgeEvidenceRatio: 0.71,
        nodeSourceRatio: 0.8,
        edgeToNodeRatio: 1.55,
      },
    };

    render(<GraphEvaluationSummary evaluation={evaluation} />);

    expect(screen.getByTestId("graph-evaluation-summary")).toBeInTheDocument();
    expect(screen.getByText("strong")).toBeInTheDocument();
    expect(screen.getByText("84")).toBeInTheDocument();
    expect(screen.getByText("Entities")).toBeInTheDocument();
    expect(screen.getByText("Relationships")).toBeInTheDocument();
    expect(screen.getByText("Few relationships carry evidence metadata.")).toBeInTheDocument();
  });
});
