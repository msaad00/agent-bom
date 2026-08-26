import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GraphRollupDecisionSurface } from "@/components/graph-rollup-decision-surface";
import type { GraphRollupContainer } from "@/lib/api-types";

function item(
  id: string,
  overrides: Partial<GraphRollupContainer> = {},
): GraphRollupContainer {
  return {
    id,
    label: `Scope ${id}`,
    entity_type: "account",
    severity: "none",
    is_container: true,
    has_children: true,
    direct_child_count: 2,
    aggregate: {
      descendant_count: 8,
      by_type: { server: 3, package: 5 },
      severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, none: 8 },
      worst_severity: "none",
      worst_severity_rank: 0,
      internet_exposed: false,
      toxic_combo: false,
      exposed_count: 0,
      toxic_count: 0,
    },
    ...overrides,
  };
}

describe("GraphRollupDecisionSurface", () => {
  it("uses a compact full-width layout when one scope matches", () => {
    render(
      <GraphRollupDecisionSurface
        items={[item("only-scope")]}
        edges={[]}
        onDrill={vi.fn()}
        onInvestigate={vi.fn()}
        onShowMap={vi.fn()}
      />,
    );

    expect(screen.getByTestId("graph-rollup-decision-surface")).toHaveAttribute(
      "data-layout",
      "compact",
    );
    expect(screen.getByTestId("graph-rollup-card-grid")).toHaveClass(
      "grid-cols-1",
    );
    expect(screen.getByTestId("graph-rollup-card-grid")).not.toHaveClass(
      "flex-1",
    );
  });

  it("opens large estate levels as paged risk decisions instead of an unreadable canvas", () => {
    const critical = item("critical", {
      severity: "critical",
      aggregate: {
        ...item("base").aggregate,
        worst_severity: "critical",
        worst_severity_rank: 5,
        internet_exposed: true,
        toxic_combo: true,
        severity_counts: { critical: 2, high: 3 },
      },
    });
    const items = [critical, ...Array.from({ length: 24 }, (_, index) => item(`quiet-${index}`))];
    const onDrill = vi.fn();
    const onInvestigate = vi.fn();
    const onShowMap = vi.fn();

    render(
      <GraphRollupDecisionSurface
        items={items}
        edges={[{ source: "critical", target: "quiet-0", count: 7, relationships: ["accesses"] }]}
        onDrill={onDrill}
        onInvestigate={onInvestigate}
        onShowMap={onShowMap}
      />,
    );

    expect(screen.getByText("Risk-prioritized scopes")).toBeInTheDocument();
    expect(screen.getByText("Toxic combination")).toBeInTheDocument();
    expect(screen.getByText("Internet exposed")).toBeInTheDocument();
    expect(screen.getByText("1 scopes")).toBeInTheDocument();
    expect(screen.queryByText("Scope quiet-23")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Drill in" }));
    expect(onDrill).toHaveBeenCalledWith(critical);
    fireEvent.click(screen.getByRole("button", { name: /Traverse/i }));
    expect(onInvestigate).toHaveBeenCalledWith(critical);
    fireEvent.click(screen.getByRole("button", { name: /Relationship map/i }));
    expect(onShowMap).toHaveBeenCalledTimes(1);
  });

  it("paginates the all-scopes view without growing a long vertical page", () => {
    const items = Array.from({ length: 25 }, (_, index) => item(`scope-${index}`));
    render(
      <GraphRollupDecisionSurface
        items={items}
        edges={[]}
        onDrill={vi.fn()}
        onInvestigate={vi.fn()}
        onShowMap={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "All 25" }));
    expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("Showing 12 of 25 matching scopes")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next scope page" }));
    expect(screen.getByText("Page 2 of 3")).toBeInTheDocument();
  });

  it("shows independent node and relationship truncation without claiming an exhaustive map", () => {
    render(
      <GraphRollupDecisionSurface
        items={[item("bounded")]}
        edges={[]}
        completeness={{
          status: "truncated",
          complete: false,
          sampled: false,
          truncated: true,
          returned: 1,
          total: 12,
          reason: "node_budget",
        }}
        edgeCountMetadata={{
          definition: "Aggregated relationship rows",
          source_total: 517,
          returned: 400,
          truncated: true,
          source_truncated: true,
          reason: "node_budget,rollup_edge_limit",
        }}
        onDrill={vi.fn()}
        onInvestigate={vi.fn()}
        onShowMap={vi.fn()}
      />,
    );

    expect(screen.getByText(/1 returned from a bounded node scope/i)).toBeInTheDocument();
    expect(screen.getByTestId("graph-rollup-relationship-completeness")).toHaveTextContent(
      "400 of 517 aggregated relationship rows returned from a bounded source graph · estate total unavailable",
    );
    expect(screen.queryByText(/complete for this scope/i)).not.toBeInTheDocument();
  });

  it("does not infer relationship completeness when the API metadata is absent", () => {
    render(
      <GraphRollupDecisionSurface
        items={[item("legacy")]}
        edges={[]}
        onDrill={vi.fn()}
        onInvestigate={vi.fn()}
        onShowMap={vi.fn()}
      />,
    );

    expect(screen.getByTestId("graph-rollup-relationship-completeness")).toHaveTextContent(
      "0 aggregated relationship rows returned · completeness unavailable",
    );
  });
});
