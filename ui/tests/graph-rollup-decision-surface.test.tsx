import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GraphRollupDecisionSurface, InvestigationViewSwitch } from "@/components/graph-rollup-decision-surface";
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
  it("combines type and context search without inventing matches", () => {
    render(<GraphRollupDecisionSurface items={[
      item("prod-agent", { entity_type: "agent", context: { environment: "production" } }),
      item("dev-agent", { entity_type: "agent", context: { environment: "development" } }),
      item("prod-server", { entity_type: "server", context: { environment: "production" } }),
    ]} edges={[]} onDrill={vi.fn()} onInvestigate={vi.fn()} />);
    fireEvent.click(screen.getByText("Filter nodes and scopes"));
    fireEvent.change(screen.getByLabelText("Asset type"), { target: { value: "agent" } });
    fireEvent.change(screen.getByLabelText("Search this scope"), { target: { value: "production" } });
    expect(screen.getByText("Scope prod-agent")).toBeInTheDocument();
    expect(screen.queryByText("Scope dev-agent")).not.toBeInTheDocument();
    expect(screen.queryByText("Scope prod-server")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search this scope"), { target: { value: "absent" } });
    expect(screen.getByRole("status")).toHaveTextContent("No nodes match");
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByText("Scope dev-agent")).toBeInTheDocument();
  });

  it("bounds relationship details and preserves direction and type", () => {
    render(<GraphRollupDecisionSurface items={[item("root"), item("neighbor")]} edges={
      Array.from({ length: 15 }, () => ({ source: "neighbor", target: "root", count: 2, relationships: ["uses"] }))
    } onDrill={vi.fn()} onInvestigate={vi.fn()} />);
    expect(screen.getAllByRole("button", { name: "Inspect relationship endpoint Scope neighbor (neighbor)" })).toHaveLength(24);
    expect(screen.getAllByText("Showing 12 of 15 rows.")).toHaveLength(2);
    expect(screen.getAllByText(/do not establish runtime execution/)).toHaveLength(2);
  });

  it("investigates the exact endpoint when labels collide and keeps unknown endpoints literal", () => {
    const onInvestigate = vi.fn();
    const selected = item("prod", { label: "Shared name" });
    render(<GraphRollupDecisionSurface items={[selected, item("dev", { label: "Shared name" })]}
      edges={[{ source: "prod", target: "external-id", count: 1, relationships: ["stores"] }]}
      onDrill={vi.fn()} onInvestigate={onInvestigate} />);
    fireEvent.click(screen.getByRole("button", { name: "Inspect relationship endpoint Shared name (prod)" }));
    expect(onInvestigate).toHaveBeenCalledWith(selected);
    expect(screen.getByText("external-id")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /external-id/ })).not.toBeInTheDocument();
    expect(screen.getByText(/Coverage may be incomplete/)).toBeInTheDocument();
  });

  it("keeps an explicit return to summary available from the graph", () => {
    const onSummary = vi.fn();
    const onGraph = vi.fn();
    render(<InvestigationViewSwitch summary={false} onSummary={onSummary} onGraph={onGraph} />);
    expect(screen.getByRole("button", { name: "Graph" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(screen.getByRole("button", { name: "Summary" }));
    expect(onSummary).toHaveBeenCalledOnce();
    expect(screen.getAllByRole("button")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Graph" }));
    expect(onGraph).toHaveBeenCalledOnce();
  });
  it("prioritizes a rated leaf without fabricating contained assets or findings", () => {
    const leaf = item("vulnerable", {
      label: "Affected package", entity_type: "package", severity: "critical",
      has_children: false, is_container: false, direct_child_count: 0,
      aggregate: { ...item("base").aggregate, descendant_count: 0 },
    });
    render(<GraphRollupDecisionSurface items={[item("quiet"), leaf]} edges={[]}
      onDrill={vi.fn()} onInvestigate={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Priority 1" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.queryByText("Scope quiet")).not.toBeInTheDocument();
    expect(screen.queryByText("Contains")).not.toBeInTheDocument();
    expect(screen.queryByText("0 / 0")).not.toBeInTheDocument();
  });

  it("uses a compact full-width layout when one scope matches", () => {
    render(
      <GraphRollupDecisionSurface
        items={[item("only-scope")]}
        edges={[]}
        onDrill={vi.fn()}
        onInvestigate={vi.fn()}

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

    render(
      <GraphRollupDecisionSurface
        items={items}
        edges={[{ source: "critical", target: "quiet-0", count: 7, relationships: ["accesses"] }]}
        onDrill={onDrill}
        onInvestigate={onInvestigate}
      />,
    );

    expect(screen.getByText("Prioritized findings and scopes")).toBeInTheDocument();
    expect(screen.getByText("Toxic combination in scope")).toBeInTheDocument();
    expect(screen.getByText("Exposure in scope")).toBeInTheDocument();
    expect(screen.queryByText("Internet exposed", { exact: true })).not.toBeInTheDocument();
    const exposedFilter = screen.getByRole("button", { name: "Exposure in scope 1" });
    fireEvent.click(exposedFilter);
    expect(exposedFilter).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("1 connected node")).toBeInTheDocument();
    expect(screen.queryByText("Scope quiet-23")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Drill in" }));
    expect(onDrill).toHaveBeenCalledWith(critical);
    fireEvent.click(screen.getByRole("button", { name: /Traverse/i }));
    expect(onInvestigate).toHaveBeenCalledWith(critical);
  });

  it("paginates the all-scopes view without growing a long vertical page", () => {
    const items = Array.from({ length: 25 }, (_, index) => item(`scope-${index}`));
    render(
      <GraphRollupDecisionSurface
        items={items}
        edges={[]}
        onDrill={vi.fn()}
        onInvestigate={vi.fn()}

      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "All 25" }));
    expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("Showing 12 of 25 matching nodes and scopes")).toBeInTheDocument();
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

      />,
    );

    expect(screen.getByTestId("graph-rollup-relationship-completeness")).toHaveTextContent(
      "0 aggregated relationship rows returned · completeness unavailable",
    );
  });
});

it("distinguishes package instances and exposes canonical IDs with their actions", () => {
  const onInspect = vi.fn();
  const items = ["billing", "claims"].map((name) => item(`pkg:${name}`, {
    label: "pyyaml@5.3", entity_type: "package", has_children: false,
    context: { image: `${name}:1.0`, environment: "production" },
  }));
  render(<GraphRollupDecisionSurface items={items} edges={[]} onDrill={vi.fn()} onInvestigate={onInspect} />);
  expect(screen.getByText(/billing:1.0/)).toBeInTheDocument();
  expect(screen.getByText(/claims:1.0/)).toBeInTheDocument();
  expect(screen.getByText("pkg:billing")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Inspect.*pkg:claims/ }));
  expect(onInspect).toHaveBeenCalledWith(items[1]);
});
