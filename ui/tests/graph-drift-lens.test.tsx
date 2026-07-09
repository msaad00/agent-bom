import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GraphDriftLegend } from "@/components/graph-drift-legend";
import {
  buildDriftIndex,
  changeKindForEdge,
  changeKindForNode,
  driftAttributeSummaries,
  driftLegendItems,
  type ChangeKind,
} from "@/lib/graph-utils";
import {
  driftFilterPasses,
  isCriticalChange,
  DRIFT_LENS_FILTERS,
  type DriftLensFilter,
} from "@/lib/filter-algebra";
import type { GraphDiffResponse } from "@/lib/api-types";

const DIFF: GraphDiffResponse = {
  nodes_added: [],
  nodes_removed: [],
  nodes_changed: [],
  edges_added: [],
  edges_removed: [],
  change_kind_index: {
    nodes: {
      "agent:new": "new",
      "vuln:changed": "changed",
      "agent:gone": "removed",
    },
    edges: {
      "agent:new|server:s|uses": "new",
    },
  },
};

const COUNTS: Record<ChangeKind, number> = {
  new: 1,
  changed: 1,
  removed: 1,
  unchanged: 4,
};

describe("drift index helpers", () => {
  it("classifies nodes and edges from the change_kind_index", () => {
    const index = buildDriftIndex(DIFF);
    expect(index.hasChanges).toBe(true);
    expect(changeKindForNode("agent:new", index)).toBe("new");
    expect(changeKindForNode("vuln:changed", index)).toBe("changed");
    expect(changeKindForNode("agent:gone", index)).toBe("removed");
    // Anything not in the index is stable estate.
    expect(changeKindForNode("server:s", index)).toBe("unchanged");
    expect(changeKindForEdge("agent:new", "server:s", "uses", index)).toBe(
      "new",
    );
    expect(changeKindForEdge("x", "y", "uses", index)).toBe("unchanged");
    expect(index.counts.new).toBe(1);
    expect(index.counts.removed).toBe(1);
  });

  it("is inert for an empty or missing diff", () => {
    expect(buildDriftIndex(null).hasChanges).toBe(false);
    expect(
      buildDriftIndex({
        nodes_added: [],
        nodes_removed: [],
        nodes_changed: [],
        edges_added: [],
        edges_removed: [],
      }).hasChanges,
    ).toBe(false);
  });

  it("emits a legend row per change kind with counts", () => {
    const items = driftLegendItems(COUNTS);
    expect(items.map((i) => i.label)).toEqual([
      "New · 1",
      "Changed · 1",
      "Removed · 1",
      "Unchanged · 4",
    ]);
  });

  it("collects attribute delta summaries from the diff payload", () => {
    const index = buildDriftIndex({
      ...DIFF,
      attribute_deltas: {
        "cloud:pii-bucket": [
          {
            field: "internet_exposed",
            before: false,
            after: true,
            summary: "Public exposure opened",
          },
        ],
      },
    });
    expect(driftAttributeSummaries(index)).toEqual(["Public exposure opened"]);
  });
});

describe("drift filter predicates", () => {
  it("passes only the matching kind for single-kind chips", () => {
    expect(driftFilterPasses("new", "new", false)).toBe(true);
    expect(driftFilterPasses("changed", "new", false)).toBe(false);
    expect(driftFilterPasses("unchanged", "all", false)).toBe(true);
  });

  it("routes the critical chip through the isCritical flag", () => {
    expect(driftFilterPasses("changed", "critical", true)).toBe(true);
    expect(driftFilterPasses("changed", "critical", false)).toBe(false);
  });

  it("marks new/changed high-severity assets as critical changes", () => {
    expect(isCriticalChange("new", "critical")).toBe(true);
    expect(isCriticalChange("changed", "high")).toBe(true);
    expect(isCriticalChange("changed", "medium")).toBe(false);
    // Removed assets are surfaced by their own chip, not "critical".
    expect(isCriticalChange("removed", "critical")).toBe(false);
    expect(isCriticalChange("new", undefined)).toBe(false);
  });
});

describe("GraphDriftLegend component", () => {
  function renderLegend(overrides: Partial<{
    active: boolean;
    filter: DriftLensFilter;
    onToggleActive: (next: boolean) => void;
    onFilterChange: (f: DriftLensFilter) => void;
  }> = {}) {
    const onToggleActive = overrides.onToggleActive ?? vi.fn();
    const onFilterChange = overrides.onFilterChange ?? vi.fn();
    render(
      <GraphDriftLegend
        active={overrides.active ?? true}
        onToggleActive={onToggleActive}
        filter={overrides.filter ?? "all"}
        onFilterChange={onFilterChange}
        counts={COUNTS}
        criticalCount={2}
        comparedLabel="abc123def456"
      />,
    );
    return { onToggleActive, onFilterChange };
  }

  it("renders the legend swatches and every chip when armed", () => {
    renderLegend({ active: true });
    expect(screen.getByTestId("graph-drift-legend")).toBeInTheDocument();
    // One legend item per change kind.
    for (const kind of ["new", "changed", "removed", "unchanged"] as ChangeKind[]) {
      expect(
        screen.getByTestId(`graph-drift-legend-item-${kind}`),
      ).toBeInTheDocument();
    }
    // One chip per drift filter.
    for (const chip of DRIFT_LENS_FILTERS) {
      expect(
        screen.getByTestId(`graph-drift-chip-${chip}`),
      ).toBeInTheDocument();
    }
    // Critical chip surfaces the critical count passed in.
    expect(screen.getByTestId("graph-drift-chip-critical").textContent).toContain(
      "2",
    );
  });

  it("hides chips until the lens is armed", () => {
    renderLegend({ active: false });
    expect(screen.queryByTestId("graph-drift-chips")).not.toBeInTheDocument();
    expect(screen.getByTestId("graph-drift-toggle").textContent).toContain(
      "Lens off",
    );
  });

  it("fires the filter callback when a chip is clicked", () => {
    const { onFilterChange } = renderLegend({ active: true, filter: "all" });
    fireEvent.click(screen.getByTestId("graph-drift-chip-new"));
    expect(onFilterChange).toHaveBeenCalledWith("new");
    fireEvent.click(screen.getByTestId("graph-drift-chip-critical"));
    expect(onFilterChange).toHaveBeenCalledWith("critical");
  });

  it("toggles the lens on/off through the switch", () => {
    const { onToggleActive } = renderLegend({ active: false });
    fireEvent.click(screen.getByTestId("graph-drift-toggle"));
    expect(onToggleActive).toHaveBeenCalledWith(true);
  });

  it("renders attribute drift summaries when provided", () => {
    render(
      <GraphDriftLegend
        active
        onToggleActive={vi.fn()}
        filter="all"
        onFilterChange={vi.fn()}
        counts={COUNTS}
        criticalCount={2}
        attributeSummaries={["Public exposure opened"]}
      />,
    );
    expect(screen.getByTestId("graph-drift-attribute-summaries")).toHaveTextContent(
      "Public exposure opened",
    );
  });
});
