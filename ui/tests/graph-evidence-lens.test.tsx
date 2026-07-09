import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GraphEvidenceLegend } from "@/components/graph-evidence-legend";
import { evidenceLensPasses } from "@/lib/filter-algebra";

describe("evidenceLensPasses", () => {
  it("matches runtime tiers when a chip is active", () => {
    expect(evidenceLensPasses("runtime_observed", "runtime_observed")).toBe(true);
    expect(evidenceLensPasses("runtime_blocked", "runtime_observed")).toBe(false);
    expect(evidenceLensPasses(undefined, "static_scan")).toBe(true);
    expect(evidenceLensPasses("static_scan", "all")).toBe(true);
  });
});

describe("GraphEvidenceLegend", () => {
  it("renders chips when armed", () => {
    render(
      <GraphEvidenceLegend
        active
        onToggleActive={vi.fn()}
        filter="all"
        onFilterChange={vi.fn()}
        counts={{
          all: 10,
          runtime_observed: 3,
          runtime_blocked: 1,
          static_scan: 6,
        }}
      />,
    );
    expect(screen.getByTestId("graph-evidence-chip-runtime_observed")).toHaveTextContent(
      "3",
    );
    expect(screen.getByTestId("graph-evidence-chip-runtime_blocked")).toHaveTextContent(
      "1",
    );
  });

  it("fires filter changes from chips", () => {
    const onFilterChange = vi.fn();
    render(
      <GraphEvidenceLegend
        active
        onToggleActive={vi.fn()}
        filter="all"
        onFilterChange={onFilterChange}
        counts={{ all: 1, runtime_observed: 1, runtime_blocked: 0, static_scan: 0 }}
      />,
    );
    fireEvent.click(screen.getByTestId("graph-evidence-chip-runtime_observed"));
    expect(onFilterChange).toHaveBeenCalledWith("runtime_observed");
  });
});
