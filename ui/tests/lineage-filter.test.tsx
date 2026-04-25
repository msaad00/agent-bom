import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  DEFAULT_FILTERS,
  FilterPanel,
  type FilterState,
} from "@/components/lineage-filter";

function renderFilterPanel(agentNames: string[], filters: FilterState = DEFAULT_FILTERS) {
  const onChange = vi.fn();
  render(<FilterPanel filters={filters} onChange={onChange} agentNames={agentNames} />);
  return onChange;
}

describe("FilterPanel", () => {
  it("windows large agent lists instead of rendering every agent option", () => {
    const agents = Array.from({ length: 5000 }, (_, index) => `agent-${index.toString().padStart(4, "0")}`);
    renderFilterPanel(agents);

    expect(screen.getByLabelText("Filter graph agents")).toBeInTheDocument();
    expect(screen.getByText("agent-0000")).toBeInTheDocument();
    expect(screen.queryByText("agent-4999")).not.toBeInTheDocument();
    expect(screen.getByText("Showing 16 of 5,000 matches.")).toBeInTheDocument();
  });

  it("filters the virtualized agent picker and preserves selection semantics", () => {
    const agents = ["Claude Desktop", "Cursor", "OpenAI Codex", "Windsurf"];
    const onChange = renderFilterPanel(agents);

    fireEvent.change(screen.getByLabelText("Filter graph agents"), { target: { value: "codex" } });
    fireEvent.click(screen.getByRole("option", { name: "OpenAI Codex" }));

    expect(onChange).toHaveBeenCalledWith({
      ...DEFAULT_FILTERS,
      agentName: "OpenAI Codex",
    });
  });
});
