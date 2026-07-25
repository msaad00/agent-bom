import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  DEFAULT_FILTERS,
  FilterPanel,
  createAssetLifecycleDriftGraphFilters,
  createCloudEstateGraphFilters,
  createEnvironmentGraphFilters,
  createExpandedGraphFilters,
  createImmediateGraphFilters,
  createRepositoryGraphFilters,
  GRAPH_SCOPE_DESCRIPTIONS,
  graphScopeLabelForFilters,
  graphScopePresetForFilters,
  type FilterState,
} from "@/components/lineage-filter";

function renderFilterPanel(agentNames: string[], filters: FilterState = DEFAULT_FILTERS) {
  const onChange = vi.fn();
  render(<FilterPanel filters={filters} onChange={onChange} agentNames={agentNames} />);
  return onChange;
}

describe("FilterPanel", () => {
  it("defaults to a bounded, readable graph scope", () => {
    expect(DEFAULT_FILTERS.maxDepth).toBe(2);
    expect(DEFAULT_FILTERS.pageSize).toBe(50);
    expect(DEFAULT_FILTERS.vulnOnly).toBe(false);
    expect(DEFAULT_FILTERS.severity).toBeNull();
    expect(graphScopePresetForFilters(DEFAULT_FILTERS)).toBe("relevant");
    expect(graphScopeLabelForFilters(DEFAULT_FILTERS)).toBe("Relevant paths");
  });

  it("offers factual type-based scopes without claiming collection provenance", () => {
    const cloud = createCloudEstateGraphFilters();
    const repository = createRepositoryGraphFilters();
    const environment = createEnvironmentGraphFilters();

    expect(cloud.layers.account).toBe(true);
    expect(cloud.layers.cloudResource).toBe(true);
    expect(cloud.layers.sourceFile).toBe(false);
    expect(graphScopePresetForFilters(cloud)).toBe("cloudEstate");

    expect(repository.layers.directory).toBe(true);
    expect(repository.layers.sourceFile).toBe(true);
    expect(repository.layers.package).toBe(true);
    expect(repository.layers.account).toBe(false);
    expect(graphScopePresetForFilters(repository)).toBe("repository");

    expect(environment.layers.environment).toBe(true);
    expect(environment.layers.agent).toBe(true);
    expect(environment.layers.server).toBe(true);
    expect(graphScopePresetForFilters(environment)).toBe("environment");
    for (const preset of ["cloudEstate", "repository", "environment"] as const) {
      expect(GRAPH_SCOPE_DESCRIPTIONS[preset]).toMatch(/^Type-based view/);
      expect(GRAPH_SCOPE_DESCRIPTIONS[preset]).not.toMatch(/observed/i);
    }
  });

  it("names graph scope presets by operator workflow instead of raw depth", () => {
    const immediate = createImmediateGraphFilters("cursor");
    const expanded = createExpandedGraphFilters();
    const assetDrift = createAssetLifecycleDriftGraphFilters();

    expect(immediate.maxDepth).toBe(1);
    expect(immediate.pageSize).toBe(25);
    expect(graphScopeLabelForFilters(immediate)).toBe("Immediate");
    expect(expanded.maxDepth).toBe(3);
    expect(expanded.pageSize).toBe(250);
    expect(graphScopeLabelForFilters(expanded)).toBe("Expanded");
    expect(assetDrift.relationshipScope).toBe("governance");
    expect(assetDrift.layers.driftIncident).toBe(true);
    expect(graphScopePresetForFilters(assetDrift)).toBe("assetDrift");
    expect(graphScopeLabelForFilters(assetDrift)).toBe(
      "Asset lifecycle drift",
    );
  });

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
