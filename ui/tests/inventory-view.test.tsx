import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AssetInventoryView } from "@/components/inventory/asset-inventory-view";
import { InventoryIndex } from "@/components/inventory/inventory-index";
import { InventoryProvider } from "@/lib/inventory-context";
import { api } from "@/lib/api";
import type { UnifiedGraphResponse } from "@/lib/api";

function node(
  id: string,
  entityType: string,
  overrides: Partial<UnifiedGraphResponse["nodes"][number]> = {},
): UnifiedGraphResponse["nodes"][number] {
  return {
    id,
    entity_type: entityType,
    label: id,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: 0,
    severity: "none",
    severity_id: 0,
    first_seen: "2026-07-01T00:00:00Z",
    last_seen: "2026-07-10T00:00:00Z",
    attributes: {},
    compliance_tags: [],
    data_sources: [],
    dimensions: {},
    ...overrides,
  } as UnifiedGraphResponse["nodes"][number];
}

function edge(source: string, target: string): UnifiedGraphResponse["edges"][number] {
  return {
    id: `${source}->${target}`,
    source,
    target,
    relationship: "vulnerable_to",
    direction: "directed",
    weight: 1,
    traversable: true,
    first_seen: "2026-07-01T00:00:00Z",
    last_seen: "2026-07-10T00:00:00Z",
    evidence: {},
    activity_id: 0,
  } as UnifiedGraphResponse["edges"][number];
}

function graph(
  nodes: UnifiedGraphResponse["nodes"],
  edges: UnifiedGraphResponse["edges"] = [],
): UnifiedGraphResponse {
  return {
    scan_id: "scan-1",
    tenant_id: "t1",
    created_at: "2026-07-10T00:00:00Z",
    nodes,
    edges,
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: {},
      severity_counts: {},
      relationship_types: {},
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
    pagination: { total: nodes.length, offset: 0, limit: 4000, has_more: false },
  } as unknown as UnifiedGraphResponse;
}

function renderWithProvider(ui: React.ReactElement) {
  return render(<InventoryProvider>{ui}</InventoryProvider>);
}

describe("AssetInventoryView", () => {
  it("renders correlated package rows from the graph", async () => {
    vi.spyOn(api, "getGraph").mockResolvedValue(
      graph(
        [
          node("requests", "package", {
            severity: "high",
            dimensions: { ecosystem: "pypi" },
            data_sources: ["sbom"],
          }),
          node("flask", "package", { severity: "none", data_sources: ["sbom"] }),
          node("CVE-2026-1", "vulnerability", { severity: "critical" }),
        ],
        [edge("CVE-2026-1", "requests")],
      ),
    );

    renderWithProvider(<AssetInventoryView kind="packages" />);

    const table = await screen.findByTestId("inventory-table-packages");
    await waitFor(() => expect(within(table).getByText("requests")).toBeInTheDocument());
    expect(within(table).getByText("flask")).toBeInTheDocument();
    // "pypi" ecosystem is shown as the row's secondary line.
    expect(within(table).getByText(/pypi/)).toBeInTheDocument();
  });

  it("filters rows by the search box", async () => {
    vi.spyOn(api, "getGraph").mockResolvedValue(
      graph([
        node("requests", "package", { data_sources: ["sbom"] }),
        node("flask", "package", { data_sources: ["sbom"] }),
      ]),
    );

    renderWithProvider(<AssetInventoryView kind="packages" />);
    const table = await screen.findByTestId("inventory-table-packages");
    await waitFor(() => expect(within(table).getByText("flask")).toBeInTheDocument());

    fireEvent.change(screen.getByPlaceholderText(/search packages/i), {
      target: { value: "requests" },
    });

    await waitFor(() => expect(within(table).queryByText("flask")).not.toBeInTheDocument());
    expect(within(table).getByText("requests")).toBeInTheDocument();
  });

  it("opens a detail pane with correlation links on row click", async () => {
    vi.spyOn(api, "getGraph").mockResolvedValue(
      graph(
        [
          node("requests", "package", { severity: "high", data_sources: ["sbom"] }),
          node("CVE-2026-1", "vulnerability", { severity: "critical" }),
        ],
        [edge("CVE-2026-1", "requests")],
      ),
    );

    renderWithProvider(<AssetInventoryView kind="packages" />);
    const table = await screen.findByTestId("inventory-table-packages");
    await waitFor(() => expect(within(table).getByText("requests")).toBeInTheDocument());

    fireEvent.click(within(table).getByText("requests"));

    // Correlation link into Findings scoped to this asset.
    const findingsLink = await screen.findByRole("link", { name: /Findings/i });
    expect(findingsLink).toHaveAttribute("href", "/findings?q=requests");
    expect(screen.getByRole("link", { name: /Security graph/i })).toHaveAttribute(
      "href",
      "/security-graph?package=requests",
    );
  });

  it("shows an honest empty state when the kind has no assets", async () => {
    vi.spyOn(api, "getGraph").mockResolvedValue(graph([node("agent-1", "agent")]));

    renderWithProvider(<AssetInventoryView kind="cloud" />);
    await waitFor(() =>
      expect(screen.getByText(/No cloud resources discovered yet/i)).toBeInTheDocument(),
    );
  });
});

describe("InventoryIndex", () => {
  it("renders one card per asset kind with counts", async () => {
    vi.spyOn(api, "getGraph").mockResolvedValue(
      graph([
        node("requests", "package"),
        node("srv-1", "server"),
        node("agent-1", "agent"),
      ]),
    );

    renderWithProvider(<InventoryIndex />);

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Asset inventory" })).toBeInTheDocument(),
    );
    expect(screen.getByRole("link", { name: /^Packages/ })).toHaveAttribute("href", "/inventory/packages");
    expect(screen.getByRole("link", { name: /^MCP servers/ })).toHaveAttribute("href", "/inventory/servers");
    expect(screen.getByRole("link", { name: /^Cloud resources/ })).toHaveAttribute("href", "/inventory/cloud");
  });
});
