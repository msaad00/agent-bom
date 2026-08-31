import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AssetInventoryView } from "@/components/inventory/asset-inventory-view";
import { InventoryIndex } from "@/components/inventory/inventory-index";
import { api } from "@/lib/api";
import type {
  InventoryAsset,
  InventoryAssetDetailResponse,
  InventoryAssetsResponse,
  InventoryFacets,
  InventorySummaryResponse,
} from "@/lib/api";
import { InventoryProvider } from "@/lib/inventory-context";
import { ASSET_KIND_BY_ID } from "@/lib/inventory";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      getInventorySummary: vi.fn(),
      getInventoryAssets: vi.fn(),
      getInventoryAsset: vi.fn(),
      getGraph: vi.fn(),
    },
  };
});

const SNAPSHOT = "scan-inventory-7";

function facets(): InventoryFacets {
  return {
    type: {
      buckets: [
        { value: "package", count: 700 },
        { value: "server", count: 200 },
        { value: "agent", count: 100 },
      ],
    },
    source: { buckets: [{ value: "sbom", count: 700 }, { value: "runtime", count: 300 }] },
    provider: { buckets: [{ value: "aws", count: 300 }] },
    environment: { buckets: [{ value: "production", count: 900 }] },
    severity: { buckets: [{ value: "critical", count: 9 }, { value: "high", count: 71 }] },
  };
}

function summary(overrides: Partial<InventorySummaryResponse> = {}): InventorySummaryResponse {
  return {
    schema_version: "inventory.summary.v1",
    tenant_id: "tenant-a",
    scan_id: SNAPSHOT,
    created_at: "2026-08-25T03:00:00Z",
    total_assets: 1000,
    by_type: { package: 700, server: 200, agent: 100 },
    by_group: { ai: 300, code: 700 },
    finding_count: 123,
    facets: facets(),
    facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: SNAPSHOT },
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 1000, total: 1000 },
    ...overrides,
  };
}

function asset(id: string, overrides: Partial<InventoryAsset> = {}): InventoryAsset {
  return {
    id,
    type: "package",
    name: id.replace(/^pkg:/, ""),
    environment: "production",
    provider: "",
    risk: 9.2,
    severity: "high",
    status: "active",
    source: "sbom",
    sources: ["sbom", "lockfile"],
    first_seen: "2026-08-20T00:00:00Z",
    last_seen: "2026-08-25T00:00:00Z",
    attributes: { license: "Apache-2.0" },
    compliance_tags: ["LLM05"],
    ecosystem: "pypi",
    version: "2.32.4",
    finding_summary: {
      total: 3,
      by_severity: { critical: 1, high: 2 },
      ids: ["finding:CVE-1", "finding:CVE-2", "finding:CVE-3"],
      top_severity: "critical",
    },
    relationship_count: 4,
    ...overrides,
  };
}

function page(
  assets: InventoryAsset[] = [asset("pkg:requests"), asset("pkg:flask", { name: "flask", severity: "none" })],
  overrides: Partial<InventoryAssetsResponse> = {},
): InventoryAssetsResponse {
  return {
    schema_version: "inventory.assets.v1",
    tenant_id: "tenant-a",
    scan_id: SNAPSHOT,
    created_at: "2026-08-25T03:00:00Z",
    assets,
    filters: {},
    pagination: { total: 700, offset: 0, limit: 100, next_cursor: "cursor-2", has_more: true, facet_filtered: false },
    facets: facets(),
    facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: SNAPSHOT },
    completeness: { status: "truncated", complete: false, sampled: false, truncated: true, returned: assets.length, total: 700, reason: "asset_page_limit" },
    ...overrides,
  };
}

function detail(row: InventoryAsset = asset("pkg:requests")): InventoryAssetDetailResponse {
  return {
    schema_version: "inventory.asset.v1",
    tenant_id: "tenant-a",
    asset: row,
    node: {
      id: row.id,
      entity_type: row.type,
      label: row.name,
      attributes: { license: "Apache-2.0", owner: "platform-security" },
      compliance_tags: ["LLM05"],
    },
    edges_out: [{ id: "e1", source: row.id, target: "finding:CVE-1", relationship: "vulnerable_to" }],
    edges_in: [],
    neighbors: ["finding:CVE-1"],
    sources: [],
    impact: { affected_count: 4, affected_by_type: { agent: 2, server: 2 } },
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 1, total: 1 },
  };
}

function renderPackages(ui: React.ReactElement) {
  return render(
    <InventoryProvider entityTypes={ASSET_KIND_BY_ID.packages.entityTypes}>
      {ui}
    </InventoryProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getInventorySummary).mockResolvedValue(summary());
  vi.mocked(api.getInventoryAssets).mockResolvedValue(page());
  vi.mocked(api.getInventoryAsset).mockResolvedValue(detail());
});

describe("AssetInventoryView inventory projection", () => {
  it("renders bounded package rows and their server-authored finding summaries", async () => {
    renderPackages(<AssetInventoryView kind="packages" />);

    const table = await screen.findByTestId("inventory-table-packages");
    await waitFor(() => expect(within(table).getByText("requests")).toBeInTheDocument());
    expect(within(table).getByText("flask")).toBeInTheDocument();
    expect(within(table).getAllByText(/pypi/)).toHaveLength(2);
    expect(within(table).getAllByText("3")).toHaveLength(2);
    expect(within(table).getAllByText("1C")).toHaveLength(2);
    expect(api.getGraph).not.toHaveBeenCalled();
  });

  it("keeps whole-query totals distinct from the two displayed rows", async () => {
    renderPackages(<AssetInventoryView kind="packages" />);

    await screen.findByTestId("inventory-table-packages");
    expect(screen.getAllByText("700").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Showing 2 of 700 matching assets/i)).toBeInTheDocument();
    expect(api.getGraph).not.toHaveBeenCalled();
  });

  it("loads full graph context lazily only after a row is selected", async () => {
    renderPackages(<AssetInventoryView kind="packages" />);
    const table = await screen.findByTestId("inventory-table-packages");
    await waitFor(() => expect(within(table).getByText("requests")).toBeInTheDocument());

    expect(api.getInventoryAsset).not.toHaveBeenCalled();
    fireEvent.click(within(table).getByText("requests"));

    await waitFor(() =>
      expect(api.getInventoryAsset).toHaveBeenCalledWith("pkg:requests", SNAPSHOT),
    );
    expect(api.getInventoryAsset).toHaveBeenCalledTimes(1);
    expect(api.getGraph).not.toHaveBeenCalled();
  });

  it("does not present a filtered empty page as an empty estate", async () => {
    vi.mocked(api.getInventoryAssets).mockResolvedValue(
      page([], {
        pagination: { total: 0, offset: 0, limit: 100, next_cursor: "", has_more: false, facet_filtered: true },
        completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 0, total: 0 },
      }),
    );

    renderPackages(<AssetInventoryView kind="packages" />);

    expect(await screen.findByText(/No packages match/i)).toBeInTheDocument();
    expect(screen.queryByText(/No packages discovered yet/i)).not.toBeInTheDocument();
    expect(api.getGraph).not.toHaveBeenCalled();
  });
});

describe("InventoryIndex whole-query truth", () => {
  it("renders authoritative snapshot and kind totals despite a bounded first page", async () => {
    render(
      <InventoryProvider>
        <InventoryIndex />
      </InventoryProvider>,
    );

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Asset inventory" })).toBeInTheDocument(),
    );
    expect(screen.getByText("1,000")).toBeInTheDocument();
    const packages = screen.getByRole("link", { name: /^Packages/ });
    expect(packages).toHaveAttribute("href", "/inventory/packages");
    expect(within(packages).getByText("700")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^MCP servers/ })).toHaveAttribute("href", "/inventory/servers");
    expect(screen.getByRole("link", { name: /^AI agents/ })).toHaveAttribute("href", "/inventory/agents");
    expect(api.getGraph).not.toHaveBeenCalled();
  });

  it.each([
    { count: 0, expected: "none yet", theme: "light" },
    { count: 1, expected: "identity", theme: "dark" },
    { count: 396, expected: "identities", theme: "light" },
    { count: 396, expected: "identities", theme: "dark" },
  ])("renders the identity inventory count for $count in $theme theme", async ({ count, expected, theme }) => {
    document.documentElement.dataset.theme = theme;
    const identityFacets = facets();
    identityFacets.type.buckets.push({ value: "user", count });
    vi.mocked(api.getInventorySummary).mockResolvedValue(
      summary({
        total_assets: 1000 + count,
        facets: identityFacets,
      }),
    );
    vi.mocked(api.getInventoryAssets).mockResolvedValue(
      page([], {
        facets: identityFacets,
        pagination: { total: 1000 + count, offset: 0, limit: 100, next_cursor: "", has_more: false, facet_filtered: false },
      }),
    );

    render(
      <InventoryProvider>
        <InventoryIndex />
      </InventoryProvider>,
    );

    const identities = await screen.findByRole("link", { name: /^Identities & credentials/ });
    expect(within(identities).getByText(count.toLocaleString())).toBeInTheDocument();
    expect(within(identities).getByText(expected)).toBeInTheDocument();
    expect(within(identities).queryByText("identitys")).not.toBeInTheDocument();
    delete document.documentElement.dataset.theme;
  });
});
