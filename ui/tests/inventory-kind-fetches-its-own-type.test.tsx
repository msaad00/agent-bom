/**
 * Inventory routes read the dedicated inventory projection, never an arbitrary
 * ranked page from `/v1/graph`. The summary selects one exact snapshot; every
 * list request and continuation cursor stays pinned to that snapshot and to
 * the route/filter scope that produced the first page.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type {
  InventoryAsset,
  InventoryAssetsResponse,
  InventoryFacets,
  InventorySummaryResponse,
} from "@/lib/api";
import { InventoryProvider, useInventory } from "@/lib/inventory-context";
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

const SNAPSHOT = "inventory-snapshot-42";

function facets(): InventoryFacets {
  return {
    type: { buckets: [{ value: "agent", count: 93 }, { value: "container", count: 258 }] },
    source: { buckets: [{ value: "runtime", count: 74 }, { value: "cloud:aws", count: 19 }] },
    provider: { buckets: [{ value: "aws", count: 19 }] },
    environment: { buckets: [{ value: "production", count: 61 }] },
    severity: { buckets: [{ value: "high", count: 11 }] },
  };
}

function summary(): InventorySummaryResponse {
  return {
    schema_version: "inventory.summary.v1",
    tenant_id: "default",
    scan_id: SNAPSHOT,
    created_at: "2026-08-25T00:00:00Z",
    total_assets: 351,
    by_type: { agent: 93, container: 258 },
    by_group: { ai: 351 },
    finding_count: 18,
    facets: facets(),
    facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: SNAPSHOT },
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 351, total: 351 },
  };
}

function asset(id: string, type = "agent"): InventoryAsset {
  return {
    id,
    type,
    name: id.replace(/^\w+:/, ""),
    environment: "production",
    provider: "aws",
    risk: 8.1,
    severity: "high",
    status: "active",
    source: "runtime",
    sources: ["runtime"],
    first_seen: "2026-08-24T00:00:00Z",
    last_seen: "2026-08-25T00:00:00Z",
    attributes: {},
    compliance_tags: [],
    ecosystem: "",
    version: "",
    finding_summary: { total: 1, by_severity: { high: 1 }, ids: [`finding:${id}`], top_severity: "high" },
    relationship_count: 2,
  };
}

function page(
  assets: InventoryAsset[] = [asset("agent:one")],
  { cursor = "cursor-2", hasMore = true }: { cursor?: string; hasMore?: boolean } = {},
): InventoryAssetsResponse {
  return {
    schema_version: "inventory.assets.v1",
    tenant_id: "default",
    scan_id: SNAPSHOT,
    created_at: "2026-08-25T00:00:00Z",
    assets,
    filters: {},
    pagination: { total: 93, offset: 0, limit: 100, next_cursor: hasMore ? cursor : "", has_more: hasMore, facet_filtered: true },
    facets: facets(),
    facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: SNAPSHOT },
    completeness: {
      status: hasMore ? "truncated" : "complete",
      complete: !hasMore,
      sampled: false,
      truncated: hasMore,
      returned: assets.length,
      total: 93,
      ...(hasMore ? { reason: "asset_page_limit" } : {}),
    },
  };
}

function InventoryProbe() {
  const { model, setFilter, loadMore } = useInventory();
  return (
    <div>
      <span data-testid="loaded-agent-count">{model?.loadedByKind.agents ?? 0}</span>
      <button
        type="button"
        onClick={() => {
          setFilter("search", "payments");
          setFilter("source", "runtime");
          setFilter("provider", "aws");
          setFilter("environment", "production");
          setFilter("severity", "high");
        }}
      >
        Apply scope
      </button>
      <button type="button" onClick={() => void loadMore()}>Load more</button>
    </div>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getInventorySummary).mockResolvedValue(summary());
  vi.mocked(api.getInventoryAssets).mockResolvedValue(page());
});

describe("inventory API route scope", () => {
  it("reads summary first, then pins the kind list to its exact snapshot", async () => {
    render(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.agents.entityTypes}>
        <InventoryProbe />
      </InventoryProvider>,
    );

    await waitFor(() => expect(api.getInventoryAssets).toHaveBeenCalledTimes(1));
    expect(api.getInventorySummary).toHaveBeenCalledTimes(1);
    expect(vi.mocked(api.getInventorySummary).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(api.getInventoryAssets).mock.invocationCallOrder[0]!,
    );
    expect(api.getInventoryAssets).toHaveBeenCalledWith({
      type: ASSET_KIND_BY_ID.agents.entityTypes,
      scanId: SNAPSHOT,
      limit: 100,
      offset: 0,
    });
    expect(api.getGraph).not.toHaveBeenCalled();
  });

  it("keeps fixed type and every server filter on the continuation cursor", async () => {
    vi.mocked(api.getInventoryAssets)
      .mockResolvedValueOnce(page())
      .mockResolvedValueOnce(page())
      .mockResolvedValueOnce(page([asset("agent:two")], { hasMore: false }));

    render(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.agents.entityTypes}>
        <InventoryProbe />
      </InventoryProvider>,
    );
    await waitFor(() => expect(api.getInventoryAssets).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("button", { name: "Apply scope" }));
    await waitFor(() => expect(api.getInventoryAssets).toHaveBeenCalledTimes(2));
    expect(api.getInventoryAssets).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: ASSET_KIND_BY_ID.agents.entityTypes,
        search: "payments",
        source: "runtime",
        provider: "aws",
        environment: "production",
        severity: "high",
        scanId: SNAPSHOT,
        offset: 0,
      }),
    );

    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => expect(api.getInventoryAssets).toHaveBeenCalledTimes(3));
    expect(api.getInventoryAssets).toHaveBeenLastCalledWith({
      type: ASSET_KIND_BY_ID.agents.entityTypes,
      search: "payments",
      source: "runtime",
      provider: "aws",
      environment: "production",
      severity: "high",
      scanId: SNAPSHOT,
      limit: 100,
      cursor: "cursor-2",
    });
    expect(api.getGraph).not.toHaveBeenCalled();
  });

  it("keeps the overview untyped while still using the inventory projection", async () => {
    render(<InventoryProvider><InventoryProbe /></InventoryProvider>);

    await waitFor(() => expect(api.getInventoryAssets).toHaveBeenCalledTimes(1));
    expect(vi.mocked(api.getInventoryAssets).mock.calls[0]?.[0]?.type).toBeUndefined();
    expect(api.getGraph).not.toHaveBeenCalled();
  });

  it("refetches the list without refetching summary when the routed kind changes", async () => {
    const { rerender } = render(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.agents.entityTypes}>
        <InventoryProbe />
      </InventoryProvider>,
    );
    await waitFor(() => expect(api.getInventoryAssets).toHaveBeenCalledTimes(1));

    rerender(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.containers.entityTypes}>
        <InventoryProbe />
      </InventoryProvider>,
    );

    await waitFor(() => expect(api.getInventoryAssets).toHaveBeenCalledTimes(2));
    expect(api.getInventorySummary).toHaveBeenCalledTimes(1);
    expect(api.getInventoryAssets).toHaveBeenLastCalledWith(
      expect.objectContaining({ type: ASSET_KIND_BY_ID.containers.entityTypes, scanId: SNAPSHOT }),
    );
    expect(api.getGraph).not.toHaveBeenCalled();
  });
});
