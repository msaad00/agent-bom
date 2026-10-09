import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AssetInventoryView } from "@/components/inventory/asset-inventory-view";
import { InventoryIndex } from "@/components/inventory/inventory-index";
import { api } from "@/lib/api";
import type { InventoryAssetsResponse, InventorySummaryResponse } from "@/lib/api";
import { ApiNetworkError, ApiRateLimitError } from "@/lib/api-errors";
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
    },
  };
});

const SNAPSHOT = "current-estate:abc";

function summary(): InventorySummaryResponse {
  return {
    schema_version: "inventory.summary.v1",
    tenant_id: "tenant-a",
    scan_id: SNAPSHOT,
    created_at: "2026-08-25T03:00:00Z",
    total_assets: 1,
    by_type: { package: 1 },
    by_group: { code: 1 },
    finding_count: 0,
    facets: {},
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 1, total: 1 },
  } as unknown as InventorySummaryResponse;
}

function page(): InventoryAssetsResponse {
  return {
    schema_version: "inventory.assets.v1",
    tenant_id: "tenant-a",
    scan_id: SNAPSHOT,
    created_at: "2026-08-25T03:00:00Z",
    assets: [{
      id: "pkg:requests", type: "package", name: "requests", environment: "", provider: "", risk: 0,
      severity: "none", status: "active", source: "sbom", sources: ["sbom"], first_seen: "", last_seen: "",
      attributes: {}, compliance_tags: [], ecosystem: "pypi", version: "2.32.4",
      finding_summary: { total: 0, by_severity: {}, ids: [], top_severity: "none" }, relationship_count: 0,
    }],
    filters: {},
    pagination: { total: 1, offset: 0, limit: 100, next_cursor: null, has_more: false, facet_filtered: false },
    facets: {},
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 1, total: 1 },
  } as unknown as InventoryAssetsResponse;
}

function rateLimited(url: string) {
  return new ApiRateLimitError("Too Many Requests", { status: 429, statusText: "Too Many Requests", url, method: "GET" }, 5);
}

// Mirrors the URL-scope wiring: resolving the snapshot pins it as a prop,
// which restarts both requests against that snapshot.
function Harness({ kind }: { kind?: boolean }) {
  const [scanId, setScanId] = useState<string | undefined>(undefined);
  return (
    <InventoryProvider scanId={scanId} onSnapshotResolved={setScanId}
      entityTypes={kind ? ASSET_KIND_BY_ID.packages.entityTypes : undefined}>
      {kind ? <AssetInventoryView kind="packages" /> : <InventoryIndex />}
    </InventoryProvider>
  );
}

describe("inventory non-2xx responses", () => {
  beforeEach(() => {
    vi.mocked(api.getInventorySummary).mockReset();
    vi.mocked(api.getInventoryAssets).mockReset();
  });

  for (const kind of [false, true]) {
    it(`shows an error with Retry instead of an endless skeleton on 429 (${kind ? "kind view" : "index"})`, async () => {
      vi.mocked(api.getInventorySummary)
        .mockResolvedValueOnce(summary())
        .mockRejectedValueOnce(rateLimited("/v1/inventory/summary"))
        .mockResolvedValue(summary());
      // The first page request is still in flight when the snapshot is pinned,
      // so its settlement is discarded as stale.
      vi.mocked(api.getInventoryAssets)
        .mockImplementationOnce(() => new Promise((_, reject) => setTimeout(() => reject(rateLimited("/v1/inventory/assets")), 50)))
        .mockResolvedValue(page());

      render(<Harness kind={kind} />);

      await waitFor(() => expect(screen.queryByText(/Loading (asset inventory|packages)/i)).not.toBeInTheDocument());
      const retry = await screen.findByRole("button", { name: "Retry" });
      expect(screen.getByText(/rate limit|too many requests/i)).toBeInTheDocument();
      expect(screen.queryByText("Cannot connect to the agent-bom API")).not.toBeInTheDocument();

      const summaryCalls = vi.mocked(api.getInventorySummary).mock.calls.length;
      fireEvent.click(retry);
      await waitFor(() => expect(vi.mocked(api.getInventorySummary).mock.calls.length).toBeGreaterThan(summaryCalls));
      await waitFor(() => expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument());
    });
  }
});

for (const kind of [false, true]) {
  it(`keeps transport failure distinct from HTTP errors (${kind ? "kind view" : "index"})`, async () => {
    vi.mocked(api.getInventorySummary).mockResolvedValue(summary());
    vi.mocked(api.getInventoryAssets).mockRejectedValue(new ApiNetworkError("Failed to fetch", {
      url: "/v1/inventory/assets", method: "GET",
    }));
    render(<Harness kind={kind} />);
    expect(await screen.findByRole("heading", { name: "Cannot connect to the agent-bom API" })).toBeVisible();
    expect(screen.queryByText(/HTTP 0/)).not.toBeInTheDocument();
    vi.mocked(api.getInventoryAssets).mockResolvedValue(page());
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Cannot connect to the agent-bom API" })).not.toBeInTheDocument());
  });
}
