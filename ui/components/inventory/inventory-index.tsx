"use client";

import Link from "next/link";
import { useMemo, useState } from "react";


import { ApiOfflineState } from "@/components/api-offline-state";
import { InventoryFacetBar } from "@/components/inventory/inventory-facet-bar";
import { PageLaneHeader } from "@/components/page-lane";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { AssetDetail } from "@/components/inventory/asset-detail";
import { SeverityBadge } from "@/components/severity-badge";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { ICON_SIZE } from "@/lib/icon-sizes";
import { useInventory } from "@/lib/inventory-context";
import { ASSET_KINDS, ASSET_KIND_BY_ID, type AssetRow } from "@/lib/inventory";

export function InventoryIndex() {
  const { model, summary, loading, error, errorKind, hasMore, loadingMore, loadMore,
    details, detailLoadingId, detailError, loadAssetDetail } = useInventory();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const rows = useMemo(() => Object.values(model?.rowsByKind ?? {}).flat(), [model]);
  const selected = rows.find((row) => row.id === selectedId) ?? null;

  const header = (
    <PageLaneHeader
      lane="command"
      title="Asset inventory"
      subtitle="Explore discovered assets and their findings. Coverage reflects scanned and connected sources."
    />
  );

  const cards = useMemo(() => {
    if (!summary) return [];
    const typeCounts = new Map(
      (model?.facets.type.buckets ?? summary.facets.type.buckets)
        .filter((bucket) => bucket.value)
        .map((bucket) => [bucket.value!, bucket.count]),
    );
    return ASSET_KINDS.map((kind) => {
      return {
        kind,
        total: kind.entityTypes.reduce(
          (count, entityType) => count + (typeCounts.get(entityType) ?? 0),
          0,
        ),
      };
    });
  }, [model, summary]);

  const totals = useMemo(() => {
    const sourceCount = summary?.facets.source.buckets.filter((bucket) => bucket.value).length ?? 0;
    return {
      assets: summary?.total_assets ?? 0,
      matching: model?.matchingTotal ?? 0,
      findings: summary?.finding_count ?? 0,
      sources: sourceCount,
    };
  }, [model, summary]);

  if (loading && !model) {
    return (
      <div className="space-y-5">
        {header}
        <PageLoadingState title="Loading asset inventory" detail="Reading the correlated asset graph for this tenant." />
      </div>
    );
  }

  if (error && errorKind !== "empty") {
    return (
      <div className="space-y-5">
        {header}
        <ApiOfflineState detail={error} kind={errorKind} />
      </div>
    );
  }

  if (!summary || totals.assets === 0) {
    return (
      <div className="space-y-5">
        {header}
        <PageEmptyState
          title="No assets discovered yet"
          detail={
            errorKind === "empty" && error
              ? error
              : "Run a scan or connect a cloud, repository, or identity source to populate the asset inventory."
          }
          actions={[
            { label: "Run a scan", href: "/scan", variant: "primary" },
            { label: "Connect a source", href: "/connections", variant: "secondary" },
          ]}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {header}

      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-ink-secondary" aria-label="Snapshot summary">
        <span><strong className="text-foreground">{totals.assets.toLocaleString()}</strong> snapshot assets</span>
        <span><strong className="text-foreground">{totals.findings.toLocaleString()}</strong> snapshot findings</span>
        <span>{totals.sources.toLocaleString()} evidence sources</span>
      </div>

      <nav aria-label="Asset types" className="flex flex-wrap gap-2">
        {cards.map(({ kind, total }) => {
          const Icon = kind.icon;
          return <Link key={kind.id} href={`/inventory/${kind.id}`} className="inline-flex items-center gap-2 rounded-lg border border-outline px-3 py-2 text-xs text-ink-secondary hover:bg-surface-muted">
            <Icon className={ICON_SIZE.sm} aria-hidden="true" />
            <span>{kind.label}</span>{" "}<strong className="tabular-nums text-foreground">{total.toLocaleString()}</strong>
          </Link>;
        })}
      </nav>

      <InventoryFacetBar />

      {model?.completeness && !model.completeness.complete ? (
        <div
          data-testid="inventory-coverage"
          className="rounded-lg border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] px-3 py-2 text-xs leading-5 text-ink-secondary"
        >
          <span className="font-medium text-foreground">Evidence coverage:</span>{" "}
          {model.completeness.status}. More assets may be available beyond the rows shown.
        </div>
      ) : null}

      {model && model.matchingTotal === 0 ? (
        <PageEmptyState
          title="No assets match these filters"
          detail="The snapshot contains assets, but none match the selected filters. Clear a filter or choose another source scope."
        />
      ) : null}

      {model && model.matchingTotal > 0 ? <>
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-ink-secondary">
          <span>Showing {rows.length.toLocaleString()} of {totals.matching.toLocaleString()} matching assets</span>
          {hasMore ? <button type="button" disabled={loadingMore} onClick={() => { void loadMore(); }}
            className="rounded-lg border border-outline px-3 py-2 text-foreground disabled:opacity-50">
            {loadingMore ? "Loading…" : "Load more"}
          </button> : null}
        </div>
        <DataTable<AssetRow> columns={columns} rows={rows} rowKey={row => row.id} caption="Asset inventory"
          selectedKey={selected?.id} maxHeight="32rem" onRowClick={row => { setSelectedId(row.id); void loadAssetDetail(row.id); }} />
        {selected && model ? <section aria-label="Selected asset details">
          <div className="mb-2 flex justify-end"><button type="button" onClick={() => setSelectedId(null)} className="text-xs underline">Close asset details</button></div>
          <AssetDetail row={selected} config={ASSET_KIND_BY_ID[selected.kind]} detail={details[selected.id]}
            loading={detailLoadingId === selected.id} error={detailError} scanId={model.scanId} />
        </section> : null}
      </> : null}

    </div>
  );
}

const columns: DataTableColumn<AssetRow>[] = [
  { key: "asset", header: "Asset", cell: row => <div className="min-w-0 [overflow-wrap:anywhere]">
    <p className="font-medium text-foreground">{row.label}</p>
    <p className="text-xs text-ink-tertiary">{[row.entityType, row.version].filter(Boolean).join(" · ")}</p>
  </div> },
  { key: "severity", header: "Finding severity", cell: row => <SeverityBadge severity={row.topFindingSeverity} /> },
  { key: "findings", header: "Findings", align: "right", cell: row => row.findingCount.toLocaleString() },
  { key: "source", header: "Sources", className: "hidden md:table-cell", cell: row => row.dataSources.join(", ") || "—" },
];
