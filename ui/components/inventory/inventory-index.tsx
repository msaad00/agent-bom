"use client";

import Link from "next/link";
import { useMemo, useState } from "react";


import { ApiOfflineState } from "@/components/api-offline-state";
import { InventoryFacetBar } from "@/components/inventory/inventory-facet-bar";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { AssetDetail } from "@/components/inventory/asset-detail";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { useInventory } from "@/lib/inventory-context";
import { ASSET_KINDS, ASSET_KIND_BY_ID, type AssetRow } from "@/lib/inventory";

export function InventoryIndex() {
  const { model, summary, loading, error, errorKind, hasMore, loadingMore, loadMore,
    details, detailLoadingId, detailError, loadAssetDetail } = useInventory();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const rows = useMemo(() => Object.values(model?.rowsByKind ?? {}).flat(), [model]);
  const selected = rows.find((row) => row.id === selectedId) ?? null;

  const header = (
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Asset inventory</h1>
        <p className="mt-1 max-w-2xl text-sm text-ink-secondary">
          Explore what exists across your environments, where it comes from, and how it connects.
        </p>
        <p className="mt-1 text-xs text-ink-tertiary">Coverage reflects scanned and connected sources.</p>
      </div>
      <Link href="/connections" className="rounded-lg border border-outline px-3 py-2 text-sm hover:bg-surface-muted">Manage connections</Link>
    </header>
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
        <span>{totals.sources.toLocaleString()} evidence sources</span>
      </div>

      <nav aria-label="Asset types" className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4">
        {cards.map(({ kind, total }) => {
          const Icon = kind.icon;
          return <Link key={kind.id} aria-label={`${kind.label} ${total.toLocaleString()}`} href={`/inventory/${kind.id}`} className="flex min-h-24 items-center gap-3 rounded-xl border border-outline bg-surface p-4 text-ink-secondary transition-colors hover:border-outline-strong hover:bg-surface-muted focus-visible:outline-2 focus-visible:outline-offset-2">
            <Icon className="h-6 w-6 shrink-0 text-cyan-600 dark:text-cyan-400" aria-hidden="true" />
            <span className="min-w-0"><strong className="block text-2xl font-semibold tabular-nums text-foreground">{total.toLocaleString()}</strong><span className="text-sm">{kind.label}</span></span>
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
  { key: "environment", header: "Environment", cell: row => row.environment || "Not recorded" },
  { key: "source", header: "Evidence sources", cell: row => row.dataSources.join(", ") || "Not recorded" },
  { key: "provider", header: "Provider", className: "hidden lg:table-cell", cell: row => row.provider || "Not recorded" },
  { key: "lastSeen", header: "Last observed", className: "hidden lg:table-cell", cell: row => row.lastSeen ? <time dateTime={row.lastSeen}>{new Date(row.lastSeen).toLocaleString()}</time> : "Not recorded" },
  { key: "findings", header: "Related findings", align: "right", cell: row => <span className="text-xs text-ink-secondary">{row.findingCount.toLocaleString()}</span> },
];
