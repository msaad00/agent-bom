"use client";

import { useMemo, useState } from "react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { InventoryFacetBar } from "@/components/inventory/inventory-facet-bar";
import { PageLaneHeader } from "@/components/page-lane";
import { SeverityBadge } from "@/components/severity-badge";
import { SplitLayout } from "@/components/split-layout";
import { StatStrip } from "@/components/stat-strip";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { AssetDetail } from "@/components/inventory/asset-detail";
import { useInventory } from "@/lib/inventory-context";
import {
  ASSET_KIND_BY_ID,
  summarizeRows,
  type AssetKindId,
  type AssetRow,
} from "@/lib/inventory";

export function AssetInventoryView({
  kind,
  severityFilter,
  onSeverityFilterChange,
}: {
  kind: AssetKindId;
  /** Controlled by the URL on routed inventory pages. */
  severityFilter?: string | undefined;
  onSeverityFilterChange?: ((severity: string) => void) | undefined;
}) {
  const config = ASSET_KIND_BY_ID[kind];
  const {
    model,
    loading,
    loadingMore,
    hasMore,
    error,
    errorKind,
    details,
    detailLoadingId,
    detailError,
    clearFilters,
    reload,
    loadMore,
    loadAssetDetail,
  } = useInventory();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const allRows = useMemo(() => model?.rowsByKind[kind] ?? [], [model, kind]);
  const total = model?.totalsByKind[kind] ?? 0;
  const loadedCount = model?.loadedByKind[kind] ?? 0;
  const summary = useMemo(() => summarizeRows(allRows), [allRows]);
  const selected = useMemo(
    () => allRows.find((row) => row.id === selectedId) ?? null,
    [allRows, selectedId],
  );

  const header = (
    <PageLaneHeader
      lane={config.lane}
      title={config.label}
      subtitle={config.description}
    />
  );

  if (loading && !model) {
    return (
      <div className="space-y-5">
        {header}
        <PageLoadingState
          title={`Loading ${config.label.toLowerCase()}`}
          detail="Reading the correlated asset graph for this tenant."
        />
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

  if (!model || total === 0) {
    return (
      <div className="space-y-5">
        {header}
        <PageEmptyState
          icon={config.icon}
          title={`No ${config.label.toLowerCase()} discovered yet`}
          detail={
            errorKind === "empty" && error
              ? error
              : `${config.coverageNote} Run a scan or connect an account to populate this inventory.`
          }
          actions={[
            { label: "Run a scan", href: "/scan", variant: "primary" },
            { label: "Connect a source", href: "/connections", variant: "secondary" },
          ]}
        />
      </div>
    );
  }

  const columns = buildColumns(kind);

  return (
    <div className="flex min-h-0 flex-col gap-5">
      {header}

      <InventoryFacetBar
        severityFilter={severityFilter === "all" ? "" : severityFilter}
        onSeverityFilterChange={onSeverityFilterChange}
      />

      <StatStrip
        items={[
          { label: "Snapshot kind assets", value: total.toLocaleString() },
          { label: "Matching filters", value: model.matchingTotal.toLocaleString() },
          { label: "Loaded rows", value: loadedCount.toLocaleString() },
          { label: "Loaded with findings", value: summary.withFindings.toLocaleString(), accent: summary.withFindings > 0 ? "warn" : "neutral" },
          { label: "Loaded direct findings", value: summary.totalFindings.toLocaleString() },
        ]}
      />

      <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs leading-5 text-[color:var(--text-secondary)]">
        <span className="font-medium text-[color:var(--text-secondary)]">Coverage:</span> {config.coverageNote}
        {model.completeness && !model.completeness.complete ? (
          <span className="ml-1 text-[color:var(--status-warn)]">
            Exact totals and facets cover the whole filtered snapshot; displayed rows and their direct correlations are {model.completeness.status}.
          </span>
        ) : null}
        {model.matchingTotal > loadedCount || hasMore ? (
          <span className="text-[color:var(--text-tertiary)]">
            {" "}
            Showing {loadedCount.toLocaleString()}
            {model.matchingTotal > loadedCount ? ` of ${model.matchingTotal.toLocaleString()} matching assets` : " matching assets"}
            {hasMore ? " — more rows are available from the pinned snapshot." : "."}
          </span>
        ) : null}
        {hasMore ? (
          <button
            type="button"
            data-testid="inventory-load-more"
            onClick={() => {
              void loadMore();
            }}
            disabled={loadingMore}
            className="ml-2 inline-flex rounded-md border border-[color:var(--border-subtle)] px-2 py-0.5 text-[11px] font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:opacity-60"
          >
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        ) : null}
      </div>

      {model.matchingTotal === 0 ? (
        <PageEmptyState
          title={`No ${config.label.toLowerCase()} match these filters`}
          detail="The selected snapshot contains this asset kind, but no rows match the current whole-inventory filters."
          action={{ label: "Clear filters", onClick: clearFilters, variant: "secondary" }}
        />
      ) : (
        <SplitLayout
        masterWidth="60%"
        master={
          <DataTable<AssetRow>
            columns={columns}
            rows={allRows}
            rowKey={(row) => row.id}
            onRowClick={(row) => {
              setSelectedId(row.id);
              void loadAssetDetail(row.id);
            }}
            selectedKey={selected?.id}
            maxHeight="calc(100vh - 22rem)"
            caption={`${config.label} inventory`}
            empty={
              <span>
                No {config.label.toLowerCase()} match the current filters.{" "}
                <button
                  type="button"
                  className="underline"
                  onClick={clearFilters}
                >
                  Clear filters
                </button>
              </span>
            }
            data-testid={`inventory-table-${kind}`}
          />
        }
        detail={selected ? (
          <AssetDetail
            row={selected}
            config={config}
            detail={details[selected.id]}
            loading={detailLoadingId === selected.id}
            error={detailError}
            scanId={model.scanId}
          />
        ) : null}
        placeholder={`Select a ${config.singular} to see its posture, attributes, and correlations.`}
        />
      )}

      {error && errorKind === "network" ? (
        <button type="button" onClick={reload} className="self-start text-xs text-[color:var(--text-tertiary)] underline">
          Retry
        </button>
      ) : null}
    </div>
  );
}

function FindingsCell({ row }: { row: AssetRow }) {
  if (row.findingCount === 0) {
    return <span className="text-[color:var(--text-tertiary)]">—</span>;
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="font-mono text-[color:var(--foreground)]">{row.findingCount}</span>
      {row.criticalCount > 0 ? (
        <span className="rounded-full border border-[color:var(--severity-critical)]/40 px-1.5 text-[10px] font-semibold text-[color:var(--severity-critical)]">
          {row.criticalCount}C
        </span>
      ) : null}
      {row.highCount > 0 ? (
        <span className="rounded-full border border-[color:var(--severity-high)]/40 px-1.5 text-[10px] font-semibold text-[color:var(--severity-high)]">
          {row.highCount}H
        </span>
      ) : null}
    </span>
  );
}

function buildColumns(kind: AssetKindId): DataTableColumn<AssetRow>[] {
  const config = ASSET_KIND_BY_ID[kind];
  const secondaryFor = (row: AssetRow): string | undefined => {
    if (kind === "packages") return [row.ecosystem, row.version].filter(Boolean).join(" · ") || undefined;
    if (kind === "cloud") return [row.provider, row.environment].filter(Boolean).join(" · ") || undefined;
    return row.entityType;
  };

  return [
    {
      key: "label",
      header: config.primaryColumn,
      sortable: false,
      cell: (row) => {
        const secondary = secondaryFor(row);
        return (
          <div className="min-w-0">
            <div className="truncate font-medium text-[color:var(--foreground)]">{row.label}</div>
            {secondary ? (
              <div className="truncate text-[11px] text-[color:var(--text-tertiary)]">{secondary}</div>
            ) : null}
          </div>
        );
      },
    },
    {
      key: "severity",
      header: "Finding severity",
      sortable: false,
      width: "7rem",
      cell: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: "findings",
      header: "Findings",
      sortable: false,
      align: "right",
      width: "8rem",
      cell: (row) => <FindingsCell row={row} />,
    },
    {
      key: "sources",
      header: "Sources",
      width: "12rem",
      cell: (row) =>
        row.dataSources.length > 0 ? (
          <span className="truncate text-[color:var(--text-tertiary)]">{row.dataSources.join(", ")}</span>
        ) : (
          <span className="text-[color:var(--text-tertiary)]">—</span>
        ),
    },
  ];
}
