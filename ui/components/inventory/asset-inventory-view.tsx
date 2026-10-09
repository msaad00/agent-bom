"use client";

import { useMemo } from "react";

import { InventoryErrorState } from "@/components/inventory/inventory-error-state";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { InventoryPagination } from "@/components/inventory/inventory-pagination";
import { InventoryFacetBar } from "@/components/inventory/inventory-facet-bar";
import { PageLaneHeader } from "@/components/page-lane";
import { SeverityBadge } from "@/components/severity-badge";
import { Drawer } from "@/components/drawer";
import { StatStrip } from "@/components/stat-strip";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { AssetDetail } from "@/components/inventory/asset-detail";
import { useInventorySelection } from "@/lib/inventory-selection";
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
    filters,
    page,
    summary: estateSummary,
    loading,
    error,
    errorKind,
    scopeConflict,
    setFilter,
    details,
    detailLoadingId,
    detailError,
    clearFilters,
    reload,
    loadAssetDetail,
  } = useInventory();

  const allRows = useMemo(() => model?.rowsByKind[kind] ?? [], [model, kind]);
  const total = model?.totalsByKind[kind] ?? 0;
  const loadedCount = model?.loadedByKind[kind] ?? 0;
  const summary = useMemo(() => summarizeRows(allRows), [allRows]);
  const { selected, select } = useInventorySelection(allRows, model?.scanId, loadAssetDetail);

  const header = (
    <PageLaneHeader
      lane={config.lane}
      title={config.label}
      subtitle={config.description}
    />
  );

  if (scopeConflict) {
    return <div className="space-y-5">
      {header}
      <PageEmptyState title="No assets match these filters"
        detail="The selected types do not belong to this asset category. Other filters and the selected snapshot are retained." />
      <button type="button" onClick={() => setFilter("type", "")} className="rounded-lg border border-outline px-3 py-2 text-sm hover:bg-surface-muted">Clear type filter</button>
    </div>;
  }

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
        <InventoryErrorState error={error} errorKind={errorKind} onRetry={reload} />
      </div>
    );
  }

  if (!model) {
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
    <div className="flex min-h-0 flex-col gap-5" aria-busy={loading}>
      {header}
      {loading ? <p role="status" className="text-xs text-ink-secondary">Updating results… showing previous results.</p> : null}

      <InventoryFacetBar
        severityFilter={severityFilter === "all" ? "" : severityFilter}
        onSeverityFilterChange={onSeverityFilterChange}
      />

      <StatStrip
        items={[
          { label: "Matching kind assets", value: total.toLocaleString() },
          { label: "Matching filters", value: model.matchingTotal.toLocaleString() },
          { label: "Loaded rows", value: loadedCount.toLocaleString() },
          { label: "Loaded with findings", value: summary.withFindings.toLocaleString(), accent: summary.withFindings > 0 ? "warn" : "neutral" },
          { label: "Loaded direct findings", value: summary.totalFindings.toLocaleString() },
        ]}
      />

      <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs leading-5 text-[color:var(--text-secondary)]">
        <span className="font-medium text-[color:var(--text-secondary)]">Coverage:</span> {config.coverageNote}

      </div>

      {estateSummary?.collection_coverage?.status === "partial" ? (
        <p role="status" className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-ink-secondary">
          Collection gap: {estateSummary.collection_coverage.reason}
        </p>
      ) : null}
      <InventoryPagination />

      {model.matchingTotal === 0 ? (
        <PageEmptyState
          title={Object.values(filters).some(Boolean) || page?.pagination.facet_filtered ? `No ${config.label.toLowerCase()} match these filters` : `No ${config.label.toLowerCase()} in the current scope`}
          detail="No recorded assets of this type match the selected snapshot and filters. This does not establish collection coverage."
          action={{ label: "Clear filters", onClick: clearFilters, variant: "secondary" }}
        />
      ) : (
        <>
          <DataTable<AssetRow>
            columns={columns}
            rows={allRows}
            rowKey={(row) => row.id}
            onRowClick={(row) => {
              select(row.id);
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
        <Drawer open={selected !== null} onClose={() => select(null)} title="Asset details" ariaLabel="Asset details" size="xl" resizable={false}>
        {selected ? (
          <AssetDetail
            row={selected}
            config={config}
            detail={details[selected.id]}
            loading={detailLoadingId === selected.id}
            error={detailError}
            scanId={model.scanId}
          />
        ) : null}
        </Drawer>
        </>
      )}

      {error && (errorKind === "network" || errorKind === "request") ? (
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
            <div className="break-words [overflow-wrap:anywhere] font-medium text-[color:var(--foreground)]">{row.label}</div>
            {secondary ? (
              <div className="break-words [overflow-wrap:anywhere] text-[11px] text-[color:var(--text-tertiary)]">{secondary}</div>
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
          <span className="break-words [overflow-wrap:anywhere] text-[color:var(--text-tertiary)]">{row.dataSources.join(", ")}</span>
        ) : (
          <span className="text-[color:var(--text-tertiary)]">—</span>
        ),
    },
  ];
}
