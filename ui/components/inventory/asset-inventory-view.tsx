"use client";

import { useMemo, useState } from "react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { PageLaneHeader } from "@/components/page-lane";
import { SeverityBadge } from "@/components/severity-badge";
import { SplitLayout } from "@/components/split-layout";
import { StatStrip } from "@/components/stat-strip";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { AssetDetail } from "@/components/inventory/asset-detail";
import { useInventory } from "@/lib/inventory-context";
import {
  ASSET_KIND_BY_ID,
  dataSourceOptions,
  filterAssetRows,
  sortAssetRows,
  summarizeRows,
  type AssetKindId,
  type AssetRow,
  type AssetSortKey,
} from "@/lib/inventory";

const SEVERITY_FILTERS: { key: string; label: string }[] = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
];

const COLUMN_TO_SORT: Record<string, AssetSortKey> = {
  label: "label",
  severity: "severity",
  findings: "findings",
};

export function AssetInventoryView({ kind }: { kind: AssetKindId }) {
  const config = ASSET_KIND_BY_ID[kind];
  const { model, loading, error, errorKind, reload } = useInventory();

  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [withFindingsOnly, setWithFindingsOnly] = useState(false);
  const [sortKey, setSortKey] = useState<AssetSortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const allRows = useMemo(() => model?.rowsByKind[kind] ?? [], [model, kind]);
  const total = model?.totalsByKind[kind] ?? 0;
  const loadedCount = model?.loadedByKind[kind] ?? 0;

  const sources = useMemo(() => dataSourceOptions(allRows), [allRows]);
  const filtered = useMemo(
    () => filterAssetRows(allRows, { query, severity, dataSource: source, withFindingsOnly }),
    [allRows, query, severity, source, withFindingsOnly],
  );
  const rows = useMemo(
    () => sortAssetRows(filtered, sortKey, sortDir),
    [filtered, sortKey, sortDir],
  );
  const summary = useMemo(() => summarizeRows(allRows), [allRows]);
  const selected = useMemo(
    () => rows.find((row) => row.id === selectedId) ?? allRows.find((row) => row.id === selectedId) ?? null,
    [rows, allRows, selectedId],
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

  if (!model || allRows.length === 0) {
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

  const onSortChange = (columnKey: string) => {
    const nextKey = COLUMN_TO_SORT[columnKey];
    if (!nextKey) return;
    if (nextKey === sortKey) {
      setSortDir((dir) => (dir === "desc" ? "asc" : "desc"));
    } else {
      setSortKey(nextKey);
      setSortDir("desc");
    }
  };

  const columns = buildColumns(kind);

  return (
    <div className="flex min-h-0 flex-col gap-5">
      {header}

      <StatStrip
        items={[
          { label: "Total", value: total, hint: total > loadedCount ? `${loadedCount} loaded` : undefined },
          { label: "With findings", value: summary.withFindings, accent: summary.withFindings > 0 ? "warn" : "neutral" },
          { label: "Critical", value: summary.criticalAssets, accent: "critical" },
          { label: "High", value: summary.highAssets, accent: "high" },
          { label: "Correlated findings", value: summary.totalFindings },
        ]}
      />

      <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs leading-5 text-[color:var(--text-secondary)]">
        <span className="font-medium text-[color:var(--text-secondary)]">Coverage:</span> {config.coverageNote}
        {total > loadedCount ? (
          <span className="text-[color:var(--text-tertiary)]">
            {" "}
            Showing the first {loadedCount.toLocaleString()} of {total.toLocaleString()} — refine with the search box.
          </span>
        ) : null}
      </div>

      {/* Filter toolbar — findings-style, token-driven. */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          {SEVERITY_FILTERS.map(({ key, label }) => (
            <button
              key={key}
              type="button"
              onClick={() => setSeverity(key)}
              className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                severity === key
                  ? "border-[color:var(--border-strong)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                  : "border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
              }`}
            >
              {label}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setWithFindingsOnly((value) => !value)}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
              withFindingsOnly
                ? "border-[color:var(--border-strong)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                : "border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
            }`}
          >
            With findings
          </button>
        </div>
        <div className="flex items-center gap-2">
          {sources.length > 1 ? (
            <select
              value={source}
              onChange={(event) => setSource(event.target.value)}
              className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-1.5 text-sm text-[color:var(--text-secondary)] focus:border-[color:var(--border-strong)] focus:outline-none"
              aria-label="Filter by data source"
            >
              <option value="all">All sources</option>
              {sources.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          ) : null}
          <input
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={`Search ${config.label.toLowerCase()}…`}
            className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-1.5 text-sm text-[color:var(--foreground)] placeholder:text-[color:var(--text-tertiary)] focus:border-[color:var(--border-strong)] focus:outline-none sm:w-60"
          />
        </div>
      </div>

      <SplitLayout
        masterWidth="60%"
        master={
          <DataTable<AssetRow>
            columns={columns}
            rows={rows}
            rowKey={(row) => row.id}
            onRowClick={(row) => setSelectedId(row.id)}
            selectedKey={selected?.id}
            sort={{ key: sortKeyToColumn(sortKey), direction: sortDir }}
            onSortChange={onSortChange}
            maxHeight="calc(100vh - 22rem)"
            caption={`${config.label} inventory`}
            empty={
              <span>
                No {config.label.toLowerCase()} match the current filters.{" "}
                <button
                  type="button"
                  className="underline"
                  onClick={() => {
                    setQuery("");
                    setSeverity("all");
                    setSource("all");
                    setWithFindingsOnly(false);
                  }}
                >
                  Clear filters
                </button>
              </span>
            }
            data-testid={`inventory-table-${kind}`}
          />
        }
        detail={selected ? <AssetDetail row={selected} config={config} /> : null}
        placeholder={`Select a ${config.singular} to see its posture, attributes, and correlations.`}
      />

      {error && errorKind === "network" ? (
        <button type="button" onClick={reload} className="self-start text-xs text-[color:var(--text-tertiary)] underline">
          Retry
        </button>
      ) : null}
    </div>
  );
}

function sortKeyToColumn(key: AssetSortKey): string {
  if (key === "label") return "label";
  if (key === "findings") return "findings";
  return "severity";
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
      sortable: true,
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
      header: "Severity",
      sortable: true,
      width: "7rem",
      cell: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: "findings",
      header: "Findings",
      sortable: true,
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
