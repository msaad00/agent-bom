"use client";

import Link from "next/link";
import { useMemo } from "react";
import { ArrowRight } from "lucide-react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { InventoryFacetBar } from "@/components/inventory/inventory-facet-bar";
import { PageLaneHeader } from "@/components/page-lane";
import { StatStrip } from "@/components/stat-strip";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { ICON_SIZE } from "@/lib/icon-sizes";
import { useInventory } from "@/lib/inventory-context";
import { ASSET_KINDS } from "@/lib/inventory";

export function InventoryIndex() {
  const { model, summary, loading, error, errorKind } = useInventory();

  const header = (
    <PageLaneHeader
      lane="command"
      title="Asset inventory"
      subtitle="Every asset the platform has discovered, by type — correlated back to findings, blast radius, and the security graph. Coverage reflects only what has actually been scanned or connected."
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

      <InventoryFacetBar />

      <StatStrip
        items={[
          { label: "Snapshot assets", value: totals.assets.toLocaleString() },
          { label: "Matching filters", value: totals.matching.toLocaleString() },
          { label: "Snapshot findings", value: totals.findings.toLocaleString(), accent: totals.findings > 0 ? "warn" : "neutral" },
          { label: "Evidence sources", value: totals.sources.toLocaleString() },
        ]}
      />

      {model?.completeness && !model.completeness.complete ? (
        <div
          data-testid="inventory-coverage"
          className="rounded-lg border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] px-3 py-2 text-xs leading-5 text-[color:var(--text-secondary)]"
        >
          <span className="font-medium text-[color:var(--foreground)]">Evidence coverage:</span>{" "}
          {model.completeness.status}. Matching totals and facets remain exact; only the displayed rows are cursor-bounded.
        </div>
      ) : null}

      {model && model.matchingTotal === 0 ? (
        <PageEmptyState
          title="No assets match these filters"
          detail="The snapshot contains assets, but none match the selected whole-inventory filters. Clear a filter or choose another source scope."
        />
      ) : null}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map(({ kind, total }) => {
          const Icon = kind.icon;
          const empty = total === 0;
          return (
            <Link
              key={kind.id}
              href={`/inventory/${kind.id}`}
              className={`group flex flex-col gap-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 transition-colors elev-1 hover:border-[color:var(--border-strong)] hover:bg-[color:var(--surface-elevated)] ${
                empty ? "opacity-70" : ""
              }`}
            >
              <div className="flex items-start gap-3">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]">
                  <Icon className={ICON_SIZE.sm} aria-hidden="true" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <h2 className="truncate text-sm font-semibold text-[color:var(--foreground)]">{kind.label}</h2>
                    <ArrowRight
                      className={`${ICON_SIZE.xs} ml-auto shrink-0 text-[color:var(--text-tertiary)] transition-transform group-hover:translate-x-0.5 group-hover:text-[color:var(--text-secondary)]`}
                      aria-hidden="true"
                    />
                  </div>
                  <p className="mt-0.5 line-clamp-2 text-[12px] leading-4 text-[color:var(--text-tertiary)]">
                    {kind.description}
                  </p>
                </div>
              </div>

              <div className="flex items-end justify-between">
                <div>
                  <span className="font-mono text-2xl font-semibold text-[color:var(--foreground)]">
                    {total.toLocaleString()}
                  </span>
                  <span className="ml-1 text-[11px] text-[color:var(--text-tertiary)]">
                    {empty ? "none yet" : total === 1 ? kind.singular : kind.plural}
                  </span>
                </div>
                <span className="text-[10px] uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">whole-query facet</span>
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
