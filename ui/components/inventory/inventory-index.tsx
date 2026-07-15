"use client";

import Link from "next/link";
import { useMemo } from "react";
import { ArrowRight } from "lucide-react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { PageLaneHeader } from "@/components/page-lane";
import { StatStrip } from "@/components/stat-strip";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { ICON_SIZE } from "@/lib/icon-sizes";
import { useInventory } from "@/lib/inventory-context";
import { ASSET_KINDS, summarizeRows } from "@/lib/inventory";

export function InventoryIndex() {
  const { model, loading, error, errorKind } = useInventory();

  const header = (
    <PageLaneHeader
      lane="command"
      title="Asset inventory"
      subtitle="Every asset the platform has discovered, by type — correlated back to findings, blast radius, and the security graph. Coverage reflects only what has actually been scanned or connected."
    />
  );

  const cards = useMemo(() => {
    if (!model) return [];
    return ASSET_KINDS.map((kind) => {
      const rows = model.rowsByKind[kind.id];
      const summary = summarizeRows(rows);
      return {
        kind,
        total: model.totalsByKind[kind.id],
        loaded: model.loadedByKind[kind.id],
        ...summary,
      };
    });
  }, [model]);

  const totals = useMemo(() => {
    if (!model) return { assets: 0, withFindings: 0, critical: 0, findings: 0 };
    let assets = 0;
    let withFindings = 0;
    let critical = 0;
    let findings = 0;
    for (const kind of ASSET_KINDS) {
      assets += model.totalsByKind[kind.id];
      const summary = summarizeRows(model.rowsByKind[kind.id]);
      withFindings += summary.withFindings;
      critical += summary.criticalAssets;
      findings += summary.totalFindings;
    }
    return { assets, withFindings, critical, findings };
  }, [model]);

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

  if (!model || totals.assets === 0) {
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

      <StatStrip
        items={[
          { label: "Assets", value: totals.assets.toLocaleString() },
          { label: "With findings", value: totals.withFindings, accent: totals.withFindings > 0 ? "warn" : "neutral" },
          { label: "Critical assets", value: totals.critical, accent: "critical" },
          { label: "Correlated findings", value: totals.findings },
        ]}
      />

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map(({ kind, total, criticalAssets, highAssets, withFindings }) => {
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
                    {empty ? "none yet" : total === 1 ? kind.singular : `${kind.singular}s`}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-[11px]">
                  {criticalAssets > 0 ? (
                    <span className="rounded-full border border-[color:var(--severity-critical)]/40 px-1.5 py-0.5 font-semibold text-[color:var(--severity-critical)]">
                      {criticalAssets} crit
                    </span>
                  ) : null}
                  {highAssets > 0 ? (
                    <span className="rounded-full border border-[color:var(--severity-high)]/40 px-1.5 py-0.5 font-semibold text-[color:var(--severity-high)]">
                      {highAssets} high
                    </span>
                  ) : null}
                  {withFindings > 0 && criticalAssets === 0 && highAssets === 0 ? (
                    <span className="rounded-full border border-[color:var(--border-subtle)] px-1.5 py-0.5 text-[color:var(--text-tertiary)]">
                      {withFindings} flagged
                    </span>
                  ) : null}
                </div>
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
