"use client";

import Link from "next/link";
import { Bot, Server, Wrench, Package, Database, UserRound, Cloud, FileCode } from "lucide-react";
import type { InventorySummaryResponse } from "@/lib/api";

const TYPES = [
  { type: "agent", label: "Agents", icon: Bot },
  { type: "server", label: "Servers", icon: Server },
  { type: "tool", label: "Tools", icon: Wrench },
  { type: "package", label: "Packages", icon: Package },
  { type: "data_store", label: "Data stores", icon: Database },
  { type: "user,service_account,service_principal,managed_identity,federated_identity", label: "Principals", icon: UserRound },
  { type: "cloud_resource", label: "Cloud resources", icon: Cloud },
  { type: "application", label: "Applications", icon: FileCode },
] as const;

export function OverviewAssets({ summary, loading, unavailable, unavailableHref = "/inventory" }: {
  summary?: InventorySummaryResponse | null | undefined;
  loading?: boolean | undefined;
  unavailable?: boolean | undefined;
  unavailableHref?: string | undefined;
}) {
  if (loading) return <p role="status" className="py-4 text-sm text-ink-secondary">Loading recorded assets…</p>;
  if (unavailable || !summary) return <div className="py-4 text-sm text-ink-secondary"><p role="status">Recorded asset summary unavailable.</p><Link href={unavailableHref} className="mt-2 inline-block text-emerald-700 dark:text-emerald-300">Open asset inventory</Link></div>;
  const scope = new URLSearchParams({ scan: summary.scan_id });
  for (const key of ["environment", "provider", "source", "search", "severity", "min_severity"] as const) {
    if (summary.filters?.[key]) scope.set(key, summary.filters[key]);
  }
  if (summary.filters?.type.length) scope.set("type", summary.filters.type.join(","));
  const exact = summary.count_exact ?? summary.facet_metadata?.exact;
  const typeScope = summary.filters?.type ?? [];

  return <section aria-label="Recorded assets" className="@container space-y-3 [overflow-wrap:anywhere]">
    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-ink-secondary">
      <span><strong className="text-foreground">{exact ? summary.total_assets.toLocaleString() : summary.total_assets > 0 ? `≥${summary.total_assets.toLocaleString()}` : "—"}</strong> recorded asset records · Snapshot {summary.scan_id}</span>
      <Link href={`/inventory?${scope}`} className="text-emerald-700 dark:text-emerald-300">Explore inventory →</Link>
    </div>
    <div className="grid grid-cols-1 gap-2 @min-[18rem]:grid-cols-2 @min-[36rem]:grid-cols-4">
      {TYPES.map(({ type, label, icon: Icon }) => {
        const selectedTypes = type.split(",").filter((entityType) => typeScope.length === 0 || typeScope.includes(entityType));
        if (selectedTypes.length === 0) return null;
        const query = new URLSearchParams(scope); query.set("type", selectedTypes.join(","));
        const count = selectedTypes.reduce((total, entityType) => total + (summary.by_type[entityType] ?? 0), 0);
        const known = exact || count > 0;
        const countLabel = exact ? count.toLocaleString() : known ? `At least ${count.toLocaleString()}` : null;
        return <Link key={type} aria-label={countLabel ? `${countLabel} ${label}` : `${label} count unavailable`} href={`/inventory?${query}`} className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border border-outline px-3 py-2.5 hover:bg-surface-muted">
          <Icon className="h-4 w-4 shrink-0 text-cyan-700 dark:text-cyan-300" aria-hidden="true" />
          <span className="max-w-full text-sm [overflow-wrap:normal]"><strong className="mr-1.5 tabular-nums">{exact ? count.toLocaleString() : known ? `≥${count.toLocaleString()}` : "—"}</strong>{label}</span>
        </Link>;
      })}
    </div>
    <div className="grid gap-3 rounded-lg bg-surface-muted p-3 text-xs text-ink-secondary sm:grid-cols-2">
      <p><strong className="block text-foreground">{exact ? "Exact within snapshot" : "Query completeness unavailable"}</strong>Counts describe typed records in this snapshot; categories above are a subset of the inventory.</p>
      <p><strong className="block text-foreground">Collection coverage: unknown</strong>Coverage not established by asset counts. Check source permissions, enabled assessments and collection results.</p>
    </div>
    <Link href="/connections" className="inline-block text-sm text-emerald-700 dark:text-emerald-300">Review sources and collection status →</Link>
  </section>;
}
