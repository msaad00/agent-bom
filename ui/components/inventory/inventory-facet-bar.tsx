"use client";

import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";

import { ICON_SIZE } from "@/lib/icon-sizes";
import { useInventory, type InventoryFilterKey } from "@/lib/inventory-context";

function label(value: string): string {
  return value.replace(/[_:.-]+/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

export function InventoryFacetBar({
  severityFilter,
  onSeverityFilterChange,
}: {
  severityFilter?: string | undefined;
  onSeverityFilterChange?: ((severity: string) => void) | undefined;
} = {}) {
  const { model, summary, filters, fixedEntityTypes, setFilter, clearFilters } = useInventory();
  const facets = model?.facets ?? summary?.facets;
  const [search, setSearch] = useState(filters.search);

  useEffect(() => setSearch(filters.search), [filters.search]);
  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (search !== filters.search) setFilter("search", search);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [search, filters.search, setFilter]);

  const typeBuckets = useMemo(() => {
    const buckets = facets?.type.buckets ?? [];
    if (fixedEntityTypes.length === 0) return buckets;
    return buckets.filter((bucket) => bucket.value && fixedEntityTypes.includes(bucket.value));
  }, [facets, fixedEntityTypes]);
  const hasActive = Object.values(filters).some(Boolean);

  const select = (
    key: InventoryFilterKey,
    title: string,
    buckets: { value: string | null; count: number }[],
  ) => (
    <label className="flex min-w-[10rem] flex-1 flex-col gap-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-ink-tertiary sm:max-w-[14rem]">
      {title}
      <select
        aria-label={`Filter by ${title.toLowerCase()}`}
        value={key === "severity" && severityFilter !== undefined ? severityFilter : filters[key]}
        onChange={(event) => {
          const value = event.target.value;
          setFilter(key, value);
          if (key === "severity") onSeverityFilterChange?.(value || "all");
        }}
        className="h-9 rounded-lg border border-outline bg-surface px-2.5 text-xs font-normal normal-case tracking-normal text-foreground focus:border-outline-strong focus:outline-none"
      >
        <option value="">All {title.toLowerCase()}</option>
        {buckets.filter((bucket) => bucket.value).map((bucket) => (
          <option key={bucket.value!} value={bucket.value!}>
            {label(bucket.value!)} ({bucket.count.toLocaleString()})
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <section
      aria-label="Inventory filters"
      className="space-y-2"
    >
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex min-w-[14rem] flex-[2] flex-col gap-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-ink-tertiary">
          Search
          <span className="relative">
            <Search className={`${ICON_SIZE.sm} absolute left-2.5 top-2.5 text-ink-tertiary`} aria-hidden="true" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Name, id, type, source…"
              className="h-9 w-full rounded-lg border border-outline bg-surface pl-8 pr-3 text-xs font-normal normal-case tracking-normal text-foreground placeholder:text-ink-tertiary focus:border-outline-strong focus:outline-none"
            />
          </span>
        </label>
        {select("type", "Type", typeBuckets)}
        {select("environment", "Environment", facets?.environment.buckets ?? [])}
        {select("source", "Source", facets?.source.buckets ?? [])}
        {hasActive ? <button type="button" onClick={() => { clearFilters(); onSeverityFilterChange?.("all"); }}
          className="h-9 px-2 text-xs text-ink-secondary underline">Clear</button> : null}
      </div>
      <details>
        <summary className="cursor-pointer text-xs text-ink-secondary">
          Advanced filters{[filters.provider, filters.severity].filter(Boolean).length > 0
            ? ` · ${[filters.provider, filters.severity].filter(Boolean).length} active` : ""}
        </summary>
        <div className="mt-2 flex flex-wrap gap-2">
          {select("severity", "Finding severity", facets?.severity.buckets ?? [])}
          {select("provider", "Provider", facets?.provider.buckets ?? [])}
        </div>
      </details>
    </section>
  );
}
