"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useRef } from "react";
import type { InventoryFilters } from "@/lib/inventory-context";

const FILTER_KEYS = ["search", "type", "environment", "provider", "source", "severity", "minSeverity"] as const;

/** Keep the resolved evidence snapshot and query scope in shareable navigation. */
export function useInventoryUrlScope() {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const query = searchParams.toString();
  const pendingQuery = useRef(query);
  const lastQuery = useRef(query);
  if (lastQuery.current !== query) {
    pendingQuery.current = query;
    lastQuery.current = query;
  }
  const replace = useCallback((next: URLSearchParams) => {
    const value = next.toString();
    if (value === pendingQuery.current) return;
    pendingQuery.current = value;
    router.replace(value ? `${pathname}?${value}` : pathname, { scroll: false });
  }, [pathname, router]);
  const initialFilters: Partial<InventoryFilters> = {};
  for (const key of FILTER_KEYS) {
    const value = searchParams.get(key === "minSeverity" ? "min_severity" : key);
    if (value) initialFilters[key] = value;
  }
  if (initialFilters.severity && !["critical", "high", "medium", "low", "info"].includes(initialFilters.severity)) {
    delete initialFilters.severity;
  }
  const onFiltersChange = useCallback((filters: InventoryFilters) => {
    const next = new URLSearchParams(pendingQuery.current);
    for (const key of FILTER_KEYS) {
      const urlKey = key === "minSeverity" ? "min_severity" : key;
      const value = filters[key];
      if (value) next.set(urlKey, value);
      else next.delete(urlKey);
    }
    replace(next);
  }, [replace]);
  const onSnapshotResolved = useCallback((scanId: string) => {
    const next = new URLSearchParams(pendingQuery.current);
    if (next.get("scan") === scanId) return;
    next.set("scan", scanId);
    next.delete("scan_id");
    replace(next);
  }, [replace]);
  return {
    scanId: searchParams.get("scan") ?? searchParams.get("scan_id") ?? undefined,
    initialFilters,
    onFiltersChange,
    onSnapshotResolved,
  };
}
