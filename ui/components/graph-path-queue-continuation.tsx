"use client";

import type { UnifiedGraphResponse } from "@/lib/api-types";

/** Distinguish loaded matches from unexamined pages and the server ranking window. */
export function GraphPathQueueContinuation({ graph, matches, hiddenMatches, narrowed, loading, error, onMore, pageSize = 12 }: {
  graph: UnifiedGraphResponse | null;
  matches: number;
  hiddenMatches: number;
  narrowed: boolean;
  loading: boolean;
  error: string | null;
  onMore: () => void;
  pageSize?: number;
}) {
  if (!graph) return null;
  const hasMore = graph.pagination.has_more;
  const ranking = graph.count_metadata?.ranking as { complete?: boolean; window?: number } | undefined;
  const limitedRanking = ranking?.complete === false;
  if (!hasMore && !hiddenMatches && !limitedRanking && !error) return null;
  const remaining = Math.max(0, graph.pagination.total - graph.pagination.offset - graph.pagination.limit);
  const label = loading ? "Loading more paths…" : hiddenMatches > 0
    ? `Show ${Math.min(pageSize, hiddenMatches)} more`
    : narrowed ? "Load next 25 paths" : `Show ${Math.min(pageSize, remaining || 1)} more`;
  return <div aria-label="Path queue coverage" className="my-3 space-y-2 rounded-xl border border-outline bg-surface-elevated p-3 text-xs text-ink-secondary">
    <p role="status">{matches} matching paths loaded. {hasMore
      ? "More queue pages remain; matches outside loaded pages are unknown."
      : "All pages in the available queue have been checked."}</p>
    {limitedRanking ? <p>Ranking covers a bounded subset of snapshot paths. Completing these pages does not establish complete snapshot coverage.</p> : null}
    {error ? <p role="alert">{error} Loaded evidence is retained; retry to continue.</p> : null}
    {hasMore || hiddenMatches > 0 ? <button type="button" disabled={loading} onClick={onMore} className="graph-page-action disabled:opacity-50">{label}</button> : null}
  </div>;
}
