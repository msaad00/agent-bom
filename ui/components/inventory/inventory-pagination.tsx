"use client";

import { useInventory } from "@/lib/inventory-context";

/** Server pages replace the current rows; paging never accumulates an unbounded table. */
export function InventoryPagination() {
  const { page, loading, loadingMore, hasMore, loadMore, previousPage, pageSize, setPageSize } = useInventory();
  if (!page) return null;
  const { offset, total } = page.pagination;
  const start = page.assets.length ? offset + 1 : 0;
  const end = offset + page.assets.length;
  const busy = loading || loadingMore;
  return <nav aria-label="Asset pages" className="flex flex-wrap items-center justify-between gap-3 text-xs text-ink-secondary">
    <span aria-live="polite">Showing {start.toLocaleString()}–{end.toLocaleString()} of {total.toLocaleString()} matching assets</span>
    <div className="flex items-center gap-3">
      <label>Rows per page <select aria-label="Rows per page" value={pageSize} disabled={busy} onChange={event => setPageSize(Number(event.target.value))} className="rounded border border-outline bg-surface px-2 py-1">{[25, 50, 100].map(size => <option key={size} value={size}>{size}</option>)}</select></label>
      <button type="button" disabled={busy || offset === 0} onClick={() => void previousPage()} className="graph-chip disabled:opacity-50">Previous</button>
      <span>Page {Math.floor(offset / pageSize) + 1} of {Math.max(1, Math.ceil(total / pageSize))}</span>
      <button type="button" disabled={busy || !hasMore} onClick={() => void loadMore()} className="graph-chip disabled:opacity-50">Next</button>
      {busy ? <span role="status">Loading page…</span> : null}
    </div>
  </nav>;
}
