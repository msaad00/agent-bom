import type { GraphRollupPagination } from "@/lib/api-types";

/** Server-side paging for a drill-down whose direct children exceed one page. */
export function GraphRollupChildPager({
  pagination,
  onPage,
}: {
  pagination?: GraphRollupPagination | undefined;
  onPage: (offset: number) => void;
}) {
  if (!pagination || (pagination.offset === 0 && !pagination.has_more)) return null;
  const { offset, returned, total, limit } = pagination;
  const pageSize = limit ?? returned;
  const first = returned > 0 ? offset + 1 : offset;
  return (
    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-ink-secondary" data-testid="graph-rollup-child-pager">
      <span>
        Showing {first.toLocaleString()}–{(offset + returned).toLocaleString()} of {total.toLocaleString()} direct children
      </span>
      <button
        type="button"
        className="graph-chip-neutral disabled:cursor-not-allowed disabled:opacity-40"
        aria-label="Previous children"
        disabled={offset === 0}
        onClick={() => onPage(Math.max(0, offset - pageSize))}
      >
        Previous
      </button>
      <button
        type="button"
        className="graph-chip-neutral disabled:cursor-not-allowed disabled:opacity-40"
        aria-label="Next children"
        disabled={!pagination.has_more || pagination.next_offset === null}
        onClick={() => {
          if (pagination.next_offset !== null) onPage(pagination.next_offset);
        }}
      >
        Next
      </button>
    </div>
  );
}
