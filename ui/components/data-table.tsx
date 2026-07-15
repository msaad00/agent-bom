"use client";

import type { ReactNode } from "react";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";

import { ICON_SIZE } from "@/lib/icon-sizes";

export type SortDirection = "asc" | "desc";

export type DataTableColumn<T> = {
  /** Stable key — also used as the sort key when `sortable`. */
  key: string;
  /** Header cell content (usually a short label). */
  header: ReactNode;
  /** Cell renderer for a row. */
  cell: (row: T) => ReactNode;
  /** Text alignment for the column. Defaults to "left". */
  align?: "left" | "center" | "right";
  /** Mark the header as a sort control. */
  sortable?: boolean;
  /** Fixed column width (e.g. "12rem", "20%"). */
  width?: string;
  /** Extra classes applied to both header + body cells. */
  className?: string;
};

export type DataTableProps<T> = {
  columns: DataTableColumn<T>[];
  rows: T[];
  /** Stable key per row. */
  rowKey: (row: T, index: number) => string;
  /** Click handler — makes rows interactive (hover + keyboard). */
  onRowClick?: ((row: T) => void) | undefined;
  /** Key of the currently selected row (accent treatment). */
  selectedKey?: string | undefined;
  /** Active sort. When set, headers reflect direction. */
  sort?: { key: string; direction: SortDirection } | undefined;
  /** Called with a column key when a sortable header is activated. */
  onSortChange?: ((key: string) => void) | undefined;
  /** Show skeleton rows instead of data. */
  loading?: boolean | undefined;
  /** Skeleton row count while loading. Defaults to 6. */
  loadingRows?: number | undefined;
  /** Rendered in place of the body when there are no rows. */
  empty?: ReactNode;
  /** Sticky header while the body scrolls. Defaults to true. */
  stickyHeader?: boolean | undefined;
  /** Cap the scroll viewport height (e.g. "28rem"); body scrolls inside. */
  maxHeight?: string | undefined;
  /** Accessible caption / summary for screen readers. */
  caption?: string | undefined;
  className?: string | undefined;
  "data-testid"?: string | undefined;
};

const ALIGN_CLASS = {
  left: "text-left",
  center: "text-center",
  right: "text-right",
} as const;

/**
 * Dense, token-styled table — the standard for list surfaces. Sticky header,
 * row hover + selection, sortable-ready headers, horizontal + vertical scroll
 * scoped inside its own container, plus loading + empty states. Both themes.
 *
 * @example
 * ```tsx
 * <DataTable
 *   rows={findings}
 *   rowKey={(f) => f.id}
 *   selectedKey={active?.id}
 *   onRowClick={setActive}
 *   sort={{ key: "cvss", direction: "desc" }}
 *   onSortChange={cycleSort}
 *   maxHeight="30rem"
 *   columns={[
 *     { key: "pkg", header: "Package", cell: (f) => f.pkg },
 *     { key: "cvss", header: "CVSS", align: "right", sortable: true,
 *       cell: (f) => f.cvss.toFixed(1) },
 *   ]}
 * />
 * ```
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  sort,
  onSortChange,
  loading = false,
  loadingRows = 6,
  empty,
  stickyHeader = true,
  maxHeight,
  caption,
  className,
  "data-testid": testId,
}: DataTableProps<T>) {
  const interactive = typeof onRowClick === "function";
  const showEmpty = !loading && rows.length === 0;

  return (
    <div
      className={`overflow-auto rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] elev-1 ${className ?? ""}`}
      style={maxHeight ? { maxHeight } : undefined}
      data-testid={testId}
    >
      <table className="w-full border-collapse text-sm">
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead
          className={`${stickyHeader ? "sticky top-0 z-10" : ""} bg-[color:var(--surface-elevated)]`}
        >
          <tr className="border-b border-[color:var(--border-subtle)]">
            {columns.map((column) => {
              const active = sort?.key === column.key;
              const align = column.align ?? "left";
              const head = (
                <span
                  className={`inline-flex items-center gap-1 ${
                    align === "right" ? "flex-row-reverse" : ""
                  }`}
                >
                  <span>{column.header}</span>
                  {column.sortable ? (
                    <SortGlyph active={active} direction={sort?.direction} />
                  ) : null}
                </span>
              );
              return (
                <th
                  key={column.key}
                  scope="col"
                  aria-sort={
                    column.sortable
                      ? active
                        ? sort?.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                      : undefined
                  }
                  style={column.width ? { width: column.width } : undefined}
                  className={`px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-[color:var(--text-tertiary)] ${ALIGN_CLASS[align]} ${column.className ?? ""}`}
                >
                  {column.sortable && onSortChange ? (
                    <button
                      type="button"
                      onClick={() => onSortChange(column.key)}
                      className={`inline-flex rounded transition-colors hover:text-[color:var(--foreground)] ${
                        active ? "text-[color:var(--foreground)]" : ""
                      }`}
                    >
                      {head}
                    </button>
                  ) : (
                    head
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {loading
            ? Array.from({ length: loadingRows }).map((_, rowIndex) => (
                <tr
                  key={`skeleton-${rowIndex}`}
                  className="border-b border-[color:var(--border-subtle)] last:border-b-0"
                >
                  {columns.map((column, colIndex) => (
                    <td key={column.key} className="px-3 py-2.5">
                      <div
                        className="h-3 animate-pulse rounded-full bg-[color:var(--surface-muted)]"
                        style={{ width: `${72 - colIndex * 9}%` }}
                      />
                    </td>
                  ))}
                </tr>
              ))
            : rows.map((row, index) => {
                const key = rowKey(row, index);
                const selected = selectedKey != null && key === selectedKey;
                return (
                  <tr
                    key={key}
                    {...(interactive
                      ? {
                          onClick: () => onRowClick?.(row),
                          onKeyDown: (event) => {
                            if (event.key === "Enter" || event.key === " ") {
                              event.preventDefault();
                              onRowClick?.(row);
                            }
                          },
                          tabIndex: 0,
                          role: "button",
                          "aria-pressed": selected,
                        }
                      : {})}
                    data-selected={selected ? "true" : undefined}
                    className={`interactive-row border-b border-[color:var(--border-subtle)] last:border-b-0 ${
                      interactive ? "cursor-pointer" : ""
                    }`}
                  >
                    {columns.map((column) => (
                      <td
                        key={column.key}
                        className={`px-3 py-2.5 align-middle text-[color:var(--text-secondary)] ${ALIGN_CLASS[column.align ?? "left"]} ${column.className ?? ""}`}
                      >
                        {column.cell(row)}
                      </td>
                    ))}
                  </tr>
                );
              })}
        </tbody>
      </table>

      {showEmpty ? (
        <div className="px-4 py-10 text-center text-sm text-[color:var(--text-tertiary)]">
          {empty ?? "No records to display."}
        </div>
      ) : null}
    </div>
  );
}

function SortGlyph({
  active,
  direction,
}: {
  active: boolean;
  direction?: SortDirection | undefined;
}) {
  if (!active) {
    return (
      <ChevronsUpDown
        className={`${ICON_SIZE.xs} text-[color:var(--text-tertiary)]`}
        aria-hidden="true"
      />
    );
  }
  const Glyph = direction === "asc" ? ArrowUp : ArrowDown;
  return (
    <Glyph
      className={`${ICON_SIZE.xs} text-[color:var(--accent)]`}
      aria-hidden="true"
    />
  );
}
