"use client";

import { ChevronLeft, ChevronRight } from "lucide-react";

interface PaginationBarProps {
  page: number;
  totalPages: number;
  totalItems?: number;
  itemLabel?: string;
  onPrevious: () => void;
  onNext: () => void;
  previousDisabled?: boolean;
  nextDisabled?: boolean;
  className?: string;
}

export function PaginationBar({
  page,
  totalPages,
  totalItems,
  itemLabel = "total",
  onPrevious,
  onNext,
  previousDisabled = page <= 1,
  nextDisabled = page >= totalPages,
  className = "",
}: PaginationBarProps) {
  const summary =
    typeof totalItems === "number"
      ? `Page ${page} of ${totalPages} (${totalItems.toLocaleString()} ${itemLabel})`
      : `Page ${page} of ${totalPages}`;

  return (
    <div className={`flex flex-wrap items-center justify-between gap-3 ${className}`}>
      <p className="text-xs text-[var(--text-tertiary)]">{summary}</p>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={onPrevious}
          disabled={previousDisabled}
          className="flex items-center gap-1 rounded-md border border-[var(--border-subtle)] px-2.5 py-1 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--border-subtle)] hover:text-[var(--foreground)] disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ChevronLeft className="h-3 w-3" />
          Prev
        </button>
        <button
          type="button"
          onClick={onNext}
          disabled={nextDisabled}
          className="flex items-center gap-1 rounded-md border border-[var(--border-subtle)] px-2.5 py-1 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--border-subtle)] hover:text-[var(--foreground)] disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next
          <ChevronRight className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}
