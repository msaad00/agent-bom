"use client";

/**
 * Honest truncation / LOD banner for estate graph lists.
 * Accepts API `graph_completeness` shapes or local visible/omitted counts.
 */

export type GraphCompletenessLike = {
  status?: "complete" | "sampled" | "truncated" | string;
  complete?: boolean;
  truncated?: boolean;
  sampled?: boolean;
  returned?: number;
  total?: number;
  reason?: string;
};

export function GraphCompletenessBanner({
  completeness,
  visibleCount,
  omittedCount,
  onLoadMore,
  loadMoreLabel = "Load more",
}: {
  completeness?: GraphCompletenessLike | null | undefined;
  visibleCount?: number | undefined;
  omittedCount?: number | undefined;
  onLoadMore?: (() => void) | undefined;
  loadMoreLabel?: string;
}) {
  const returned = completeness?.returned ?? visibleCount;
  const total =
    completeness?.total ??
    (returned != null && omittedCount != null ? returned + omittedCount : undefined);
  const omitted =
    omittedCount ??
    (returned != null && total != null ? Math.max(0, total - returned) : 0);
  const truncated =
    Boolean(completeness?.truncated) ||
    completeness?.status === "truncated" ||
    completeness?.status === "sampled" ||
    omitted > 0;

  if (!truncated) return null;

  const shown = returned ?? visibleCount;
  const detail =
    shown != null && total != null
      ? `Showing ${shown.toLocaleString()} of ${total.toLocaleString()}`
      : shown != null
        ? `Showing ${shown.toLocaleString()} items`
        : "Result set is bounded";
  const reason = completeness?.reason?.trim();

  return (
    <div
      role="status"
      data-testid="graph-completeness-banner"
      className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-900 dark:text-amber-100"
    >
      <div className="min-w-0 space-y-0.5">
        <p className="font-medium">
          {detail}
          {omitted > 0 ? ` · ${omitted.toLocaleString()} omitted` : ""}
        </p>
        <p className="text-[11px] opacity-90">
          {reason ||
            (completeness?.status === "sampled"
              ? "Sampled for readability — expand, filter, or page to see more."
              : "Truncated for the interactive render budget — filter or page rather than treating this as the full estate.")}
        </p>
      </div>
      {onLoadMore ? (
        <button
          type="button"
          onClick={onLoadMore}
          className="shrink-0 rounded-lg border border-amber-500/40 bg-[color:var(--surface)] px-2.5 py-1 font-medium text-[color:var(--foreground)] transition hover:border-amber-400"
        >
          {loadMoreLabel}
        </button>
      ) : null}
    </div>
  );
}
