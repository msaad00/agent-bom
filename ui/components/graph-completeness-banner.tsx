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
  total?: number | undefined;
  reason?: string | undefined;
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
  // ONE derivation per sentence. These three numbers appear together, so they
  // must come from the same source: mixing an API `returned`/`total` with a
  // locally-computed `omitted` produced "Showing 5,264 of 4,904 · 4,798
  // omitted" — more shown than exist, and no two figures reconciling.
  //
  // The envelope wins wholesale when it carries counts; the local props are the
  // fallback for callers that have no envelope, never a supplement to one.
  const hasEnvelopeCounts = completeness?.returned != null || completeness?.total != null;

  const returned = hasEnvelopeCounts ? completeness?.returned : visibleCount;
  const rawTotal = hasEnvelopeCounts
    ? completeness?.total
    : returned != null && omittedCount != null
      ? returned + omittedCount
      : undefined;

  // A total below what was returned is upstream incoherence, not something to
  // render as fact. Widen to what we can actually stand behind rather than
  // printing an impossibility.
  const total = rawTotal != null && returned != null ? Math.max(rawTotal, returned) : rawTotal;

  const omitted =
    returned != null && total != null
      ? Math.max(0, total - returned)
      : !hasEnvelopeCounts && omittedCount != null
        ? omittedCount
        : 0;
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
