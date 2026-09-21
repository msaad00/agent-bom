import type { GraphRollupAggregateCountMetadata } from "@/lib/api-types";

/** One scoped explanation where shared descendants make card counts non-additive. */
export function GraphRollupCountNotice({ metadata }: { metadata?: GraphRollupAggregateCountMetadata | undefined }) {
  if (!metadata || metadata.extra_memberships === 0) return null;
  return (
    <p className="mt-1 text-xs text-ink-secondary" title={metadata.definition}>
      {metadata.source_truncated ? "Loaded scope: " : "This level: "}
      {metadata.distinct_descendants.toLocaleString()} unique {metadata.distinct_descendants === 1 ? "descendant" : "descendants"} · {metadata.descendant_memberships.toLocaleString()} scope memberships.
      {" "}Shared descendants are counted in each scope.
    </p>
  );
}
