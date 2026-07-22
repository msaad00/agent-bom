/**
 * Both-theme tone classes for graph edge lifecycle rows.
 * Avoids pale-on-pale chips that only read on the dark canvas.
 */
export type GraphEdgeChangeTone = "added" | "removed" | "changed";

const ROW_TONE: Readonly<Record<GraphEdgeChangeTone, string>> = {
  added:
    "border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-100",
  removed:
    "border-rose-500/30 bg-rose-500/10 text-rose-800 dark:border-rose-500/25 dark:bg-rose-500/10 dark:text-rose-100",
  changed:
    "border-amber-500/30 bg-amber-500/10 text-amber-800 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100",
};

const META_TONE: Readonly<Record<GraphEdgeChangeTone, string>> = {
  added: "text-emerald-700/80 dark:text-emerald-200/80",
  removed: "text-rose-700/80 dark:text-rose-200/80",
  changed: "text-amber-700/80 dark:text-amber-200/80",
};

const HEADING_TONE: Readonly<Record<GraphEdgeChangeTone, string>> = {
  added: "text-emerald-700 dark:text-emerald-400",
  removed: "text-rose-700 dark:text-rose-400",
  changed: "text-amber-700 dark:text-amber-400",
};

export function graphEdgeChangeRowClass(tone: GraphEdgeChangeTone): string {
  return ROW_TONE[tone];
}

export function graphEdgeChangeMetaClass(tone: GraphEdgeChangeTone): string {
  return META_TONE[tone];
}

export function graphEdgeChangeHeadingClass(tone: GraphEdgeChangeTone): string {
  return HEADING_TONE[tone];
}
