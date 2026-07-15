/**
 * Both-theme legible "toned chip" classes.
 *
 * The dark-canvas UI historically styled status/severity chips with
 * `bg-<hue>-950 text-<hue>-200`, which computes pale-on-pale (≈1.1:1) on the
 * light surface. Every tone below ships a light pair (`bg-<hue>-500/10
 * text-<hue>-700 border-<hue>-500/30`, AA ≥ 4.5:1 on the light card) plus a
 * `dark:`-scoped restore of the original dark treatment. Use this for
 * semantic status/severity chips instead of hand-rolling color classes.
 */
export type ChipTone =
  // severity
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  // status
  | "ok"
  | "warn"
  | "danger"
  | "neutral"
  // brand
  | "accent";

const TONE_CLASS: Readonly<Record<ChipTone, string>> = {
  critical:
    "border-red-500/30 bg-red-500/10 text-red-700 dark:border-red-500/40 dark:bg-red-950/40 dark:text-red-200",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:border-orange-500/40 dark:bg-orange-950/40 dark:text-orange-200",
  medium:
    "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-200",
  low: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:border-sky-500/40 dark:bg-sky-950/40 dark:text-sky-200",
  info: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:border-blue-500/40 dark:bg-blue-950/40 dark:text-blue-200",
  ok: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:border-emerald-500/40 dark:bg-emerald-950/40 dark:text-emerald-200",
  warn: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-200",
  danger:
    "border-red-500/30 bg-red-500/10 text-red-700 dark:border-red-500/40 dark:bg-red-950/40 dark:text-red-200",
  neutral:
    "border-slate-500/30 bg-slate-500/10 text-slate-700 dark:border-slate-500/40 dark:bg-slate-900/50 dark:text-slate-200",
  accent:
    "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:border-emerald-500/40 dark:bg-emerald-950/40 dark:text-emerald-200",
};

/** Both-theme (light + dark) border/bg/text classes for a semantic chip tone. */
export function tonedChipClass(tone: ChipTone): string {
  return TONE_CLASS[tone];
}
