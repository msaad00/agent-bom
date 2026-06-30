/**
 * Canonical icon-size tokens. The app currently mixes 13+ ad-hoc icon sizes
 * (w-2.5, w-3, w-3.5, w-4, w-[18px], w-5, …). Use these four tokens instead so
 * icon scale stays consistent with its role on the page:
 *
 *   icon-xs  inline glyphs inside dense text / badges
 *   icon-sm  row-leading icons in lists and tables
 *   icon-md  section / card header icons
 *   icon-lg  empty / hero state icons
 *
 * Pass the value straight into a Lucide icon's `className`, optionally combined
 * with a color utility, e.g. `<Bug className={`${ICON_SIZE.sm} text-red-400`} />`.
 */
export const ICON_SIZE = {
  xs: "w-3.5 h-3.5",
  sm: "w-4 h-4",
  md: "w-5 h-5",
  lg: "w-10 h-10",
} as const;

export type IconSize = keyof typeof ICON_SIZE;

/** Resolve an icon-size token to its Tailwind class string. */
export function iconSize(size: IconSize = "sm"): string {
  return ICON_SIZE[size];
}
