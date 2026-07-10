"use client";

import { useThemeMode } from "@/lib/theme-mode";

/** Icon-only canonical mark (dashboard favicon-scale placements). */
export function BrandMark({ className = "h-8 w-8" }: { className?: string }) {
  const theme = useThemeMode();

  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={`/brand/mark-${theme}.svg`}
      alt=""
      aria-hidden="true"
      className={`${className} object-contain`}
    />
  );
}
