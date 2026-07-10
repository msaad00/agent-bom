"use client";

import { useThemeMode } from "@/lib/theme-mode";

type BrandLogoProps = {
  className?: string;
  showWordmark?: boolean;
  markClassName?: string;
  wordmarkClassName?: string;
};

/** Canonical mark + wordmark lockup from docs/images/brand (theme-aware). */
export function BrandLogo({
  className = "",
  showWordmark = true,
  markClassName = "h-8 w-8",
  wordmarkClassName = "h-[22px] w-auto",
}: BrandLogoProps) {
  const theme = useThemeMode();

  return (
    <span className={`inline-flex min-w-0 items-center gap-2.5 ${className}`}>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={`/brand/mark-${theme}.svg`}
        alt=""
        aria-hidden="true"
        className={`${markClassName} shrink-0 object-contain`}
      />
      {showWordmark && (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={`/brand/wordmark-${theme}.svg`}
          alt="agent-bom"
          className={`${wordmarkClassName} max-w-[9.5rem] shrink-0 object-contain object-left`}
        />
      )}
    </span>
  );
}
