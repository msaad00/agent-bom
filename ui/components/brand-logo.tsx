"use client";

import { useThemeMode } from "@/lib/theme-mode";

/** Bump when mark/wordmark SVGs change so browsers drop stale caches. */
const BRAND_ASSET_REV = "v8";

/**
 * Product name is always `agent-bom`. The mark is BOM-with-agent-O (logo only).
 * No lockup tagline — the wordmark is enough. See docs/VISUAL_LANGUAGE.md.
 */

type BrandLogoProps = {
  className?: string;
  showWordmark?: boolean;
  /** @deprecated Tagline removed from lockup; prop kept as no-op for callers. */
  showTagline?: boolean;
  markClassName?: string;
  wordmarkClassName?: string;
  /** @deprecated Unused — tagline removed from lockup. */
  taglineClassName?: string;
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
        src={`/brand/mark-${theme}.svg?${BRAND_ASSET_REV}`}
        alt=""
        aria-hidden="true"
        className={`${markClassName} shrink-0 object-contain`}
      />
      {showWordmark ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={`/brand/wordmark-${theme}.svg?${BRAND_ASSET_REV}`}
          alt="agent-bom"
          className={`${wordmarkClassName} max-w-[9.5rem] shrink-0 object-contain object-left`}
        />
      ) : null}
    </span>
  );
}
