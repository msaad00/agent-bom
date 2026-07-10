"use client";

import { useThemeMode } from "@/lib/theme-mode";

const TAGLINE = "BOM for humans & agents";
/** Bump when mark/wordmark SVGs change so browsers drop stale caches. */
const BRAND_ASSET_REV = "v6";

type BrandLogoProps = {
  className?: string;
  showWordmark?: boolean;
  showTagline?: boolean;
  markClassName?: string;
  wordmarkClassName?: string;
  taglineClassName?: string;
};

/** Canonical mark + wordmark lockup from docs/images/brand (theme-aware). */
export function BrandLogo({
  className = "",
  showWordmark = true,
  showTagline = false,
  markClassName = "h-8 w-8",
  wordmarkClassName = "h-[22px] w-auto",
  taglineClassName = "block text-[10px] font-medium leading-tight tracking-wide text-[color:var(--text-tertiary)] max-[479px]:hidden",
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
      {(showWordmark || showTagline) && (
        <span className="flex min-w-0 flex-col justify-center gap-0.5">
          {showWordmark && (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={`/brand/wordmark-${theme}.svg?${BRAND_ASSET_REV}`}
              alt="agent-bom"
              className={`${wordmarkClassName} max-w-[9.5rem] shrink-0 object-contain object-left`}
            />
          )}
          {showTagline && (
            <span className={`${taglineClassName} max-w-[14rem] truncate`}>{TAGLINE}</span>
          )}
        </span>
      )}
    </span>
  );
}
