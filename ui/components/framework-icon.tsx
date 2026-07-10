"use client";

import { useState } from "react";

import { frameworkLogoMeta } from "@/lib/framework-logos";

type FrameworkIconProps = {
  frameworkId: string;
  size?: number;
  className?: string;
};

/**
 * Small framework mark. Vendored SVGs use `currentColor`, which does not
 * inherit through `<img>` — paint them via CSS mask so they follow theme
 * foreground. Monogram badges use theme tokens (not dark-only pastels).
 */
export function FrameworkIcon({ frameworkId, size = 20, className = "" }: FrameworkIconProps) {
  const meta = frameworkLogoMeta(frameworkId);
  const [imageFailed, setImageFailed] = useState(false);

  if (!meta) return null;

  const dimension = { width: size, height: size };

  if (meta.src && !imageFailed) {
    return (
      <span
        aria-hidden="true"
        className={`relative inline-block shrink-0 ${className}`}
        style={dimension}
      >
        {/* Hidden probe — if the asset 404s, fall back to monogram. */}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={meta.src}
          alt=""
          className="pointer-events-none absolute h-0 w-0 opacity-0"
          onError={() => setImageFailed(true)}
        />
        <span
          className="block h-full w-full bg-[color:var(--foreground)] opacity-80"
          style={{
            WebkitMaskImage: `url(${meta.src})`,
            maskImage: `url(${meta.src})`,
            WebkitMaskSize: "contain",
            maskSize: "contain",
            WebkitMaskRepeat: "no-repeat",
            maskRepeat: "no-repeat",
            WebkitMaskPosition: "center",
            maskPosition: "center",
          }}
        />
      </span>
    );
  }

  const fontSize = meta.monogram.length > 2 ? Math.max(7, size * 0.32) : Math.max(8, size * 0.38);

  return (
    <span
      aria-hidden="true"
      className={`inline-flex shrink-0 items-center justify-center rounded-md border font-mono font-semibold leading-none ${meta.badgeClass} ${className}`}
      style={{ ...dimension, fontSize }}
    >
      {meta.monogram}
    </span>
  );
}
