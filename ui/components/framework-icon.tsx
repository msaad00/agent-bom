"use client";

import { useState } from "react";

import { frameworkLogoMeta } from "@/lib/framework-logos";

type FrameworkIconProps = {
  frameworkId: string;
  size?: number;
  className?: string;
};

/**
 * Fixed-size framework brand tile. Logos are full-bleed in a square slot so
 * padding/alignment stays consistent across Overview and Compliance.
 */
export function FrameworkIcon({ frameworkId, size = 32, className = "" }: FrameworkIconProps) {
  const meta = frameworkLogoMeta(frameworkId);
  const [imageFailed, setImageFailed] = useState(false);

  if (!meta) return null;

  const slot = {
    width: size,
    height: size,
    minWidth: size,
    minHeight: size,
  };

  if (meta.src && !imageFailed) {
    return (
      <span
        aria-hidden="true"
        className={`inline-flex shrink-0 overflow-hidden rounded-lg ring-1 ring-[color:var(--border-subtle)] ${className}`}
        style={slot}
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={meta.src}
          alt=""
          className="h-full w-full object-cover"
          onError={() => setImageFailed(true)}
        />
      </span>
    );
  }

  const fontSize = meta.monogram.length > 2 ? Math.max(8, size * 0.3) : Math.max(10, size * 0.36);

  return (
    <span
      aria-hidden="true"
      className={`inline-flex shrink-0 items-center justify-center rounded-lg border font-mono font-semibold leading-none ${meta.badgeClass} ${className}`}
      style={{ ...slot, fontSize }}
    >
      {meta.monogram}
    </span>
  );
}
