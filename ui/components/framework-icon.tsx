"use client";

import { useState } from "react";

import { frameworkLogoMeta } from "@/lib/framework-logos";

type FrameworkIconProps = {
  frameworkId: string;
  size?: number;
  className?: string;
};

/**
 * Framework brand tile — full-color vendored marks (console-style), with
 * monogram fallback when no asset ships or the image fails to load.
 */
export function FrameworkIcon({ frameworkId, size = 24, className = "" }: FrameworkIconProps) {
  const meta = frameworkLogoMeta(frameworkId);
  const [imageFailed, setImageFailed] = useState(false);

  if (!meta) return null;

  const dimension = { width: size, height: size };

  if (meta.src && !imageFailed) {
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img
        src={meta.src}
        alt=""
        aria-hidden="true"
        className={`shrink-0 rounded-md object-contain shadow-sm ring-1 ring-[color:var(--border-subtle)] ${className}`}
        style={dimension}
        onError={() => setImageFailed(true)}
      />
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
