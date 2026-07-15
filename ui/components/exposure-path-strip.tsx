"use client";

import { pathDisplayTitle, type ExposurePath } from "@/lib/exposure-path";

export function ExposurePathStrip({
  path,
  active = false,
  actionLabel,
  onAction,
  showTitle = true,
}: {
  path: ExposurePath;
  active?: boolean;
  actionLabel?: string | undefined;
  onAction?: (() => void) | undefined;
  showTitle?: boolean;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border-subtle)] bg-red-950/15 px-4 py-2 text-sm">
      <span className="shrink-0 rounded border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-red-700 dark:text-red-200">
        {path.severity}
      </span>
      {typeof path.riskScore === "number" && Number.isFinite(path.riskScore) && (
        <span className="shrink-0 rounded border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 font-mono text-[11px] text-orange-700 dark:text-orange-200">
          risk {path.riskScore.toFixed(1)}
        </span>
      )}
      {showTitle ? (
        <span
          className="min-w-0 flex-1 truncate font-medium text-[var(--foreground)]"
          title={path.label}
        >
          {pathDisplayTitle(path)}
        </span>
      ) : null}
      {onAction && actionLabel && (
        <button
          type="button"
          onClick={onAction}
          className="shrink-0 rounded border border-red-500/30 px-2 py-1 text-xs text-red-700 dark:text-red-200 transition hover:border-red-400 hover:bg-red-500/10"
        >
          {active ? "Show all" : actionLabel}
        </button>
      )}
    </div>
  );
}
