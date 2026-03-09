"use client";

import type { LucideIcon } from "lucide-react";
import Link from "next/link";

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: {
    label: string;
    href: string;
  };
  /** Pass a retry function instead of a link */
  onRetry?: () => void;
  retryLabel?: string;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  onRetry,
  retryLabel = "Retry",
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center border border-dashed border-zinc-800 rounded-xl bg-zinc-950/30">
      <Icon className="w-10 h-10 text-zinc-700 mb-4" />
      <p className="text-sm font-medium text-zinc-400">{title}</p>
      {description && (
        <p className="text-xs text-zinc-600 mt-1 max-w-sm">{description}</p>
      )}
      {action && (
        <Link
          href={action.href}
          className="mt-5 inline-flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
        >
          {action.label}
        </Link>
      )}
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-5 inline-flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
        >
          {retryLabel}
        </button>
      )}
    </div>
  );
}

/** Compact error banner with optional retry */
export function ErrorBanner({
  message,
  hint,
  onRetry,
}: {
  message: string;
  hint?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="rounded-lg border border-red-800/50 bg-red-950/30 p-5 text-center space-y-2">
      <p className="text-sm text-red-300">{message}</p>
      {hint && <p className="text-xs text-zinc-500">{hint}</p>}
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
        >
          Retry
        </button>
      )}
    </div>
  );
}
