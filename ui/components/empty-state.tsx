"use client";

import type { LucideIcon } from "lucide-react";
import { Info } from "lucide-react";

import { PageEmptyState, PageErrorState, PageState } from "@/components/states/page-state";

/**
 * These three helpers are now thin, backward-compatible wrappers over the
 * token-based, theme-aware components in `states/page-state`. The export names
 * and prop shapes are unchanged so existing importers keep working, while the
 * rendering (and dark/light theme support) is consolidated in one place.
 */

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
  icon,
  title,
  description,
  action,
  onRetry,
  retryLabel = "Retry",
}: EmptyStateProps) {
  const resolvedAction = action ?? (onRetry ? { label: retryLabel, onClick: onRetry } : undefined);
  return (
    <PageEmptyState
      title={title}
      detail={description ?? ""}
      icon={icon}
      {...(resolvedAction ? { action: resolvedAction } : {})}
    />
  );
}

/** Banner shown when a page isn't relevant to the current scan context */
export function ContextBanner({
  message,
  scanSources,
}: {
  message: string;
  scanSources?: string[];
}) {
  const suggestions = scanSources && scanSources.length > 0 ? [`Current scan sources: ${scanSources.join(", ")}`] : [];
  return (
    <PageState
      title={message}
      detail="Run a scan with MCP agent discovery to populate this page."
      icon={Info}
      tone="neutral"
      suggestions={suggestions}
    />
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
    <PageErrorState
      title={message}
      detail={hint ?? ""}
      {...(onRetry ? { action: { label: "Retry", onClick: onRetry } } : {})}
    />
  );
}
