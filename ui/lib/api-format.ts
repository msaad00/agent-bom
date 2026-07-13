/**
 * Presentation helpers shared across the dashboard. Lives next to
 * `api.ts` because callers currently import these from `@/lib/api`;
 * `api.ts` re-exports each one to preserve that surface while letting
 * the actual implementations live in this smaller, single-purpose
 * module. First step toward the broader `ui/lib/api.ts` decomposition
 * tracked in #1965.
 */

import type { Agent } from "./api";

export function severityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "text-[color:var(--severity-critical)] bg-[color:var(--severity-critical-bg)] border-[color:var(--severity-critical-border)]";
    case "high":
      return "text-[color:var(--severity-high)] bg-[color:var(--severity-high-bg)] border-[color:var(--severity-high-border)]";
    case "medium":
      return "text-[color:var(--severity-medium)] bg-[color:var(--severity-medium-bg)] border-[color:var(--severity-medium-border)]";
    case "low":
      return "text-[color:var(--severity-low)] bg-[color:var(--severity-low-bg)] border-[color:var(--severity-low-border)]";
    default:
      return "text-[color:var(--text-secondary)] bg-[color:var(--surface-muted)] border-[color:var(--border-subtle)]";
  }
}

export function severityDot(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "bg-[color:var(--severity-critical)]";
    case "high":
      return "bg-[color:var(--severity-high)]";
    case "medium":
      return "bg-[color:var(--severity-medium)]";
    case "low":
      return "bg-[color:var(--severity-low)]";
    default:
      return "bg-[color:var(--text-tertiary)]";
  }
}

export function formatDate(iso: string): string {
  if (!iso?.trim()) return "—";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return "—";
  return parsed.toLocaleString();
}

export function isConfigured(agent: Agent): boolean {
  return agent.status !== "installed-not-configured";
}
