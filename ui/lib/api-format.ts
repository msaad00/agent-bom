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
      return "text-red-400 bg-red-950 border-red-800";
    case "high":
      return "text-orange-400 bg-orange-950 border-orange-800";
    case "medium":
      return "text-yellow-400 bg-yellow-950 border-yellow-800";
    case "low":
      return "text-blue-400 bg-blue-950 border-blue-800";
    default:
      return "text-zinc-400 bg-zinc-800 border-zinc-700";
  }
}

export function severityDot(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "bg-red-500";
    case "high":
      return "bg-orange-500";
    case "medium":
      return "bg-yellow-500";
    case "low":
      return "bg-blue-500";
    default:
      return "bg-zinc-500";
  }
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

export function isConfigured(agent: Agent): boolean {
  return agent.status !== "installed-not-configured";
}
