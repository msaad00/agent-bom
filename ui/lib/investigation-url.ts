import type { ExposurePathView } from "@/components/exposure-path-command-center";

/** Preserve existing deep-link context while changing the bounded investigation. */
export function investigationHref(pathname: string, query: string, patch: Record<string, string | null>): string {
  const params = new URLSearchParams(query);
  for (const [key, value] of Object.entries(patch)) {
    if (value) params.set(key, value);
    else params.delete(key);
  }
  return `${pathname}${params.size ? `?${params}` : ""}`;
}

export function investigationView(value: string | null): ExposurePathView {
  return value === "graph" || value === "list" ? value : "path";
}
