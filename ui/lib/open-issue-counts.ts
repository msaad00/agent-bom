import type { IssueSeverityCounts } from "@/lib/api-types";

type SeverityCounts = Pick<IssueSeverityCounts, "critical" | "high" | "medium" | "low" | "total">;

export function openIssueSeverity(
  source: (SeverityCounts & { issues?: IssueSeverityCounts | undefined }) | null | undefined,
): SeverityCounts | null {
  return source ? (source.issues ?? source) : null;
}
