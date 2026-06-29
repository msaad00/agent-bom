export const SEVERITY_ORDER: Readonly<Record<string, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
  unknown: -1,
};

export function severityRank(severity: string | null | undefined): number {
  return SEVERITY_ORDER[(severity ?? "unknown").toLowerCase()] ?? -1;
}

export function severityAtOrAbove(severity: string | null | undefined, threshold: string): boolean {
  return severityRank(severity) >= severityRank(threshold);
}
