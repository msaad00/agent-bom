/** Only these non-sensitive column keys are persisted; no query or finding data. */
export const FINDING_COLUMN_LABELS = {
  priority: "Priority", asset: "Affected asset", detection: "Detection", observed: "Observed",
  remediation: "Remediation", reach: "Reach / exploit", owner: "Owner / SLA", controls: "Control mapping",
  disposition: "Disposition / attestation", scope: "Affected scope",
} as const;
export type FindingColumnKey = keyof typeof FINDING_COLUMN_LABELS;
export type FindingColumnPreferences = { version: 1; order: FindingColumnKey[]; hidden: FindingColumnKey[] };
const KEY = "agent-bom:findings-columns:v1";
export function defaultFindingColumns(): FindingColumnPreferences {
  return { version: 1, order: Object.keys(FINDING_COLUMN_LABELS) as FindingColumnKey[], hidden: ["reach", "owner", "controls", "disposition", "scope"] };
}
export function readFindingColumns(): FindingColumnPreferences {
  try {
    const value: unknown = JSON.parse(window.localStorage.getItem(KEY) ?? "null");
    if (!value || typeof value !== "object") return defaultFindingColumns();
    const raw = value as Record<string, unknown>;
    const valid = (items: unknown): items is FindingColumnKey[] => Array.isArray(items) && items.every(item => typeof item === "string" && Object.hasOwn(FINDING_COLUMN_LABELS, item)) && new Set(items).size === items.length;
    if (raw.version !== 1 || !valid(raw.order) || raw.order.length !== Object.keys(FINDING_COLUMN_LABELS).length || !valid(raw.hidden)) return defaultFindingColumns();
    return { version: 1, order: raw.order, hidden: raw.hidden };
  } catch { return defaultFindingColumns(); }
}
export function writeFindingColumns(value: FindingColumnPreferences): void {
  try { window.localStorage.setItem(KEY, JSON.stringify({ version: 1, order: value.order, hidden: value.hidden })); } catch { /* Preference storage is optional. */ }
}
